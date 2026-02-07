#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scapy_xss_analyzer.py

Учебный скрипт для ДЗ:
- перехват HTTP-трафика Scapy (sniff) + сохранение в .pcap
- разбор HTTP запросов/ответов (GET/POST, URL/параметры, headers, body)
- корректное отображение сжатых ответов (gzip/deflate) и chunked
- поиск XSS payload в запросах и отражения в ответах при анализе pcap

⚠️ Используйте только учебный сайт Google Gruyere (локально/учебный инстанс) и свои тестовые данные.
"""

from __future__ import annotations

import argparse
import gzip
import os
import random
import socket
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from scapy.all import sniff, wrpcap, rdpcap
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw


CRLF = b"\r\n"
HDR_END = b"\r\n\r\n"


# ---------------------------
# Utils: URL / DNS
# ---------------------------

def resolve_hostname(hostname: str) -> Optional[str]:
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка DNS '{hostname}': {e}")
        return None


def parse_url(url_arg: str) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
    """
    Парсит URL, возвращает hostname, port, path_with_query, scheme.
    Поддерживает: host/path, http://host:port/path?x=1
    """
    if not url_arg.startswith("http://") and not url_arg.startswith("https://"):
        url_arg = "http://" + url_arg
    try:
        p = urlparse(url_arg)
        hostname = p.hostname
        scheme = p.scheme or "http"
        port = p.port
        if port is None:
            port = 80 if scheme == "http" else 443
        path = p.path or "/"
        if p.query:
            path = f"{path}?{p.query}"
        return hostname, port, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None, None


# ---------------------------
# HTTP parsing helpers
# ---------------------------

@dataclass
class HTTPMessage:
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    direction: str  # c2s / s2c
    start_line: str
    headers: Dict[str, str] = field(default_factory=dict)  # lowercased keys
    body: bytes = b""
    body_decoded: Optional[str] = None
    is_request: bool = True

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    def when(self) -> str:
        return datetime.fromtimestamp(self.ts).strftime("%H:%M:%S.%f")[:-3]


def _safe_decode(b: bytes, enc: str) -> str:
    try:
        return b.decode(enc, errors="replace")
    except Exception:
        return b.decode("latin-1", errors="replace")


def _parse_headers(raw_headers: bytes) -> Tuple[str, Dict[str, str]]:
    text = raw_headers.decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    start = (lines[0] if lines else "").strip()
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return start, headers


def _guess_charset(content_type: Optional[str]) -> str:
    if not content_type:
        return "utf-8"
    low = content_type.lower()
    # charset=...
    if "charset=" in low:
        try:
            return low.split("charset=", 1)[1].split(";", 1)[0].strip().strip("\"'")
        except Exception:
            return "utf-8"
    return "utf-8"


def _decompress(body: bytes, content_encoding: Optional[str]) -> bytes:
    if not content_encoding:
        return body
    enc = content_encoding.lower()
    if "gzip" in enc:
        try:
            return gzip.decompress(body)
        except Exception:
            return body
    if "deflate" in enc:
        # deflate бывает "zlib-wrapped" и "raw"
        try:
            return zlib.decompress(body)
        except Exception:
            try:
                return zlib.decompress(body, -zlib.MAX_WBITS)
            except Exception:
                return body
    return body


def _dechunk(body: bytes) -> Optional[bytes]:
    """
    Раскодирует Transfer-Encoding: chunked.
    Возвращает bytes, либо None если данных недостаточно.
    """
    out = bytearray()
    i = 0
    while True:
        j = body.find(CRLF, i)
        if j == -1:
            return None
        line = body[i:j].split(b";", 1)[0].strip()
        try:
            size = int(line, 16)
        except ValueError:
            return None
        i = j + 2
        if size == 0:
            # конец чанков; далее могут быть trailer headers, но для учебных целей не критично
            return bytes(out)
        if len(body) < i + size + 2:
            return None
        out += body[i:i + size]
        i += size
        if body[i:i + 2] != CRLF:
            return None
        i += 2


def _looks_like_http_start(line: str) -> bool:
    if not line:
        return False
    return (
        line.startswith("GET ") or line.startswith("POST ") or line.startswith("PUT ")
        or line.startswith("DELETE ") or line.startswith("HEAD ") or line.startswith("OPTIONS ")
        or line.startswith("HTTP/")
    )


def parse_http_from_buffer(buf: bytes) -> Tuple[List[Tuple[bytes, bytes]], bytes]:
    """
    Достаёт из буфера 1..N HTTP сообщений. Возвращает [(raw_headers, body)], remainder.
    Поддержка:
      - Content-Length
      - Transfer-Encoding: chunked
    """
    out: List[Tuple[bytes, bytes]] = []
    i = 0

    while True:
        hdr_end = buf.find(HDR_END, i)
        if hdr_end == -1:
            break

        raw_headers = buf[i:hdr_end]
        start, headers = _parse_headers(raw_headers)

        if not _looks_like_http_start(start):
            i += 1
            continue

        body_start = hdr_end + 4
        remaining = buf[body_start:]

        transfer = headers.get("transfer-encoding", "").lower()
        clen = headers.get("content-length")

        if "chunked" in transfer:
            dechunked = _dechunk(remaining)
            if dechunked is None:
                break
            out.append((raw_headers, dechunked))

            # чтобы сдвинуть i на конец chunked сообщения — пройдём chunked ещё раз и найдём индекс
            idx = 0
            while True:
                j = remaining.find(CRLF, idx)
                size_line = remaining[idx:j].split(b";", 1)[0].strip()
                size = int(size_line, 16)
                idx = j + 2
                if size == 0:
                    # после 0 чанка обычно \r\n
                    if len(remaining) >= idx + 2 and remaining[idx:idx+2] == CRLF:
                        idx += 2
                    break
                idx = idx + size + 2  # data + \r\n
            i = body_start + idx
            continue

        if clen is None:
            # тела нет или оно в другом TCP сегменте: здесь считаем пустым телом
            out.append((raw_headers, b""))
            i = body_start
            continue

        try:
            n = int(clen)
        except ValueError:
            n = 0

        if len(remaining) < n:
            break

        body = remaining[:n]
        out.append((raw_headers, body))
        i = body_start + n

    return out, buf[i:]


def build_http_message(ts: float, src: str, sport: int, dst: str, dport: int, direction: str,
                       raw_headers: bytes, body: bytes) -> HTTPMessage:
    start, headers = _parse_headers(raw_headers)
    is_request = not start.startswith("HTTP/")
    msg = HTTPMessage(
        ts=ts, src=src, sport=sport, dst=dst, dport=dport, direction=direction,
        start_line=start, headers=headers, body=body, is_request=is_request
    )

    # decode body (если похоже на текст)
    ctype = msg.header("content-type") or ""
    charset = _guess_charset(ctype)
    decoded_body_bytes = _decompress(body, msg.header("content-encoding"))

    if "text/" in ctype.lower() or "html" in ctype.lower() or "json" in ctype.lower() or "javascript" in ctype.lower():
        msg.body_decoded = _safe_decode(decoded_body_bytes, charset)
    else:
        # всё равно попробуем текст
        if decoded_body_bytes:
            msg.body_decoded = _safe_decode(decoded_body_bytes, "utf-8")

    return msg


def pkt_addrs(pkt) -> Tuple[Optional[str], Optional[str]]:
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None


class HTTPReassembler:
    """
    Простой reassembly: буферим payload по 4-tuple (src,sport,dst,dport) в порядке захвата.
    Для localhost/учебного стенда обычно достаточно.
    """
    def __init__(self):
        self.buffers: Dict[Tuple[str, int, str, int], bytearray] = {}

    def feed(self, flow: Tuple[str, int, str, int], data: bytes):
        self.buffers.setdefault(flow, bytearray()).extend(data)

    def pop(self, flow: Tuple[str, int, str, int]) -> List[Tuple[bytes, bytes]]:
        buf = bytes(self.buffers.get(flow, b""))
        msgs, rem = parse_http_from_buffer(buf)
        self.buffers[flow] = bytearray(rem)
        return msgs


# ---------------------------
# Output helpers
# ---------------------------

def print_message(msg: HTTPMessage, show_body: bool = False, max_body: int = 1500):
    print(f"\n=== {msg.when()} [{msg.direction}] {msg.src}:{msg.sport} -> {msg.dst}:{msg.dport} ===")
    print(msg.start_line)

    # headers
    for k, v in sorted(msg.headers.items()):
        print(f"{k}: {v}")

    if show_body:
        if msg.body_decoded:
            s = msg.body_decoded
            if len(s) > max_body:
                s = s[:max_body] + "\n... (truncated) ..."
            print("\n--- body(decoded) ---")
            print(s)
        elif msg.body:
            print("\n--- body(bytes) ---")
            print(msg.body[:min(len(msg.body), 200)])


def extract_request_details(start_line: str, headers: Dict[str, str], body: bytes) -> Dict[str, object]:
    """
    Для отчёта: метод, path, query params, form params (если urlencoded).
    """
    out: Dict[str, object] = {}
    parts = start_line.split()
    if len(parts) >= 2:
        out["method"] = parts[0]
        out["path"] = parts[1]
        # query params
        if "?" in parts[1]:
            q = parts[1].split("?", 1)[1]
            out["query"] = parse_qs(q, keep_blank_values=True)
        else:
            out["query"] = {}
    out["host"] = headers.get("host")
    ctype = headers.get("content-type", "")
    if body and "application/x-www-form-urlencoded" in ctype.lower():
        try:
            out["form"] = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        except Exception:
            out["form"] = {}
    else:
        out["form"] = {}
    return out


def find_payload(haystack: bytes, payload: str) -> bool:
    try:
        return payload.encode("utf-8") in haystack
    except Exception:
        return False


def find_payload_in_text(text: Optional[str], payload: str) -> bool:
    if not text:
        return False
    return payload in text


# ---------------------------
# Stage 3 helper: send request (optional)
# ---------------------------

def send_http_request_scapy(hostname: str, port: int, path: str, custom_request: Optional[str] = None) -> bool:
    """
    Отправляет HTTP запрос через Scapy (без полноценного TCP стека).
    Может потребовать отключения RST пакетов (iptables), как в задании.
    """
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return False

    client_sport = random.randint(1025, 65500)

    if custom_request:
        http_req = custom_request
    else:
        http_req = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"

    # SYN
    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags="S", seq=random.randint(0, 2**32 - 1))
    syn_ack = sniff_one(syn, timeout=5)
    if syn_ack is None or not syn_ack.haslayer(TCP):
        print(f"Не удалось получить SYN/ACK от {hostname}:{port}")
        return False

    if syn_ack[TCP].flags != 0x12:  # SYN+ACK
        print(f"Ожидали SYN/ACK, получили flags={syn_ack[TCP].flags}")
        return False

    my_seq = syn_ack[TCP].ack
    my_ack = syn_ack[TCP].seq + 1

    # ACK
    ack = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags="A", seq=my_seq, ack=my_ack)
    from scapy.sendrecv import send
    send(ack, verbose=False)

    time.sleep(0.05)

    # PSH+ACK + Raw payload
    req = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags="PA", seq=my_seq, ack=my_ack) / http_req
    send(req, verbose=False)
    return True


def sniff_one(pkt, timeout: int = 3):
    """Мини-хелпер для получения одного ответа на отправленный пакет (используем sr1 без импорта всего)."""
    from scapy.sendrecv import sr1
    try:
        return sr1(pkt, timeout=timeout, verbose=False)
    except Exception:
        return None


# ---------------------------
# Capture + Analyze
# ---------------------------

def capture_traffic(hostname: str, port: int, timeout: int, output_file: Optional[str], iface: Optional[str]) -> List:
    """Перехватывает TCP трафик к хосту/порту."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return []

    bpf = f"tcp and host {dest_ip} and port {port}"
    print(f"[+] Capture: {hostname} ({dest_ip}) port={port}, timeout={timeout}s")
    print(f"[+] BPF: {bpf}")
    print("[+] Делай действия в браузере. Перехват идёт...")

    packets = sniff(filter=bpf, timeout=timeout, iface=iface)
    print(f"[+] Перехвачено пакетов: {len(packets)}")

    if output_file:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        wrpcap(output_file, packets)
        print(f"[+] Сохранено в: {output_file}")

    return packets


def analyze_packets(packets, port: int, payload: Optional[str] = None, show_body: bool = False, max_body: int = 2000):
    """Разбирает пакеты в HTTP сообщения, показывает и (опционально) ищет XSS payload."""
    if not packets:
        print("Нет пакетов для анализа")
        return

    reas = HTTPReassembler()
    http_msgs: List[HTTPMessage] = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        src, dst = pkt_addrs(pkt)
        if not src or not dst:
            continue

        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        raw = bytes(pkt[Raw].load)
        if not raw:
            continue

        # направление относительно "целевого порта"
        direction = "c2s" if dport == port else ("s2c" if sport == port else "tcp")
        flow = (src, sport, dst, dport)

        reas.feed(flow, raw)
        for raw_headers, body in reas.pop(flow):
            msg = build_http_message(pkt.time, src, sport, dst, dport, direction, raw_headers, body)
            http_msgs.append(msg)

    print(f"[+] Найдено HTTP сообщений (после reassembly): {len(http_msgs)}")

    # Поиск payload
    if payload:
        print(f"[+] Поиск payload: {payload}")
        req_hits: List[HTTPMessage] = []
        resp_reflect: List[HTTPMessage] = []

        for m in http_msgs:
            raw_http = (m.start_line + "\r\n").encode("latin-1", errors="ignore")
            for k, v in m.headers.items():
                raw_http += f"{k}: {v}\r\n".encode("latin-1", errors="ignore")
            raw_http += b"\r\n" + m.body

            if m.is_request and find_payload(raw_http, payload):
                req_hits.append(m)
            if (not m.is_request) and (find_payload_in_text(m.body_decoded, payload) or find_payload(raw_http, payload)):
                resp_reflect.append(m)

        print(f"[+] Requests with payload: {len(req_hits)}")
        print(f"[+] Responses reflecting payload: {len(resp_reflect)}")

        # показать детали
        for m in req_hits[:5]:
            print_message(m, show_body=show_body, max_body=max_body)
            det = extract_request_details(m.start_line, m.headers, m.body)
            if det.get("query") or det.get("form"):
                print("\n--- parsed params ---")
                print(f"host: {det.get('host')}")
                print(f"query: {det.get('query')}")
                print(f"form:  {det.get('form')}")
        for m in resp_reflect[:5]:
            print_message(m, show_body=True, max_body=max_body)

        return

    # Без payload: показать первые несколько запросов/ответов
    for m in http_msgs[:10]:
        print_message(m, show_body=show_body, max_body=max_body)


def analyze_saved_traffic(pcap_file: str, port: int, payload: Optional[str], show_body: bool, max_body: int):
    """Анализирует сохранённый трафик из .pcap файла."""
    print(f"[+] Анализ pcap: {pcap_file}")
    packets = rdpcap(pcap_file)
    analyze_packets(packets, port=port, payload=payload, show_body=show_body, max_body=max_body)


# ---------------------------
# CLI
# ---------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Анализ HTTP трафика и XSS следов в Google Gruyere с использованием Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:

1) Перехват трафика (локальный Gruyere на 8008) + сохранить pcap:
  sudo python3 scapy_xss_analyzer.py capture --host 127.0.0.1 --port 8008 --timeout 90 --output captures/traffic.pcap --show-body

2) Анализ сохранённого pcap и поиск XSS payload:
  python3 scapy_xss_analyzer.py analyze --pcap captures/traffic.pcap --port 8008 --payload "<script>alert('XSS')</script>" --show-body

3) (Опционально) отправить кастомный HTTP запрос через Scapy:
  sudo python3 scapy_xss_analyzer.py send --url "http://127.0.0.1:8008/" --request "GET / HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n"
"""
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_send = sub.add_parser("send", help="Отправить HTTP запрос (опционально, через Scapy)")
    p_send.add_argument("--url", required=True, help="URL (http://host:port/path)")
    p_send.add_argument("--request", default=None, help="Кастомный HTTP запрос строкой (\\r\\n)")
    p_send.set_defaults(_cmd="send")

    p_cap = sub.add_parser("capture", help="Перехватить трафик")
    p_cap.add_argument("--host", required=True, help="Hostname или IP (например, 127.0.0.1)")
    p_cap.add_argument("--port", type=int, default=8008, help="Порт HTTP (по умолчанию 8008)")
    p_cap.add_argument("--timeout", type=int, default=60, help="Таймаут перехвата (сек)")
    p_cap.add_argument("--iface", default=None, help="Интерфейс (опционально)")
    p_cap.add_argument("--output", default=None, help="Файл .pcap для сохранения")
    p_cap.add_argument("--payload", default=None, help="Payload для поиска прямо после захвата (опционально)")
    p_cap.add_argument("--show-body", action="store_true", help="Показывать body (decoded)")
    p_cap.add_argument("--max-body", type=int, default=2000, help="Макс символов body для вывода")
    p_cap.set_defaults(_cmd="capture")

    p_an = sub.add_parser("analyze", help="Проанализировать pcap")
    p_an.add_argument("--pcap", required=True, help="Файл .pcap")
    p_an.add_argument("--port", type=int, default=8008, help="Порт HTTP (нужен для направления c2s/s2c)")
    p_an.add_argument("--payload", default=None, help="Payload для поиска (например, <script>alert('XSS')</script>)")
    p_an.add_argument("--show-body", action="store_true", help="Показывать body (decoded)")
    p_an.add_argument("--max-body", type=int, default=4000, help="Макс символов body для вывода")
    p_an.set_defaults(_cmd="analyze")

    args = parser.parse_args()

    if args._cmd == "send":
        hostname, port, path, scheme = parse_url(args.url)
        if not hostname or not port or not path or not scheme:
            print("Ошибка: не удалось распарсить URL")
            return 2
        if scheme.lower() != "http":
            print("[-] URL использует HTTPS. Scapy-анализ полезен для HTTP (без шифрования).")
            print("    Для ДЗ поднимите Gruyere локально по HTTP.")
            return 2
        ok = send_http_request_scapy(hostname, port, path, args.request)
        print("[+]" if ok else "[-]", "Запрос отправлен" if ok else "Ошибка отправки")
        return 0 if ok else 2

    if args._cmd == "capture":
        packets = capture_traffic(args.host, args.port, args.timeout, args.output, args.iface)
        analyze_packets(packets, port=args.port, payload=args.payload, show_body=args.show_body, max_body=args.max_body)
        return 0

    if args._cmd == "analyze":
        analyze_saved_traffic(args.pcap, port=args.port, payload=args.payload, show_body=args.show_body, max_body=args.max_body)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
