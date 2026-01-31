from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from scapy.all import DNS, DNSQR, IP, TCP, UDP, PcapReader, Raw


@dataclass(frozen=True)
class Flow:
    key: str
    packets: int
    bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {"flow": self.key, "packets": self.packets, "bytes": self.bytes}


def _flow_key(src: str, sport: int, dst: str, dport: int, proto: str) -> str:
    return f"{src}:{sport}->{dst}:{dport} {proto}"


def _iter_packets(path: Path) -> Iterable[Any]:
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            yield pkt


def _extract_dns(pkt: Any) -> dict[str, Any] | None:
    if not pkt.haslayer(DNS):
        return None
    dns = pkt[DNS]
    query = None
    if dns.qd and isinstance(dns.qd, DNSQR):
        query = dns.qd.qname.decode(errors="ignore").rstrip(".")
    return {"type": "dns", "id": dns.id, "qr": dns.qr, "qname": query}


def _extract_http(pkt: Any) -> dict[str, Any] | None:
    if not pkt.haslayer(Raw):
        return None
    payload = bytes(pkt[Raw].load)
    if payload.startswith(b"GET ") or payload.startswith(b"POST "):
        try:
            line = payload.split(b"\r\n", 1)[0].decode("iso-8859-1")
        except UnicodeDecodeError:
            return None
        return {"type": "http", "request_line": line}
    if payload.startswith(b"HTTP/"):
        try:
            line = payload.split(b"\r\n", 1)[0].decode("iso-8859-1")
        except UnicodeDecodeError:
            return None
        return {"type": "http", "status_line": line}
    return None


def inspect_pcap(path: Path, out_path: Path, max_packets: int) -> int:
    flows: dict[str, Flow] = {}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out_path.open("w", encoding="utf-8") as out:
        for pkt in _iter_packets(path):
            count += 1
            if max_packets and count > max_packets:
                break
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "IP"
            sport = (
                int(pkt[TCP].sport)
                if pkt.haslayer(TCP)
                else int(pkt[UDP].sport)
                if pkt.haslayer(UDP)
                else 0
            )
            dport = (
                int(pkt[TCP].dport)
                if pkt.haslayer(TCP)
                else int(pkt[UDP].dport)
                if pkt.haslayer(UDP)
                else 0
            )
            key = _flow_key(ip.src, sport, ip.dst, dport, proto)
            prev = flows.get(key)
            if prev:
                flows[key] = Flow(key, prev.packets + 1, prev.bytes + len(pkt))
            else:
                flows[key] = Flow(key, 1, len(pkt))

            event = _extract_dns(pkt) or _extract_http(pkt)
            if event:
                event["flow"] = key
                out.write(json.dumps(event) + "\n")

        for flow in flows.values():
            out.write(json.dumps({"type": "flow", **flow.to_dict()}) + "\n")
    print(f"wrote {out_path}")
    return 0
