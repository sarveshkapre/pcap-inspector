from __future__ import annotations

# ruff: noqa: E402

import logging
import json
import sys
from collections import Counter
from contextlib import nullcontext
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any, Iterable, TextIO, cast

# Scapy emits noisy runtime warnings on some macOS interface configurations.
# We only use Scapy for offline PCAP parsing, so keep runtime logs quiet by default.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.utils import PcapReader

_HTTP_METHODS = {
    b"GET",
    b"POST",
    b"PUT",
    b"DELETE",
    b"HEAD",
    b"OPTIONS",
    b"PATCH",
    b"CONNECT",
    b"TRACE",
}


@dataclass(frozen=True)
class Flow:
    key: str
    packets: int
    bytes: int
    first_ts: float | None = None
    last_ts: float | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"flow": self.key, "packets": self.packets, "bytes": self.bytes}
        if self.first_ts is not None:
            out["first_ts"] = self.first_ts
        if self.last_ts is not None:
            out["last_ts"] = self.last_ts
        return out


class PcapInspectorError(RuntimeError):
    pass


def _flow_key(src: str, sport: int, dst: str, dport: int, proto: str) -> str:
    return f"{_fmt_hostport(src, sport)}->{_fmt_hostport(dst, dport)} {proto}"


def _normalized_flow_key(src: str, sport: int, dst: str, dport: int, proto: str) -> str:
    left = (src, sport)
    right = (dst, dport)
    if right < left:
        left, right = right, left
    return f"{_fmt_hostport(left[0], left[1])}<->{_fmt_hostport(right[0], right[1])} {proto}"


def _flow_key_with_mode(
    src: str,
    sport: int,
    dst: str,
    dport: int,
    proto: str,
    *,
    normalize_flows: bool,
) -> str:
    if normalize_flows:
        return _normalized_flow_key(src, sport, dst, dport, proto)
    return _flow_key(src, sport, dst, dport, proto)


def _fmt_hostport(host: str, port: int) -> str:
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _iter_packets(path: Path) -> Iterable[Any]:
    try:
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                yield pkt
    except Exception as e:  # Scapy throws a variety of exceptions for invalid pcaps.
        raise PcapInspectorError(f"failed to read pcap: {path}: {e}") from e


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
    first_line = bytes(pkt[Raw].load).split(b"\r\n", 1)[0]
    try:
        line = first_line.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None
    if first_line.startswith(b"HTTP/"):
        return {"type": "http", "status_line": line}

    parts = first_line.split(b" ", 2)
    if len(parts) < 3:
        return None
    method = parts[0].upper()
    if method in _HTTP_METHODS and parts[2].startswith(b"HTTP/"):
        return {"type": "http", "request_line": line}
    return None


def _extract_flow_parts(pkt: Any) -> tuple[str, int, str, int, str] | None:
    if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
        return None
    ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
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
    return str(ip.src), sport, str(ip.dst), dport, proto


@dataclass(slots=True)
class _TcpStream:
    max_bytes: int = 256 * 1024
    max_gap: int = 512 * 1024
    max_buffered_bytes: int = 512 * 1024
    base_seq: int | None = None
    next_seq: int | None = None
    assembled: bytearray = field(default_factory=bytearray)
    segments: dict[int, bytes] = field(default_factory=dict)
    extracted: bool = False

    def push(self, seq: int, payload: bytes) -> None:
        if self.extracted or not payload:
            return
        existing = self.segments.get(seq)
        if existing is None or len(payload) > len(existing):
            self.segments[seq] = payload
        self._prune_segments()
        self._rebuild()

    def _prune_segments(self) -> None:
        if not self.segments:
            return
        start = min(self.segments)
        max_seq = start + self.max_gap
        for seg_seq in list(self.segments):
            if seg_seq > max_seq:
                del self.segments[seg_seq]

        total = sum(len(seg_payload) for seg_payload in self.segments.values())
        if total <= self.max_buffered_bytes:
            return
        for seg_seq in sorted(self.segments, reverse=True):
            if total <= self.max_buffered_bytes:
                break
            total -= len(self.segments[seg_seq])
            del self.segments[seg_seq]

    def _rebuild(self) -> None:
        if not self.segments:
            self.base_seq = None
            self.next_seq = None
            self.assembled.clear()
            return

        start = min(self.segments)
        self.base_seq = start
        self.next_seq = start
        self.assembled.clear()

        consumed: set[int] = set()
        while self.next_seq is not None and len(self.assembled) < self.max_bytes:
            candidate_seq: int | None = None
            candidate_payload: bytes | None = None
            for seg_seq, seg_payload in self.segments.items():
                if seg_seq in consumed:
                    continue
                seg_end = seg_seq + len(seg_payload)
                if seg_seq <= self.next_seq < seg_end:
                    if candidate_seq is None or seg_seq < candidate_seq:
                        candidate_seq = seg_seq
                        candidate_payload = seg_payload
            if candidate_seq is None or candidate_payload is None:
                return

            consumed.add(candidate_seq)
            if self.next_seq > candidate_seq:
                candidate_payload = candidate_payload[self.next_seq - candidate_seq :]
            if not candidate_payload:
                continue

            limit = self.max_bytes - len(self.assembled)
            take = candidate_payload[:limit]
            self.assembled.extend(take)
            self.next_seq += len(take)
            if len(take) < len(candidate_payload):
                return


def _extract_tls_client_hello_metadata(data: bytes) -> dict[str, Any] | None:
    scan_limit = min(256, max(0, len(data) - 5))
    for offset in range(scan_limit + 1):
        if data[offset : offset + 2] != b"\x16\x03":
            continue
        if offset + 5 > len(data):
            continue
        rec_len = int.from_bytes(data[offset + 3 : offset + 5], "big")
        if rec_len <= 0:
            continue
        rec_end = offset + 5 + rec_len
        if rec_end > len(data):
            continue

        body = data[offset + 5 : rec_end]
        pos = 0
        while pos + 4 <= len(body):
            hs_type = body[pos]
            hs_len = int.from_bytes(body[pos + 1 : pos + 4], "big")
            hs_start = pos + 4
            hs_end = hs_start + hs_len
            if hs_end > len(body):
                break
            if hs_type == 0x01:  # ClientHello
                meta = _parse_tls_client_hello(body[hs_start:hs_end])
                if meta:
                    return meta
            pos = hs_end
    return None


def _parse_tls_client_hello(hello: bytes) -> dict[str, Any] | None:
    # RFC 5246 (TLS 1.2) + RFC 8446 (TLS 1.3): best-effort parsing for SNI/ALPN.
    if len(hello) < 34:  # version(2) + random(32)
        return None
    idx = 2 + 32
    if idx + 1 > len(hello):
        return None
    session_id_len = hello[idx]
    idx += 1 + session_id_len
    if idx + 2 > len(hello):
        return None
    cipher_suites_len = int.from_bytes(hello[idx : idx + 2], "big")
    idx += 2 + cipher_suites_len
    if idx + 1 > len(hello):
        return None
    compression_methods_len = hello[idx]
    idx += 1 + compression_methods_len
    if idx + 2 > len(hello):
        return None
    extensions_len = int.from_bytes(hello[idx : idx + 2], "big")
    idx += 2
    if idx + extensions_len > len(hello):
        return None

    sni: str | None = None
    alpn: list[str] = []
    end = idx + extensions_len
    while idx + 4 <= end:
        ext_type = int.from_bytes(hello[idx : idx + 2], "big")
        ext_len = int.from_bytes(hello[idx + 2 : idx + 4], "big")
        idx += 4
        if idx + ext_len > end:
            break
        ext = hello[idx : idx + ext_len]
        idx += ext_len

        if ext_type == 0x0000:  # server_name
            parsed = _parse_tls_sni_extension(ext)
            if parsed:
                sni = parsed
        elif ext_type == 0x0010:  # ALPN
            alpn = _parse_tls_alpn_extension(ext)

    if not sni and not alpn:
        return None
    out: dict[str, Any] = {}
    if sni:
        out["sni"] = sni
    if alpn:
        out["alpn"] = alpn
    return out


def _parse_tls_sni_extension(ext: bytes) -> str | None:
    if len(ext) < 2:
        return None
    list_len = int.from_bytes(ext[0:2], "big")
    if 2 + list_len > len(ext):
        return None
    pos = 2
    end = 2 + list_len
    while pos + 3 <= end:
        name_type = ext[pos]
        name_len = int.from_bytes(ext[pos + 1 : pos + 3], "big")
        pos += 3
        if pos + name_len > end:
            return None
        name = ext[pos : pos + name_len]
        pos += name_len
        if name_type == 0x00:
            raw = name.decode("ascii", errors="ignore")
            if not raw:
                return None
            try:
                return raw.encode("ascii").decode("idna")
            except UnicodeError:
                return raw
    return None


def _parse_tls_alpn_extension(ext: bytes) -> list[str]:
    if len(ext) < 2:
        return []
    list_len = int.from_bytes(ext[0:2], "big")
    if 2 + list_len > len(ext):
        return []
    pos = 2
    end = 2 + list_len
    protos: list[str] = []
    while pos < end:
        if pos + 1 > end:
            break
        proto_len = ext[pos]
        pos += 1
        if pos + proto_len > end:
            break
        proto = ext[pos : pos + proto_len]
        pos += proto_len
        decoded = proto.decode("ascii", errors="ignore")
        if decoded:
            protos.append(decoded)
    return protos


def inspect_pcap(
    path: Path,
    out_path: Path,
    max_packets: int,
    *,
    include_flows: bool = True,
    sort_flows: bool = False,
    include_dns: bool = True,
    include_http: bool = True,
    include_tls: bool = True,
    top_flows: int = 0,
    top_events: int = 0,
    since_ts: float | None = None,
    until_ts: float | None = None,
    normalize_flows: bool = False,
    include_flow_times: bool = False,
    stats_out: TextIO | None = None,
    stats_json: bool = False,
) -> int:
    flows: dict[str, Flow] = {}
    tcp_streams: dict[str, _TcpStream] = {}
    use_stdout = out_path.as_posix() == "-"
    if not use_stdout:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    packets_seen = 0
    ip_packets = 0
    ip_bytes = 0
    dns_events = 0
    http_events = 0
    tls_events = 0
    events_emitted = 0
    out_ctx = nullcontext(sys.stdout) if use_stdout else out_path.open("w", encoding="utf-8")
    with out_ctx as out:
        out = cast(TextIO, out)
        for pkt in _iter_packets(path):
            pkt_ts = float(getattr(pkt, "time", 0.0))
            if since_ts is not None and pkt_ts < since_ts:
                continue
            if until_ts is not None and pkt_ts > until_ts:
                continue
            flow_parts = _extract_flow_parts(pkt)
            if flow_parts is None:
                continue
            if max_packets and packets_seen >= max_packets:
                break
            packets_seen += 1
            ip_packets += 1
            ip_bytes += len(pkt)
            src, sport, dst, dport, proto = flow_parts
            stream_key = _flow_key(src, sport, dst, dport, proto)
            key = _flow_key_with_mode(
                src,
                sport,
                dst,
                dport,
                proto,
                normalize_flows=normalize_flows,
            )
            prev = flows.get(key)
            if prev:
                if include_flow_times:
                    first_ts = prev.first_ts
                    last_ts = prev.last_ts
                    if first_ts is None or pkt_ts < first_ts:
                        first_ts = pkt_ts
                    if last_ts is None or pkt_ts > last_ts:
                        last_ts = pkt_ts
                    flows[key] = Flow(
                        key,
                        prev.packets + 1,
                        prev.bytes + len(pkt),
                        first_ts=first_ts,
                        last_ts=last_ts,
                    )
                else:
                    flows[key] = Flow(key, prev.packets + 1, prev.bytes + len(pkt))
            else:
                if include_flow_times:
                    flows[key] = Flow(key, 1, len(pkt), first_ts=pkt_ts, last_ts=pkt_ts)
                else:
                    flows[key] = Flow(key, 1, len(pkt))

            if top_events == 0 or events_emitted < top_events:
                event: dict[str, Any] | None = None
                if include_dns:
                    event = _extract_dns(pkt)
                if event is None and include_http:
                    event = _extract_http(pkt)
                if event:
                    event["ts"] = pkt_ts
                    event["flow"] = key
                    out.write(json.dumps(event) + "\n")
                    events_emitted += 1
                    if event.get("type") == "dns":
                        dns_events += 1
                    elif event.get("type") == "http":
                        http_events += 1

            if (
                (top_events == 0 or events_emitted < top_events)
                and include_tls
                and pkt.haslayer(TCP)
                and pkt.haslayer(Raw)
            ):
                payload = bytes(pkt[Raw].load)
                stream = tcp_streams.setdefault(stream_key, _TcpStream())
                stream.push(int(pkt[TCP].seq), payload)
                if not stream.extracted:
                    meta = _extract_tls_client_hello_metadata(bytes(stream.assembled))
                    if meta:
                        out.write(
                            json.dumps(
                                {
                                    "type": "tls",
                                    "ts": pkt_ts,
                                    "flow": key,
                                    **meta,
                                }
                            )
                            + "\n"
                        )
                        stream.extracted = True
                        tls_events += 1
                        events_emitted += 1

        if include_flows:
            flow_values = list(flows.values())
            if top_flows > 0:
                flow_values = sorted(flow_values, key=lambda f: (-f.bytes, f.key))[:top_flows]
            if sort_flows:
                flow_values.sort(key=lambda f: f.key)
            for flow in flow_values:
                out.write(json.dumps({"type": "flow", **flow.to_dict()}) + "\n")
    if stats_out is not None:
        stats: dict[str, int | str | float | None] = {
            "pcap": str(path),
            "max_packets": max_packets,
            "packets_seen": packets_seen,
            "ip_packets": ip_packets,
            "ip_bytes": ip_bytes,
            "flows": len(flows),
            "top_events": top_events,
            "events_emitted": events_emitted,
            "dns_events": dns_events,
            "http_events": http_events,
            "tls_events": tls_events,
            "since_ts": since_ts,
            "until_ts": until_ts,
        }
        if stats_json:
            stats_out.write(json.dumps(stats, indent=2) + "\n")
        else:
            _write_stats_text(stats_out, stats)
    return 0


def _write_stats_text(out: TextIO, stats: dict[str, int | str | float | None]) -> None:
    out.write("Inspect Stats\n")
    out.write(f"PCAP: {stats['pcap']}\n")
    if stats["max_packets"]:
        out.write(f"Max packets: {stats['max_packets']}\n")
    if stats["top_events"]:
        out.write(f"Max events: {stats['top_events']}\n")
    if stats.get("since_ts") is not None or stats.get("until_ts") is not None:
        out.write(f"Time window: {stats.get('since_ts')}..{stats.get('until_ts')}\n")
    out.write(
        "Packets: {packets_seen} (IP: {ip_packets})\n"
        "Flows: {flows}\n"
        "Events emitted: {events_emitted}\n"
        "Bytes: {ip_bytes}\n"
        "DNS events: {dns_events}\n"
        "HTTP events: {http_events}\n"
        "TLS events: {tls_events}\n".format(**stats)
    )


def summarize_pcap(
    path: Path,
    max_packets: int,
    top_n: int = 10,
    *,
    since_ts: float | None = None,
    until_ts: float | None = None,
    normalize_flows: bool = False,
) -> dict[str, Any]:
    flows: dict[str, Flow] = {}
    tcp_streams: dict[str, _TcpStream] = {}

    ip_packets = 0
    ip_bytes = 0
    packets_seen = 0
    first_ts: float | None = None
    last_ts: float | None = None

    dns_qnames: Counter[str] = Counter()
    tls_sni: Counter[str] = Counter()
    http_methods: Counter[str] = Counter()
    http_status_codes: Counter[str] = Counter()

    http_requests = 0
    http_responses = 0
    tls_client_hellos = 0

    tcp_flow_keys: set[str] = set()
    udp_flow_keys: set[str] = set()

    for pkt in _iter_packets(path):
        pkt_ts = float(getattr(pkt, "time", 0.0))
        if since_ts is not None and pkt_ts < since_ts:
            continue
        if until_ts is not None and pkt_ts > until_ts:
            continue

        flow_parts = _extract_flow_parts(pkt)
        if flow_parts is None:
            continue
        if max_packets and packets_seen >= max_packets:
            break
        packets_seen += 1

        ip_packets += 1
        ip_bytes += len(pkt)
        if first_ts is None or pkt_ts < first_ts:
            first_ts = pkt_ts
        if last_ts is None or pkt_ts > last_ts:
            last_ts = pkt_ts

        src, sport, dst, dport, proto = flow_parts
        stream_key = _flow_key(src, sport, dst, dport, proto)
        key = _flow_key_with_mode(
            src,
            sport,
            dst,
            dport,
            proto,
            normalize_flows=normalize_flows,
        )
        prev = flows.get(key)
        if prev:
            flows[key] = Flow(key, prev.packets + 1, prev.bytes + len(pkt))
        else:
            flows[key] = Flow(key, 1, len(pkt))

        if proto == "TCP":
            tcp_flow_keys.add(key)
        elif proto == "UDP":
            udp_flow_keys.add(key)

        dns = _extract_dns(pkt)
        if dns and dns.get("qname"):
            dns_qnames[str(dns["qname"])] += 1

        http = _extract_http(pkt)
        if http:
            if "request_line" in http:
                http_requests += 1
                method = str(http["request_line"]).split(" ", 1)[0]
                if method:
                    http_methods[method] += 1
            elif "status_line" in http:
                http_responses += 1
                parts = str(http["status_line"]).split(" ", 2)
                if len(parts) >= 2 and parts[1].isdigit():
                    http_status_codes[parts[1]] += 1

        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            stream = tcp_streams.setdefault(stream_key, _TcpStream())
            stream.push(int(pkt[TCP].seq), payload)
            if not stream.extracted:
                meta = _extract_tls_client_hello_metadata(bytes(stream.assembled))
                if meta:
                    tls_client_hellos += 1
                    if "sni" in meta:
                        tls_sni[str(meta["sni"])] += 1
                    stream.extracted = True

    return {
        "pcap": str(path),
        "totals": {
            "packets_seen": packets_seen,
            "max_packets": max_packets,
            "ip_packets": ip_packets,
            "ip_bytes": ip_bytes,
            "flows": len(flows),
            "tcp_flows": len(tcp_flow_keys),
            "udp_flows": len(udp_flow_keys),
            "dns_queries": sum(dns_qnames.values()),
            "http_requests": http_requests,
            "http_responses": http_responses,
            "tls_client_hellos": tls_client_hellos,
            "first_ts": first_ts,
            "last_ts": last_ts,
            "duration_s": (last_ts - first_ts)
            if first_ts is not None and last_ts is not None
            else None,
            "since_ts": since_ts,
            "until_ts": until_ts,
        },
        "top_dns_qnames": _top_named(dns_qnames, top_n),
        "top_tls_sni": _top_named(tls_sni, top_n),
        "http_methods": dict(http_methods),
        "http_status_codes": dict(http_status_codes),
        "top_flows_by_bytes": _top_flows_by_bytes(flows, top_n),
    }


def _top_named(counter: Counter[str], top_n: int) -> list[dict[str, object]]:
    if top_n <= 0:
        return []
    return [{"name": name, "count": count} for name, count in counter.most_common(top_n)]


def _top_flows_by_bytes(flows: dict[str, Flow], top_n: int) -> list[dict[str, object]]:
    if top_n <= 0:
        return []
    top = sorted(flows.values(), key=lambda f: (-f.bytes, f.key))[:top_n]
    return [{"name": f.key, "count": f.bytes} for f in top]
