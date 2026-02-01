from __future__ import annotations

import io
import json
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, IPv6, UDP, wrpcap
from scapy.all import Raw, TCP

from pcap_inspector.inspector import inspect_pcap, summarize_pcap


def _tls_client_hello_record(*, sni: str) -> bytes:
    server_name = sni.encode("idna")
    sni_list = b"\x00" + len(server_name).to_bytes(2, "big") + server_name
    sni_ext = (
        b"\x00\x00"
        + (2 + len(sni_list)).to_bytes(2, "big")
        + len(sni_list).to_bytes(2, "big")
        + sni_list
    )
    extensions = sni_ext

    client_hello = (
        b"\x03\x03"  # client_version
        + b"\x00" * 32  # random
        + b"\x00"  # session_id_len
        + b"\x00\x02"  # cipher_suites_len
        + b"\x13\x01"  # TLS_AES_128_GCM_SHA256
        + b"\x01"  # compression_methods_len
        + b"\x00"  # null compression
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(client_hello).to_bytes(3, "big") + client_hello
    record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    return record


def test_inspect_pcap(tmp_path: Path) -> None:
    pkt = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com"))
    )
    pcap = tmp_path / "test.pcap"
    wrpcap(str(pcap), [pkt])

    out = tmp_path / "out.jsonl"
    inspect_pcap(pcap, out, max_packets=0)
    lines = out.read_text(encoding="utf-8").splitlines()
    assert any(json.loads(line).get("type") == "dns" for line in lines)
    assert any("ts" in json.loads(line) for line in lines)


def test_inspect_pcap_extracts_tls_sni(tmp_path: Path) -> None:
    pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=443, seq=1)
        / Raw(load=_tls_client_hello_record(sni="example.com"))
    )
    pcap = tmp_path / "tls.pcap"
    wrpcap(str(pcap), [pkt])

    out = tmp_path / "out.jsonl"
    inspect_pcap(pcap, out, max_packets=0)
    events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert any(e.get("type") == "tls" and e.get("sni") == "example.com" for e in events)


def test_inspect_pcap_ipv6_flow_keys(tmp_path: Path) -> None:
    pkt = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com"))
    )
    pcap = tmp_path / "v6.pcap"
    wrpcap(str(pcap), [pkt])

    out = tmp_path / "out.jsonl"
    inspect_pcap(pcap, out, max_packets=0)
    events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert any(
        e.get("type") == "dns" and e.get("flow") == "[2001:db8::1]:1234->[2001:db8::2]:53 UDP"
        for e in events
    )


def test_inspect_pcap_no_flows(tmp_path: Path) -> None:
    pkt = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com"))
    )
    pcap = tmp_path / "test.pcap"
    wrpcap(str(pcap), [pkt])

    out = tmp_path / "out.jsonl"
    inspect_pcap(pcap, out, max_packets=0, include_flows=False)
    events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert any(e.get("type") == "dns" for e in events)
    assert not any(e.get("type") == "flow" for e in events)


def test_inspect_pcap_event_filters(tmp_path: Path) -> None:
    dns_pkt = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com"))
    )
    tls_pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=443, seq=1)
        / Raw(load=_tls_client_hello_record(sni="example.com"))
    )
    pcap = tmp_path / "events.pcap"
    wrpcap(str(pcap), [dns_pkt, tls_pkt])

    out = tmp_path / "out.jsonl"
    inspect_pcap(
        pcap,
        out,
        max_packets=0,
        include_flows=False,
        include_dns=True,
        include_http=False,
        include_tls=False,
    )
    events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert any(e.get("type") == "dns" for e in events)
    assert not any(e.get("type") == "tls" for e in events)


def test_inspect_pcap_sort_flows(tmp_path: Path) -> None:
    pkt_a = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=5000, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="a.example"))
    )
    pkt_b = (
        IP(src="1.1.1.2", dst="8.8.8.8")
        / UDP(sport=4000, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="b.example"))
    )
    pcap = tmp_path / "flows.pcap"
    wrpcap(str(pcap), [pkt_a, pkt_b])

    out = tmp_path / "out.jsonl"
    inspect_pcap(
        pcap,
        out,
        max_packets=0,
        include_dns=False,
        include_http=False,
        include_tls=False,
        sort_flows=True,
    )
    flow_rows = [
        json.loads(line)
        for line in out.read_text(encoding="utf-8").splitlines()
        if json.loads(line).get("type") == "flow"
    ]
    flows = [row["flow"] for row in flow_rows]
    assert flows == sorted(flows)


def test_summarize_pcap(tmp_path: Path) -> None:
    dns_pkt = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com"))
    )
    http_pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=80, seq=1)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    pcap = tmp_path / "mix.pcap"
    wrpcap(str(pcap), [dns_pkt, http_pkt])

    summary = summarize_pcap(pcap, max_packets=0, top_n=10)
    totals = summary["totals"]
    assert totals["flows"] == 2
    assert totals["dns_queries"] == 1
    assert totals["http_requests"] == 1


def test_inspect_pcap_stats_json(tmp_path: Path) -> None:
    pkt = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com"))
    )
    pcap = tmp_path / "stats.pcap"
    wrpcap(str(pcap), [pkt])

    out = tmp_path / "out.jsonl"
    stats_out = io.StringIO()
    inspect_pcap(pcap, out, max_packets=0, stats_out=stats_out, stats_json=True)
    stats = json.loads(stats_out.getvalue())
    assert stats["flows"] == 1
    assert stats["dns_events"] == 1
