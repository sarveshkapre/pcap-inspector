from __future__ import annotations

# ruff: noqa: E402

import io
import ipaddress
import json
import logging
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, wrpcap

from pcap_inspector.inspector import inspect_pcap, summarize_pcap, timeline_pcap


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


def test_inspect_pcap_reads_pcapng(tmp_path: Path) -> None:
    pkt = (
        Ether()
        / IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com"))
    )
    pcapng = tmp_path / "test.pcapng"
    with PcapNgWriter(str(pcapng)) as writer:
        writer.write(pkt)

    out = tmp_path / "out.jsonl"
    inspect_pcap(pcapng, out, max_packets=0)
    lines = out.read_text(encoding="utf-8").splitlines()
    assert any(json.loads(line).get("type") == "dns" for line in lines)


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


def test_inspect_pcap_extracts_tls_sni_out_of_order(tmp_path: Path) -> None:
    hello = _tls_client_hello_record(sni="example.com")
    split = 20
    pkt_second = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=443, seq=100 + split)
        / Raw(load=hello[split:])
    )
    pkt_first = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=443, seq=100)
        / Raw(load=hello[:split])
    )
    pcap = tmp_path / "tls-out-of-order.pcap"
    wrpcap(str(pcap), [pkt_second, pkt_first])

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


def test_inspect_pcap_dns_ports_filter_excludes_dns(tmp_path: Path) -> None:
    pkt = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com"))
    )
    pcap = tmp_path / "dns.pcap"
    wrpcap(str(pcap), [pkt])

    out = tmp_path / "out.jsonl"
    inspect_pcap(pcap, out, max_packets=0, include_flows=False, dns_ports={54})
    lines = out.read_text(encoding="utf-8").splitlines()
    assert not any(json.loads(line).get("type") == "dns" for line in lines)


def test_summarize_pcap_dns_ports_filter_excludes_dns(tmp_path: Path) -> None:
    pkt = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com"))
    )
    pcap = tmp_path / "dns.pcap"
    wrpcap(str(pcap), [pkt])

    summary = summarize_pcap(pcap, max_packets=0, top_n=10, dns_ports={54})
    assert summary["totals"]["dns_queries"] == 0
    assert summary["top_dns_qnames"] == []


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


def test_inspect_pcap_flow_times(tmp_path: Path) -> None:
    pkt_a = IP(src="1.1.1.1", dst="8.8.8.8") / UDP(sport=1234, dport=53) / Raw(load=b"x")
    pkt_b = IP(src="1.1.1.1", dst="8.8.8.8") / UDP(sport=1234, dport=53) / Raw(load=b"y")
    pkt_a.time = 5.0
    pkt_b.time = 1.0
    pcap = tmp_path / "flow-times.pcap"
    wrpcap(str(pcap), [pkt_a, pkt_b])

    out = tmp_path / "out.jsonl"
    inspect_pcap(
        pcap,
        out,
        max_packets=0,
        include_dns=False,
        include_http=False,
        include_tls=False,
        include_flow_times=True,
    )
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    flow_rows = [r for r in rows if r.get("type") == "flow"]
    assert len(flow_rows) == 1
    assert flow_rows[0]["first_ts"] == 1.0
    assert flow_rows[0]["last_ts"] == 5.0


def test_inspect_pcap_time_window_filters_packets(tmp_path: Path) -> None:
    pkt_a = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1111, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="a.example"))
    )
    pkt_b = (
        IP(src="1.1.1.2", dst="8.8.8.8")
        / UDP(sport=2222, dport=53)
        / DNS(id=2, qr=0, qd=DNSQR(qname="b.example"))
    )
    pkt_c = (
        IP(src="1.1.1.3", dst="8.8.8.8")
        / UDP(sport=3333, dport=53)
        / DNS(id=3, qr=0, qd=DNSQR(qname="c.example"))
    )
    pkt_a.time = 1.0
    pkt_b.time = 3.0
    pkt_c.time = 5.0
    pcap = tmp_path / "time-window.pcap"
    wrpcap(str(pcap), [pkt_a, pkt_b, pkt_c])

    out = tmp_path / "out.jsonl"
    inspect_pcap(pcap, out, max_packets=0, since_ts=2.0, until_ts=4.0)
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    dns_rows = [r for r in rows if r.get("type") == "dns"]
    flow_rows = [r for r in rows if r.get("type") == "flow"]
    assert len(dns_rows) == 1
    assert dns_rows[0]["qname"] == "b.example"
    assert len(flow_rows) == 1
    assert flow_rows[0]["packets"] == 1


def test_summarize_pcap_time_window_filters_packets(tmp_path: Path) -> None:
    pkt_a = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1111, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="a.example"))
    )
    pkt_b = (
        IP(src="1.1.1.2", dst="8.8.8.8")
        / UDP(sport=2222, dport=53)
        / DNS(id=2, qr=0, qd=DNSQR(qname="b.example"))
    )
    pkt_c = (
        IP(src="1.1.1.3", dst="8.8.8.8")
        / UDP(sport=3333, dport=53)
        / DNS(id=3, qr=0, qd=DNSQR(qname="c.example"))
    )
    pkt_a.time = 1.0
    pkt_b.time = 3.0
    pkt_c.time = 5.0
    pcap = tmp_path / "summary-time-window.pcap"
    wrpcap(str(pcap), [pkt_a, pkt_b, pkt_c])

    summary = summarize_pcap(pcap, max_packets=0, top_n=10, since_ts=2.0, until_ts=4.0)
    totals = summary["totals"]
    assert totals["flows"] == 1
    assert totals["packets_seen"] == 1
    assert totals["first_ts"] == 3.0
    assert totals["last_ts"] == 3.0


def test_inspect_pcap_flow_filters_host_port_proto(tmp_path: Path) -> None:
    dns_pkt = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1111, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="a.example"))
    )
    http_pkt = (
        IP(src="2.2.2.2", dst="93.184.216.34")
        / TCP(sport=55555, dport=80, seq=1)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    pcap = tmp_path / "filters.pcap"
    wrpcap(str(pcap), [dns_pkt, http_pkt])

    out = tmp_path / "out.jsonl"
    inspect_pcap(
        pcap,
        out,
        max_packets=0,
        include_flows=True,
        include_dns=True,
        include_http=True,
        include_tls=False,
        hosts={"1.1.1.1"},
        ports={53},
        protos={"UDP"},
    )
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert any(r.get("type") == "dns" for r in rows)
    assert not any(r.get("type") == "http" for r in rows)
    flow_rows = [r for r in rows if r.get("type") == "flow"]
    assert len(flow_rows) == 1
    assert flow_rows[0]["flow"].endswith(" UDP")


def test_summarize_pcap_flow_filters_host_port_proto(tmp_path: Path) -> None:
    dns_pkt = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1111, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="a.example"))
    )
    http_pkt = (
        IP(src="2.2.2.2", dst="93.184.216.34")
        / TCP(sport=55555, dport=80, seq=1)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    pcap = tmp_path / "summary-filters.pcap"
    wrpcap(str(pcap), [dns_pkt, http_pkt])

    summary = summarize_pcap(
        pcap,
        max_packets=0,
        top_n=10,
        hosts={"1.1.1.1"},
        ports={53},
        protos={"UDP"},
    )
    totals = summary["totals"]
    assert totals["flows"] == 1
    assert totals["udp_flows"] == 1
    assert totals["tcp_flows"] == 0


def test_inspect_pcap_host_cidr_filter_ipv4(tmp_path: Path) -> None:
    pkt_in = (
        IP(src="10.0.0.5", dst="8.8.8.8")
        / UDP(sport=1111, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="in.example"))
    )
    pkt_out = (
        IP(src="10.1.0.5", dst="8.8.8.8")
        / UDP(sport=2222, dport=53)
        / DNS(id=2, qr=0, qd=DNSQR(qname="out.example"))
    )
    pcap = tmp_path / "cidr-v4.pcap"
    wrpcap(str(pcap), [pkt_in, pkt_out])

    out = tmp_path / "out.jsonl"
    inspect_pcap(
        pcap,
        out,
        max_packets=0,
        include_flows=True,
        include_dns=True,
        include_http=False,
        include_tls=False,
        host_nets=[ipaddress.ip_network("10.0.0.0/16")],
    )
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    dns_rows = [r for r in rows if r.get("type") == "dns"]
    assert len(dns_rows) == 1
    assert dns_rows[0]["qname"] == "in.example"


def test_summarize_pcap_host_cidr_filter_ipv6(tmp_path: Path) -> None:
    pkt_in = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=1111, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="in.example"))
    )
    pkt_out = (
        IPv6(src="2001:db9::1", dst="2001:db9::2")
        / UDP(sport=2222, dport=53)
        / DNS(id=2, qr=0, qd=DNSQR(qname="out.example"))
    )
    pcap = tmp_path / "cidr-v6.pcap"
    wrpcap(str(pcap), [pkt_in, pkt_out])

    summary = summarize_pcap(
        pcap,
        max_packets=0,
        top_n=10,
        host_nets=[ipaddress.ip_network("2001:db8::/32")],
    )
    totals = summary["totals"]
    assert totals["flows"] == 1
    assert totals["dns_queries"] == 1


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


def test_timeline_pcap_top_flows_by_bytes(tmp_path: Path) -> None:
    pkt_big_a = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=1111, dport=53) / Raw(load=b"x" * 200)
    pkt_big_b = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=1111, dport=53) / Raw(load=b"y" * 200)
    pkt_small = IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=2222, dport=53) / Raw(load=b"z")
    pkt_big_a.time = 2.0
    pkt_big_b.time = 1.0
    pkt_small.time = 3.0
    pcap = tmp_path / "timeline.pcap"
    wrpcap(str(pcap), [pkt_big_a, pkt_big_b, pkt_small])

    timeline = timeline_pcap(pcap, max_packets=0, top_n=1)
    flows = timeline["flows"]
    assert len(flows) == 1
    assert flows[0]["flow"].startswith("10.0.0.1:")
    assert flows[0]["first_ts"] == 1.0
    assert flows[0]["last_ts"] == 2.0


def test_inspect_pcap_http_put_method(tmp_path: Path) -> None:
    pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=80, seq=1)
        / Raw(load=b"PUT /resource HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    pcap = tmp_path / "http-put.pcap"
    wrpcap(str(pcap), [pkt])

    out = tmp_path / "out.jsonl"
    inspect_pcap(pcap, out, max_packets=0, include_flows=False)
    events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert any(
        e.get("type") == "http" and "PUT /resource HTTP/1.1" in e.get("request_line", "")
        for e in events
    )


def test_inspect_pcap_http_ports_filter(tmp_path: Path) -> None:
    pkt_ok = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=80, seq=1)
        / Raw(load=b"GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    pkt_skip = (
        IP(src="10.0.0.2", dst="93.184.216.34")
        / TCP(sport=55556, dport=12345, seq=1)
        / Raw(load=b"GET /skip HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    pcap = tmp_path / "http-ports.pcap"
    wrpcap(str(pcap), [pkt_ok, pkt_skip])

    out = tmp_path / "out.jsonl"
    inspect_pcap(pcap, out, max_packets=0, include_flows=False, http_ports={80})
    events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    http_lines = [e.get("request_line", "") for e in events if e.get("type") == "http"]
    assert http_lines == ["GET /ok HTTP/1.1"]


def test_summarize_and_timeline_http_ports_filter(tmp_path: Path) -> None:
    pkt_ok = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=80, seq=1)
        / Raw(load=b"GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    pkt_skip = (
        IP(src="10.0.0.2", dst="93.184.216.34")
        / TCP(sport=55556, dport=12345, seq=1)
        / Raw(load=b"GET /skip HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    pcap = tmp_path / "http-ports-summary-timeline.pcap"
    wrpcap(str(pcap), [pkt_ok, pkt_skip])

    summary = summarize_pcap(pcap, max_packets=0, top_n=10, http_ports={80})
    assert summary["totals"]["http_requests"] == 1
    assert summary["totals"]["http_ports"] == [80]

    timeline = timeline_pcap(pcap, max_packets=0, top_n=10, http_ports={80})
    assert sum(int(flow["http_events"]) for flow in timeline["flows"]) == 1
    assert timeline["totals"]["http_ports"] == [80]


def test_inspect_pcap_tls_ports_filter(tmp_path: Path) -> None:
    pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=443, seq=1)
        / Raw(load=_tls_client_hello_record(sni="example.com"))
    )
    pcap = tmp_path / "tls-ports.pcap"
    wrpcap(str(pcap), [pkt])

    out_skip = tmp_path / "out-skip.jsonl"
    inspect_pcap(
        pcap,
        out_skip,
        max_packets=0,
        include_flows=False,
        include_dns=False,
        include_http=False,
        include_tls=True,
        tls_ports={8443},
    )
    events_skip = [json.loads(line) for line in out_skip.read_text(encoding="utf-8").splitlines()]
    assert not any(e.get("type") == "tls" for e in events_skip)

    out_ok = tmp_path / "out-ok.jsonl"
    inspect_pcap(
        pcap,
        out_ok,
        max_packets=0,
        include_flows=False,
        include_dns=False,
        include_http=False,
        include_tls=True,
        tls_ports={443},
    )
    events_ok = [json.loads(line) for line in out_ok.read_text(encoding="utf-8").splitlines()]
    assert any(e.get("type") == "tls" and e.get("sni") == "example.com" for e in events_ok)


def test_summarize_and_timeline_tls_ports_filter(tmp_path: Path) -> None:
    pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=443, seq=1)
        / Raw(load=_tls_client_hello_record(sni="example.com"))
    )
    pcap = tmp_path / "tls-ports-summary.pcap"
    wrpcap(str(pcap), [pkt])

    summary = summarize_pcap(pcap, max_packets=0, top_n=10, tls_ports={8443})
    assert summary["totals"]["tls_client_hellos"] == 0
    assert summary["top_tls_sni"] == []

    timeline = timeline_pcap(pcap, max_packets=0, top_n=10, tls_ports={8443})
    assert timeline["flows"][0]["tls_client_hellos"] == 0
    assert timeline["flows"][0]["tls_sni"] is None


def test_inspect_pcap_max_packets_stats_json(tmp_path: Path) -> None:
    pkt_a = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="a.example"))
    )
    pkt_b = (
        IP(src="1.1.1.2", dst="8.8.8.8")
        / UDP(sport=1235, dport=53)
        / DNS(id=2, qr=0, qd=DNSQR(qname="b.example"))
    )
    pcap = tmp_path / "max-packets.pcap"
    wrpcap(str(pcap), [pkt_a, pkt_b])

    out = tmp_path / "out.jsonl"
    stats_out = io.StringIO()
    inspect_pcap(pcap, out, max_packets=1, stats_out=stats_out, stats_json=True)
    stats = json.loads(stats_out.getvalue())
    assert stats["packets_seen"] == 1
    assert stats["flows"] == 1


def test_summarize_pcap_max_packets_counts_processed_only(tmp_path: Path) -> None:
    pkt_a = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="a.example"))
    )
    pkt_b = (
        IP(src="1.1.1.2", dst="8.8.8.8")
        / UDP(sport=1235, dport=53)
        / DNS(id=2, qr=0, qd=DNSQR(qname="b.example"))
    )
    pcap = tmp_path / "summary-max-packets.pcap"
    wrpcap(str(pcap), [pkt_a, pkt_b])

    summary = summarize_pcap(pcap, max_packets=1, top_n=10)
    assert summary["totals"]["packets_seen"] == 1
    assert summary["totals"]["flows"] == 1


def test_inspect_pcap_top_flows(tmp_path: Path) -> None:
    pkt_small = (
        IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=1000, dport=9999) / Raw(load=b"x" * 10)
    )
    pkt_medium = (
        IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=1001, dport=9999) / Raw(load=b"x" * 40)
    )
    pkt_large = (
        IP(src="10.0.0.3", dst="8.8.8.8") / UDP(sport=1002, dport=9999) / Raw(load=b"x" * 70)
    )
    pcap = tmp_path / "top-flows.pcap"
    wrpcap(str(pcap), [pkt_small, pkt_medium, pkt_large])

    out = tmp_path / "out.jsonl"
    inspect_pcap(
        pcap,
        out,
        max_packets=0,
        include_dns=False,
        include_http=False,
        include_tls=False,
        top_flows=2,
    )
    flow_rows = [
        json.loads(line)
        for line in out.read_text(encoding="utf-8").splitlines()
        if json.loads(line).get("type") == "flow"
    ]
    assert len(flow_rows) == 2
    assert all(row["flow"] != "10.0.0.1:1000->8.8.8.8:9999 UDP" for row in flow_rows)


def test_inspect_pcap_top_events(tmp_path: Path) -> None:
    dns_pkt_a = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1111, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="a.example"))
    )
    http_pkt = (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=55555, dport=80, seq=1)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    dns_pkt_b = (
        IP(src="1.1.1.2", dst="8.8.8.8")
        / UDP(sport=2222, dport=53)
        / DNS(id=2, qr=0, qd=DNSQR(qname="b.example"))
    )
    pcap = tmp_path / "top-events.pcap"
    wrpcap(str(pcap), [dns_pkt_a, http_pkt, dns_pkt_b])

    out = tmp_path / "out.jsonl"
    inspect_pcap(pcap, out, max_packets=0, include_flows=False, top_events=2)
    events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 2
    assert [e["type"] for e in events] == ["dns", "http"]


def test_inspect_pcap_top_events_flow_bytes_mode(tmp_path: Path) -> None:
    pkt_small = (
        IP(src="10.0.0.10", dst="93.184.216.34")
        / TCP(sport=40000, dport=80, seq=1)
        / Raw(load=b"GET /small HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    pkt_big = (
        IP(src="10.0.0.11", dst="93.184.216.34")
        / TCP(sport=40001, dport=80, seq=1)
        / Raw(load=b"GET /big HTTP/1.1\r\nHost: example.com\r\n\r\n" + b"x" * 800)
    )
    pkt_small.time = 1.0
    pkt_big.time = 2.0
    pcap = tmp_path / "top-events-flow-bytes.pcap"
    wrpcap(str(pcap), [pkt_small, pkt_big])

    out = tmp_path / "out.jsonl"
    inspect_pcap(
        pcap,
        out,
        max_packets=0,
        include_flows=False,
        top_events=1,
        top_events_mode="flow-bytes",
        include_dns=False,
        include_http=True,
        include_tls=False,
    )
    events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 1
    assert events[0].get("type") == "http"
    assert "GET /big HTTP/1.1" in (events[0].get("request_line") or "")


def test_inspect_pcap_normalize_flows(tmp_path: Path) -> None:
    pkt_a = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53) / Raw(load=b"x")
    pkt_b = IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=5000) / Raw(load=b"y")
    pcap = tmp_path / "normalize-inspect.pcap"
    wrpcap(str(pcap), [pkt_a, pkt_b])

    out = tmp_path / "out.jsonl"
    inspect_pcap(
        pcap,
        out,
        max_packets=0,
        include_dns=False,
        include_http=False,
        include_tls=False,
        normalize_flows=True,
    )
    flow_rows = [
        json.loads(line)
        for line in out.read_text(encoding="utf-8").splitlines()
        if json.loads(line).get("type") == "flow"
    ]
    assert len(flow_rows) == 1
    assert flow_rows[0]["packets"] == 2
    assert "<->" in flow_rows[0]["flow"]


def test_summarize_pcap_normalize_flows(tmp_path: Path) -> None:
    pkt_a = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53) / Raw(load=b"x")
    pkt_b = IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=5000) / Raw(load=b"y")
    pcap = tmp_path / "normalize-summary.pcap"
    wrpcap(str(pcap), [pkt_a, pkt_b])

    summary = summarize_pcap(pcap, max_packets=0, top_n=10, normalize_flows=True)
    assert summary["totals"]["flows"] == 1
    assert summary["totals"]["udp_flows"] == 1
    assert "<->" in summary["top_flows_by_bytes"][0]["name"]


def test_summarize_pcap_top_flows_tie_breaker(tmp_path: Path) -> None:
    pkt_b = IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=1001, dport=9999) / Raw(load=b"x" * 40)
    pkt_a = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=1000, dport=9999) / Raw(load=b"x" * 40)
    pcap = tmp_path / "tie-break.pcap"
    wrpcap(str(pcap), [pkt_b, pkt_a])

    summary = summarize_pcap(pcap, max_packets=0, top_n=2)
    top_names = [item["name"] for item in summary["top_flows_by_bytes"]]
    assert top_names == [
        "10.0.0.1:1000->8.8.8.8:9999 UDP",
        "10.0.0.2:1001->8.8.8.8:9999 UDP",
    ]


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


def test_inspect_pcap_stats_json_includes_event_limit(tmp_path: Path) -> None:
    dns_pkt_a = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1111, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="a.example"))
    )
    dns_pkt_b = (
        IP(src="1.1.1.2", dst="8.8.8.8")
        / UDP(sport=2222, dport=53)
        / DNS(id=2, qr=0, qd=DNSQR(qname="b.example"))
    )
    pcap = tmp_path / "stats-top-events.pcap"
    wrpcap(str(pcap), [dns_pkt_a, dns_pkt_b])

    out = tmp_path / "out.jsonl"
    stats_out = io.StringIO()
    inspect_pcap(pcap, out, max_packets=0, top_events=1, stats_out=stats_out, stats_json=True)
    stats = json.loads(stats_out.getvalue())
    assert stats["top_events"] == 1
    assert stats["events_emitted"] == 1
