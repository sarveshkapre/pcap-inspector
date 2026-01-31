from __future__ import annotations

import json
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, UDP, wrpcap

from pcap_inspector.inspector import inspect_pcap


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
