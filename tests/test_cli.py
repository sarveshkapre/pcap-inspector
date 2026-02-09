from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

from pcap_inspector.cli import main


def _write_small_pcap(path: Path) -> None:
    pkt = (
        IP(src="1.1.1.1", dst="8.8.8.8")
        / UDP(sport=1234, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com"))
    )
    wrpcap(str(path), [pkt])


def test_summary_format_json(tmp_path: Path, capsys: Any) -> None:
    pcap = tmp_path / "fixture.pcap"
    _write_small_pcap(pcap)

    rc = main(["summary", "--pcap", str(pcap), "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["totals"]["flows"] == 1


def test_timeline_format_json(tmp_path: Path, capsys: Any) -> None:
    pcap = tmp_path / "fixture.pcap"
    _write_small_pcap(pcap)

    rc = main(["timeline", "--pcap", str(pcap), "--top", "1", "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["totals"]["flows"] == 1
    assert len(parsed["flows"]) == 1


def test_json_alias_conflict_with_format_text(tmp_path: Path, capsys: Any) -> None:
    pcap = tmp_path / "fixture.pcap"
    _write_small_pcap(pcap)

    rc = main(["summary", "--pcap", str(pcap), "--json", "--format", "text"])
    assert rc != 0
    err = capsys.readouterr().err
    assert "conflicts" in err
