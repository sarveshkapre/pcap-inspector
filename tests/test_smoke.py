from __future__ import annotations

import subprocess
import sys


def test_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "pcap_inspector", "--help"], check=False)
    assert proc.returncode == 0


def test_schema() -> None:
    proc = subprocess.run([sys.executable, "-m", "pcap_inspector", "schema"], check=False)
    assert proc.returncode == 0


def test_invalid_negative_numeric_arg() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pcap_inspector",
            "inspect",
            "--pcap",
            "missing.pcap",
            "--top-flows",
            "-1",
        ],
        check=False,
    )
    assert proc.returncode != 0


def test_invalid_negative_top_events_arg() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pcap_inspector",
            "inspect",
            "--pcap",
            "missing.pcap",
            "--top-events",
            "-1",
        ],
        check=False,
    )
    assert proc.returncode != 0


def test_missing_pcap_errors_cleanly() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "pcap_inspector", "inspect", "--pcap", "missing.pcap", "--out", "-"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "error:" in (proc.stderr or "")
    assert "missing.pcap" in (proc.stderr or "")


def test_missing_pcap_errors_cleanly_summary() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "pcap_inspector", "summary", "--pcap", "missing.pcap"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "error:" in (proc.stderr or "")
    assert "missing.pcap" in (proc.stderr or "")
