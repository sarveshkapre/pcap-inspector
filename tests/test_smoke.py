from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_help() -> None:
    proc = subprocess.run([sys.executable, "-m", "pcap_inspector", "--help"], check=False)
    assert proc.returncode == 0


def test_schema() -> None:
    proc = subprocess.run([sys.executable, "-m", "pcap_inspector", "schema"], check=False)
    assert proc.returncode == 0


def test_summary_schema() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "pcap_inspector", "schema", "--summary"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert '"title"' in (proc.stdout or "")


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


def test_invalid_time_window_rejected(tmp_path: Path) -> None:
    pcap = tmp_path / "empty.pcap"
    pcap.write_bytes(b"")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pcap_inspector",
            "inspect",
            "--pcap",
            str(pcap),
            "--out",
            "-",
            "--since-ts",
            "2",
            "--until-ts",
            "1",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "since-ts must be <=" in (proc.stderr or "")


def test_pcapng_errors_cleanly(tmp_path: Path) -> None:
    pcapng = tmp_path / "fixture.pcapng"
    pcapng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 64)
    proc = subprocess.run(
        [sys.executable, "-m", "pcap_inspector", "inspect", "--pcap", str(pcapng), "--out", "-"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "error:" in (proc.stderr or "")
    assert "pcapng" in (proc.stderr or "").lower()


def test_top_events_mode_requires_top_events(tmp_path: Path) -> None:
    pcap = tmp_path / "dummy.pcap"
    pcap.write_bytes(b"")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pcap_inspector",
            "inspect",
            "--pcap",
            str(pcap),
            "--out",
            "-",
            "--top-events-mode",
            "flow-bytes",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "--top-events-mode requires --top-events" in (proc.stderr or "")
