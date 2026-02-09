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
