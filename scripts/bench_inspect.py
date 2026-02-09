from __future__ import annotations

# ruff: noqa: E402

import argparse
import json
import logging
import os
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

from pcap_inspector.inspector import inspect_pcap


@dataclass(frozen=True)
class _RunResult:
    elapsed_s: float
    packets: int
    maxrss_kb: int | None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "elapsed_s": self.elapsed_s,
            "packets": self.packets,
            "packets_per_s": (self.packets / self.elapsed_s) if self.elapsed_s > 0 else 0.0,
        }
        if self.maxrss_kb is not None:
            out["maxrss_kb"] = self.maxrss_kb
        return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bench_inspect")
    p.add_argument("--pcap", default="", help="PCAP path. If omitted, generate a fixture PCAP.")
    p.add_argument("--packets", type=int, default=50_000, help="Fixture packet count")
    p.add_argument("--flows", type=int, default=500, help="Fixture unique flow count")
    p.add_argument(
        "--payload-bytes", type=int, default=0, help="Optional UDP payload padding bytes"
    )
    p.add_argument("--repeat", type=int, default=3, help="Number of measured runs")
    p.add_argument(
        "--max-packets", type=int, default=0, help="Pass-through to inspect (0 = no limit)"
    )
    p.add_argument(
        "--top-events", type=int, default=0, help="Pass-through to inspect (0 = no limit)"
    )
    p.add_argument(
        "--no-events",
        action="store_true",
        help="Disable DNS/HTTP/TLS event extraction (flows-only).",
    )
    p.add_argument("--child", action="store_true", help=argparse.SUPPRESS)

    args = p.parse_args(argv)
    if args.child:
        return _child(args)

    fixture = Path(args.pcap) if args.pcap else _ensure_fixture(args)
    if not fixture.exists():
        raise SystemExit(f"fixture not found: {fixture}")

    packets_for_reporting = 0 if args.pcap else int(args.packets)
    cmd_base = [
        sys.executable,
        os.fspath(Path(__file__)),
        "--child",
        "--pcap",
        os.fspath(fixture),
        "--packets",
        str(packets_for_reporting),
        "--max-packets",
        str(int(args.max_packets)),
        "--top-events",
        str(int(args.top_events)),
    ]
    if args.no_events:
        cmd_base.append("--no-events")

    results: list[_RunResult] = []
    for _ in range(max(1, int(args.repeat))):
        proc = subprocess.run(cmd_base, check=False, capture_output=True, text=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            return int(proc.returncode) or 1
        payload = json.loads(proc.stdout)
        results.append(
            _RunResult(
                elapsed_s=float(payload["elapsed_s"]),
                packets=int(payload["packets"]),
                maxrss_kb=int(payload["maxrss_kb"]) if "maxrss_kb" in payload else None,
            )
        )

    elapsed = [r.elapsed_s for r in results]
    pps = [(r.packets / r.elapsed_s) if r.elapsed_s > 0 else 0.0 for r in results]
    out = {
        "pcap": os.fspath(fixture),
        "repeat": len(results),
        "elapsed_s": {
            "min": min(elapsed),
            "median": statistics.median(elapsed),
            "max": max(elapsed),
        },
        "packets_per_s": {"min": min(pps), "median": statistics.median(pps), "max": max(pps)},
        "runs": [r.to_dict() for r in results],
    }
    sys.stdout.write(json.dumps(out, indent=2) + "\n")
    return 0


def _ensure_fixture(args: argparse.Namespace) -> Path:
    packets = int(args.packets)
    flows = max(1, int(args.flows))
    payload_bytes = max(0, int(args.payload_bytes))

    out_dir = Path("bench")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"fixture-{packets}p-{flows}f-{payload_bytes}b.pcap"
    if out_path.exists():
        return out_path

    pkts = []
    base_time = 1_700_000_000.0
    for i in range(packets):
        flow_idx = i % flows
        src = f"10.0.{(flow_idx // 256) % 256}.{flow_idx % 256}"
        dst = "8.8.8.8"
        sport = 1024 + (flow_idx % 20_000)
        qname = f"bench{flow_idx}.example"
        pkt = (
            IP(src=src, dst=dst)
            / UDP(sport=sport, dport=53)
            / DNS(id=(i % 65535), qr=0, qd=DNSQR(qname=qname))
        )
        if payload_bytes:
            pkt = pkt / (b"x" * payload_bytes)
        pkt.time = base_time + (i * 0.000_001)
        pkts.append(pkt)

    wrpcap(os.fspath(out_path), pkts)
    return out_path


def _child(args: argparse.Namespace) -> int:
    import resource

    pcap = Path(args.pcap)
    max_packets = max(0, int(args.max_packets))
    top_events = max(0, int(args.top_events))
    no_events = bool(args.no_events)

    with tempfile.TemporaryDirectory() as td:
        out_path = Path(td) / "out.jsonl"
        start = time.perf_counter()
        inspect_pcap(
            pcap,
            out_path,
            max_packets,
            include_flows=True,
            include_flow_times=False,
            include_dns=not no_events,
            include_http=not no_events,
            include_tls=not no_events,
            top_events=top_events,
        )
        elapsed = time.perf_counter() - start

    # ru_maxrss units: KiB on Linux, bytes on macOS. Normalize to KiB.
    maxrss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        maxrss_kb = int(maxrss // 1024)
    else:
        maxrss_kb = int(maxrss)

    packets = max_packets if max_packets > 0 else int(getattr(args, "packets", 0) or 0)
    if packets <= 0:
        # We generated the fixture with --packets in the parent; when a custom pcap is supplied,
        # this value is informational only.
        packets = 0

    sys.stdout.write(
        json.dumps({"elapsed_s": elapsed, "packets": packets, "maxrss_kb": maxrss_kb}) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
