from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .inspector import inspect_pcap, summarize_pcap


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pcap-inspector")
    parser.add_argument("--version", action="version", version="0.1.0")

    sub = parser.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("inspect", help="Inspect a PCAP file")
    p_run.add_argument("--pcap", required=True, help="Path to .pcap file")
    p_run.add_argument(
        "--out", default="pcap-report.jsonl", help="Output path (.jsonl) or '-' for stdout"
    )
    p_run.add_argument("--max-packets", type=int, default=0, help="0 = no limit")
    p_run.set_defaults(func=_run)

    p_summary = sub.add_parser("summary", help="Print an aggregate summary (no JSONL output)")
    p_summary.add_argument("--pcap", required=True, help="Path to .pcap file")
    p_summary.add_argument("--max-packets", type=int, default=0, help="0 = no limit")
    p_summary.add_argument("--top", type=int, default=10, help="Number of top items to show")
    p_summary.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_summary.set_defaults(func=_summary)

    args = parser.parse_args(argv)
    return int(args.func(args))


def _run(args: argparse.Namespace) -> int:
    return inspect_pcap(Path(args.pcap), Path(args.out), args.max_packets)


def _summary(args: argparse.Namespace) -> int:
    summary = summarize_pcap(
        Path(args.pcap), max_packets=int(args.max_packets), top_n=int(args.top)
    )
    if args.json:
        sys.stdout.write(json.dumps(summary, indent=2) + "\n")
        return 0

    totals = summary["totals"]
    sys.stdout.write(f"PCAP Summary: {summary['pcap']}\n")
    if totals.get("max_packets"):
        sys.stdout.write(f"Max packets: {totals['max_packets']}\n")
    sys.stdout.write(
        f"Packets: {totals['packets_seen']} (IP: {totals['ip_packets']})\n"
        f"Flows: {totals['flows']} (TCP: {totals['tcp_flows']}, UDP: {totals['udp_flows']})\n"
        f"Bytes: {totals['ip_bytes']}\n"
    )
    _write_top_list("Top DNS QNAMEs", summary["top_dns_qnames"])
    _write_top_list("Top TLS SNI", summary["top_tls_sni"])
    _write_kv_list("HTTP Methods", summary["http_methods"])
    _write_kv_list("HTTP Status Codes", summary["http_status_codes"])
    _write_top_list("Top Flows (bytes)", summary["top_flows_by_bytes"])
    return 0


def _write_top_list(title: str, items: Sequence[dict[str, object]]) -> None:
    if not items:
        return
    sys.stdout.write(f"\n{title}\n")
    for item in items:
        name_obj = item.get("name", "")
        name = name_obj if isinstance(name_obj, str) else str(name_obj)
        count_obj = item.get("count", 0)
        count = count_obj if isinstance(count_obj, int) else 0
        sys.stdout.write(f"  {count:>6}  {name}\n")


def _write_kv_list(title: str, mapping: dict[str, int]) -> None:
    if not mapping:
        return
    sys.stdout.write(f"\n{title}\n")
    for key in sorted(mapping):
        sys.stdout.write(f"  {key:<8} {mapping[key]}\n")


if __name__ == "__main__":
    raise SystemExit(main())
