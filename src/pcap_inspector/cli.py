from __future__ import annotations

import argparse
from pathlib import Path

from .inspector import inspect_pcap


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

    args = parser.parse_args(argv)
    return int(args.func(args))


def _run(args: argparse.Namespace) -> int:
    return inspect_pcap(Path(args.pcap), Path(args.out), args.max_packets)


if __name__ == "__main__":
    raise SystemExit(main())
