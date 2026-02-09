from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .inspector import PcapInspectorError, inspect_pcap, summarize_pcap
from .schema import JSONL_SCHEMA


def _non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def _non_negative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def _port(value: str) -> int:
    parsed = int(value)
    if parsed <= 0 or parsed > 65535:
        raise argparse.ArgumentTypeError("must be in 1..65535")
    return parsed


def _proto(value: str) -> str:
    parsed = value.strip().upper()
    if parsed not in {"TCP", "UDP", "IP"}:
        raise argparse.ArgumentTypeError("must be one of: TCP, UDP, IP")
    return parsed


def _split_csv(values: Sequence[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part:
                out.append(part)
    return out


def _normalize_hosts(values: Sequence[str]) -> set[str]:
    out: set[str] = set()
    for raw in _split_csv(values):
        raw = raw.strip()
        if raw.startswith("[") and raw.endswith("]") and len(raw) >= 2:
            raw = raw[1:-1]
        if raw:
            out.add(raw)
    return out


def _normalize_protos(values: Sequence[str]) -> set[str]:
    out: set[str] = set()
    for raw in _split_csv(values):
        out.add(_proto(raw))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pcap-inspector")
    parser.add_argument("--version", action="version", version="0.1.0")

    sub = parser.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("inspect", help="Inspect a PCAP file")
    p_run.add_argument("--pcap", required=True, help="Path to .pcap file")
    p_run.add_argument(
        "--out", default="pcap-report.jsonl", help="Output path (.jsonl) or '-' for stdout"
    )
    p_run.add_argument("--max-packets", type=_non_negative_int, default=0, help="0 = no limit")
    p_run.add_argument(
        "--include-flows",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include flow summary rows in JSONL output",
    )
    p_run.add_argument(
        "--include-flow-times",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Include per-flow first_ts/last_ts timestamps in flow rows",
    )
    p_run.add_argument(
        "--include-dns",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include DNS events in JSONL output",
    )
    p_run.add_argument(
        "--include-http",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include HTTP events in JSONL output",
    )
    p_run.add_argument(
        "--include-tls",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include TLS ClientHello events in JSONL output",
    )
    p_run.add_argument(
        "--sort-flows",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Sort flow summary rows by flow key",
    )
    p_run.add_argument(
        "--top-flows",
        type=_non_negative_int,
        default=0,
        help="Only include top N flow rows by bytes (0 = all flows)",
    )
    p_run.add_argument(
        "--top-events",
        type=_non_negative_int,
        default=0,
        help="Only include first N event rows (DNS/HTTP/TLS) in packet order (0 = all events)",
    )
    p_run.add_argument(
        "--host",
        action="append",
        default=[],
        help="Only include flows where src or dst matches host (repeatable; comma-separated)",
    )
    p_run.add_argument(
        "--port",
        action="append",
        default=[],
        type=_port,
        help="Only include flows where sport or dport matches port (repeatable)",
    )
    p_run.add_argument(
        "--proto",
        action="append",
        default=[],
        help="Only include flows with protocol (TCP/UDP/IP) (repeatable; comma-separated)",
    )
    p_run.add_argument(
        "--since-ts",
        type=_non_negative_float,
        default=None,
        help="Only process packets with ts >= since-ts (seconds since epoch)",
    )
    p_run.add_argument(
        "--until-ts",
        type=_non_negative_float,
        default=None,
        help="Only process packets with ts <= until-ts (seconds since epoch)",
    )
    p_run.add_argument(
        "--normalize-flows",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Normalize bidirectional flow keys as A:port<->B:port",
    )
    p_run.add_argument(
        "--stats",
        action="store_true",
        help="Write a short summary to stderr after inspection",
    )
    p_run.add_argument(
        "--stats-json",
        action="store_true",
        help="Write a JSON summary to stderr after inspection",
    )
    p_run.set_defaults(func=_run)

    p_summary = sub.add_parser("summary", help="Print an aggregate summary (no JSONL output)")
    p_summary.add_argument("--pcap", required=True, help="Path to .pcap file")
    p_summary.add_argument("--max-packets", type=_non_negative_int, default=0, help="0 = no limit")
    p_summary.add_argument(
        "--top", type=_non_negative_int, default=10, help="Number of top items to show"
    )
    p_summary.add_argument(
        "--host",
        action="append",
        default=[],
        help="Only include flows where src or dst matches host (repeatable; comma-separated)",
    )
    p_summary.add_argument(
        "--port",
        action="append",
        default=[],
        type=_port,
        help="Only include flows where sport or dport matches port (repeatable)",
    )
    p_summary.add_argument(
        "--proto",
        action="append",
        default=[],
        help="Only include flows with protocol (TCP/UDP/IP) (repeatable; comma-separated)",
    )
    p_summary.add_argument(
        "--since-ts",
        type=_non_negative_float,
        default=None,
        help="Only process packets with ts >= since-ts (seconds since epoch)",
    )
    p_summary.add_argument(
        "--until-ts",
        type=_non_negative_float,
        default=None,
        help="Only process packets with ts <= until-ts (seconds since epoch)",
    )
    p_summary.add_argument(
        "--normalize-flows",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Normalize bidirectional flow keys as A:port<->B:port",
    )
    p_summary.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_summary.set_defaults(func=_summary)

    p_schema = sub.add_parser("schema", help="Print JSON Schema for JSONL records")
    p_schema.set_defaults(func=_schema)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except PcapInspectorError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2


def _run(args: argparse.Namespace) -> int:
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        sys.stderr.write(f"error: pcap not found: {pcap_path}\n")
        return 2
    if not pcap_path.is_file():
        sys.stderr.write(f"error: pcap is not a file: {pcap_path}\n")
        return 2

    since_ts = args.since_ts if args.since_ts is not None else None
    until_ts = args.until_ts if args.until_ts is not None else None
    if since_ts is not None and until_ts is not None and since_ts > until_ts:
        sys.stderr.write("error: since-ts must be <= until-ts\n")
        return 2

    stats_out = sys.stderr if args.stats or args.stats_json else None
    out_path = Path(args.out)
    hosts = _normalize_hosts(args.host)
    ports = set(args.port)
    protos = _normalize_protos(args.proto)
    rc = inspect_pcap(
        pcap_path,
        out_path,
        int(args.max_packets),
        include_flows=bool(args.include_flows),
        include_flow_times=bool(args.include_flow_times),
        sort_flows=bool(args.sort_flows),
        top_flows=int(args.top_flows),
        top_events=int(args.top_events),
        since_ts=since_ts,
        until_ts=until_ts,
        hosts=hosts if hosts else None,
        ports=ports if ports else None,
        protos=protos if protos else None,
        normalize_flows=bool(args.normalize_flows),
        include_dns=bool(args.include_dns),
        include_http=bool(args.include_http),
        include_tls=bool(args.include_tls),
        stats_out=stats_out,
        stats_json=bool(args.stats_json),
    )
    if out_path.as_posix() != "-":
        sys.stdout.write(f"wrote {out_path}\n")
    return rc


def _summary(args: argparse.Namespace) -> int:
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        sys.stderr.write(f"error: pcap not found: {pcap_path}\n")
        return 2
    if not pcap_path.is_file():
        sys.stderr.write(f"error: pcap is not a file: {pcap_path}\n")
        return 2

    since_ts = args.since_ts if args.since_ts is not None else None
    until_ts = args.until_ts if args.until_ts is not None else None
    if since_ts is not None and until_ts is not None and since_ts > until_ts:
        sys.stderr.write("error: since-ts must be <= until-ts\n")
        return 2

    summary = summarize_pcap(
        pcap_path,
        max_packets=int(args.max_packets),
        top_n=int(args.top),
        since_ts=since_ts,
        until_ts=until_ts,
        hosts=_normalize_hosts(args.host) or None,
        ports=set(args.port) or None,
        protos=_normalize_protos(args.proto) or None,
        normalize_flows=bool(args.normalize_flows),
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


def _schema(_: argparse.Namespace) -> int:
    sys.stdout.write(json.dumps(JSONL_SCHEMA, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
