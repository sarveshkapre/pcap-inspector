from __future__ import annotations

import argparse
import json
import sys
import ipaddress
from collections.abc import Sequence
from pathlib import Path

from .inspector import PcapInspectorError, inspect_pcap, summarize_pcap, timeline_pcap
from .schema import JSONL_SCHEMA, SUMMARY_JSON_SCHEMA


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


def _normalize_host_nets(
    values: Sequence[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in _split_csv(values):
        raw = raw.strip()
        if raw.startswith("[") and raw.endswith("]") and len(raw) >= 2:
            raw = raw[1:-1]
        if not raw or "/" not in raw:
            continue
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError as e:
            raise PcapInspectorError(f"invalid --host CIDR '{raw}': {e}") from e
    return nets


def _normalize_host_exact(values: Sequence[str]) -> set[str]:
    out: set[str] = set()
    for raw in _split_csv(values):
        raw = raw.strip()
        if raw.startswith("[") and raw.endswith("]") and len(raw) >= 2:
            raw = raw[1:-1]
        if raw and "/" not in raw:
            out.add(raw)
    return out


def _normalize_protos(values: Sequence[str]) -> set[str]:
    out: set[str] = set()
    for raw in _split_csv(values):
        out.add(_proto(raw))
    return out


def _normalize_ports_csv(values: Sequence[str]) -> set[int]:
    out: set[int] = set()
    for raw in _split_csv(values):
        out.add(_port(raw))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pcap-inspector")
    parser.add_argument("--version", action="version", version="0.1.2")

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
        "--top-events-mode",
        choices=["packet", "flow-bytes"],
        default="packet",
        help=(
            "How to choose events when --top-events is set. "
            "'packet' keeps first N in packet order; "
            "'flow-bytes' prioritizes events from the highest-byte flows (two-pass)."
        ),
    )
    p_run.add_argument(
        "--http-ports",
        action="append",
        default=[],
        help=(
            "Only attempt HTTP parsing when sport or dport matches one of these ports "
            "(repeatable; comma-separated; example: 80,8080)"
        ),
    )
    p_run.add_argument(
        "--host",
        action="append",
        default=[],
        help=(
            "Only include flows where src or dst matches host or CIDR "
            "(repeatable; comma-separated; examples: 10.0.0.5, 10.0.0.0/8, 2001:db8::/32)"
        ),
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
        help=(
            "Only include flows where src or dst matches host or CIDR "
            "(repeatable; comma-separated; examples: 10.0.0.5, 10.0.0.0/8, 2001:db8::/32)"
        ),
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

    p_schema = sub.add_parser("schema", help="Print JSON Schema for JSON output formats")
    p_schema.add_argument(
        "--summary", action="store_true", help="Print schema for `summary --json`"
    )
    p_schema.set_defaults(func=_schema)

    p_timeline = sub.add_parser(
        "timeline", help="Print a compact conversation timeline for top flows"
    )
    p_timeline.add_argument("--pcap", required=True, help="Path to .pcap file")
    p_timeline.add_argument("--max-packets", type=_non_negative_int, default=0, help="0 = no limit")
    p_timeline.add_argument(
        "--top", type=_non_negative_int, default=20, help="Number of flows to show (0 = all)"
    )
    p_timeline.add_argument(
        "--host",
        action="append",
        default=[],
        help=(
            "Only include flows where src or dst matches host or CIDR "
            "(repeatable; comma-separated; examples: 10.0.0.5, 10.0.0.0/8, 2001:db8::/32)"
        ),
    )
    p_timeline.add_argument(
        "--port",
        action="append",
        default=[],
        type=_port,
        help="Only include flows where sport or dport matches port (repeatable)",
    )
    p_timeline.add_argument(
        "--proto",
        action="append",
        default=[],
        help="Only include flows with protocol (TCP/UDP/IP) (repeatable; comma-separated)",
    )
    p_timeline.add_argument(
        "--since-ts",
        type=_non_negative_float,
        default=None,
        help="Only process packets with ts >= since-ts (seconds since epoch)",
    )
    p_timeline.add_argument(
        "--until-ts",
        type=_non_negative_float,
        default=None,
        help="Only process packets with ts <= until-ts (seconds since epoch)",
    )
    p_timeline.add_argument(
        "--normalize-flows",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Normalize bidirectional flow keys as A:port<->B:port",
    )
    p_timeline.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p_timeline.set_defaults(func=_timeline)

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
    if args.top_events_mode != "packet" and int(args.top_events) <= 0:
        sys.stderr.write("error: --top-events-mode requires --top-events > 0\n")
        return 2

    stats_out = sys.stderr if args.stats or args.stats_json else None
    out_path = Path(args.out)
    hosts = _normalize_host_exact(args.host)
    host_nets = _normalize_host_nets(args.host)
    http_ports = _normalize_ports_csv(args.http_ports)
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
        top_events_mode=str(args.top_events_mode),
        since_ts=since_ts,
        until_ts=until_ts,
        hosts=hosts if hosts else None,
        host_nets=host_nets if host_nets else None,
        http_ports=http_ports if http_ports else None,
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
        hosts=_normalize_host_exact(args.host) or None,
        host_nets=_normalize_host_nets(args.host) or None,
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


def _schema(args: argparse.Namespace) -> int:
    schema = SUMMARY_JSON_SCHEMA if args.summary else JSONL_SCHEMA
    sys.stdout.write(json.dumps(schema, indent=2, sort_keys=True) + "\n")
    return 0


def _timeline(args: argparse.Namespace) -> int:
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

    hosts = _normalize_host_exact(args.host) or None
    host_nets = _normalize_host_nets(args.host) or None
    ports = set(args.port) or None
    protos = _normalize_protos(args.proto) or None
    timeline = timeline_pcap(
        pcap_path,
        max_packets=int(args.max_packets),
        top_n=int(args.top),
        since_ts=since_ts,
        until_ts=until_ts,
        hosts=hosts,
        host_nets=host_nets,
        ports=ports,
        protos=protos,
        normalize_flows=bool(args.normalize_flows),
    )
    if args.json:
        sys.stdout.write(json.dumps(timeline, indent=2) + "\n")
        return 0

    totals = timeline["totals"]
    sys.stdout.write(f"PCAP Timeline: {timeline['pcap']}\n")
    if totals.get("max_packets"):
        sys.stdout.write(f"Max packets: {totals['max_packets']}\n")
    if totals.get("since_ts") is not None or totals.get("until_ts") is not None:
        sys.stdout.write(f"Time window: {totals.get('since_ts')}..{totals.get('until_ts')}\n")
    if totals.get("hosts") is not None or totals.get("host_nets") is not None:
        sys.stdout.write(
            "Host filters: host={hosts} cidr={cidr}\n".format(
                hosts=totals.get("hosts"),
                cidr=totals.get("host_nets"),
            )
        )
    if totals.get("ports") is not None or totals.get("protos") is not None:
        sys.stdout.write(
            "Flow filters: port={ports} proto={protos}\n".format(
                ports=totals.get("ports"),
                protos=totals.get("protos"),
            )
        )
    sys.stdout.write(
        "Packets: {packets_seen} (IP: {ip_packets})\nFlows: {flows}\nBytes: {ip_bytes}\n".format(
            **totals
        )
    )

    flows = timeline["flows"]
    if not flows:
        return 0

    base = totals.get("first_ts")
    sys.stdout.write("\nTimeline (top flows by bytes)\n")
    for row in flows:
        first_ts = row.get("first_ts")
        last_ts = row.get("last_ts")
        offset = (
            (float(first_ts) - float(base)) if base is not None and first_ts is not None else 0.0
        )
        duration = (
            (float(last_ts) - float(first_ts))
            if first_ts is not None and last_ts is not None
            else 0.0
        )
        sys.stdout.write(
            "  +{offset:>8.3f}s  {duration:>8.3f}s  {bytes:>10}B  {packets:>6}p  "
            "dns={dns_events:>4} http={http_events:>4} tls={tls_client_hellos:>3}  {flow}\n".format(
                offset=offset,
                duration=duration,
                bytes=int(row.get("bytes", 0) or 0),
                packets=int(row.get("packets", 0) or 0),
                dns_events=int(row.get("dns_events", 0) or 0),
                http_events=int(row.get("http_events", 0) or 0),
                tls_client_hellos=int(row.get("tls_client_hellos", 0) or 0),
                flow=str(row.get("flow", "")),
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
