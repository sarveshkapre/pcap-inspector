# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration
- GitHub issues and Actions runs (2026-02-09)

## Candidate Features To Do
- [ ] P1: Add `--since-ts/--until-ts` timestamp-range filtering for `inspect` and `summary` (epoch seconds, inclusive).
- [ ] P1: Add simple flow filtering flags (`--host`, `--port`, `--proto`) for fast triage without post-processing.
- [ ] P2: Add event-priority mode (for example rank by flow byte-volume) to complement packet-order `--top-events`.
- [ ] P2: Add a compact flow timeline output format for quick conversation sequencing (for example top flows with start/end/duration + event counts).
- [ ] P2: Add `make bench-events` to benchmark DNS/HTTP/TLS extraction paths in addition to flows-only throughput.
- [ ] P3: Improve PCAPNG compatibility story (detect file type; document behavior; better errors if unsupported).
- [ ] P3: Add a JSON Schema for `summary --json` output for tooling integration / stability.
- [ ] P3: Release hygiene: move shipped items into a new version in `CHANGELOG.md`/`RELEASE.md`, and bump version strings.

## Implemented
- [x] 2026-02-09 P0: Add a benchmark script + reproducible fixture generator to track `inspect` throughput and memory (RSS).
  Evidence: `scripts/bench_inspect.py`, `Makefile` (`make bench`)
- [x] 2026-02-09 P0: Silence noisy Scapy runtime warnings during CLI usage.
  Evidence: `src/pcap_inspector/inspector.py`; smoke: `.venv/bin/python -m pcap_inspector --help` (no warnings)
- [x] 2026-02-09 P0: Improve CLI error handling for missing/corrupt PCAP files (no traceback; actionable message).
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_smoke.py` (`test_missing_pcap_errors_cleanly*`)
- [x] 2026-02-09 P1: Add `inspect --include-flow-times` to include per-flow `first_ts`/`last_ts` in flow rows.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `src/pcap_inspector/schema.py`, `tests/test_inspector.py` (`test_inspect_pcap_flow_times`)
- [x] 2026-02-09 P0: Improved TCP stream reassembly robustness for out-of-order and retransmitted segments.
  Evidence: `src/pcap_inspector/inspector.py`, `tests/test_inspector.py` (`test_inspect_pcap_extracts_tls_sni_out_of_order`)
- [x] 2026-02-09 P0: Fixed `max_packets` accounting to avoid off-by-one stats in `inspect` and `summary`.
  Evidence: `src/pcap_inspector/inspector.py`, `tests/test_inspector.py` (`test_inspect_pcap_max_packets_stats_json`, `test_summarize_pcap_max_packets_counts_processed_only`)
- [x] 2026-02-09 P1: Added `inspect --top-flows N` to emit only highest-byte flow rows.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_inspector.py` (`test_inspect_pcap_top_flows`)
- [x] 2026-02-09 P1: Expanded HTTP request detection to common methods (GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH/CONNECT/TRACE).
  Evidence: `src/pcap_inspector/inspector.py`, `tests/test_inspector.py` (`test_inspect_pcap_http_put_method`)
- [x] 2026-02-09 P1: Added targeted regression tests for reassembly ordering, packet-limit accounting, and top-flow filtering.
  Evidence: `tests/test_inspector.py`, `tests/test_smoke.py`
- [x] 2026-02-09 P2: Added CLI argument validation for invalid negative numeric values (`--max-packets`, `--top`, `--top-flows`).
  Evidence: `src/pcap_inspector/cli.py`, `tests/test_smoke.py` (`test_invalid_negative_numeric_arg`)
- [x] 2026-02-09 P2: Updated docs to match shipped CLI and behavior.
  Evidence: `README.md`, `PROJECT.md`, `PLAN.md`, `CHANGELOG.md`, `UPDATE.md`
- [x] 2026-02-09 P2: Ran full quality gate and real CLI smoke path.
  Evidence: `make check`; smoke commands for `inspect --top-flows 1 --stats-json` and `summary --json` on generated pcap.
- [x] 2026-02-09 P0: Added `inspect --top-events N` to cap emitted DNS/HTTP/TLS event rows.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_inspector.py` (`test_inspect_pcap_top_events`, `test_inspect_pcap_stats_json_includes_event_limit`)
- [x] 2026-02-09 P0: Added `--normalize-flows` mode for `inspect` and `summary` bidirectional conversation aggregation.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_inspector.py` (`test_inspect_pcap_normalize_flows`, `test_summarize_pcap_normalize_flows`)
- [x] 2026-02-09 P1: Removed duplicated flow-part extraction logic shared by `inspect` and `summary`.
  Evidence: `src/pcap_inspector/inspector.py` (`_extract_flow_parts`, `_flow_key_with_mode`)
- [x] 2026-02-09 P1: Added deterministic tie-break ordering for summary top-flow output when bytes tie.
  Evidence: `src/pcap_inspector/inspector.py` (`_top_flows_by_bytes`), `tests/test_inspector.py` (`test_summarize_pcap_top_flows_tie_breaker`)
- [x] 2026-02-09 P2: Added persistent maintainer records (`PROJECT_MEMORY.md`, `INCIDENTS.md`) and synchronized docs.
  Evidence: `PROJECT_MEMORY.md`, `INCIDENTS.md`, `SCHEMA.md`, `README.md`, `PROJECT.md`, `PLAN.md`, `ROADMAP.md`, `CHANGELOG.md`, `UPDATE.md`
- [x] 2026-02-09 P2: Verified local smoke path for new options on generated PCAP.
  Evidence: `.venv/bin/python -m pcap_inspector inspect --top-events 1 --normalize-flows --stats-json`; `.venv/bin/python -m pcap_inspector summary --json --normalize-flows`

## Insights
- `main` is currently green in GitHub Actions; no open owner/bot-authored issues are pending.
- Rebuilding stream assembly from retained segments materially improves TLS metadata recovery when packets arrive out of order.
- Packet-limit stats now align with processed packets, making summary output trustworthy for bounded runs.
- `--top-flows` is a practical way to control JSONL size for noisy captures without losing event records.
- `--top-events` now provides independent event-row backpressure for large captures.
- `--normalize-flows` enables cleaner conversation-centric triage and reduces directional flow duplication in summaries.
- Market scan (bounded): comparable tools emphasize time-range filtering, fast field filters, timelines, and machine-readable exports.
  Links:
  - Wireshark: display filters like `frame.time_epoch` enable time-range filtering while iterating captures: https://www.wireshark.org/docs/dfref/f/frame.html
  - Zeek: protocol-aware logs designed for triage at scale (structured logging model): https://docs.zeek.org/en/master/logs/
  - Arkime: indexing + session timeline UI; APIs support `startTime`/`stopTime` for time windows: https://arkime.com/api
  - Suricata: produces JSON (EVE) events for alerts/metadata pipelines: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
  - Brimcap/Zui: query-centric exploration of PCAP-derived structured data: https://github.com/brimdata/zui

## Notes
- This file is maintained by the autonomous clone loop.
