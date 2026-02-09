# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration
- GitHub issues and Actions runs (2026-02-09)

## Candidate Features To Do
- [ ] P2: Add `--progress` to emit periodic stderr progress (packets processed, rate, flows, events) for long-running runs.
- [ ] P3: Add a streaming mode to emit flow rows periodically (not just at end) for very large captures.
- [ ] P3: Add a `--bpf` or `--filter` option (restricted safe subset; likely via a conversion/prefilter fallback) for parity with common PCAP tooling.
- [ ] P3: Add `pcap-inspector schema --timeline` for `timeline --json` output shape.
- [ ] P3: Add `inspect --dns-ports` to reduce false-positive DNS parsing from arbitrary UDP payloads.
- [ ] P3: Add `inspect --flows-only` output mode (emit only flow rows; no DNS/HTTP/TLS events) for very fast top-N flow triage.

## Implemented
- [x] 2026-02-09 P1: PCAPNG support: read `.pcapng` inputs via Scapy `PcapNgReader`.
  Evidence: `src/pcap_inspector/inspector.py`, `tests/test_inspector.py`, `CHANGELOG.md`, `ROADMAP.md`
- [x] 2026-02-09 P1: Add optional TLS port filtering (`--tls-ports`) to reduce false-positive TLS parsing.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_inspector.py`, `README.md`, `PROJECT.md`, `PLAN.md`
- [x] 2026-02-09 P2: Add `summary/timeline --format text|json` (keep `--json` as alias).
  Evidence: `src/pcap_inspector/cli.py`, `tests/test_cli.py`, `README.md`, `PROJECT.md`
- [x] 2026-02-09 P1: Add `inspect --top-events-mode flow-bytes` to prioritize events from highest-byte flows when `--top-events` is set.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_inspector.py`, `tests/test_smoke.py`
- [x] 2026-02-09 P1: Add `inspect --http-ports` to reduce false-positive HTTP parsing from arbitrary TCP payloads.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_inspector.py`
- [x] 2026-02-09 P1: Release hygiene: bump version to `v0.1.2` and align release docs with shipped features/options.
  Evidence: `pyproject.toml`, `CHANGELOG.md`, `RELEASE.md`, `README.md`, `PROJECT.md`, `PLAN.md`, `ROADMAP.md`, `UPDATE.md`
- [x] 2026-02-09 P2: CI ergonomics: add `workflow_dispatch` trigger so `ci` can be run manually via GitHub UI/CLI.
  Evidence: `.github/workflows/ci.yml`
- [x] 2026-02-09 P1: Add `timeline` command (text + `--json`) to show top conversations with start/end/duration and event counts.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py` (`timeline_pcap`), `tests/test_inspector.py`, docs in `README.md`
- [x] 2026-02-09 P1: Extend `--host` filtering to accept CIDR ranges (IPv4 + IPv6), for example `10.0.0.0/8` and `2001:db8::/32`.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py` (`_host_matches`, `host_nets`), `tests/test_inspector.py`
- [x] 2026-02-09 P1: Update docs/examples to prefer `.venv/bin/pcap-inspector ...` over `python -m ...` for better out-of-the-box UX on systems without `python`.
  Evidence: `README.md`, `PROJECT.md`, `SCHEMA.md`, `UPDATE.md`
- [x] 2026-02-09 P2: Add a JSON Schema for `summary --json` output and expose it via `pcap-inspector schema --summary`.
  Evidence: `src/pcap_inspector/schema.py`, `src/pcap_inspector/cli.py`, `tests/test_smoke.py`, `SCHEMA.md`
- [x] 2026-02-09 P1: Add `--since-ts/--until-ts` timestamp-window filtering for `inspect` and `summary`.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_inspector.py`, `tests/test_smoke.py`
- [x] 2026-02-09 P1: Add basic flow filters (`--host/--port/--proto`) for `inspect` and `summary`.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_inspector.py`, docs in `README.md`
- [x] 2026-02-09 P2: Improve operator errors for PCAPNG/non-PCAP inputs (no traceback; actionable hint).
  Evidence: `src/pcap_inspector/inspector.py`, `tests/test_smoke.py` (`test_pcapng_errors_cleanly`)
- [x] 2026-02-09 P2: Add `make bench-events` to benchmark event extraction throughput and memory signals.
  Evidence: `Makefile`, `scripts/bench_inspect.py`, `PROJECT.md`
- [x] 2026-02-09 P2: Release hygiene: move shipped items into `v0.1.1` in `CHANGELOG.md`/`RELEASE.md` and bump version strings.
  Evidence: `CHANGELOG.md`, `RELEASE.md`, `pyproject.toml`, `src/pcap_inspector/cli.py`, `README.md`, `ROADMAP.md`
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
- PCAPNG inputs are now supported (via Scapy `PcapNgReader`), removing a common friction point when captures come from modern tooling.
- `--tls-ports` provides a high-leverage precision knob for TLS metadata extraction, similar to `--http-ports` for HTTP.
- Rebuilding stream assembly from retained segments materially improves TLS metadata recovery when packets arrive out of order.
- Packet-limit stats now align with processed packets, making summary output trustworthy for bounded runs.
- `timeline` provides a lightweight top-conversation sequencing view without producing a full JSONL report.
- CIDR host filters are a high-leverage triage primitive (`--host 10.0.0.0/8`) that avoids post-processing.
- `schema --summary` makes `summary --json` safer to consume in tooling (stable shape + backwards-compatible extensions).
- `--top-flows` is a practical way to control JSONL size for noisy captures without losing event records.
- `--top-events` now provides independent event-row backpressure for large captures.
- `--top-events-mode flow-bytes` is useful for “what matters most” triage when you want a small event sample from the highest-volume conversations.
- `--http-ports` is a low-cost precision knob that reduces spurious HTTP events when inspecting arbitrary TCP payloads.
- `--normalize-flows` enables cleaner conversation-centric triage and reduces directional flow duplication in summaries.
- Market scan (bounded): comparable tools emphasize time-range filtering, fast field filters, timelines, and machine-readable exports.
  Links:
  - Wireshark: display filters like `frame.time_epoch` enable time-range filtering while iterating captures: https://www.wireshark.org/docs/dfref/f/frame.html
  - Tshark: JSON output modes (`-T ek/json/fields`) and format caveats for automation: https://www.wireshark.org/docs/man-pages/tshark.html
  - Termshark: terminal UI on top of tshark with Wireshark display filters + conversation/stream workflows: https://termshark.io/
  - Zeek: protocol-aware logs designed for triage at scale (structured logging model): https://docs.zeek.org/en/master/logs/
  - Arkime: indexing + session timeline UI; APIs support `startTime`/`stopTime` for time windows: https://arkime.com/api
  - Suricata: produces JSON (EVE) events for alerts/metadata pipelines: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
  - Brimcap/Zui: query-centric exploration of PCAP-derived structured data: https://github.com/brimdata/zui
  - Wireshark tools: `capinfos` for quick capture metadata/stats; `editcap` for conversion/slicing: https://www.wireshark.org/docs/man-pages/capinfos.html https://www.wireshark.org/docs/man-pages/editcap.html

## Notes
- This file is maintained by the autonomous clone loop.
