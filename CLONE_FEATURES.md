# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration
- GitHub issues and Actions runs (2026-02-11)

## Candidate Features To Do
- [ ] P1: Add `inspect --progress` + `--progress-every` periodic stderr telemetry for long-running runs.
  Score: impact 4, effort 3, strategic fit 4, differentiation 3, risk 2, confidence 4.
- [ ] P1: Add `stats`/summary reporting for unmatched packets and filtered-out counts to improve operator trust.
  Score: impact 3, effort 2, strategic fit 4, differentiation 2, risk 2, confidence 4.
- [ ] P1: Add explicit CLI validation for contradictory include flags (for example `--flows-only --no-include-flows`).
  Score: impact 3, effort 1, strategic fit 4, differentiation 1, risk 1, confidence 5.
- [ ] P2: Add optional gzip output (`--out report.jsonl.gz`) for large captures.
  Score: impact 3, effort 3, strategic fit 3, differentiation 2, risk 2, confidence 4.
- [ ] P2: Add a lightweight `info` command (capture metadata only) for instant preflight checks.
  Score: impact 3, effort 2, strategic fit 4, differentiation 2, risk 2, confidence 4.
- [ ] P2: Add deterministic ordering option for events in flow-bytes mode (`--top-events-order packet|score`).
  Score: impact 2, effort 2, strategic fit 3, differentiation 2, risk 1, confidence 4.
- [ ] P2: Add malformed-packet counters in totals for summary/timeline outputs.
  Score: impact 3, effort 2, strategic fit 4, differentiation 1, risk 2, confidence 4.
- [ ] P2: Add fixture-backed performance guardrails (event-heavy + TLS-heavy) with threshold reporting.
  Score: impact 3, effort 3, strategic fit 4, differentiation 2, risk 2, confidence 3.
- [ ] P3: Add a streaming mode to emit flow rows periodically (not just at end) for very large captures.
  Score: impact 2, effort 4, strategic fit 3, differentiation 3, risk 3, confidence 3.
- [ ] P3: Add a restricted `--bpf` / `--filter` option (safe subset) for parity with common tooling.
  Score: impact 4, effort 5, strategic fit 4, differentiation 2, risk 4, confidence 2.
- [ ] P3: Add schema version tagging in all JSON outputs to stabilize downstream parser upgrades.
  Score: impact 2, effort 2, strategic fit 3, differentiation 2, risk 1, confidence 4.
- [ ] P3: Add PCAP processing resume/checkpoint support for multi-GB captures.
  Score: impact 2, effort 5, strategic fit 2, differentiation 4, risk 4, confidence 2.
- [ ] P3: Add optional protocol plugin hooks for custom event extraction.
  Score: impact 2, effort 5, strategic fit 2, differentiation 4, risk 4, confidence 2.

## Implemented
- [x] 2026-02-11 P0: Add stdin PCAP ingestion (`--pcap -`) for `inspect`, `summary`, and `timeline`, with safe temp-file spooling and empty-stdin error handling.
  Evidence: `src/pcap_inspector/cli.py`, `tests/test_smoke.py`, `README.md`, `PROJECT.md`, `CHANGELOG.md`
- [x] 2026-02-11 P0: Add `--http-ports` support to `summary` and `timeline` for parsing precision parity with `inspect`.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `src/pcap_inspector/schema.py`, `tests/test_inspector.py`, `README.md`, `PROJECT.md`, `CHANGELOG.md`
- [x] 2026-02-10 P0: Add `pcap-inspector schema --timeline` for `timeline --json` output shape.
  Evidence: `src/pcap_inspector/schema.py`, `src/pcap_inspector/cli.py`, `tests/test_smoke.py`, `README.md`, `PROJECT.md`, `SCHEMA.md`
- [x] 2026-02-10 P0: Add `inspect --flows-only` output mode (emit only flow rows; no DNS/HTTP/TLS events) for fast flow triage.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_cli.py`, `README.md`, `PROJECT.md`
- [x] 2026-02-10 P1: Add `--dns-ports` for `inspect/summary/timeline` to reduce false-positive DNS parsing.
  Evidence: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`, `tests/test_inspector.py`, `README.md`, `PROJECT.md`, `CHANGELOG.md`
- [x] 2026-02-10 P2: CLI polish: explicitly document `.pcapng` support in usage docs and CLI help text.
  Evidence: `src/pcap_inspector/cli.py`, `README.md`, `PROJECT.md`
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
- Latest `main` GitHub Actions runs are green as of 2026-02-10; three failures on 2026-02-09 were historical and tied to formatting drift and a transient PCAPNG test fixture mismatch.
- No open GitHub issues are currently present; owner/bot-authored issue queue is empty as of 2026-02-11.
- PCAPNG inputs are now supported (via Scapy `PcapNgReader`), removing a common friction point when captures come from modern tooling.
- `--tls-ports` provides a high-leverage precision knob for TLS metadata extraction, similar to `--http-ports` for HTTP.
- `--pcap -` closes a parity gap with tcpdump/tshark-style pipeline usage and enables fast shell chaining without temporary artifacts.
- `summary` and `timeline` now share the same HTTP parsing scope control (`--http-ports`) as `inspect`, which removes cross-command drift in noisy captures.
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
- Market scan (bounded, 2026-02-11): comparable tools emphasize pipeline ingestion, filter richness, timelines/conversation workflows, and machine-readable exports.
  Links:
  - Wireshark: display filters like `frame.time_epoch` enable time-range filtering while iterating captures: https://www.wireshark.org/docs/dfref/f/frame.html
  - Tshark: JSON output modes (`-T ek/json/fields`) and format caveats for automation: https://www.wireshark.org/docs/man-pages/tshark.html
  - Tcpdump: `-r -` explicitly supports reading captures from stdin in CLI pipelines: https://man7.org/linux/man-pages/man1/tcpdump.1.html
  - Termshark: terminal UI on top of tshark with Wireshark display filters + conversation/stream workflows: https://termshark.io/
  - Zeek: protocol-aware logs designed for triage at scale (structured logging model): https://docs.zeek.org/en/master/logs/
  - Arkime: indexing + session timeline UI; APIs support `startTime`/`stopTime` for time windows: https://arkime.com/api
  - Suricata: produces JSON (EVE) events for alerts/metadata pipelines: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
  - Brimcap/Zui: query-centric exploration of PCAP-derived structured data: https://github.com/brimdata/zui
  - Wireshark tools: `capinfos` for quick capture metadata/stats; `editcap` for conversion/slicing: https://www.wireshark.org/docs/man-pages/capinfos.html https://www.wireshark.org/docs/man-pages/editcap.html
- Gap map (2026-02-11):
  - Missing: restricted `--bpf`/filter expression support; inspect progress telemetry.
  - Weak: capture metadata preflight (`info`-style command) and explicit filtered-out packet counters.
  - Parity: stdin ingestion and HTTP port-scoping parity are now closed.
  - Differentiator opportunities: event-priority controls beyond top-N and lightweight streaming flow emission for huge captures.

## Notes
- This file is maintained by the autonomous clone loop.
