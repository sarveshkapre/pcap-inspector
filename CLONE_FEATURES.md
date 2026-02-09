# Clone Feature Tracker

## Context Sources
- README and docs
- TODO/FIXME markers in code
- Test and build failures
- Gaps found during codebase exploration
- GitHub issues and Actions runs (2026-02-09)

## Candidate Features To Do
- [ ] P1: Add `inspect --top-events N` filtering for high-volume captures so event output can be bounded similarly to flow rows.
- [ ] P1: Add optional bidirectional flow normalization mode (`A:port <-> B:port`) for conversation-centric triage.
- [ ] P2: Add a small benchmark script/fixture to track `inspect` throughput and memory across releases.

## Implemented
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

## Insights
- `main` is currently green in GitHub Actions; no open owner/bot-authored issues are pending.
- Rebuilding stream assembly from retained segments materially improves TLS metadata recovery when packets arrive out of order.
- Packet-limit stats now align with processed packets, making summary output trustworthy for bounded runs.
- `--top-flows` is a practical way to control JSONL size for noisy captures without losing event records.

## Notes
- This file is maintained by the autonomous clone loop.
