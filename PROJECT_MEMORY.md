# PROJECT_MEMORY

## Entry: 2026-02-09-cycle1-clean-cli-errors-and-flow-times
- Decision: Silence Scapy runtime warnings by default; add clean CLI errors for unreadable PCAPs; add optional flow timestamps via `inspect --include-flow-times`.
- Why: Keep CLI output clean for piping/grep, avoid traceback-on-user-error, and lay groundwork for future flow timeline features.
- Evidence:
  - Code: `src/pcap_inspector/inspector.py`, `src/pcap_inspector/cli.py`, `src/pcap_inspector/schema.py`
  - Tests: `tests/test_smoke.py` (`test_missing_pcap_errors_cleanly*`), `tests/test_inspector.py` (`test_inspect_pcap_flow_times`)
  - Verification: `make check`; `.venv/bin/python -m pcap_inspector --help` (no Scapy warnings)
- Commit: `2767abf865490cf666b1ccae09e243f304154932`
- Confidence: High
- Trust Label: trusted
- Follow-ups:
  - Add timestamp range filtering (`--since-ts/--until-ts`) and compact flow timeline output.

## Entry: 2026-02-09-cycle1-benchmark-harness
- Decision: Add a lightweight benchmark harness (`make bench`) with a reproducible fixture generator and JSON output.
- Why: Track throughput and memory regressions across changes without requiring external PCAP artifacts in-repo.
- Evidence:
  - Code: `scripts/bench_inspect.py`, `Makefile`, `.gitignore`, `ROADMAP.md`
  - Verification: `make bench` (produces JSON with elapsed_s, packets_per_s, maxrss_kb)
- Commit: `fd1475e6455a0f72fcb5b28ed18317599c490d15`
- Confidence: High
- Trust Label: trusted
- Follow-ups:
  - Add a second bench mode that includes event extraction (`--top-events`) to track TLS/DNS/HTTP paths too.

## Entry: 2026-02-09-cycle2-event-volume-and-flow-normalization
- Decision: Add `inspect --top-events N`, add `--normalize-flows` to `inspect`/`summary`, and unify packet flow-part extraction between code paths.
- Why: High-volume captures could overwhelm JSONL event output, and directional-only flows made conversation-level triage harder. Shared extraction logic prevents divergence bugs between `inspect` and `summary`.
- Evidence:
  - Code: `src/pcap_inspector/inspector.py`, `src/pcap_inspector/cli.py`
  - Tests: `tests/test_inspector.py`, `tests/test_smoke.py`
  - Verification: `make check`; CLI smoke commands listed in `CLONE_FEATURES.md`
- Commit: `3b5fe08c98bf3972d829e02be82d4278a4bb6f22`
- Confidence: High
- Trust Label: trusted
- Follow-ups:
  - Add benchmark fixture/script for throughput and memory regression tracking.
  - Consider event-priority ranking mode beyond packet-order capping.

## Entry: 2026-02-09-cycle2-doc-sync
- Decision: Synchronize docs and trackers for new CLI behavior and maintenance process artifacts.
- Why: Keep operator-facing docs and autonomous-maintainer records consistent with shipped behavior.
- Evidence:
  - Docs: `README.md`, `PROJECT.md`, `PLAN.md`, `ROADMAP.md`, `SCHEMA.md`, `CHANGELOG.md`, `UPDATE.md`, `CLONE_FEATURES.md`
  - Process records: `PROJECT_MEMORY.md`, `INCIDENTS.md`
- Commit: `e87e5709f04bbb30e82d84ee95fc255f21d47289`
- Confidence: High
- Trust Label: trusted
- Follow-ups:
  - Keep memory entries updated with concrete commit IDs after each ship.

## Entry: 2026-02-09-cycle2-triage-filters-and-input-hygiene
- Decision: Add timestamp window filtering (`--since-ts/--until-ts`), add basic flow filters (`--host/--port/--proto`), and improve operator errors for PCAPNG/non-PCAP inputs.
- Why: Real-world triage usually starts by narrowing to a time window and a small set of conversations; clearer errors reduce friction and avoid tracebacks on common file-format mistakes.
- Evidence:
  - Code: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`
  - Tests: `tests/test_inspector.py`, `tests/test_smoke.py` (`test_invalid_time_window_rejected`, `test_pcapng_errors_cleanly`)
  - Smoke: `.venv/bin/python -m pcap_inspector inspect --pcap bench/fixture-20000p-500f-0b.pcap --out - --max-packets 50 --top-events 3 --top-flows 2 --since-ts 1700000000 --until-ts 1700000000.01 --host 10.0.0.0 --port 53 --proto udp --stats-json`
  - Verification: `make check`
- Commit:
  - Timestamp window: `89ece344d8994e4398de096249306eeda50ff78b`
  - Flow filters: `5ba540f98e7fc96ac8aecab91796112ac9839058`
  - PCAPNG/non-PCAP errors: `16d36224725407732cedd3ee747b46027054347d`
- Confidence: High
- Trust Label: trusted
- Follow-ups:
  - Add a compact flow timeline output mode (top flows with start/end/duration + event counts).
  - Add event-priority mode for `--top-events` beyond packet order.

## Entry: 2026-02-09-cycle2-bench-events
- Decision: Add `make bench-events` to benchmark DNS extraction paths (and optional TLS/HTTP when fixtures evolve) in addition to flows-only throughput.
- Why: Reassembly and event extraction are the most likely sources of throughput and memory regressions; we want a quick regression signal in CI and local dev.
- Evidence:
  - Code: `Makefile`, `scripts/bench_inspect.py`, `PROJECT.md`
  - Verification: `make bench-events` (prints JSON with elapsed_s/packets_per_s/maxrss_kb)
- Commit: `d8346a657b5208e00cfc8ae2dd6e18f65107c092`
- Confidence: High
- Trust Label: trusted

## Entry: 2026-02-09-cycle2-release-hygiene-v0-1-1
- Decision: Consolidate shipped items into `v0.1.1` in release docs and bump version strings.
- Why: Keep docs aligned with behavior and give users a stable version reference when scripts and options evolve quickly.
- Evidence:
  - Docs: `CHANGELOG.md`, `RELEASE.md`, `ROADMAP.md`, `UPDATE.md`, `README.md`
  - Versioning: `pyproject.toml`, `src/pcap_inspector/cli.py`
  - Verification: `make check`
- Commit: `2763c2c18e143901416f48cd7aec716bdf797fae`
- Confidence: High
- Trust Label: trusted

## Entry: 2026-02-09-cycle3-timeline-cidr-and-summary-schema
- Decision: Add `timeline` as a first-class command for compact conversation sequencing, extend `--host` to accept CIDR filters, and publish a JSON Schema for `summary --json`.
- Why: Timeline views are a baseline expectation for PCAP triage, CIDR filtering is a high-leverage primitive for narrowing noisy captures, and schemas reduce downstream tooling risk as outputs evolve.
- Evidence:
  - Code: `src/pcap_inspector/inspector.py` (`timeline_pcap`, CIDR filtering), `src/pcap_inspector/cli.py` (`timeline`, `schema --summary`, CIDR parsing), `src/pcap_inspector/schema.py` (`SUMMARY_JSON_SCHEMA`)
  - Tests: `tests/test_inspector.py` (CIDR + timeline), `tests/test_smoke.py` (`schema --summary`)
  - Docs: `README.md`, `PROJECT.md`, `SCHEMA.md` (schema + timeline usage)
  - Verification:
    - `make check` (pass)
    - `.venv/bin/pcap-inspector timeline --pcap bench/fixture-20000p-500f-0b.pcap --top 3` (prints timeline rows)
- Mistakes And Fixes:
  - Root cause: IPv6 CIDR test fixture accidentally matched on the destination address, so the filter did not exclude the "out" packet.
  - Fix: Adjust the negative fixture so both src and dst fall outside the CIDR.
  - Prevention rule: For filter tests, ensure "excluded" fixtures have no field (src/dst) that could match the filter predicate.
- Commit:
  - CIDR host filters: `ef4d5aad72d3353638263f503422dfe226439ffd`
  - Summary JSON Schema: `951b6af632171ef651fb0b2eb1ca5496b7bb8bba`
  - Timeline command: `5713f4afb1ba7624ae063c0c929d158524610cc4`
  - Doc UX (use `.venv/bin/pcap-inspector`): `5e366e2d383788d1e7a6e3c1e46a9fc19bdd73e5`
- Confidence: High
- Trust Label: trusted
- Follow-ups:
  - Event-priority mode for `--top-events` beyond packet order.
  - Optional HTTP port filtering to reduce false positives from arbitrary TCP payloads.

## Entry: 2026-02-09-cycle4-event-ranking-http-ports-and-v0-1-2
- Decision: Add `inspect --top-events-mode flow-bytes` (two-pass, flow-ranked event selection) and add `inspect --http-ports` to reduce false-positive HTTP extraction; bump version/docs to `v0.1.2`.
- Why: In large captures, “first N events” is often not representative; ranking by highest-byte conversations improves triage value. Port-scoping HTTP detection reduces spurious request/status lines from arbitrary TCP payloads.
- Evidence:
  - Code: `src/pcap_inspector/cli.py`, `src/pcap_inspector/inspector.py`
  - Tests: `tests/test_inspector.py` (`test_inspect_pcap_top_events_flow_bytes_mode`, `test_inspect_pcap_http_ports_filter`), `tests/test_smoke.py` (`test_top_events_mode_requires_top_events`)
  - Docs/version: `pyproject.toml`, `README.md`, `PROJECT.md`, `CHANGELOG.md`, `RELEASE.md`, `ROADMAP.md`, `PLAN.md`, `UPDATE.md`, `CLONE_FEATURES.md`
- Verification Evidence:
  - `make check` (pass)
  - Smoke: `.venv/bin/pcap-inspector inspect --pcap bench/fixture-20000p-500f-0b.pcap --out - --no-include-flows --top-events 5 --top-events-mode flow-bytes --http-ports 80,8080 --stats-json` (pass; stats include `top_events_mode: flow-bytes`)
  - Smoke: `.venv/bin/pcap-inspector timeline --pcap bench/fixture-20000p-500f-0b.pcap --top 3` (pass)
  - Smoke: `.venv/bin/pcap-inspector schema --summary` (pass)
  - GitHub Actions: workflow `ci` runs `21837369543`, `21837429175`, `21837431468` (all success)
- Mistakes And Fixes:
  - Root cause: `git push` over HTTPS can hang due to global `credential.helper=osxkeychain` in headless automation.
  - Fix: Use GitHub API (git data endpoints) to advance `refs/heads/main` when git smart-HTTP is unreachable; for normal pushes, prefer `gh auth git-credential` helper overrides.
  - Prevention rule: In automation, force a non-interactive credential helper and fail fast; if git transport is unreliable, use `gh api` as the fallback path.
- Commit:
  - Candidate tasks refresh: `f5492fc9c0a07d26464068ba45bfbf0a243ab794`
  - Features + tests: `485564bca2bed3ec54b377d1946b28387837c494`
  - Release/doc alignment (local): `d8c5c249f9ba50ece4fc70e38dff4868d258b47a`
  - Release/doc alignment (remote, via GitHub API ref update): `1bcfd94c29809e18a4712ca4fbdb6ef86050d7eb`
- Confidence: High
- Trust Label: trusted
