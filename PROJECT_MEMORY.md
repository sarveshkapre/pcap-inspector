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
- Trust Label: verified-local
- Follow-ups:
  - Add timestamp range filtering (`--since-ts/--until-ts`) and compact flow timeline output.

## Entry: 2026-02-09-cycle2-event-volume-and-flow-normalization
- Decision: Add `inspect --top-events N`, add `--normalize-flows` to `inspect`/`summary`, and unify packet flow-part extraction between code paths.
- Why: High-volume captures could overwhelm JSONL event output, and directional-only flows made conversation-level triage harder. Shared extraction logic prevents divergence bugs between `inspect` and `summary`.
- Evidence:
  - Code: `src/pcap_inspector/inspector.py`, `src/pcap_inspector/cli.py`
  - Tests: `tests/test_inspector.py`, `tests/test_smoke.py`
  - Verification: `make check`; CLI smoke commands listed in `CLONE_FEATURES.md`
- Commit: `3b5fe08c98bf3972d829e02be82d4278a4bb6f22`
- Confidence: High
- Trust Label: verified-local
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
- Trust Label: verified-local
- Follow-ups:
  - Keep memory entries updated with concrete commit IDs after each ship.
