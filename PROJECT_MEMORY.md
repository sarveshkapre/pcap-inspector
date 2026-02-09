# PROJECT_MEMORY

## Entry: 2026-02-09-cycle2-event-volume-and-flow-normalization
- Decision: Add `inspect --top-events N`, add `--normalize-flows` to `inspect`/`summary`, and unify packet flow-part extraction between code paths.
- Why: High-volume captures could overwhelm JSONL event output, and directional-only flows made conversation-level triage harder. Shared extraction logic prevents divergence bugs between `inspect` and `summary`.
- Evidence:
  - Code: `src/pcap_inspector/inspector.py`, `src/pcap_inspector/cli.py`
  - Tests: `tests/test_inspector.py`, `tests/test_smoke.py`
  - Verification: `make check`; CLI smoke commands listed in `CLONE_FEATURES.md`
- Commit: `<pending>`
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
- Commit: `<pending>`
- Confidence: High
- Trust Label: verified-local
- Follow-ups:
  - Keep memory entries updated with concrete commit IDs after each ship.
