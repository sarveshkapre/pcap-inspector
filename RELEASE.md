# RELEASE

This repo uses SemVer. `v0.x` may include breaking changes.

## v0.1.1 - 2026-02-09

- Add `summary` + `schema` commands for machine-readable workflows.
- Add flow/event backpressure (`--top-flows`, `--top-events`) and bidirectional normalization (`--normalize-flows`).
- Add targeted triage filters: timestamp window (`--since-ts/--until-ts`) and flow filters (`--host/--port/--proto`).
- Improve reliability and operator UX: TCP stream reassembly robustness, quieter Scapy logs, and cleaner errors.
- Add benchmarks (`make bench`, `make bench-events`) to track throughput and memory signals.

## v0.1.0 - 2026-01-31

- Flow summaries and DNS/HTTP metadata extraction.
- JSONL report output.
