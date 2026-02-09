# RELEASE

This repo uses SemVer. `v0.x` may include breaking changes.

## v0.1.3 - 2026-02-09

- PCAPNG read support via Scapy `PcapNgReader`.
- Add `--tls-ports` to scope TLS parsing and reduce false positives.
- Add `summary/timeline --format text|json` (keep `--json` alias).

## v0.1.2 - 2026-02-09

- Add `timeline` command (text + `--json`) for compact conversation sequencing.
- Extend `--host` filtering to accept CIDR ranges (IPv4 + IPv6).
- Add JSON Schema for `summary --json` output and expose it via `pcap-inspector schema --summary`.
- Add `inspect --top-events-mode flow-bytes` to prioritize events from highest-byte flows.
- Add `inspect --http-ports` to reduce false-positive HTTP parsing from arbitrary TCP payloads.

## v0.1.1 - 2026-02-09

- Add `summary` + `schema` commands for machine-readable workflows.
- Add flow/event backpressure (`--top-flows`, `--top-events`) and bidirectional normalization (`--normalize-flows`).
- Add targeted triage filters: timestamp window (`--since-ts/--until-ts`) and flow filters (`--host/--port/--proto`).
- Improve reliability and operator UX: TCP stream reassembly robustness, quieter Scapy logs, and cleaner errors.
- Add benchmarks (`make bench`, `make bench-events`) to track throughput and memory signals.

## v0.1.0 - 2026-01-31

- Flow summaries and DNS/HTTP metadata extraction.
- JSONL report output.
