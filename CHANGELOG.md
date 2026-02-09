# CHANGELOG

## Unreleased

- Flow timeline visualization (compact timeline output for top conversations).
- Event-priority mode for `--top-events` (packet-order vs flow-ranked).
- Add a JSON Schema for `summary --json` output.

## v0.1.1 - 2026-02-09

- CLI: `summary`, `schema`, `--out -`, `--stats/--stats-json`.
- Filtering/controls: `--top-flows`, `--top-events`, `--normalize-flows`, `--since-ts/--until-ts`,
  `--host/--port/--proto`, `--no-include-flows`, `--include-*`/`--no-include-*`,
  `--sort-flows`, `--include-flow-times`.
- Metadata: DNS qname extraction; HTTP request/status lines (expanded methods); TLS ClientHello SNI/ALPN
  (best-effort).
- Reliability: improved TCP stream reassembly for out-of-order/retransmits; quieter Scapy logs; cleaner
  errors for missing/corrupt inputs including PCAPNG hints.
- Bench: `make bench` and `make bench-events` to track throughput and memory regression signals.

## v0.1.0 - 2026-01-31

- Flow summaries and DNS/HTTP metadata extraction.
- JSONL report output.
