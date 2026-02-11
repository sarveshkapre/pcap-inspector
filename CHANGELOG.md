# CHANGELOG

## Unreleased

- Restricted `--bpf` / `--filter` option for parity with common PCAP tooling.
- Add `inspect --flows-only` for fast flow-only triage.
- Add `--dns-ports` for `inspect/summary/timeline` to reduce false-positive DNS parsing.
- Add `pcap-inspector schema --timeline` for `timeline --json` output shape.
- Add stdin PCAP ingestion (`--pcap -`) across `inspect`, `summary`, and `timeline`.
- Add `--http-ports` to `summary` and `timeline` for HTTP parsing precision parity with `inspect`.

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
