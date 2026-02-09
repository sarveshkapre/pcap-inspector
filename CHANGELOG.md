# CHANGELOG

## Unreleased

- Add `make bench` and a benchmark script to track `inspect` throughput and memory (RSS).
- Silence noisy Scapy runtime warnings during CLI usage.
- Improve CLI errors for missing/corrupt PCAP files (no traceback; actionable message).
- Add `inspect --include-flow-times` to include per-flow `first_ts`/`last_ts` timestamps in flow rows.
- Improve TCP stream reassembly handling for out-of-order and retransmitted segments.
- Fix `max_packets` packet accounting in `inspect` and `summary`.
- Add `inspect --top-flows N` to include only top flow rows by bytes.
- Add `inspect --top-events N` to cap emitted DNS/HTTP/TLS event rows.
- Add optional bidirectional flow normalization via `--normalize-flows`.
- Refactor shared flow parsing logic used by both `inspect` and `summary`.
- Make `summary` top-flow ordering deterministic when byte counts tie.
- Expand HTTP request detection to common methods beyond GET/POST.
- Add TLS ClientHello SNI/ALPN extraction (best-effort).
- Support `--out -` to write JSONL to stdout.
- Add IPv6 support for flow keys + metadata extraction.
- Add `summary` command for aggregate stats.
- Add `--no-include-flows` to omit flow rows from JSONL output.
- Add `ts` timestamps to event records (dns/http/tls).
- Add `--include-*`/`--no-include-*` event filters (dns/http/tls).
- Add `--sort-flows` for stable flow row ordering.
- Add `schema` command and `SCHEMA.md` to document JSONL record fields.
- Add `--stats`/`--stats-json` to emit a summary to stderr after inspection.

## v0.1.0 - 2026-01-31

- Flow summaries and DNS/HTTP metadata extraction.
- JSONL report output.
