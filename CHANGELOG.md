# CHANGELOG

## Unreleased

- Add TLS ClientHello SNI/ALPN extraction (best-effort).
- Support `--out -` to write JSONL to stdout.
- Add IPv6 support for flow keys + metadata extraction.
- Add `summary` command for aggregate stats.
- Add `--no-include-flows` to omit flow rows from JSONL output.
- Add `ts` timestamps to event records (dns/http/tls).
- Add `--include-*`/`--no-include-*` event filters (dns/http/tls).
- Add `--sort-flows` for stable flow row ordering.

## v0.1.0 - 2026-01-31

- Flow summaries and DNS/HTTP metadata extraction.
- JSONL report output.
