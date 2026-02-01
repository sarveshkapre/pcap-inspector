# Update (2026-02-01)

## What shipped

- Extract TLS ClientHello metadata (best-effort): `sni` + optional `alpn` in JSONL output.
- Support `--out -` to stream JSONL to stdout (useful for piping into `jq`, `rg`, etc.).
- Add IPv6 support for flow keys + metadata extraction.
- Add `summary` command for aggregate stats (use `--json` for machine-readable output).
- Add `--no-include-flows` to output events-only JSONL.
- Add `ts` timestamps to event records (dns/http/tls).
- Add `--include-*`/`--no-include-*` filters for dns/http/tls events.
- Add `--sort-flows` for deterministic flow row ordering.
- Add `schema` command and `SCHEMA.md` documenting JSONL record fields.
- Add `--stats`/`--stats-json` to emit a summary to stderr after inspection.

## How to verify

```bash
make check
python -m pcap_inspector inspect --pcap path/to/capture.pcap --out -
python -m pcap_inspector summary --pcap path/to/capture.pcap
```

## PR

Do not open PRs for this repo; commit directly to `main`.
