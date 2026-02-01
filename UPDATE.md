# Update (2026-02-01)

## What shipped

- Extract TLS ClientHello metadata (best-effort): `sni` + optional `alpn` in JSONL output.
- Support `--out -` to stream JSONL to stdout (useful for piping into `jq`, `rg`, etc.).
- Add IPv6 support for flow keys + metadata extraction.
- Add `summary` command for aggregate stats (use `--json` for machine-readable output).

## How to verify

```bash
make check
python -m pcap_inspector inspect --pcap path/to/capture.pcap --out -
python -m pcap_inspector summary --pcap path/to/capture.pcap
```

## PR

Do not open PRs for this repo; commit directly to `main`.
