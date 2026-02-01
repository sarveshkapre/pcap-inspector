# Update (2026-02-01)

## What shipped

- Extract TLS ClientHello metadata (best-effort): `sni` + optional `alpn` in JSONL output.
- Support `--out -` to stream JSONL to stdout (useful for piping into `jq`, `rg`, etc.).

## How to verify

```bash
make check
python -m pcap_inspector inspect --pcap path/to/capture.pcap --out -
```

## PR

If you have GitHub CLI set up:

```bash
git push -u origin HEAD
gh pr create --fill
```

