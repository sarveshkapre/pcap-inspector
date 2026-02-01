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

PR: https://github.com/sarveshkapre/pcap-inspector/pull/1

If you need to recreate the PR:

```bash
git checkout feat/tls-sni-stdout
git push -u origin HEAD
gh pr create --fill
```
