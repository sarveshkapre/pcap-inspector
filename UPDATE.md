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

---

# Update (2026-02-09)

## What shipped

- Improve TCP stream reassembly handling for out-of-order and retransmitted TCP segments.
- Add `inspect --top-flows N` to keep only top flow rows by bytes in JSONL output.
- Expand HTTP request extraction to support common methods beyond GET/POST.
- Fix `max_packets` accounting so packet totals reflect processed packets only.
- Add regression tests for out-of-order TLS, top-flow filtering, expanded HTTP methods, and packet-limit accounting.
- Add `inspect --top-events N` to cap DNS/HTTP/TLS event rows in packet order.
- Add `--normalize-flows` to aggregate bidirectional conversations in both `inspect` and `summary`.
- Refactor shared flow parsing used by `inspect` and `summary` to reduce behavior drift.
- Make summary top-flow ordering deterministic when flows have equal byte counts.
- Add timestamp window filtering for targeted triage (`--since-ts/--until-ts`).
- Add basic flow filters (`--host/--port/--proto`) to focus on specific conversations quickly.
- Improve operator errors for PCAPNG and non-PCAP inputs (no traceback; actionable hint).
- Add `make bench-events` to benchmark event extraction paths (in addition to flows-only bench).

## How to verify

```bash
make check
python -m pcap_inspector inspect --pcap path/to/capture.pcap --out pcap-report.jsonl --top-flows 20 --top-events 200 --normalize-flows --since-ts 1700000000 --until-ts 1700003600 --host 10.0.0.5 --port 443 --proto tcp --stats-json
python -m pcap_inspector summary --pcap path/to/capture.pcap --json --normalize-flows --since-ts 1700000000 --until-ts 1700003600 --host 10.0.0.5 --port 443 --proto tcp
make bench
make bench-events
```
