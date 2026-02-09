# PCAP Inspector

Minimal PCAP analyzer that extracts flow summaries and basic DNS/HTTP metadata.

## Scope (v0.1.1)

- Flow summary (src/dst/ports/proto).
- IPv4 + IPv6 support.
- DNS query metadata.
- HTTP request/response line extraction (best-effort).
- TLS ClientHello SNI/ALPN extraction (best-effort).
- Timestamp window filtering (`--since-ts/--until-ts`) for targeted triage runs.
- Flow filtering (`--host/--port/--proto`) to reduce noise without post-processing.
- JSONL output.
- Event records include `ts` (pcap packet timestamp, seconds since epoch).

## Quickstart

```bash
make setup
make check
```

## Usage

```bash
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl
# or stream JSONL to stdout:
python -m pcap_inspector inspect --pcap capture.pcap --out -
# or omit flow summary rows (events-only):
python -m pcap_inspector inspect --pcap capture.pcap --out - --no-include-flows
# or filter event types:
python -m pcap_inspector inspect --pcap capture.pcap --out - --no-include-http --no-include-tls
# or keep only the top 20 flows by bytes in flow rows:
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl --top-flows 20
# or emit only the first 200 DNS/HTTP/TLS events:
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl --top-events 200
# or normalize directional flows into bidirectional conversations:
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl --normalize-flows
# or limit inspection to a time window (epoch seconds):
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl --since-ts 1700000000 --until-ts 1700003600
# or filter to a specific host/port/proto:
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl --host 10.0.0.5 --port 443 --proto tcp
# include per-flow start/end timestamps in flow rows:
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl --include-flow-times
# stable ordering for diffing:
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl --sort-flows
# emit a quick summary to stderr:
python -m pcap_inspector inspect --pcap capture.pcap --out - --stats
```

## Summary

```bash
python -m pcap_inspector summary --pcap capture.pcap
python -m pcap_inspector summary --pcap capture.pcap --json
python -m pcap_inspector summary --pcap capture.pcap --json --normalize-flows
```

## JSONL Schema

```bash
python -m pcap_inspector schema > schema.json
```

See `SCHEMA.md` for documented fields.
