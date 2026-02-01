# PCAP Inspector

Minimal PCAP analyzer that extracts flow summaries and basic DNS/HTTP metadata.

## Scope (v0.1.0)

- Flow summary (src/dst/ports/proto).
- IPv4 + IPv6 support.
- DNS query metadata.
- HTTP request/response line extraction (best-effort).
- TLS ClientHello SNI/ALPN extraction (best-effort).
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
```

## Summary

```bash
python -m pcap_inspector summary --pcap capture.pcap
python -m pcap_inspector summary --pcap capture.pcap --json
```
