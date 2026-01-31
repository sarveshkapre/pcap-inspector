# PCAP Inspector

Minimal PCAP analyzer that extracts flow summaries and basic DNS/HTTP metadata.

## Scope (v0.1.0)

- Flow summary (src/dst/ports/proto).
- DNS query metadata.
- HTTP request/response line extraction (best-effort).
- JSONL output.

## Quickstart

```bash
make setup
make check
```

## Usage

```bash
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl
```
