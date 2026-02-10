# PROJECT.md

Exact commands for working in this repo.

## Setup

```bash
make setup
```

## Quality gate

```bash
make check
```

## Benchmark

```bash
make bench
make bench-events
```

## Run

```bash
.venv/bin/pcap-inspector --help
```

## Example

```bash
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out pcap-report.jsonl
# or stream JSONL to stdout:
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out -
# or omit flow summary rows (events-only):
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out - --no-include-flows
# or filter event types:
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out - --no-include-http --no-include-tls
# or emit only flow summary rows (no DNS/HTTP/TLS events):
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out - --flows-only
# or keep only the top 20 flows by bytes in flow rows:
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out pcap-report.jsonl --top-flows 20
# or cap event rows for large captures:
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out pcap-report.jsonl --top-events 200
# or prioritize events from highest-byte flows (two-pass selection):
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out pcap-report.jsonl --top-events 200 --top-events-mode flow-bytes
# or normalize directional flows into bidirectional conversations:
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out pcap-report.jsonl --normalize-flows
# or limit inspection to a time window (epoch seconds):
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out pcap-report.jsonl --since-ts 1700000000 --until-ts 1700003600
# or filter to a specific host/port/proto:
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out pcap-report.jsonl --host 10.0.0.5 --port 443 --proto tcp
# or only attempt HTTP parsing on specific ports (reduce false positives):
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out - --http-ports 80,8080
# or only attempt DNS parsing on specific ports (reduce false positives):
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out - --dns-ports 53,853
# or only attempt TLS parsing on specific ports (reduce false positives):
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out - --tls-ports 443,8443
# include per-flow start/end timestamps in flow rows:
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out pcap-report.jsonl --include-flow-times
# stable ordering for diffing:
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out pcap-report.jsonl --sort-flows
# emit a quick summary to stderr:
.venv/bin/pcap-inspector inspect --pcap capture.pcap --out - --stats
```

## Summary

```bash
.venv/bin/pcap-inspector summary --pcap capture.pcap
.venv/bin/pcap-inspector summary --pcap capture.pcap --json
.venv/bin/pcap-inspector summary --pcap capture.pcap --format json
.venv/bin/pcap-inspector summary --pcap capture.pcap --json --normalize-flows
.venv/bin/pcap-inspector summary --pcap capture.pcap --json --since-ts 1700000000 --until-ts 1700003600
.venv/bin/pcap-inspector summary --pcap capture.pcap --json --host 10.0.0.5 --port 443 --proto tcp
```

## Timeline

```bash
.venv/bin/pcap-inspector timeline --pcap capture.pcap --top 20
.venv/bin/pcap-inspector timeline --pcap capture.pcap --top 20 --json
.venv/bin/pcap-inspector timeline --pcap capture.pcap --top 20 --format json
```

## Schema

```bash
.venv/bin/pcap-inspector schema > inspect-jsonl.schema.json
.venv/bin/pcap-inspector schema --summary > summary.schema.json
.venv/bin/pcap-inspector schema --timeline > timeline.schema.json
```
