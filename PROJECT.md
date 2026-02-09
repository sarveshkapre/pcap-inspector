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

## Run

```bash
python -m pcap_inspector --help
```

## Example

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
# or cap event rows for large captures:
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl --top-events 200
# or normalize directional flows into bidirectional conversations:
python -m pcap_inspector inspect --pcap capture.pcap --out pcap-report.jsonl --normalize-flows
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

## Schema

```bash
python -m pcap_inspector schema > schema.json
```
