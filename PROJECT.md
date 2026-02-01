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
```
