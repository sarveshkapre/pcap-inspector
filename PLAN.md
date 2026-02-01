# PLAN.md

## Product Pitch

PCAP Inspector is a minimalist CLI that turns a `.pcap` into JSONL flow summaries + protocol metadata for fast triage.

## Current Features

- Flow summaries (src/dst/ports/proto, packet/byte counts).
- DNS query metadata (qname, id, qr).
- HTTP request/status line extraction (best-effort, per packet).
- TLS ClientHello metadata extraction (best-effort: SNI, ALPN).
- JSONL output to a file or stdout (`--out -`).

## Top Risks / Unknowns

- TCP stream reassembly is best-effort; out-of-order/retransmits and multi-record handshakes may be missed.
- TLS parsing is intentionally minimal (ClientHello-only), and will not decode encrypted application data.
- IPv6 parsing is new; validate against real-world captures.
- PCAPNG support is not guaranteed (depends on Scapy reader support for the file).

## Commands

See `PROJECT.md` for the canonical commands, or run:

```bash
make setup
make check
make test
make lint
make typecheck
```

## Shipped

### 2026-02-01

- TLS ClientHello SNI/ALPN extraction (best-effort).
- `--out -` support to stream JSONL to stdout.
- IPv6 support (`IPv6` layer) for flow keys + metadata extraction.
- `summary` command to print aggregate stats (optionally JSON).
- `--no-include-flows` option to emit events-only JSONL.

## Next Up (Tight Scope)

- Make TLS/HTTP parsing more reliable with better TCP stream reassembly.
- Add per-event timestamps (pcap time) to JSONL records.
