# PLAN.md

## Product Pitch

PCAP Inspector is a minimalist CLI that turns a `.pcap` into JSONL flow summaries + protocol metadata for fast triage.

## Current Features

- Flow summaries (src/dst/ports/proto, packet/byte counts).
- DNS query metadata (qname, id, qr).
- HTTP request/status line extraction (best-effort, per packet; optional `--http-ports` filter).
- TLS ClientHello metadata extraction (best-effort: SNI, ALPN).
- JSONL output to a file or stdout (`--out -`).
- Event output capping for high-volume captures (`--top-events`).
- Event selection modes for capping (`--top-events-mode packet|flow-bytes`).
- Optional bidirectional flow normalization (`--normalize-flows`).
- Compact conversation timeline output (`timeline`, text or `--json`).
- Machine-readable JSON schemas for JSON outputs (`schema`, `schema --summary`).

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
- Event records now include `ts` (pcap packet timestamp).
- Event filters: `--no-include-dns/--no-include-http/--no-include-tls`.
- Stable flow ordering: `--sort-flows`.
- JSONL schema: `schema` command + `SCHEMA.md`.
- Inspect stats: `--stats` / `--stats-json` to stderr.

### 2026-02-09

- Improve TCP stream reassembly handling for out-of-order/retransmitted segments.
- Add `inspect --top-flows N` to include only top flow rows by bytes.
- Expand HTTP request extraction to include common methods beyond GET/POST.
- Fix `max_packets` packet accounting to count only processed packets.
- Add `inspect --top-events N` to bound DNS/HTTP/TLS event rows.
- Add `--normalize-flows` support in `inspect` and `summary` for conversation-centric triage.
- Deduplicate inspect/summary packet-flow parsing logic to reduce maintenance drift.
- Ensure summary top-flow ordering is deterministic on byte-count ties.

## Next Up (Tight Scope)

- Add PCAPNG support (if feasible) via an alternate reader or conversion fallback.
- Add restricted `--bpf` / `--filter` support for parity with common PCAP tooling.
- Add optional TLS port filtering (`--tls-ports`) to reduce false positives.
