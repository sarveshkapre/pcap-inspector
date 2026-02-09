# JSONL Schema

`pcap-inspector` writes one JSON object per line (JSONL).

To get the machine-readable JSON Schema:

```bash
pcap-inspector schema > inspect-jsonl.schema.json
```

## JSONL Record Types (`inspect`)

All records include a `type` field.

### `flow`

Flow summary emitted at the end of `inspect` (unless `--no-include-flows`).

- `type`: `"flow"`
- `flow`: string (e.g. `1.2.3.4:1234->5.6.7.8:80 TCP`, `[2001:db8::1]:1234->[2001:db8::2]:53 UDP`, or normalized `1.2.3.4:1234<->5.6.7.8:80 TCP` when `--normalize-flows` is enabled)
- `packets`: integer
- `bytes`: integer
- `first_ts`: number (optional; only when `inspect --include-flow-times` is enabled)
- `last_ts`: number (optional; only when `inspect --include-flow-times` is enabled)

### `dns`

DNS metadata extracted from packets with a DNS layer.

- `type`: `"dns"`
- `ts`: number (packet timestamp, seconds since epoch)
- `flow`: string
- `id`: integer
- `qr`: integer (0=query, 1=response)
- `qname`: string | null

### `http`

Best-effort per-packet HTTP parsing from `Raw` TCP payloads.

- `type`: `"http"`
- `ts`: number
- `flow`: string
- `request_line`: string (for requests) OR `status_line`: string (for responses)

### `tls`

Best-effort TLS ClientHello parsing from TCP streams.

- `type`: `"tls"`
- `ts`: number
- `flow`: string
- `sni`: string (if present)
- `alpn`: string[] (if present)

## Summary JSON Schema (`summary --json`)

`summary --json` emits a single JSON object (not JSONL).

To get the machine-readable JSON Schema:

```bash
pcap-inspector schema --summary > summary.schema.json
```
