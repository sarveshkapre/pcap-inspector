# ROADMAP

## v0.1.1

- Flow summary + DNS/HTTP/TLS metadata.
- Timestamp window filtering and basic flow filters for fast triage.

## Next

- PCAPNG support (if feasible) via an alternate reader or conversion fallback.
- Restricted `--bpf` / `--filter` option for parity with common PCAP tooling.
- Optional TLS port filtering (`--tls-ports`) to reduce false positives.
