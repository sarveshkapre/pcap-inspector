from __future__ import annotations

from typing import Any

JSONL_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "pcap-inspector JSONL record",
    "type": "object",
    "oneOf": [
        {
            "title": "Flow summary",
            "type": "object",
            "required": ["type", "flow", "packets", "bytes"],
            "properties": {
                "type": {"const": "flow"},
                "flow": {"type": "string"},
                "packets": {"type": "integer", "minimum": 0},
                "bytes": {"type": "integer", "minimum": 0},
                "first_ts": {"type": "number"},
                "last_ts": {"type": "number"},
            },
            "additionalProperties": True,
        },
        {
            "title": "DNS event",
            "type": "object",
            "required": ["type", "ts", "flow", "id", "qr"],
            "properties": {
                "type": {"const": "dns"},
                "ts": {"type": "number"},
                "flow": {"type": "string"},
                "id": {"type": "integer"},
                "qr": {"type": "integer"},
                "qname": {"type": ["string", "null"]},
            },
            "additionalProperties": True,
        },
        {
            "title": "HTTP request event",
            "type": "object",
            "required": ["type", "ts", "flow", "request_line"],
            "properties": {
                "type": {"const": "http"},
                "ts": {"type": "number"},
                "flow": {"type": "string"},
                "request_line": {"type": "string"},
            },
            "additionalProperties": True,
        },
        {
            "title": "HTTP response event",
            "type": "object",
            "required": ["type", "ts", "flow", "status_line"],
            "properties": {
                "type": {"const": "http"},
                "ts": {"type": "number"},
                "flow": {"type": "string"},
                "status_line": {"type": "string"},
            },
            "additionalProperties": True,
        },
        {
            "title": "TLS ClientHello event",
            "type": "object",
            "required": ["type", "ts", "flow"],
            "properties": {
                "type": {"const": "tls"},
                "ts": {"type": "number"},
                "flow": {"type": "string"},
                "sni": {"type": "string"},
                "alpn": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": True,
        },
    ],
    "additionalProperties": True,
}
