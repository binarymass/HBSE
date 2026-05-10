"""Canonical serialization helpers for protocol-bound inputs."""

from __future__ import annotations

import base64
import json
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any


def b64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode_no_padding(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def utc_millis(timestamp: datetime) -> str:
    if timestamp.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    value = timestamp.astimezone(UTC)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_for_canonical_json(value: Any) -> Any:
    if isinstance(value, bytes):
        return b64url_no_padding(value)
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, datetime):
        return utc_millis(value)
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        raise TypeError("floats are forbidden in canonical protocol serialization")
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical object keys must be strings")
            normalized[unicodedata.normalize("NFC", key)] = normalize_for_canonical_json(item)
        return normalized
    if isinstance(value, Sequence):
        return [normalize_for_canonical_json(item) for item in value]
    raise TypeError(f"unsupported canonical serialization type: {type(value)!r}")


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    normalized = normalize_for_canonical_json(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
