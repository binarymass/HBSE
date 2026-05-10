"""Vault root key derivation and per-secret key hierarchy."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256


KEY_SIZE = 32
PROTOCOL_VERSION = "v1"


def _counter_kdf_hmac_sha256(root_key: bytes, label: str, length: int = KEY_SIZE) -> bytes:
    if len(root_key) != KEY_SIZE:
        raise ValueError("vault root key must be 32 bytes")
    if not label or label in {"key", "secret", "encrypt", "default"}:
        raise ValueError("KDF label is not domain-separated")
    if f"HBSE:{PROTOCOL_VERSION}:" not in label:
        raise ValueError("KDF label must include HBSE protocol version")

    result = b""
    counter = 1
    label_bytes = label.encode("utf-8")
    while len(result) < length:
        block = counter.to_bytes(4, "big") + label_bytes + b"\x00" + (length * 8).to_bytes(4, "big")
        result += hmac.new(root_key, block, sha256).digest()
        counter += 1
    return result[:length]


@dataclass(frozen=True)
class KeyHierarchy:
    vault_id: str
    root_key: bytes

    def metadata_key(self) -> bytes:
        return self._derive(f"HBSE:v1:vault:{self.vault_id}:metadata")

    def audit_integrity_key(self) -> bytes:
        return self._derive(f"HBSE:v1:vault:{self.vault_id}:audit-integrity")

    def redaction_fingerprint_key(self) -> bytes:
        return self._derive(f"HBSE:v1:vault:{self.vault_id}:redaction-fingerprint")

    def ticket_mac_key(self) -> bytes:
        return self._derive(f"HBSE:v1:vault:{self.vault_id}:ticket-mac")

    def secret_kek(self, secret_id: str, version: int) -> bytes:
        return self._derive(
            f"HBSE:v1:vault:{self.vault_id}:secret:{secret_id}:version:{version}:dek-wrap"
        )

    def secret_kek_label(self, secret_id: str, version: int) -> str:
        return f"HBSE:v1:vault:{self.vault_id}:secret:{secret_id}:version:{version}:dek-wrap"

    def _derive(self, label: str) -> bytes:
        return _counter_kdf_hmac_sha256(self.root_key, label)
