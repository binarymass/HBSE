"""Hash-chained audit events."""

from __future__ import annotations

import hmac
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from pydantic import BaseModel, ConfigDict

from hbse.core.redaction import RedactionEngine
from hbse.core.serialization import b64url_no_padding, canonical_json_bytes, utc_millis


ZERO_HASH = b64url_no_padding(b"\x00" * 32)


class AuditVerificationError(ValueError):
    """Raised when the audit chain does not verify."""


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    timestamp: str
    vault_id: str
    namespace_id: str
    event_type: str
    severity: str
    decision: str
    previous_hash: str
    event_hash: str
    event_mac: str
    metadata: dict[str, Any]

    def mac_payload(self) -> dict[str, Any]:
        data = self.model_dump()
        data.pop("event_mac")
        return data

    def hash_payload(self) -> dict[str, Any]:
        data = self.model_dump()
        data.pop("event_hash")
        data.pop("event_mac")
        return data


@dataclass
class AuditManager:
    mac_key: bytes
    redaction: RedactionEngine
    existing_events: list[AuditEvent] | None = None

    def append(
        self,
        *,
        vault_id: str,
        namespace_id: str,
        event_type: str,
        severity: str,
        decision: str,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        safe_metadata = metadata or {}
        self.redaction.assert_no_known_secret(str(safe_metadata))
        previous_hash = self.existing_events[-1].event_hash if self.existing_events else ZERO_HASH
        base = {
            "event_id": str(uuid.uuid4()),
            "timestamp": utc_millis(datetime.now(UTC)),
            "vault_id": vault_id,
            "namespace_id": namespace_id,
            "event_type": event_type,
            "severity": severity,
            "decision": decision,
            "previous_hash": previous_hash,
            "metadata": safe_metadata,
        }
        event_hash = b64url_no_padding(sha256(canonical_json_bytes(base)).digest())
        mac_payload = {**base, "event_hash": event_hash}
        event_mac = b64url_no_padding(
            hmac.new(self.mac_key, canonical_json_bytes(mac_payload), sha256).digest()
        )
        event = AuditEvent(**mac_payload, event_mac=event_mac)
        if self.existing_events is None:
            self.existing_events = []
        self.existing_events.append(event)
        return event


def verify_audit_chain(events: list[AuditEvent], mac_key: bytes) -> None:
    previous_hash = ZERO_HASH
    for event in events:
        if event.previous_hash != previous_hash:
            raise AuditVerificationError("audit previous hash mismatch")
        expected_hash = b64url_no_padding(
            sha256(canonical_json_bytes(event.hash_payload())).digest()
        )
        if not hmac.compare_digest(expected_hash, event.event_hash):
            raise AuditVerificationError("audit event hash mismatch")
        expected_mac = b64url_no_padding(
            hmac.new(mac_key, canonical_json_bytes(event.mac_payload()), sha256).digest()
        )
        if not hmac.compare_digest(expected_mac, event.event_mac):
            raise AuditVerificationError("audit event MAC mismatch")
        previous_hash = event.event_hash
