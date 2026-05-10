"""Secret Access Ticket lifecycle."""

from __future__ import annotations

import hmac
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from pydantic import BaseModel, ConfigDict, Field

from hbse.core.policy import AccessPolicy, AccessRequest, DeliveryMode
from hbse.core.serialization import b64url_no_padding, canonical_json_bytes, utc_millis


class TicketValidationError(ValueError):
    """Raised when a Secret Access Ticket is invalid."""


class SecretAccessTicket(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ticket_id: str
    vault_id: str
    secret_ref: str
    consumer: str
    purpose: str
    delivery_mode: DeliveryMode
    http_host: str | None = None
    http_scheme: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_request_body_bytes: int | None = None
    os_uid: int | None = None
    executable_path: str | None = None
    executable_sha256: str | None = None
    policy_id: str
    policy_hash: str
    issued_at: str
    expires_at: str
    max_uses: int = Field(ge=1)
    uses_remaining: int = Field(ge=0)
    revoked: bool = False
    mac: str

    def payload(self) -> dict[str, object]:
        data = self.model_dump(mode="json")
        data.pop("mac")
        return data


@dataclass
class TicketManager:
    mac_key: bytes

    def issue(
        self,
        *,
        vault_id: str,
        request: AccessRequest,
        policy: AccessPolicy,
        policy_hash: str,
    ) -> SecretAccessTicket:
        issued_at = request.now
        expires_at = issued_at + timedelta(seconds=policy.max_ticket_ttl_seconds)
        payload = {
            "ticket_id": str(uuid.uuid4()),
            "vault_id": vault_id,
            "secret_ref": request.secret_ref,
            "consumer": request.consumer,
            "purpose": request.purpose,
            "delivery_mode": request.delivery_mode,
            "http_host": request.http_host,
            "http_scheme": request.http_scheme,
            "http_method": request.http_method,
            "http_path": request.http_path,
            "http_request_body_bytes": request.http_request_body_bytes,
            "os_uid": request.os_uid,
            "executable_path": request.executable_path,
            "executable_sha256": request.executable_sha256,
            "policy_id": policy.policy_id,
            "policy_hash": policy_hash,
            "issued_at": utc_millis(issued_at),
            "expires_at": utc_millis(expires_at),
            "max_uses": policy.max_uses,
            "uses_remaining": policy.max_uses,
            "revoked": False,
        }
        return SecretAccessTicket(**payload, mac=self._mac(payload))

    def validate(
        self,
        *,
        ticket: SecretAccessTicket,
        request: AccessRequest,
        now: datetime | None = None,
    ) -> None:
        if not hmac.compare_digest(self._mac(ticket.payload()), ticket.mac):
            raise TicketValidationError("ticket MAC mismatch")
        if ticket.revoked:
            raise TicketValidationError("ticket revoked")
        if ticket.uses_remaining < 1:
            raise TicketValidationError("ticket replay denied")
        effective_now = now or datetime.now(UTC)
        if effective_now > datetime.fromisoformat(ticket.expires_at.replace("Z", "+00:00")):
            raise TicketValidationError("ticket expired")
        if ticket.secret_ref != request.secret_ref:
            raise TicketValidationError("ticket secret context mismatch")
        if ticket.consumer != request.consumer:
            raise TicketValidationError("ticket consumer context mismatch")
        if ticket.purpose != request.purpose:
            raise TicketValidationError("ticket purpose context mismatch")
        if ticket.delivery_mode != request.delivery_mode:
            raise TicketValidationError("ticket delivery context mismatch")
        if ticket.http_host != request.http_host:
            raise TicketValidationError("ticket HTTP host context mismatch")
        if ticket.http_scheme != request.http_scheme:
            raise TicketValidationError("ticket HTTP scheme context mismatch")
        if ticket.http_method != request.http_method:
            raise TicketValidationError("ticket HTTP method context mismatch")
        if ticket.http_path != request.http_path:
            raise TicketValidationError("ticket HTTP path context mismatch")
        if ticket.http_request_body_bytes != request.http_request_body_bytes:
            raise TicketValidationError("ticket HTTP request body context mismatch")
        if ticket.os_uid != request.os_uid:
            raise TicketValidationError("ticket OS user context mismatch")
        if ticket.executable_path != request.executable_path:
            raise TicketValidationError("ticket executable path context mismatch")
        if ticket.executable_sha256 != request.executable_sha256:
            raise TicketValidationError("ticket executable hash context mismatch")

    def consume(self, ticket: SecretAccessTicket, request: AccessRequest) -> SecretAccessTicket:
        self.validate(ticket=ticket, request=request)
        updated = ticket.model_copy(update={"uses_remaining": ticket.uses_remaining - 1})
        return updated.model_copy(update={"mac": self._mac(updated.payload())})

    def revoke(self, ticket: SecretAccessTicket) -> SecretAccessTicket:
        if not hmac.compare_digest(self._mac(ticket.payload()), ticket.mac):
            raise TicketValidationError("ticket MAC mismatch")
        updated = ticket.model_copy(update={"revoked": True})
        return updated.model_copy(update={"mac": self._mac(updated.payload())})

    def _mac(self, payload: dict[str, object]) -> str:
        return b64url_no_padding(hmac.new(self.mac_key, canonical_json_bytes(payload), sha256).digest())
