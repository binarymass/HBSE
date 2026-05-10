"""Python SDK helpers for safer callback-oriented secret use."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from hbse.core.broker import BrokeredHttpResponse, LocalBroker
from hbse.core.policy import DeliveryMode
from hbse.core.store import SQLiteVaultStore
from hbse.core.vault import LocalVault


T = TypeVar("T")


@dataclass
class HBSEClient:
    """Local SDK client.

    The callback API avoids returning a raw secret from the public SDK method.
    Python cannot guarantee memory erasure, but the bytearray is cleared after
    the callback returns.
    """

    store: SQLiteVaultStore
    vault: LocalVault

    @classmethod
    def from_path(cls, path: str) -> "HBSEClient":
        store = SQLiteVaultStore(path)
        return cls(store=store, vault=LocalVault(store=store))

    def with_secret(
        self,
        *,
        secret_ref: str,
        passphrase: str,
        consumer: str,
        purpose: str,
        callback: Callable[[memoryview], T],
    ) -> T:
        ticket = self.vault.issue_ticket(
            secret_ref=secret_ref,
            consumer=consumer,
            purpose=purpose,
            delivery_mode=DeliveryMode.CALLBACK,
            passphrase=passphrase,
            raw_export_requested=False,
        )
        secret = bytearray(
            self.vault.consume_ticket_for_secret(
                ticket_id=ticket.ticket_id,
                consumer=consumer,
                purpose=purpose,
                delivery_mode=DeliveryMode.CALLBACK,
                passphrase=passphrase,
            )
        )
        try:
            return callback(memoryview(secret))
        finally:
            secret[:] = b"\x00" * len(secret)

    def brokered_http_request(
        self,
        *,
        secret_ref: str,
        passphrase: str,
        consumer: str,
        purpose: str,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
        credential_header: str = "Authorization",
        credential_prefix: str = "Bearer ",
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 10 * 1024 * 1024,
    ) -> BrokeredHttpResponse:
        return LocalBroker(store=self.store, vault=self.vault).brokered_http_request(
            secret_ref=secret_ref,
            consumer=consumer,
            purpose=purpose,
            method=method,
            url=url,
            headers=headers,
            body=body,
            passphrase=passphrase,
            credential_header=credential_header,
            credential_prefix=credential_prefix,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
