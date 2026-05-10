from __future__ import annotations

from datetime import UTC, datetime, timedelta
import base64

import pytest

from hbse.core.audit import AuditEvent, AuditVerificationError, verify_audit_chain
from hbse.core.keys import KeyHierarchy
from hbse.core.policy import AccessPolicy, AccessRequest, DeliveryMode, PolicyDecision, PolicyEngine
from hbse.core.redaction import RedactionEngine, RedactionLeakError
from hbse.core.store import SQLiteVaultStore
from hbse.core.tickets import TicketManager, TicketValidationError
from hbse.core.vault import LocalVault


ROOT = bytes.fromhex("22" * 32)


def test_policy_engine_denies_by_default_and_allows_exact_match() -> None:
    request = AccessRequest(
        secret_ref="secret://default/api",
        consumer="cli",
        purpose="deploy",
        delivery_mode=DeliveryMode.TERMINAL_PRINT,
        provider_assurance="A1",
        raw_export_requested=True,
    )

    assert PolicyEngine().evaluate(request).decision == PolicyDecision.DENY

    policy = AccessPolicy(
        policy_id="p1",
        secret_refs=["secret://default/api"],
        allowed_consumers=["cli"],
        allowed_purposes=["deploy"],
        allowed_delivery_modes=[DeliveryMode.TERMINAL_PRINT],
        exportable=True,
    )

    assert PolicyEngine([policy]).evaluate(request).decision == PolicyDecision.ALLOW


def test_ticket_replay_expiry_and_wrong_context_fail() -> None:
    keys = KeyHierarchy(vault_id="vault-1", root_key=ROOT)
    manager = TicketManager(keys.ticket_mac_key())
    request = AccessRequest(
        secret_ref="secret://default/api",
        consumer="cli",
        purpose="deploy",
        delivery_mode=DeliveryMode.TERMINAL_PRINT,
        provider_assurance="A1",
        raw_export_requested=True,
    )
    policy = AccessPolicy(
        policy_id="p1",
        secret_refs=["secret://default/api"],
        allowed_consumers=["cli"],
        allowed_purposes=["deploy"],
        allowed_delivery_modes=[DeliveryMode.TERMINAL_PRINT],
        exportable=True,
        max_ticket_ttl_seconds=1,
        max_uses=1,
    )
    ticket = manager.issue(vault_id="vault-1", request=request, policy=policy, policy_hash="hash")

    consumed = manager.consume(ticket, request)
    with pytest.raises(TicketValidationError):
        manager.consume(consumed, request)

    wrong = AccessRequest(
        secret_ref="secret://default/api",
        consumer="other",
        purpose="deploy",
        delivery_mode=DeliveryMode.TERMINAL_PRINT,
        provider_assurance="A1",
    )
    with pytest.raises(TicketValidationError):
        manager.validate(ticket=ticket, request=wrong)

    with pytest.raises(TicketValidationError):
        manager.validate(
            ticket=ticket,
            request=request,
            now=datetime.now(UTC) + timedelta(seconds=5),
        )


def test_vault_access_path_uses_policy_ticket_and_audit(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="passphrase")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"sk-test",
        passphrase="passphrase",
    )
    vault.create_policy(
        AccessPolicy(
            policy_id="cli",
            secret_refs=["secret://default/api"],
            allowed_consumers=["cli"],
            allowed_purposes=["deploy"],
            allowed_delivery_modes=[DeliveryMode.TERMINAL_PRINT],
            exportable=True,
        )
    )

    ticket = vault.issue_ticket(
        secret_ref="secret://default/api",
        consumer="cli",
        purpose="deploy",
        delivery_mode=DeliveryMode.TERMINAL_PRINT,
        passphrase="passphrase",
        raw_export_requested=True,
    )
    assert vault.consume_ticket_for_secret(
        ticket_id=ticket.ticket_id,
        consumer="cli",
        purpose="deploy",
        delivery_mode=DeliveryMode.TERMINAL_PRINT,
        passphrase="passphrase",
    ) == b"sk-test"
    with pytest.raises(TicketValidationError):
        vault.consume_ticket_for_secret(
            ticket_id=ticket.ticket_id,
            consumer="cli",
            purpose="deploy",
            delivery_mode=DeliveryMode.TERMINAL_PRINT,
            passphrase="passphrase",
        )

    vault.verify_audit(passphrase="passphrase")


def test_audit_chain_tampering_is_detected(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="passphrase")
    _header, keys = vault._unlock("passphrase")
    events = [AuditEvent.model_validate_json(raw) for raw in store.list_audit_event_json()]
    tampered = events[0].model_copy(update={"decision": "deny"})

    with pytest.raises(AuditVerificationError):
        verify_audit_chain([tampered], keys.audit_integrity_key())


def test_vault_lockdown_revokes_active_tickets(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="passphrase")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"sk-test",
        passphrase="passphrase",
    )
    vault.create_policy(
        AccessPolicy(
            policy_id="callback",
            secret_refs=["secret://default/api"],
            allowed_consumers=["test"],
            allowed_purposes=["callback"],
            allowed_delivery_modes=[DeliveryMode.CALLBACK],
        )
    )
    ticket = vault.issue_ticket(
        secret_ref="secret://default/api",
        consumer="test",
        purpose="callback",
        delivery_mode=DeliveryMode.CALLBACK,
        passphrase="passphrase",
    )

    assert vault.revoke_all_tickets(passphrase="passphrase", reason="test lockdown") == 1
    with pytest.raises(TicketValidationError, match="revoked"):
        vault.consume_ticket_for_secret(
            ticket_id=ticket.ticket_id,
            consumer="test",
            purpose="callback",
            delivery_mode=DeliveryMode.CALLBACK,
            passphrase="passphrase",
        )


def test_redaction_detects_known_secret() -> None:
    engine = RedactionEngine(b"r" * 32)
    fingerprint = engine.learn(b"sk-test")

    assert f"[REDACTED:secret:{fingerprint}]" in engine.redact_text("value=sk-test")
    with pytest.raises(RedactionLeakError):
        engine.assert_no_known_secret("token=sk-test")


def test_redaction_detects_encoded_and_structured_secret_forms() -> None:
    engine = RedactionEngine(b"r" * 32)
    engine.learn(b"sk-test/value")

    assert "[REDACTED:secret:" in engine.redact_text(base64.b64encode(b"sk-test/value").decode())
    assert "[REDACTED:secret:" in engine.redact_text("sk-test%2Fvalue")
    assert "Bearer [REDACTED:bearer]" in engine.redact_text("Authorization: Bearer abc123")
    assert 'password="[REDACTED]"' in engine.redact_text('password="secret";')
