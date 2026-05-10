from __future__ import annotations

import pytest

from hbse.core.backup import create_backup, restore_backup
from hbse.core.policy import AccessPolicy, DeliveryMode
from hbse.core.readiness import check_local_readiness
from hbse.core.release import (
    generate_release_evidence,
    generate_signing_keypair,
    sign_release_artifacts,
    verify_release_evidence,
)
from hbse.core.store import SQLiteVaultStore
from hbse.core.vault import LocalVault


def _initialized_vault(tmp_path):
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
    return store, vault


def test_backup_restore_preserves_encrypted_vault_without_plaintext(tmp_path) -> None:
    store, _vault = _initialized_vault(tmp_path)
    backup_path = tmp_path / "backup.hbse.zip"

    manifest = create_backup(store, backup_path)
    assert manifest.contains_plaintext_secrets is False
    assert b"sk-test" not in backup_path.read_bytes()

    restored_store = SQLiteVaultStore(tmp_path / "restored.db")
    restore_backup(backup_path, restored_store.path)
    restored_vault = LocalVault(store=restored_store)

    assert restored_vault.raw_get_secret(
        secret_ref="secret://default/api", passphrase="passphrase"
    ) == b"sk-test"


def test_rotation_creates_new_version_and_old_ticket_does_not_bypass_latest_value(tmp_path) -> None:
    store, vault = _initialized_vault(tmp_path)
    ticket = vault.issue_ticket(
        secret_ref="secret://default/api",
        consumer="cli",
        purpose="deploy",
        delivery_mode=DeliveryMode.TERMINAL_PRINT,
        passphrase="passphrase",
        raw_export_requested=True,
    )
    version = vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"sk-rotated",
        passphrase="passphrase",
    )

    assert version == 2
    assert store.list_secrets()[0].latest_version == 2
    assert vault.consume_ticket_for_secret(
        ticket_id=ticket.ticket_id,
        consumer="cli",
        purpose="deploy",
        delivery_mode=DeliveryMode.TERMINAL_PRINT,
        passphrase="passphrase",
    ) == b"sk-rotated"


def test_disabled_secret_denies_materialization(tmp_path) -> None:
    _store, vault = _initialized_vault(tmp_path)
    ticket = vault.issue_ticket(
        secret_ref="secret://default/api",
        consumer="cli",
        purpose="deploy",
        delivery_mode=DeliveryMode.TERMINAL_PRINT,
        passphrase="passphrase",
        raw_export_requested=True,
    )
    vault.disable_secret(secret_ref="secret://default/api", passphrase="passphrase")

    with pytest.raises(PermissionError):
        vault.consume_ticket_for_secret(
            ticket_id=ticket.ticket_id,
            consumer="cli",
            purpose="deploy",
            delivery_mode=DeliveryMode.TERMINAL_PRINT,
            passphrase="passphrase",
        )


def test_readiness_reports_local_passes_and_external_a4_blockers(tmp_path) -> None:
    store, vault = _initialized_vault(tmp_path)

    a2 = check_local_readiness(store=store, vault=vault, passphrase="passphrase", target="A2")
    assert any(item.area == "Audit" and item.status == "pass" for item in a2.items)

    a4 = check_local_readiness(store=store, vault=vault, passphrase="passphrase", target="A4")
    assert not a4.passed
    assert any(item.area == "Review" and item.status == "fail" for item in a4.items)


def test_release_evidence_generation_creates_supply_chain_files(tmp_path) -> None:
    evidence = generate_release_evidence(
        output_dir=tmp_path / "release",
        project_root=".",
        version="0.1.0",
    )

    assert evidence.source_digest
    assert (tmp_path / "release" / "sbom.json").exists()
    assert (tmp_path / "release" / "provenance.json").exists()
    assert (tmp_path / "release" / "production_checklist.json").exists()
    assert (tmp_path / "release" / "artifact.sig").exists()
    assert (tmp_path / "release" / "dependency-lock.json").exists()


def test_release_verification_reports_missing_and_present_artifacts(tmp_path) -> None:
    release_dir = tmp_path / "release"
    generate_release_evidence(
        output_dir=release_dir,
        project_root=".",
        version="0.1.0",
    )
    missing = verify_release_evidence(release_dir=release_dir)
    assert not missing.passed
    assert any(check.name == "openapi.json" and check.status == "fail" for check in missing.checks)

    (release_dir / "openapi.json").write_text('{"openapi":"3.1.0","paths":{}}', encoding="utf-8")
    proto_path = release_dir / "proto/hbse/v1"
    proto_path.mkdir(parents=True)
    (proto_path / "hbse.proto").write_text('syntax = "proto3";', encoding="utf-8")
    present = verify_release_evidence(release_dir=release_dir)
    assert not present.passed
    assert any(check.name == "artifact.sig:mode" and check.status == "warn" for check in present.checks)


def test_release_ed25519_signing_verifies_and_detects_tampering(tmp_path) -> None:
    release_dir = tmp_path / "release"
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    wheel = dist_dir / "hbse-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel-bytes")
    generate_release_evidence(
        output_dir=release_dir,
        project_root=".",
        version="0.1.0",
    )
    (release_dir / "openapi.json").write_text('{"openapi":"3.1.0","paths":{}}', encoding="utf-8")
    proto_path = release_dir / "proto/hbse/v1"
    proto_path.mkdir(parents=True)
    (proto_path / "hbse.proto").write_text('syntax = "proto3";', encoding="utf-8")
    key_info = generate_signing_keypair(
        private_key_path=tmp_path / "release-private.pem",
        public_key_path=tmp_path / "release-public.pem",
    )
    sign_release_artifacts(
        release_dir=release_dir,
        artifact_paths=[wheel],
        private_key_path=key_info["private_key_path"],
        public_key_path=release_dir / "signing_public_key.pem",
        version="0.1.0",
    )

    verified = verify_release_evidence(release_dir=release_dir)
    assert verified.passed
    assert any(check.name == "artifact.sig:signature" and check.status == "pass" for check in verified.checks)

    wheel.write_bytes(b"tampered")
    tampered = verify_release_evidence(release_dir=release_dir)
    assert not tampered.passed
    assert any(check.name == f"artifact:{wheel}" and check.status == "fail" for check in tampered.checks)
