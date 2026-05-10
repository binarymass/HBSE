from __future__ import annotations

import pytest

from hbse.core.crypto import AuthenticationFailed, CryptoEngine
from hbse.core.keys import KeyHierarchy
from hbse.core.models import SecretType
from hbse.core.nonce import NonceCollisionError, NonceRegistry
from hbse.core.records import SecretRecord
from hbse.core.serialization import canonical_json_bytes


ROOT = bytes.fromhex("11" * 32)


def test_canonical_serialization_sorts_keys_and_encodes_bytes() -> None:
    left = canonical_json_bytes({"b": 2, "a": b"\x01\x02"})
    right = canonical_json_bytes({"a": b"\x01\x02", "b": 2})

    assert left == right
    assert left == b'{"a":"AQI","b":2}'


def test_kdf_domain_separates_internal_keys_and_secret_versions() -> None:
    keys = KeyHierarchy(vault_id="vault-1", root_key=ROOT)

    derived = {
        keys.metadata_key(),
        keys.audit_integrity_key(),
        keys.redaction_fingerprint_key(),
        keys.ticket_mac_key(),
        keys.secret_kek("api", 1),
        keys.secret_kek("api", 2),
    }

    assert len(derived) == 6


def test_secret_round_trip_uses_per_secret_dek_and_authenticated_aad() -> None:
    engine = CryptoEngine()
    keys = KeyHierarchy(vault_id="vault-1", root_key=ROOT)

    record = engine.encrypt_secret(
        key_hierarchy=keys,
        namespace_id="default",
        secret_id="openai",
        secret_ref="secret://default/openai",
        version=1,
        plaintext=b"sk-test",
        secret_type=SecretType.API_KEY,
        policy_hash="policy-hash",
        metadata_hash="metadata-hash",
    )

    assert record.ciphertext != "sk-test"
    assert engine.decrypt_secret(key_hierarchy=keys, record=record) == b"sk-test"


def test_tampered_policy_hash_fails_before_decryption() -> None:
    engine = CryptoEngine()
    keys = KeyHierarchy(vault_id="vault-1", root_key=ROOT)
    record = engine.encrypt_secret(
        key_hierarchy=keys,
        namespace_id="default",
        secret_id="db",
        secret_ref="secret://default/db",
        version=1,
        plaintext=b"password",
        policy_hash="policy-hash",
        metadata_hash="metadata-hash",
    )
    tampered = record.model_copy(update={"policy_hash": "different"})

    with pytest.raises(AuthenticationFailed):
        engine.decrypt_secret(key_hierarchy=keys, record=tampered)


def test_wrong_secret_id_fails_authenticated_unwrap() -> None:
    engine = CryptoEngine()
    keys = KeyHierarchy(vault_id="vault-1", root_key=ROOT)
    record = engine.encrypt_secret(
        key_hierarchy=keys,
        namespace_id="default",
        secret_id="db",
        secret_ref="secret://default/db",
        version=1,
        plaintext=b"password",
        policy_hash="policy-hash",
        metadata_hash="metadata-hash",
    )
    aad_rehashed = SecretRecord(
        **{
            **record.model_dump(),
            "secret_id": "other",
            "secret_aad_hash": CryptoEngine._hash_bytes(
                CryptoEngine._secret_aad(
                    vault_id=record.vault_id,
                    namespace_id=record.namespace_id,
                    secret_id="other",
                    secret_ref=record.secret_ref,
                    version=record.secret_version,
                    secret_type=record.secret_type.value,
                    policy_id=record.policy_id,
                    policy_hash=record.policy_hash,
                    metadata_hash=record.metadata_hash,
                    created_at=record.created_at,
                )
            ),
            "dek_wrap_aad_hash": CryptoEngine._hash_bytes(
                CryptoEngine._dek_wrap_aad(
                    vault_id=record.vault_id,
                    secret_id="other",
                    version=record.secret_version,
                    kdf_label=keys.secret_kek_label("other", record.secret_version),
                    provider_policy_hash=record.provider_policy_hash,
                    created_at=record.created_at,
                )
            ),
        }
    )

    with pytest.raises(AuthenticationFailed):
        engine.decrypt_secret(key_hierarchy=keys, record=aad_rehashed)


def test_nonce_registry_regenerates_once_on_collision() -> None:
    duplicate = b"\x00" * 12
    replacement = b"\x01" * 12
    values = iter([duplicate, duplicate, replacement])
    registry = NonceRegistry(lambda _: next(values))

    assert registry.generate("scope") == duplicate
    assert registry.generate("scope") == replacement


def test_nonce_registry_fails_after_collision_limit() -> None:
    registry = NonceRegistry(lambda _: b"\x00" * 12)
    registry.generate("scope", max_attempts=1)

    with pytest.raises(NonceCollisionError):
        registry.generate("scope", max_attempts=2)
