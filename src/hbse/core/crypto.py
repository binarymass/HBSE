"""Protocol-bound cryptographic operations for HBSE Phase 1."""

from __future__ import annotations

import os
from hashlib import sha256

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hbse.core.keys import KEY_SIZE, KeyHierarchy
from hbse.core.models import SecretType, now_utc
from hbse.core.nonce import NonceRegistry
from hbse.core.records import SecretRecord
from hbse.core.serialization import b64url_no_padding, canonical_json_bytes


class AuthenticationFailed(ValueError):
    """Raised when authenticated decryption fails."""


class CryptoEngine:
    """Encrypts and decrypts v1 secret records using per-secret DEKs."""

    def __init__(self, nonce_registry: NonceRegistry | None = None) -> None:
        self._nonces = nonce_registry or NonceRegistry()

    def encrypt_secret(
        self,
        *,
        key_hierarchy: KeyHierarchy,
        namespace_id: str,
        secret_id: str,
        secret_ref: str,
        version: int,
        plaintext: bytes,
        secret_type: SecretType = SecretType.GENERIC,
        policy_id: str = "default-deny",
        policy_hash: str,
        metadata_hash: str,
        provider_policy_hash: str = "unbound-provider-policy",
    ) -> SecretRecord:
        created_at = now_utc()
        dek = os.urandom(KEY_SIZE)
        kek = key_hierarchy.secret_kek(secret_id, version)
        kdf_label = key_hierarchy.secret_kek_label(secret_id, version)

        secret_aad = self._secret_aad(
            vault_id=key_hierarchy.vault_id,
            namespace_id=namespace_id,
            secret_id=secret_id,
            secret_ref=secret_ref,
            version=version,
            secret_type=secret_type.value,
            policy_id=policy_id,
            policy_hash=policy_hash,
            metadata_hash=metadata_hash,
            created_at=created_at,
        )
        wrap_aad = self._dek_wrap_aad(
            vault_id=key_hierarchy.vault_id,
            secret_id=secret_id,
            version=version,
            kdf_label=kdf_label,
            provider_policy_hash=provider_policy_hash,
            created_at=created_at,
        )

        secret_nonce = self._nonces.generate(f"secret:{key_hierarchy.vault_id}:{secret_id}:{version}")
        dek_nonce = self._nonces.generate(f"dek:{key_hierarchy.vault_id}:{secret_id}:{version}")
        ciphertext = AESGCM(dek).encrypt(secret_nonce, plaintext, secret_aad)
        wrapped_dek = AESGCM(kek).encrypt(dek_nonce, dek, wrap_aad)

        return SecretRecord(
            vault_id=key_hierarchy.vault_id,
            namespace_id=namespace_id,
            secret_id=secret_id,
            secret_ref=secret_ref,
            secret_version=version,
            secret_type=secret_type,
            policy_id=policy_id,
            policy_hash=policy_hash,
            metadata_hash=metadata_hash,
            provider_policy_hash=provider_policy_hash,
            created_at=created_at,
            secret_nonce=b64url_no_padding(secret_nonce),
            ciphertext=b64url_no_padding(ciphertext),
            dek_nonce=b64url_no_padding(dek_nonce),
            wrapped_dek=b64url_no_padding(wrapped_dek),
            secret_aad_hash=self._hash_bytes(secret_aad),
            dek_wrap_aad_hash=self._hash_bytes(wrap_aad),
        )

    def decrypt_secret(self, *, key_hierarchy: KeyHierarchy, record: SecretRecord) -> bytes:
        if record.vault_id != key_hierarchy.vault_id:
            raise AuthenticationFailed("record belongs to a different vault")

        kdf_label = key_hierarchy.secret_kek_label(record.secret_id, record.secret_version)
        secret_aad = self._secret_aad(
            vault_id=record.vault_id,
            namespace_id=record.namespace_id,
            secret_id=record.secret_id,
            secret_ref=record.secret_ref,
            version=record.secret_version,
            secret_type=record.secret_type.value,
            policy_id=record.policy_id,
            policy_hash=record.policy_hash,
            metadata_hash=record.metadata_hash,
            created_at=record.created_at,
        )
        wrap_aad = self._dek_wrap_aad(
            vault_id=record.vault_id,
            secret_id=record.secret_id,
            version=record.secret_version,
            kdf_label=kdf_label,
            provider_policy_hash=record.provider_policy_hash,
            created_at=record.created_at,
        )

        if self._hash_bytes(secret_aad) != record.secret_aad_hash:
            raise AuthenticationFailed("secret AAD hash mismatch")
        if self._hash_bytes(wrap_aad) != record.dek_wrap_aad_hash:
            raise AuthenticationFailed("DEK-wrap AAD hash mismatch")

        kek = key_hierarchy.secret_kek(record.secret_id, record.secret_version)
        try:
            dek = AESGCM(kek).decrypt(record.dek_nonce_bytes(), record.wrapped_dek_bytes(), wrap_aad)
            return AESGCM(dek).decrypt(
                record.secret_nonce_bytes(), record.ciphertext_bytes(), secret_aad
            )
        except InvalidTag as exc:
            raise AuthenticationFailed("authenticated decryption failed") from exc

    @staticmethod
    def _hash_bytes(value: bytes) -> str:
        return b64url_no_padding(sha256(value).digest())

    @staticmethod
    def _secret_aad(**fields: object) -> bytes:
        return canonical_json_bytes(
            {
                "aad_version": "1",
                "record_type": "secret",
                "algorithm_id": "AES-256-GCM",
                "schema_version": "1",
                **fields,
            }
        )

    @staticmethod
    def _dek_wrap_aad(**fields: object) -> bytes:
        return canonical_json_bytes(
            {
                "aad_version": "1",
                "wrap_algorithm_id": "AES-256-GCM",
                **fields,
            }
        )
