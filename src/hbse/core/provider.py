"""MVP provider helpers for protecting vault root keys."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from hbse.core.keys import KEY_SIZE
from hbse.core.serialization import b64url_decode_no_padding, b64url_no_padding, canonical_json_bytes


PASSPHRASE_PROVIDER_ID = "passphrase-scrypt-aesgcm"


class ProviderUnlockFailed(ValueError):
    """Raised when a provider cannot unlock the vault root key."""


@dataclass(frozen=True)
class PassphraseProvider:
    """MVP passphrase provider used until hardware providers are implemented."""

    n: int = 2**14
    r: int = 8
    p: int = 1

    def wrap_root_key(self, *, vault_id: str, root_key: bytes, passphrase: str) -> dict[str, object]:
        if len(root_key) != KEY_SIZE:
            raise ValueError("vault root key must be 32 bytes")
        salt = os.urandom(16)
        nonce = os.urandom(12)
        wrapping_key = self._derive(passphrase=passphrase, salt=salt)
        aad = self._aad(vault_id=vault_id)
        wrapped_root_key = AESGCM(wrapping_key).encrypt(nonce, root_key, aad)
        return {
            "provider_id": PASSPHRASE_PROVIDER_ID,
            "kdf": "scrypt",
            "kdf_params": {"n": self.n, "r": self.r, "p": self.p},
            "salt": b64url_no_padding(salt),
            "nonce": b64url_no_padding(nonce),
            "wrapped_root_key": b64url_no_padding(wrapped_root_key),
            "assurance_level": "A1",
            "warning": "MVP passphrase provider; enroll a hardware provider before production use.",
        }

    def unwrap_root_key(self, *, vault_id: str, binding: dict[str, object], passphrase: str) -> bytes:
        if binding.get("provider_id") != PASSPHRASE_PROVIDER_ID:
            raise ProviderUnlockFailed("unsupported provider binding")
        salt = b64url_decode_no_padding(str(binding["salt"]))
        nonce = b64url_decode_no_padding(str(binding["nonce"]))
        wrapped_root_key = b64url_decode_no_padding(str(binding["wrapped_root_key"]))
        params = binding.get("kdf_params")
        if not isinstance(params, dict):
            raise ProviderUnlockFailed("invalid provider KDF parameters")

        provider = PassphraseProvider(n=int(params["n"]), r=int(params["r"]), p=int(params["p"]))
        wrapping_key = provider._derive(passphrase=passphrase, salt=salt)
        try:
            return AESGCM(wrapping_key).decrypt(nonce, wrapped_root_key, self._aad(vault_id=vault_id))
        except InvalidTag as exc:
            raise ProviderUnlockFailed("passphrase unlock failed") from exc

    def _derive(self, *, passphrase: str, salt: bytes) -> bytes:
        if not passphrase:
            raise ValueError("passphrase must not be empty")
        return Scrypt(salt=salt, length=KEY_SIZE, n=self.n, r=self.r, p=self.p).derive(
            passphrase.encode("utf-8")
        )

    @staticmethod
    def _aad(*, vault_id: str) -> bytes:
        return canonical_json_bytes(
            {"provider_id": PASSPHRASE_PROVIDER_ID, "record_type": "vault-root-wrap", "vault_id": vault_id}
        )
