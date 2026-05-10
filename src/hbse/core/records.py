"""Encrypted secret record models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from hbse.core.models import SecretStatus, SecretType
from hbse.core.serialization import b64url_decode_no_padding, b64url_no_padding


class SecretRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = "1"
    vault_id: str
    namespace_id: str
    secret_id: str
    secret_ref: str
    secret_version: int = Field(ge=1)
    status: SecretStatus = SecretStatus.ACTIVE
    secret_type: SecretType = SecretType.GENERIC
    algorithm_id: Literal["AES-256-GCM"] = "AES-256-GCM"
    wrap_algorithm_id: Literal["AES-256-GCM"] = "AES-256-GCM"
    policy_id: str = "default-deny"
    policy_hash: str
    metadata_hash: str
    provider_policy_hash: str = "unbound-provider-policy"
    created_at: datetime
    secret_nonce: str
    ciphertext: str
    dek_nonce: str
    wrapped_dek: str
    secret_aad_hash: str
    dek_wrap_aad_hash: str

    @classmethod
    def encode_bytes(cls, value: bytes) -> str:
        return b64url_no_padding(value)

    def ciphertext_bytes(self) -> bytes:
        return b64url_decode_no_padding(self.ciphertext)

    def secret_nonce_bytes(self) -> bytes:
        return b64url_decode_no_padding(self.secret_nonce)

    def dek_nonce_bytes(self) -> bytes:
        return b64url_decode_no_padding(self.dek_nonce)

    def wrapped_dek_bytes(self) -> bytes:
        return b64url_decode_no_padding(self.wrapped_dek)
