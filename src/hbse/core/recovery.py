"""Encrypted recovery package support."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from hbse.core.provider import PassphraseProvider
from hbse.core.serialization import utc_millis


class RecoveryError(RuntimeError):
    """Raised when recovery package handling fails."""


class RecoveryPackage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: int = 1
    recovery_id: str
    vault_id: str
    created_at: str
    root_binding: dict[str, Any]
    warning: str = "Recovery package can rewrap the vault root key. Protect it separately."

    def write(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        destination.chmod(0o600)

    @classmethod
    def read(cls, path: str | Path) -> "RecoveryPackage":
        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class RecoveryManager:
    provider: PassphraseProvider = PassphraseProvider()

    def create_package(
        self,
        *,
        vault_id: str,
        root_key: bytes,
        recovery_secret: str,
    ) -> RecoveryPackage:
        recovery_id = str(uuid.uuid4())
        binding = self.provider.wrap_root_key(
            vault_id=vault_id,
            root_key=root_key,
            passphrase=recovery_secret,
        )
        binding["recovery_id"] = recovery_id
        return RecoveryPackage(
            recovery_id=recovery_id,
            vault_id=vault_id,
            created_at=utc_millis(datetime.now(UTC)),
            root_binding=binding,
        )

    def unwrap_root_key(self, *, package: RecoveryPackage, recovery_secret: str) -> bytes:
        return self.provider.unwrap_root_key(
            vault_id=package.vault_id,
            binding=package.root_binding,
            passphrase=recovery_secret,
        )
