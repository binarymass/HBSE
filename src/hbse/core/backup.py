"""Encrypted vault backup and restore helpers."""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from hbse.core.serialization import b64url_no_padding, utc_millis
from hbse.core.store import SQLiteVaultStore


class BackupError(RuntimeError):
    """Raised when backup or restore fails."""


@dataclass(frozen=True)
class BackupManifest:
    format_version: int
    created_at: str
    vault_id: str
    database_sha256: str
    contains_plaintext_secrets: bool = False
    contains_plaintext_root_key: bool = False

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True, indent=2)

    @classmethod
    def from_json(cls, value: str) -> "BackupManifest":
        return cls(**json.loads(value))


def create_backup(store: SQLiteVaultStore, destination: str | Path) -> BackupManifest:
    header = store.load_header()
    source = store.path
    if not source.exists():
        raise BackupError("vault database does not exist")
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        with sqlite3.connect(source) as src, sqlite3.connect(tmp.name) as dst:
            src.backup(dst)
        data = Path(tmp.name).read_bytes()
    manifest = BackupManifest(
        format_version=1,
        created_at=utc_millis(datetime.now(UTC)),
        vault_id=header.vault_id,
        database_sha256=b64url_no_padding(sha256(data).digest()),
    )
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", manifest.to_json())
        archive.writestr("vault.db", data)
    return manifest


def restore_backup(source: str | Path, destination_db: str | Path) -> BackupManifest:
    source = Path(source)
    destination_db = Path(destination_db)
    with zipfile.ZipFile(source, "r") as archive:
        names = set(archive.namelist())
        if names != {"manifest.json", "vault.db"}:
            raise BackupError("backup has unexpected contents")
        manifest = BackupManifest.from_json(archive.read("manifest.json").decode("utf-8"))
        db_data = archive.read("vault.db")
    actual_hash = b64url_no_padding(sha256(db_data).digest())
    if actual_hash != manifest.database_sha256:
        raise BackupError("backup database hash mismatch")
    destination_db.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination_db.with_suffix(destination_db.suffix + ".tmp")
    tmp.write_bytes(db_data)
    shutil.move(str(tmp), destination_db)
    return manifest
