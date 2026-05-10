"""SQLite vault store for HBSE MVP."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from hbse.core.records import SecretRecord
from hbse.core.models import SecretStatus


SCHEMA_VERSION = 1


class VaultNotInitialized(RuntimeError):
    """Raised when a store operation requires an initialized vault."""


class VaultAlreadyInitialized(RuntimeError):
    """Raised when initialization would overwrite an existing vault."""


class SecretNotFound(KeyError):
    """Raised when a secret reference does not exist."""


class VaultHeader(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    vault_id: str
    namespace_id: str
    provider_binding: dict[str, Any]
    created_at: str


@dataclass
class SecretSummary:
    secret_ref: str
    secret_id: str
    namespace_id: str
    latest_version: int
    status: str
    secret_type: str
    created_at: str


class SQLiteVaultStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def initialize_schema(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS vault_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS secret_records (
                    secret_ref TEXT NOT NULL,
                    secret_id TEXT NOT NULL,
                    namespace_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    secret_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (secret_ref, version)
                );
                CREATE INDEX IF NOT EXISTS idx_secret_records_ref_version
                    ON secret_records(secret_ref, version DESC);
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id TEXT PRIMARY KEY,
                    policy_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tickets (
                    ticket_id TEXT PRIMARY KEY,
                    ticket_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS redaction_fingerprints (
                    secret_ref TEXT NOT NULL,
                    secret_version INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    PRIMARY KEY (secret_ref, secret_version)
                );
                CREATE TABLE IF NOT EXISTS rotation_jobs (
                    job_id TEXT PRIMARY KEY,
                    secret_ref TEXT NOT NULL,
                    status TEXT NOT NULL,
                    job_json TEXT NOT NULL
                );
                """
            )

    def create_vault(self, header: VaultHeader) -> None:
        self.initialize_schema()
        with self._connect() as conn:
            if self._get_metadata(conn, "vault_header") is not None:
                raise VaultAlreadyInitialized("vault is already initialized")
            conn.execute(
                "INSERT INTO vault_metadata (key, value) VALUES (?, ?)",
                ("vault_header", header.model_dump_json()),
            )

    def load_header(self) -> VaultHeader:
        self.initialize_schema()
        with self._connect() as conn:
            raw = self._get_metadata(conn, "vault_header")
        if raw is None:
            raise VaultNotInitialized("vault is not initialized")
        return VaultHeader.model_validate_json(raw)

    def update_header(self, header: VaultHeader) -> None:
        self.initialize_schema()
        with self._connect() as conn:
            if self._get_metadata(conn, "vault_header") is None:
                raise VaultNotInitialized("vault is not initialized")
            conn.execute(
                "UPDATE vault_metadata SET value = ? WHERE key = ?",
                (header.model_dump_json(), "vault_header"),
            )

    def save_secret_record(self, record: SecretRecord) -> None:
        self.initialize_schema()
        with self._connect() as conn:
            if self._get_metadata(conn, "vault_header") is None:
                raise VaultNotInitialized("vault is not initialized")
            conn.execute(
                """
                INSERT OR REPLACE INTO secret_records (
                    secret_ref, secret_id, namespace_id, version, status, secret_type, created_at, record_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.secret_ref,
                    record.secret_id,
                    record.namespace_id,
                    record.secret_version,
                    record.status.value,
                    record.secret_type.value,
                    record.created_at.isoformat(),
                    record.model_dump_json(),
                ),
            )

    def latest_version(self, secret_ref: str) -> int | None:
        self.initialize_schema()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT MAX(version) FROM secret_records WHERE secret_ref = ?", (secret_ref,)
            ).fetchone()
        value = row[0] if row else None
        return int(value) if value is not None else None

    def load_latest_secret(self, secret_ref: str) -> SecretRecord:
        self.initialize_schema()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT record_json FROM secret_records
                WHERE secret_ref = ?
                ORDER BY version DESC
                LIMIT 1
                """,
                (secret_ref,),
            ).fetchone()
        if row is None:
            raise SecretNotFound(secret_ref)
        return SecretRecord.model_validate_json(row[0])

    def save_updated_secret_status(self, secret_ref: str, status: str) -> SecretRecord:
        record = self.load_latest_secret(secret_ref)
        updated = record.model_copy(update={"status": SecretStatus(status)})
        self.save_secret_record(updated)
        return updated

    def load_secret_metadata(self, secret_ref: str) -> SecretSummary:
        record = self.load_latest_secret(secret_ref)
        return SecretSummary(
            secret_ref=record.secret_ref,
            secret_id=record.secret_id,
            namespace_id=record.namespace_id,
            latest_version=record.secret_version,
            status=record.status.value,
            secret_type=record.secret_type.value,
            created_at=record.created_at.isoformat(),
        )

    def list_secrets(self) -> list[SecretSummary]:
        self.initialize_schema()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT sr.secret_ref, sr.secret_id, sr.namespace_id, sr.version, sr.status,
                       sr.secret_type, sr.created_at
                FROM secret_records sr
                JOIN (
                    SELECT secret_ref, MAX(version) AS version
                    FROM secret_records
                    GROUP BY secret_ref
                ) latest
                ON sr.secret_ref = latest.secret_ref AND sr.version = latest.version
                ORDER BY sr.secret_ref
                """
            ).fetchall()
        return [
            SecretSummary(
                secret_ref=row[0],
                secret_id=row[1],
                namespace_id=row[2],
                latest_version=int(row[3]),
                status=row[4],
                secret_type=row[5],
                created_at=row[6],
            )
            for row in rows
        ]

    def save_policy_json(self, policy_id: str, policy_json: str) -> None:
        self.initialize_schema()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO policies (policy_id, policy_json) VALUES (?, ?)",
                (policy_id, policy_json),
            )

    def load_policy_json(self, policy_id: str) -> str | None:
        self.initialize_schema()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT policy_json FROM policies WHERE policy_id = ?", (policy_id,)
            ).fetchone()
        return None if row is None else str(row[0])

    def list_policy_json(self) -> list[str]:
        self.initialize_schema()
        with self._connect() as conn:
            rows = conn.execute("SELECT policy_json FROM policies ORDER BY policy_id").fetchall()
        return [str(row[0]) for row in rows]

    def save_ticket_json(self, ticket_id: str, ticket_json: str) -> None:
        self.initialize_schema()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO tickets (ticket_id, ticket_json) VALUES (?, ?)",
                (ticket_id, ticket_json),
            )

    def load_ticket_json(self, ticket_id: str) -> str | None:
        self.initialize_schema()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT ticket_json FROM tickets WHERE ticket_id = ?", (ticket_id,)
            ).fetchone()
        return None if row is None else str(row[0])

    def list_ticket_json(self) -> list[str]:
        self.initialize_schema()
        with self._connect() as conn:
            rows = conn.execute("SELECT ticket_json FROM tickets ORDER BY ticket_id").fetchall()
        return [str(row[0]) for row in rows]

    def integrity_check(self) -> str:
        self.initialize_schema()
        with self._connect() as conn:
            row = conn.execute("PRAGMA integrity_check").fetchone()
        return str(row[0]) if row else "unknown"

    def save_audit_event_json(self, event_id: str, event_json: str) -> None:
        self.initialize_schema()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audit_events (event_id, event_json) VALUES (?, ?)",
                (event_id, event_json),
            )

    def list_audit_event_json(self) -> list[str]:
        self.initialize_schema()
        with self._connect() as conn:
            rows = conn.execute("SELECT event_json FROM audit_events ORDER BY sequence").fetchall()
        return [str(row[0]) for row in rows]

    def save_redaction_fingerprint(self, secret_ref: str, secret_version: int, fingerprint: str) -> None:
        self.initialize_schema()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO redaction_fingerprints
                    (secret_ref, secret_version, fingerprint)
                VALUES (?, ?, ?)
                """,
                (secret_ref, secret_version, fingerprint),
            )

    def list_redaction_fingerprints(self) -> list[str]:
        self.initialize_schema()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT fingerprint FROM redaction_fingerprints ORDER BY secret_ref, secret_version"
            ).fetchall()
        return [str(row[0]) for row in rows]

    def save_rotation_job_json(self, job_id: str, secret_ref: str, status: str, job_json: str) -> None:
        self.initialize_schema()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO rotation_jobs (job_id, secret_ref, status, job_json)
                VALUES (?, ?, ?, ?)
                """,
                (job_id, secret_ref, status, job_json),
            )

    def load_rotation_job_json(self, job_id: str) -> str | None:
        self.initialize_schema()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT job_json FROM rotation_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return None if row is None else str(row[0])

    def list_rotation_job_json(self) -> list[str]:
        self.initialize_schema()
        with self._connect() as conn:
            rows = conn.execute("SELECT job_json FROM rotation_jobs ORDER BY job_id").fetchall()
        return [str(row[0]) for row in rows]

    def export_redacted(self) -> dict[str, Any]:
        header = self.load_header()
        return {
            "vault": {
                "vault_id": header.vault_id,
                "namespace_id": header.namespace_id,
                "schema_version": header.schema_version,
                "provider_id": header.provider_binding.get("provider_id"),
                "assurance_level": header.provider_binding.get("assurance_level"),
            },
            "secrets": [summary.__dict__ for summary in self.list_secrets()],
        }

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _get_metadata(conn: sqlite3.Connection, key: str) -> str | None:
        row = conn.execute("SELECT value FROM vault_metadata WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row[0])


def json_dumps_redacted(value: object) -> str:
    return json.dumps(value, sort_keys=True, indent=2)
