"""Staged secret rotation jobs."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from hbse.core.records import SecretRecord
from hbse.core.serialization import utc_millis


class RotationJobStatus(StrEnum):
    STAGED = "staged"
    VERIFIED = "verified"
    PROMOTED = "promoted"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class RotationJob(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: str
    vault_id: str
    secret_ref: str
    staged_version: int
    status: RotationJobStatus
    created_at: str
    updated_at: str
    staged_record: SecretRecord
    verifier: str = "decrypt-self-test"
    failure_reason: str | None = None

    @classmethod
    def create(
        cls,
        *,
        vault_id: str,
        secret_ref: str,
        staged_version: int,
        staged_record: SecretRecord,
    ) -> "RotationJob":
        now = utc_millis(datetime.now(UTC))
        return cls(
            job_id=str(uuid.uuid4()),
            vault_id=vault_id,
            secret_ref=secret_ref,
            staged_version=staged_version,
            status=RotationJobStatus.STAGED,
            created_at=now,
            updated_at=now,
            staged_record=staged_record,
        )

    def transition(
        self,
        status: RotationJobStatus,
        *,
        failure_reason: str | None = None,
    ) -> "RotationJob":
        return self.model_copy(
            update={
                "status": status,
                "updated_at": utc_millis(datetime.now(UTC)),
                "failure_reason": failure_reason,
            }
        )
