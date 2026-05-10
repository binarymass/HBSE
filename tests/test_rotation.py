from __future__ import annotations

import json

import pytest

from hbse.core.policy import AccessPolicy, DeliveryMode
from hbse.core.rotation import RotationJobStatus
from hbse.core.store import SQLiteVaultStore
from hbse.core.vault import LocalVault


def _vault(tmp_path):
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="passphrase")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"old",
        passphrase="passphrase",
    )
    vault.create_policy(
        AccessPolicy(
            policy_id="raw",
            secret_refs=["secret://default/api"],
            allowed_consumers=["test"],
            allowed_purposes=["read"],
            allowed_delivery_modes=[DeliveryMode.CALLBACK],
        )
    )
    return store, vault


def test_staged_rotation_does_not_promote_until_verified_and_promoted(tmp_path) -> None:
    store, vault = _vault(tmp_path)
    job = vault.start_rotation(
        secret_ref="secret://default/api",
        new_plaintext=b"new",
        passphrase="passphrase",
    )

    assert job.status == RotationJobStatus.STAGED
    assert store.list_secrets()[0].latest_version == 1
    assert vault.raw_get_secret(secret_ref="secret://default/api", passphrase="passphrase") == b"old"

    verified = vault.verify_rotation(job_id=job.job_id, passphrase="passphrase")
    assert verified.status == RotationJobStatus.VERIFIED
    promoted = vault.promote_rotation(job_id=job.job_id, passphrase="passphrase")
    assert promoted.status == RotationJobStatus.PROMOTED
    assert store.list_secrets()[0].latest_version == 2
    assert vault.raw_get_secret(secret_ref="secret://default/api", passphrase="passphrase") == b"new"


def test_staged_rotation_can_be_rolled_back(tmp_path) -> None:
    store, vault = _vault(tmp_path)
    job = vault.start_rotation(
        secret_ref="secret://default/api",
        new_plaintext=b"new",
        passphrase="passphrase",
    )
    rolled_back = vault.rollback_rotation(job_id=job.job_id, passphrase="passphrase")

    assert rolled_back.status == RotationJobStatus.ROLLED_BACK
    assert store.list_secrets()[0].latest_version == 1
    with pytest.raises(ValueError):
        vault.promote_rotation(job_id=job.job_id, passphrase="passphrase")
