from __future__ import annotations

from hbse.core.recovery import RecoveryPackage
from hbse.core.store import SQLiteVaultStore
from hbse.core.vault import LocalVault


def test_recovery_package_rewraps_lost_passphrase_provider(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="old")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"sk-test",
        passphrase="old",
    )
    package = vault.create_recovery_package(
        passphrase="old",
        recovery_secret="recovery-secret",
    )
    package_path = tmp_path / "recovery.json"
    package.write(package_path)

    loaded = RecoveryPackage.read(package_path)
    header = vault.recover_provider_from_package(
        package=loaded,
        recovery_secret="recovery-secret",
        new_provider="passphrase",
        new_passphrase="new",
    )

    assert header.provider_binding["provider_id"] == "passphrase-scrypt-aesgcm"
    assert vault.raw_get_secret(secret_ref="secret://default/api", passphrase="new") == b"sk-test"


def test_recovery_package_file_is_0600_and_does_not_contain_secret(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="old")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"sk-test",
        passphrase="old",
    )
    package_path = tmp_path / "recovery.json"
    vault.create_recovery_package(passphrase="old", recovery_secret="recovery-secret").write(package_path)

    assert oct(package_path.stat().st_mode & 0o777) == "0o600"
    assert b"sk-test" not in package_path.read_bytes()
