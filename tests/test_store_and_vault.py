from __future__ import annotations

import pytest

from hbse.core.provider import ProviderUnlockFailed
from hbse.core.store import SQLiteVaultStore, VaultAlreadyInitialized
from hbse.core.vault import LocalVault


def test_vault_init_persists_redacted_header(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)

    header = vault.init(passphrase="correct horse battery staple")
    exported = store.export_redacted()

    assert exported["vault"]["vault_id"] == header.vault_id
    assert exported["vault"]["provider_id"] == "passphrase-scrypt-aesgcm"
    assert "wrapped_root_key" not in exported["vault"]


def test_vault_cannot_be_initialized_twice(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="correct horse battery staple")

    with pytest.raises(VaultAlreadyInitialized):
        vault.init(passphrase="correct horse battery staple")


def test_secret_put_versions_and_round_trips(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="correct horse battery staple")

    assert vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"first",
        passphrase="correct horse battery staple",
    ) == 1
    assert vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"second",
        passphrase="correct horse battery staple",
    ) == 2

    summaries = store.list_secrets()
    assert len(summaries) == 1
    assert summaries[0].latest_version == 2
    assert vault.raw_get_secret(
        secret_ref="secret://default/api", passphrase="correct horse battery staple"
    ) == b"second"


def test_store_file_does_not_contain_plaintext_secret(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    store = SQLiteVaultStore(vault_path)
    vault = LocalVault(store=store)
    vault.init(passphrase="correct horse battery staple")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"unique-plaintext-token",
        passphrase="correct horse battery staple",
    )

    assert b"unique-plaintext-token" not in vault_path.read_bytes()


def test_wrong_passphrase_cannot_decrypt_secret(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="correct horse battery staple")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"first",
        passphrase="correct horse battery staple",
    )

    with pytest.raises(ProviderUnlockFailed):
        vault.raw_get_secret(secret_ref="secret://default/api", passphrase="wrong")


def test_provider_rewrap_rotates_passphrase_binding_without_reencrypting_secret(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="old passphrase")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"first",
        passphrase="old passphrase",
    )

    header = vault.rewrap_provider(
        current_passphrase="old passphrase",
        new_provider="passphrase",
        new_passphrase="new passphrase",
    )

    assert header.provider_binding["provider_id"] == "passphrase-scrypt-aesgcm"
    assert vault.raw_get_secret(
        secret_ref="secret://default/api",
        passphrase="new passphrase",
    ) == b"first"
    with pytest.raises(ProviderUnlockFailed):
        vault.raw_get_secret(secret_ref="secret://default/api", passphrase="old passphrase")
