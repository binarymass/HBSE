from __future__ import annotations

from hbse.core.dotenv import parse_dotenv, scan_dotenv, split_dotenv_values
from hbse.core.policy import AccessPolicy, DeliveryMode
from hbse.core.store import SQLiteVaultStore
from hbse.core.vault import LocalVault
from hbse.sdk import HBSEClient


def test_sdk_callback_uses_policy_ticket_flow(tmp_path) -> None:
    store = SQLiteVaultStore(tmp_path / "vault.db")
    vault = LocalVault(store=store)
    vault.init(passphrase="passphrase")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"sk-test",
        passphrase="passphrase",
    )
    vault.create_policy(
        AccessPolicy(
            policy_id="sdk",
            secret_refs=["secret://default/api"],
            allowed_consumers=["sdk-test"],
            allowed_purposes=["connect"],
            allowed_delivery_modes=[DeliveryMode.CALLBACK],
            exportable=False,
        )
    )
    client = HBSEClient(store=store, vault=vault)

    result = client.with_secret(
        secret_ref="secret://default/api",
        passphrase="passphrase",
        consumer="sdk-test",
        purpose="connect",
        callback=lambda secret: bytes(secret).decode("utf-8").replace("sk-", "ok-"),
    )

    assert result == "ok-test"


def test_dotenv_scan_detects_refs_and_likely_raw_secrets(tmp_path) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "APP_ENV=dev\nAPI_KEY=sk-1234567890abcdef\nDB_PASSWORD_REF=secret://default/db\n",
        encoding="utf-8",
    )

    findings = scan_dotenv(dotenv)

    assert any(finding.kind == "secret_ref" for finding in findings)
    assert any(finding.kind == "likely_raw_secret" for finding in findings)


def test_dotenv_parse_splits_plain_values_and_secret_refs(tmp_path) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "APP_ENV=dev\nTOKEN=secret://default/api\n",
        encoding="utf-8",
    )

    plain, refs = split_dotenv_values(parse_dotenv(dotenv))

    assert plain == {"APP_ENV": "dev"}
    assert refs == {"TOKEN": "secret://default/api"}
