from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from fastapi.testclient import TestClient

from hbse.api import create_app
from hbse.core.store import SQLiteVaultStore
from hbse.core.vault import LocalVault


API_KEY = "test-api-key"


def _client(tmp_path):
    vault_path = tmp_path / "api-vault.db"
    store = SQLiteVaultStore(vault_path)
    vault = LocalVault(store=store)
    vault.init(passphrase="passphrase")
    return TestClient(create_app(vault_path=vault_path, api_key=API_KEY))


def _headers() -> dict[str, str]:
    return {"X-HBSE-API-Key": API_KEY}


class _ProviderHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        auth = self.headers.get("Authorization", "")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"auth={auth}".encode("utf-8"))

    def log_message(self, format, *args):  # noqa: A002, ANN001
        return


def test_api_requires_authentication(tmp_path) -> None:
    client = _client(tmp_path)

    response = client.get("/v1/vault/status")

    assert response.status_code == 401


def test_api_put_list_policy_and_materialize_callback(tmp_path) -> None:
    client = _client(tmp_path)
    assert client.post(
        "/v1/secrets",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "value": "sk-test",
            "passphrase": "passphrase",
        },
    ).status_code == 200

    listed = client.get("/v1/secrets", headers=_headers())
    assert listed.status_code == 200
    assert listed.json()["secrets"][0]["secret_ref"] == "secret://default/api"
    assert "sk-test" not in listed.text

    denied = client.post(
        "/v1/materialize/callback",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "consumer": "api-test",
            "purpose": "connect",
            "delivery_mode": "callback",
            "passphrase": "passphrase",
        },
    )
    assert denied.status_code == 403

    assert client.post(
        "/v1/policies",
        headers=_headers(),
        json={
            "policy_id": "api-callback",
            "secret_refs": ["secret://default/api"],
            "allowed_consumers": ["api-test"],
            "allowed_purposes": ["connect"],
            "allowed_delivery_modes": ["callback"],
            "exportable": False,
        },
    ).status_code == 200

    materialized = client.post(
        "/v1/materialize/callback",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "consumer": "api-test",
            "purpose": "connect",
            "delivery_mode": "callback",
            "passphrase": "passphrase",
        },
    )

    assert materialized.status_code == 200
    assert materialized.json()["secret"] == "sk-test"


def test_api_provider_gateway_http_injects_and_redacts_secret(tmp_path) -> None:
    client = _client(tmp_path)
    assert client.post(
        "/v1/secrets",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "value": "sk-test",
            "passphrase": "passphrase",
        },
    ).status_code == 200
    assert client.post(
        "/v1/policies",
        headers=_headers(),
        json={
            "policy_id": "api-brokered-http",
            "secret_refs": ["secret://default/api"],
            "allowed_consumers": ["api-test"],
            "allowed_purposes": ["provider-call"],
            "allowed_delivery_modes": ["brokered_http"],
            "allowed_http_hosts": ["*"],
            "exportable": False,
        },
    ).status_code == 200
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = client.post(
            "/v1/provider-gateway/http",
            headers=_headers(),
            json={
                "secret_ref": "secret://default/api",
                "consumer": "api-test",
                "purpose": "provider-call",
                "method": "GET",
                "url": f"http://127.0.0.1:{server.server_port}/",
                "passphrase": "passphrase",
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert response.status_code == 200
    payload = response.json()
    assert payload["status_code"] == 200
    assert payload["body"] == "auth=Bearer [REDACTED:hbse-secret]"
    assert payload["redacted"] is True
    assert "sk-test" not in response.text


def test_api_idempotency_request_id_unlock_lock_backup_restore(tmp_path) -> None:
    client = _client(tmp_path)
    first = client.post(
        "/v1/secrets",
        headers={**_headers(), "Idempotency-Key": "put-1", "X-Request-ID": "req-1"},
        json={
            "secret_ref": "secret://default/api",
            "value": "sk-test",
            "passphrase": "passphrase",
        },
    )
    second = client.post(
        "/v1/secrets",
        headers={**_headers(), "Idempotency-Key": "put-1"},
        json={
            "secret_ref": "secret://default/api",
            "value": "sk-test-changed",
            "passphrase": "passphrase",
        },
    )

    assert first.headers["X-Request-ID"] == "req-1"
    assert first.json()["version"] == 1
    assert second.json()["version"] == 1

    assert client.post(
        "/v1/vault/unlock",
        headers=_headers(),
        json={"passphrase": "passphrase"},
    ).json()["unlocked"] is True
    assert client.post("/v1/vault/lock", headers=_headers()).json()["locked"] is True

    backup_path = tmp_path / "api-backup.zip"
    backup = client.post(
        "/v1/vault/backup",
        headers={**_headers(), "Idempotency-Key": "backup-1"},
        json={"destination": str(backup_path)},
    )
    assert backup.status_code == 200
    assert backup_path.exists()

    restored_path = tmp_path / "restored.db"
    restored = TestClient(create_app(vault_path=restored_path, api_key=API_KEY))
    restore = restored.post(
        "/v1/vault/restore",
        headers=_headers(),
        json={"source": str(backup_path)},
    )
    assert restore.status_code == 200
    assert restored.get("/v1/secrets", headers=_headers()).json()["secrets"][0]["latest_version"] == 1


def test_api_recovery_package_recovers_provider(tmp_path) -> None:
    client = _client(tmp_path)
    client.post(
        "/v1/secrets",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "value": "sk-test",
            "passphrase": "passphrase",
        },
    )
    recovery_path = tmp_path / "recovery.json"
    created = client.post(
        "/v1/vault/recovery-package",
        headers=_headers(),
        json={
            "passphrase": "passphrase",
            "recovery_secret": "recovery",
            "destination": str(recovery_path),
        },
    )
    assert created.status_code == 200
    assert recovery_path.exists()
    recovered = client.post(
        "/v1/vault/recover",
        headers=_headers(),
        json={
            "package_path": str(recovery_path),
            "recovery_secret": "recovery",
            "new_provider": "passphrase",
            "new_passphrase": "new",
        },
    )
    assert recovered.status_code == 200

    client.post(
        "/v1/policies",
        headers=_headers(),
        json={
            "policy_id": "api-callback",
            "secret_refs": ["secret://default/api"],
            "allowed_consumers": ["api-test"],
            "allowed_purposes": ["connect"],
            "allowed_delivery_modes": ["callback"],
            "exportable": False,
        },
    )
    materialized = client.post(
        "/v1/materialize/callback",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "consumer": "api-test",
            "purpose": "connect",
            "delivery_mode": "callback",
            "passphrase": "new",
        },
    )
    assert materialized.status_code == 200
    assert materialized.json()["secret"] == "sk-test"


def test_api_staged_rotation_flow(tmp_path) -> None:
    client = _client(tmp_path)
    client.post(
        "/v1/secrets",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "value": "old",
            "passphrase": "passphrase",
        },
    )
    started = client.post(
        "/v1/rotation/jobs",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "value": "new",
            "passphrase": "passphrase",
        },
    )
    assert started.status_code == 200
    job_id = started.json()["job_id"]
    assert client.get("/v1/rotation/jobs", headers=_headers()).json()["rotation_jobs"]
    assert client.post(
        f"/v1/rotation/jobs/{job_id}/verify",
        headers=_headers(),
        json={"passphrase": "passphrase"},
    ).json()["status"] == "verified"
    assert client.post(
        f"/v1/rotation/jobs/{job_id}/promote",
        headers=_headers(),
        json={"passphrase": "passphrase"},
    ).json()["status"] == "promoted"
    assert client.get("/v1/secrets/default/api", headers=_headers()).json()["version"] == 2


def test_api_raw_materialization_requires_explicit_policy_and_request(tmp_path) -> None:
    client = _client(tmp_path)
    client.post(
        "/v1/secrets",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "value": "sk-test",
            "passphrase": "passphrase",
        },
    )
    client.post(
        "/v1/policies",
        headers=_headers(),
        json={
            "policy_id": "api-raw",
            "secret_refs": ["secret://default/api"],
            "allowed_consumers": ["api-test"],
            "allowed_purposes": ["debug"],
            "allowed_delivery_modes": ["raw"],
            "exportable": True,
        },
    )

    missing_explicit_request = client.post(
        "/v1/materialize/callback",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "consumer": "api-test",
            "purpose": "debug",
            "delivery_mode": "raw",
            "passphrase": "passphrase",
        },
    )
    assert missing_explicit_request.status_code == 403

    allowed = client.post(
        "/v1/materialize/callback",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "consumer": "api-test",
            "purpose": "debug",
            "delivery_mode": "raw",
            "passphrase": "passphrase",
            "raw_export_requested": True,
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["secret"] == "sk-test"


def test_api_pipe_materialization_and_provider_endpoints(tmp_path) -> None:
    client = _client(tmp_path)
    client.post(
        "/v1/secrets",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "value": "sk-test",
            "passphrase": "passphrase",
        },
    )
    client.post(
        "/v1/policies",
        headers=_headers(),
        json={
            "policy_id": "api-pipe",
            "secret_refs": ["secret://default/api"],
            "allowed_consumers": ["api-test"],
            "allowed_purposes": ["pipe"],
            "allowed_delivery_modes": ["pipe"],
            "exportable": False,
        },
    )
    pipe = client.post(
        "/v1/materialize/pipe",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "consumer": "api-test",
            "purpose": "pipe",
            "passphrase": "passphrase",
        },
    )

    assert pipe.status_code == 200
    assert pipe.content == b"sk-test"
    providers = client.get("/v1/providers", headers=_headers())
    assert providers.status_code == 200
    assert providers.json()["providers"]
    missing = client.post("/v1/providers/missing/enroll", headers=_headers(), json={})
    assert missing.status_code == 404


def test_api_provider_enroll_rewraps_passphrase_provider(tmp_path) -> None:
    client = _client(tmp_path)
    client.post(
        "/v1/secrets",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "value": "sk-test",
            "passphrase": "passphrase",
        },
    )
    response = client.post(
        "/v1/providers/passphrase/enroll",
        headers=_headers(),
        json={
            "current_passphrase": "passphrase",
            "new_passphrase": "new-passphrase",
        },
    )
    assert response.status_code == 200
    assert response.json()["provider_id"] == "passphrase-scrypt-aesgcm"

    client.post(
        "/v1/policies",
        headers=_headers(),
        json={
            "policy_id": "api-callback",
            "secret_refs": ["secret://default/api"],
            "allowed_consumers": ["api-test"],
            "allowed_purposes": ["connect"],
            "allowed_delivery_modes": ["callback"],
            "exportable": False,
        },
    )
    old_passphrase = client.post(
        "/v1/materialize/callback",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "consumer": "api-test",
            "purpose": "connect",
            "delivery_mode": "callback",
            "passphrase": "passphrase",
        },
    )
    assert old_passphrase.status_code == 400

    new_passphrase = client.post(
        "/v1/materialize/callback",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "consumer": "api-test",
            "purpose": "connect",
            "delivery_mode": "callback",
            "passphrase": "new-passphrase",
        },
    )
    assert new_passphrase.status_code == 200
    assert new_passphrase.json()["secret"] == "sk-test"


def test_api_metadata_rotate_disable_policy_test_ticket_revoke_and_audit(tmp_path) -> None:
    client = _client(tmp_path)
    client.post(
        "/v1/secrets",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "value": "sk-test",
            "passphrase": "passphrase",
        },
    )
    metadata = client.get("/v1/secrets/default/api", headers=_headers())
    assert metadata.status_code == 200
    assert metadata.json()["version"] == 1
    assert "sk-test" not in metadata.text

    rotated = client.post(
        "/v1/secrets/default/api/rotate",
        headers=_headers(),
        json={
            "secret_ref": "ignored-by-path",
            "value": "sk-rotated",
            "passphrase": "passphrase",
        },
    )
    assert rotated.status_code == 200
    assert rotated.json()["version"] == 2

    client.post(
        "/v1/policies",
        headers=_headers(),
        json={
            "policy_id": "api-callback",
            "secret_refs": ["secret://default/api"],
            "allowed_consumers": ["api-test"],
            "allowed_purposes": ["connect"],
            "allowed_delivery_modes": ["callback"],
            "exportable": False,
        },
    )
    policy_result = client.post(
        "/v1/policies/api-callback/test",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "consumer": "api-test",
            "purpose": "connect",
            "delivery_mode": "callback",
        },
    )
    assert policy_result.status_code == 200
    assert policy_result.json()["decision"] == "allow"

    ticket = client.post(
        "/v1/tickets",
        headers=_headers(),
        json={
            "secret_ref": "secret://default/api",
            "consumer": "api-test",
            "purpose": "connect",
            "delivery_mode": "callback",
            "passphrase": "passphrase",
        },
    ).json()
    ticket_id = ticket["ticket_id"]
    assert client.get(f"/v1/tickets/{ticket_id}", headers=_headers()).status_code == 200
    revoked = client.post(
        f"/v1/tickets/{ticket_id}/revoke",
        headers=_headers(),
        json={"passphrase": "passphrase"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True

    disabled = client.post(
        "/v1/secrets/default/api/disable",
        headers=_headers(),
        json={"passphrase": "passphrase"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "disabled"

    destroyed = client.post(
        "/v1/secrets/default/api/destroy",
        headers=_headers(),
        json={"passphrase": "passphrase", "reason": "api test"},
    )
    assert destroyed.status_code == 200
    assert destroyed.json()["status"] == "destroyed"
    assert client.get("/v1/secrets/default/api", headers=_headers()).json()["status"] == "destroyed"

    audit = client.get("/v1/audit", headers=_headers())
    assert audit.status_code == 200
    assert audit.json()["events"]
