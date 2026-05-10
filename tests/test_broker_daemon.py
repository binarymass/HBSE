from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from hbse import broker_daemon
from hbse.core.policy import AccessPolicy, DeliveryMode
from hbse.core.store import SQLiteVaultStore
from hbse.core.vault import LocalVault


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _ProviderHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("X-Provider-Auth", self.headers.get("Authorization", ""))
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):  # noqa: A002, ANN001
        return


def test_broker_daemon_unlock_materialize_and_lock(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    socket_path = tmp_path / "broker.sock"
    store = SQLiteVaultStore(vault_path)
    vault = LocalVault(store=store)
    vault.init(passphrase="passphrase")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"sk-test",
        passphrase="passphrase",
    )
    vault.create_policy(
        AccessPolicy(
            policy_id="broker",
            secret_refs=["secret://default/api"],
            allowed_consumers=["broker-test"],
            allowed_purposes=["daemon"],
            allowed_delivery_modes=[DeliveryMode.CALLBACK],
            allowed_os_uids=[os.getuid()],
            allowed_executable_sha256=[_sha256_file(os.readlink(f"/proc/{os.getpid()}/exe"))],
        )
    )

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "hbse.broker_daemon",
            "--vault",
            str(vault_path),
            "--socket",
            str(socket_path),
            "--idle-timeout-seconds",
            "0.2",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.time() + 5
        while not socket_path.exists() and time.time() < deadline:
            time.sleep(0.05)
        assert socket_path.exists()

        locked = broker_daemon.request(
            socket_path,
            {
                "command": "materialize",
                "secret_ref": "secret://default/api",
                "consumer": "broker-test",
                "purpose": "daemon",
                "delivery_mode": "callback",
            },
        )
        assert locked["ok"] is False
        assert "locked" in locked["error"]["message"]

        assert broker_daemon.request(
            socket_path,
            {"command": "unlock", "passphrase": "passphrase"},
        )["ok"] is True
        time.sleep(0.3)
        expired_status = broker_daemon.request(socket_path, {"command": "status"})
        assert expired_status["ok"] is True
        assert expired_status["unlocked"] is False

        assert broker_daemon.request(
            socket_path,
            {"command": "unlock", "passphrase": "passphrase"},
        )["ok"] is True

        checkout = broker_daemon.request(
            socket_path,
            {
                "command": "checkout",
                "secret_ref": "secret://default/api",
                "consumer": "broker-test",
                "purpose": "daemon",
                "delivery_mode": "callback",
            },
        )
        assert checkout["ok"] is True
        assert checkout["ticket"]["secret_ref"] == "secret://default/api"
        assert checkout["ticket"]["delivery_mode"] == "callback"
        assert "sk-test" not in str(checkout)

        materialized = broker_daemon.request(
            socket_path,
            {
                "command": "materialize",
                "secret_ref": "secret://default/api",
                "consumer": "broker-test",
                "purpose": "daemon",
                "delivery_mode": "callback",
            },
        )
        assert materialized["ok"] is True
        assert materialized["secret"] == "sk-test"
        assert materialized["peer"]["uid"] >= 0
        assert materialized["peer"]["exe_path"]
        assert len(materialized["peer"]["exe_sha256"]) == 64

        assert broker_daemon.request(socket_path, {"command": "lock"})["ok"] is True
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_broker_daemon_provider_http_facilitates_credential_call(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    socket_path = tmp_path / "broker.sock"
    store = SQLiteVaultStore(vault_path)
    vault = LocalVault(store=store)
    vault.init(passphrase="passphrase")
    vault.put_secret(
        secret_ref="secret://default/api",
        plaintext=b"sk-test",
        passphrase="passphrase",
    )
    vault.create_policy(
        AccessPolicy(
            policy_id="broker-http",
            secret_refs=["secret://default/api"],
            allowed_consumers=["broker-test"],
            allowed_purposes=["provider-call"],
            allowed_delivery_modes=[DeliveryMode.BROKERED_HTTP],
        )
    )
    provider = ThreadingHTTPServer(("127.0.0.1", 0), _ProviderHandler)
    provider_thread = Thread(target=provider.serve_forever, daemon=True)
    provider_thread.start()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "hbse.broker_daemon",
            "--vault",
            str(vault_path),
            "--socket",
            str(socket_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.time() + 5
        while not socket_path.exists() and time.time() < deadline:
            time.sleep(0.05)
        assert socket_path.exists()
        assert broker_daemon.request(
            socket_path,
            {"command": "unlock", "passphrase": "passphrase"},
        )["ok"] is True

        response = broker_daemon.request(
            socket_path,
            {
                "command": "provider_http",
                "secret_ref": "secret://default/api",
                "consumer": "broker-test",
                "purpose": "provider-call",
                "method": "GET",
                "url": f"http://127.0.0.1:{provider.server_port}/",
            },
        )
        assert response["ok"] is True
        assert response["status_code"] == 200
        assert response["headers"]["X-Provider-Auth"] == "Bearer [REDACTED:hbse-secret]"
        assert "sk-test" not in str(response)
    finally:
        process.terminate()
        process.wait(timeout=5)
        provider.shutdown()
        provider.server_close()
        provider_thread.join(timeout=5)
