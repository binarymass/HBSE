from __future__ import annotations

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from hbse.core.broker import LocalBroker
from hbse.core.materialization import Materializer
from hbse.core.policy import AccessPolicy, DeliveryMode
from hbse.core.store import SQLiteVaultStore
from hbse.core.vault import LocalVault


def _vault_with_policy(tmp_path, delivery_mode: DeliveryMode):
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
            policy_id=f"policy-{delivery_mode.value}",
            secret_refs=["secret://default/api"],
            allowed_consumers=["broker-test"],
            allowed_purposes=["use-secret"],
            allowed_delivery_modes=[delivery_mode],
            exportable=False,
        )
    )
    return store, vault


class _EchoAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        auth = self.headers.get("Authorization", "")
        if auth == "Bearer sk-test":
            self.send_response(200)
            self.send_header("X-Echo-Auth", auth)
            self.end_headers()
            self.wfile.write(f"accepted {auth}".encode("utf-8"))
            return
        self.send_response(401)
        self.end_headers()
        self.wfile.write(b"missing auth")

    def do_POST(self) -> None:
        self.do_GET()

    def log_message(self, format, *args):  # noqa: A002, ANN001
        return


def test_brokered_http_injects_credential_and_redacts_response(tmp_path) -> None:
    store, vault = _vault_with_policy(tmp_path, DeliveryMode.BROKERED_HTTP)
    broker = LocalBroker(store=store, vault=vault)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoAuthHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = broker.brokered_http_request(
            secret_ref="secret://default/api",
            consumer="broker-test",
            purpose="use-secret",
            method="GET",
            url=f"http://127.0.0.1:{server.server_port}/v1/models",
            passphrase="passphrase",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert response.status_code == 200
    assert "sk-test" not in response.body
    assert response.body == "accepted Bearer [REDACTED:hbse-secret]"
    assert response.headers["X-Echo-Auth"] == "Bearer [REDACTED:hbse-secret]"
    assert response.redacted is True


def test_brokered_http_blocks_known_secret_in_request_body(tmp_path) -> None:
    store, vault = _vault_with_policy(tmp_path, DeliveryMode.BROKERED_HTTP)
    broker = LocalBroker(store=store, vault=vault)

    try:
        broker.brokered_http_request(
            secret_ref="secret://default/api",
            consumer="broker-test",
            purpose="use-secret",
            method="POST",
            url="http://127.0.0.1:9/",
            body="leak sk-test",
            passphrase="passphrase",
            timeout_seconds=0.1,
        )
    except PermissionError as exc:
        assert "request body contains" in str(exc)
    else:
        raise AssertionError("known secret was allowed in request body")


def test_brokered_http_policy_can_bind_provider_host(tmp_path) -> None:
    store, vault = _vault_with_policy(tmp_path, DeliveryMode.BROKERED_HTTP)
    vault.create_policy(
        AccessPolicy(
            policy_id="host-bound",
            secret_refs=["secret://default/api"],
            allowed_consumers=["host-test"],
            allowed_purposes=["use-secret"],
            allowed_delivery_modes=[DeliveryMode.BROKERED_HTTP],
            allowed_http_hosts=["api.example.test"],
        )
    )
    broker = LocalBroker(store=store, vault=vault)

    try:
        broker.brokered_http_request(
            secret_ref="secret://default/api",
            consumer="host-test",
            purpose="use-secret",
            method="GET",
            url="http://127.0.0.1:9/",
            passphrase="passphrase",
            timeout_seconds=0.1,
        )
    except PermissionError as exc:
        assert "matching allow policy" in str(exc)
    else:
        raise AssertionError("provider host binding was not enforced")


def test_brokered_http_policy_can_bind_method_and_path(tmp_path) -> None:
    store, vault = _vault_with_policy(tmp_path, DeliveryMode.BROKERED_HTTP)
    broker = LocalBroker(store=store, vault=vault)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoAuthHandler)
    vault.create_policy(
        AccessPolicy(
            policy_id="method-path-bound",
            secret_refs=["secret://default/api"],
            allowed_consumers=["method-path-test"],
            allowed_purposes=["use-secret"],
            allowed_delivery_modes=[DeliveryMode.BROKERED_HTTP],
            allowed_http_hosts=[f"127.0.0.1:{server.server_port}"],
            allowed_http_methods=["GET"],
            allowed_http_path_prefixes=["/v1/"],
        )
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        allowed = broker.brokered_http_request(
            secret_ref="secret://default/api",
            consumer="method-path-test",
            purpose="use-secret",
            method="GET",
            url=f"http://127.0.0.1:{server.server_port}/v1/models",
            passphrase="passphrase",
        )
        assert allowed.status_code == 200
        try:
            broker.brokered_http_request(
                secret_ref="secret://default/api",
                consumer="method-path-test",
                purpose="use-secret",
                method="POST",
                url=f"http://127.0.0.1:{server.server_port}/v1/models",
                passphrase="passphrase",
            )
        except PermissionError as exc:
            assert "matching allow policy" in str(exc)
        else:
            raise AssertionError("HTTP method binding was not enforced")
        try:
            broker.brokered_http_request(
                secret_ref="secret://default/api",
                consumer="method-path-test",
                purpose="use-secret",
                method="GET",
                url=f"http://127.0.0.1:{server.server_port}/admin",
                passphrase="passphrase",
            )
        except PermissionError as exc:
            assert "matching allow policy" in str(exc)
        else:
            raise AssertionError("HTTP path binding was not enforced")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_brokered_http_policy_can_require_https_and_body_limit(tmp_path) -> None:
    store, vault = _vault_with_policy(tmp_path, DeliveryMode.BROKERED_HTTP)
    vault.create_policy(
        AccessPolicy(
            policy_id="https-body-bound",
            secret_refs=["secret://default/api"],
            allowed_consumers=["https-test"],
            allowed_purposes=["use-secret"],
            allowed_delivery_modes=[DeliveryMode.BROKERED_HTTP],
            allowed_http_hosts=["127.0.0.1:9"],
            require_https_for_brokered_http=True,
            max_http_request_body_bytes=4,
        )
    )
    broker = LocalBroker(store=store, vault=vault)

    try:
        broker.brokered_http_request(
            secret_ref="secret://default/api",
            consumer="https-test",
            purpose="use-secret",
            method="POST",
            url="http://127.0.0.1:9/",
            body="abcd",
            passphrase="passphrase",
            timeout_seconds=0.1,
        )
    except PermissionError as exc:
        assert "matching allow policy" in str(exc)
    else:
        raise AssertionError("HTTPS requirement was not enforced")

    vault.create_policy(
        AccessPolicy(
            policy_id="body-bound",
            secret_refs=["secret://default/api"],
            allowed_consumers=["body-test"],
            allowed_purposes=["use-secret"],
            allowed_delivery_modes=[DeliveryMode.BROKERED_HTTP],
            allowed_http_hosts=["127.0.0.1:9"],
            max_http_request_body_bytes=4,
        )
    )
    try:
        broker.brokered_http_request(
            secret_ref="secret://default/api",
            consumer="body-test",
            purpose="use-secret",
            method="POST",
            url="http://127.0.0.1:9/",
            body="abcde",
            passphrase="passphrase",
            timeout_seconds=0.1,
        )
    except PermissionError as exc:
        assert "matching allow policy" in str(exc)
    else:
        raise AssertionError("request body size limit was not enforced")


def test_brokered_http_response_size_limit(tmp_path) -> None:
    class LargeResponseHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * 16)

        def log_message(self, format, *args):  # noqa: A002, ANN001
            return

    store, vault = _vault_with_policy(tmp_path, DeliveryMode.BROKERED_HTTP)
    broker = LocalBroker(store=store, vault=vault)
    server = ThreadingHTTPServer(("127.0.0.1", 0), LargeResponseHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            broker.brokered_http_request(
                secret_ref="secret://default/api",
                consumer="broker-test",
                purpose="use-secret",
                method="GET",
                url=f"http://127.0.0.1:{server.server_port}/",
                passphrase="passphrase",
                max_response_bytes=8,
            )
        except PermissionError as exc:
            assert "response body too large" in str(exc)
        else:
            raise AssertionError("response size limit was not enforced")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_broker_child_env_materialization_is_policy_enforced(tmp_path) -> None:
    store, vault = _vault_with_policy(tmp_path, DeliveryMode.CHILD_ENV)
    broker = LocalBroker(store=store, vault=vault)

    result = broker.run_with_env(
        secret_ref="secret://default/api",
        env_name="HBSE_TEST_SECRET",
        command=[
            sys.executable,
            "-c",
            "import os; print(os.environ['HBSE_TEST_SECRET'].replace('sk-', 'ok-'))",
        ],
        consumer="broker-test",
        purpose="use-secret",
        passphrase="passphrase",
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "ok-test"


def test_broker_pipe_materialization_returns_one_time_read_fd(tmp_path) -> None:
    store, vault = _vault_with_policy(tmp_path, DeliveryMode.PIPE)
    broker = LocalBroker(store=store, vault=vault)

    read_fd = broker.materialize_pipe(
        secret_ref="secret://default/api",
        consumer="broker-test",
        purpose="use-secret",
        passphrase="passphrase",
    )
    try:
        assert os.read(read_fd, 64) == b"sk-test"
    finally:
        os.close(read_fd)


def test_temp_file_materialization_uses_0600_and_cleanup(tmp_path) -> None:
    store, vault = _vault_with_policy(tmp_path, DeliveryMode.TEMP_FILE)
    broker = LocalBroker(store=store, vault=vault)
    path = broker.materialize_temp_file(
        secret_ref="secret://default/api",
        consumer="broker-test",
        purpose="use-secret",
        passphrase="passphrase",
    )

    assert path.read_bytes() == b"sk-test"
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    Materializer().cleanup_temp_file(path)
    assert not path.exists()
