"""Local broker facade for policy-enforced materialization."""

from __future__ import annotations

import base64
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from hbse.core.materialization import Materializer
from hbse.core.policy import DeliveryMode
from hbse.core.store import SQLiteVaultStore
from hbse.core.tickets import SecretAccessTicket
from hbse.core.vault import LocalVault


@dataclass(frozen=True)
class BrokeredHttpResponse:
    """Provider-gateway response with HBSE-managed secret material removed."""

    status_code: int
    headers: dict[str, str]
    body: str
    redacted: bool = False


@dataclass
class LocalBroker:
    """Synchronous local broker facade.

    It centralizes the access flow so CLI, SDK, REST, and IPC paths use one
    policy/ticket/audit sequence.
    """

    store: SQLiteVaultStore
    vault: LocalVault
    materializer: Materializer = field(default_factory=Materializer)

    def checkout(
        self,
        *,
        secret_ref: str,
        consumer: str,
        purpose: str,
        delivery_mode: DeliveryMode,
        passphrase: str | None,
        url: str | None = None,
        method: str | None = None,
        os_uid: int | None = None,
        executable_path: str | None = None,
        executable_sha256: str | None = None,
    ) -> SecretAccessTicket:
        http_host: str | None = None
        http_scheme: str | None = None
        http_method: str | None = None
        http_path: str | None = None
        http_request_body_bytes: int | None = None
        if delivery_mode == DeliveryMode.BROKERED_HTTP:
            if url is None or method is None:
                raise ValueError("brokered_http checkout requires URL and method")
            parsed_url = _parse_http_url(url)
            http_host = parsed_url.host
            http_scheme = parsed_url.scheme
            http_method = method.upper()
            http_path = parsed_url.path
            http_request_body_bytes = 0
        return self.vault.issue_ticket(
            secret_ref=secret_ref,
            consumer=consumer,
            purpose=purpose,
            delivery_mode=delivery_mode,
            passphrase=passphrase,
            raw_export_requested=False,
            http_host=http_host,
            http_scheme=http_scheme,
            http_method=http_method,
            http_path=http_path,
            http_request_body_bytes=http_request_body_bytes,
            os_uid=os_uid,
            executable_path=executable_path,
            executable_sha256=executable_sha256,
        )

    def materialize_bytes(
        self,
        *,
        secret_ref: str,
        consumer: str,
        purpose: str,
        delivery_mode: DeliveryMode,
        passphrase: str | None,
        raw_export_requested: bool = False,
        http_host: str | None = None,
        http_scheme: str | None = None,
        http_method: str | None = None,
        http_path: str | None = None,
        http_request_body_bytes: int | None = None,
        os_uid: int | None = None,
        executable_path: str | None = None,
        executable_sha256: str | None = None,
    ) -> bytes:
        ticket = self.vault.issue_ticket(
            secret_ref=secret_ref,
            consumer=consumer,
            purpose=purpose,
            delivery_mode=delivery_mode,
            passphrase=passphrase,
            raw_export_requested=raw_export_requested,
            http_host=http_host,
            http_scheme=http_scheme,
            http_method=http_method,
            http_path=http_path,
            http_request_body_bytes=http_request_body_bytes,
            os_uid=os_uid,
            executable_path=executable_path,
            executable_sha256=executable_sha256,
        )
        return self.vault.consume_ticket_for_secret(
            ticket_id=ticket.ticket_id,
            consumer=consumer,
            purpose=purpose,
            delivery_mode=delivery_mode,
            passphrase=passphrase,
            http_host=http_host,
            http_scheme=http_scheme,
            http_method=http_method,
            http_path=http_path,
            http_request_body_bytes=http_request_body_bytes,
            os_uid=os_uid,
            executable_path=executable_path,
            executable_sha256=executable_sha256,
        )

    def brokered_http_request(
        self,
        *,
        secret_ref: str,
        consumer: str,
        purpose: str,
        method: str,
        url: str,
        passphrase: str | None,
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
        credential_header: str = "Authorization",
        credential_prefix: str = "Bearer ",
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 10 * 1024 * 1024,
        os_uid: int | None = None,
        executable_path: str | None = None,
        executable_sha256: str | None = None,
    ) -> BrokeredHttpResponse:
        """Facilitate one credential-bearing HTTP call without exposing the secret.

        The caller owns request construction and response interpretation. HBSE only
        authorizes secret use, injects the credential into the configured header,
        forwards the request, audits the materialization path, and redacts
        HBSE-managed secret material from the returned response.
        """

        parsed_url = _parse_http_url(url)
        http_method = method.upper()
        request_body = body.encode("utf-8") if isinstance(body, str) else body
        request_body_bytes = 0 if request_body is None else len(request_body)
        secret = self.materialize_bytes(
            secret_ref=secret_ref,
            consumer=consumer,
            purpose=purpose,
            delivery_mode=DeliveryMode.BROKERED_HTTP,
            passphrase=passphrase,
            raw_export_requested=False,
            http_host=parsed_url.host,
            http_scheme=parsed_url.scheme,
            http_method=http_method,
            http_path=parsed_url.path,
            http_request_body_bytes=request_body_bytes,
            os_uid=os_uid,
            executable_path=executable_path,
            executable_sha256=executable_sha256,
        )
        request_headers = dict(headers or {})
        _assert_no_secret_leak(
            secret=secret,
            values=[url, *(f"{key}: {value}" for key, value in request_headers.items())],
            body=request_body,
        )
        request_headers[credential_header] = credential_prefix + secret.decode("utf-8")
        request = Request(
            url=url,
            data=request_body,
            headers=request_headers,
            method=http_method,
        )
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                status_code = int(response.status)
                response_headers = dict(response.headers.items())
                response_body = _read_limited(response, max_response_bytes)
        except HTTPError as exc:
            status_code = int(exc.code)
            response_headers = dict(exc.headers.items())
            response_body = _read_limited(exc, max_response_bytes)
        redacted_body, body_changed = _redact_known_secret(response_body.decode("utf-8", "replace"), secret)
        redacted_headers: dict[str, str] = {}
        headers_changed = False
        for key, value in response_headers.items():
            redacted_value, changed = _redact_known_secret(value, secret)
            redacted_headers[key] = redacted_value
            headers_changed = headers_changed or changed
        return BrokeredHttpResponse(
            status_code=status_code,
            headers=redacted_headers,
            body=redacted_body,
            redacted=body_changed or headers_changed,
        )

    def materialize_pipe(
        self,
        *,
        secret_ref: str,
        consumer: str,
        purpose: str,
        passphrase: str | None,
    ) -> int:
        secret = self.materialize_bytes(
            secret_ref=secret_ref,
            consumer=consumer,
            purpose=purpose,
            delivery_mode=DeliveryMode.PIPE,
            passphrase=passphrase,
        )
        read_fd, _ = self.materializer.to_pipe(secret)
        return read_fd

    def materialize_temp_file(
        self,
        *,
        secret_ref: str,
        consumer: str,
        purpose: str,
        passphrase: str | None,
    ) -> Path:
        secret = self.materialize_bytes(
            secret_ref=secret_ref,
            consumer=consumer,
            purpose=purpose,
            delivery_mode=DeliveryMode.TEMP_FILE,
            passphrase=passphrase,
        )
        return self.materializer.to_temp_file(secret)

    def run_with_env(
        self,
        *,
        secret_ref: str,
        env_name: str,
        command: list[str],
        consumer: str,
        purpose: str,
        passphrase: str | None,
    ) -> subprocess.CompletedProcess[str]:
        secret = self.materialize_bytes(
            secret_ref=secret_ref,
            consumer=consumer,
            purpose=purpose,
            delivery_mode=DeliveryMode.CHILD_ENV,
            passphrase=passphrase,
        )
        return self.materializer.run_child_env(
            secret=secret,
            env_name=env_name,
            command=command,
        )

    def run_with_env_refs(
        self,
        *,
        refs: dict[str, str],
        plain_env: dict[str, str],
        command: list[str],
        consumer: str,
        purpose: str,
        passphrase: str | None,
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update(plain_env)
        for env_name, secret_ref in refs.items():
            secret = self.materialize_bytes(
                secret_ref=secret_ref,
                consumer=consumer,
                purpose=purpose,
                delivery_mode=DeliveryMode.CHILD_ENV,
                passphrase=passphrase,
            )
            env[env_name] = secret.decode("utf-8")
        return subprocess.run(command, env=env, text=True, capture_output=True, check=False)

    @staticmethod
    def default_consumer() -> str:
        return f"local:{os.getuid()}:{os.getpid()}"


def _assert_no_secret_leak(*, secret: bytes, values: list[str], body: bytes | None) -> None:
    for value in values:
        if _contains_secret(value, secret):
            raise PermissionError("request contains HBSE-managed secret outside credential injection")
    if body is not None and _contains_secret(body.decode("utf-8", "replace"), secret):
        raise PermissionError("request body contains HBSE-managed secret")


def _contains_secret(value: str, secret: bytes) -> bool:
    return any(representation in value for representation in _secret_representations(secret))


def _redact_known_secret(value: str, secret: bytes) -> tuple[str, bool]:
    redacted = value
    for representation in sorted(_secret_representations(secret), key=len, reverse=True):
        redacted = redacted.replace(representation, "[REDACTED:hbse-secret]")
    return redacted, redacted != value


def _secret_representations(secret: bytes) -> set[str]:
    values = {
        base64.b64encode(secret).decode("ascii"),
        base64.urlsafe_b64encode(secret).decode("ascii").rstrip("="),
    }
    try:
        secret_text = secret.decode("utf-8")
        values.add(secret_text)
        values.add(quote(secret_text, safe=""))
    except UnicodeDecodeError:
        pass
    return {value for value in values if value}


@dataclass(frozen=True)
class _ParsedHttpUrl:
    scheme: str
    host: str
    path: str


def _parse_http_url(url: str) -> _ParsedHttpUrl:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("brokered HTTP URL must use http or https and include a host")
    host = parsed.hostname.lower()
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return _ParsedHttpUrl(scheme=parsed.scheme, host=host, path=path)


def _read_limited(response, max_bytes: int) -> bytes:  # noqa: ANN001
    data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise PermissionError("brokered HTTP response body too large")
    return data
