"""REST API surface for HBSE local/service integrations."""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from hbse.core.backup import create_backup, restore_backup
from hbse.core.broker import LocalBroker
from hbse.core.policy import AccessPolicy, AccessRequest, DeliveryMode, PolicyEngine
from hbse.core.provider_tpm2 import LinuxTPM2ToolsProvider
from hbse.core.recovery import RecoveryPackage
from hbse.core.store import SQLiteVaultStore, VaultNotInitialized, json_dumps_redacted
from hbse.core.tickets import TicketValidationError
from hbse.core.vault import LocalVault


class SecretPutRequest(BaseModel):
    secret_ref: str
    value: str
    passphrase: str | None = None


class RotationStartRequest(BaseModel):
    secret_ref: str
    value: str
    passphrase: str | None = None


class PolicyCreateRequest(BaseModel):
    policy_id: str
    secret_refs: list[str]
    allowed_consumers: list[str]
    allowed_purposes: list[str]
    allowed_delivery_modes: list[DeliveryMode]
    allowed_http_hosts: list[str] = Field(default_factory=list)
    denied_http_hosts: list[str] = Field(default_factory=list)
    allowed_http_methods: list[str] = Field(default_factory=list)
    denied_http_methods: list[str] = Field(default_factory=list)
    allowed_http_path_prefixes: list[str] = Field(default_factory=list)
    denied_http_path_prefixes: list[str] = Field(default_factory=list)
    require_https_for_brokered_http: bool = False
    max_http_request_body_bytes: int | None = Field(default=None, ge=0)
    allowed_os_uids: list[int] = Field(default_factory=list)
    denied_os_uids: list[int] = Field(default_factory=list)
    allowed_executable_paths: list[str] = Field(default_factory=list)
    denied_executable_paths: list[str] = Field(default_factory=list)
    allowed_executable_sha256: list[str] = Field(default_factory=list)
    denied_executable_sha256: list[str] = Field(default_factory=list)
    exportable: bool = False
    max_ticket_ttl_seconds: int = Field(default=60, ge=1, le=3600)
    max_uses: int = Field(default=1, ge=1, le=100)


class TicketIssueRequest(BaseModel):
    secret_ref: str
    consumer: str
    purpose: str
    delivery_mode: DeliveryMode
    passphrase: str | None = None
    raw_export_requested: bool = False


class MaterializeRequest(BaseModel):
    secret_ref: str
    consumer: str
    purpose: str
    delivery_mode: DeliveryMode = DeliveryMode.CALLBACK
    passphrase: str | None = None
    raw_export_requested: bool = False


class BrokeredHttpRequest(BaseModel):
    secret_ref: str
    consumer: str
    purpose: str
    method: str = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    passphrase: str | None = None
    credential_header: str = "Authorization"
    credential_prefix: str = "Bearer "
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    max_response_bytes: int = Field(default=10 * 1024 * 1024, gt=0, le=50 * 1024 * 1024)


class BackupRequest(BaseModel):
    destination: str


class RestoreRequest(BaseModel):
    source: str


class ProviderEnrollRequest(BaseModel):
    current_passphrase: str | None = None
    new_passphrase: str | None = None
    tpm_device: str = "/dev/tpmrm0"


class RecoveryCreateRequest(BaseModel):
    passphrase: str | None = None
    recovery_secret: str
    destination: str | None = None


class RecoveryUseRequest(BaseModel):
    package_path: str
    recovery_secret: str
    new_provider: str
    new_passphrase: str | None = None
    tpm_device: str = "/dev/tpmrm0"


class PassphraseRequest(BaseModel):
    passphrase: str | None = None


class SecretDestroyRequest(BaseModel):
    passphrase: str | None = None
    reason: str


class PolicyTestRequest(BaseModel):
    secret_ref: str
    consumer: str
    purpose: str
    delivery_mode: DeliveryMode
    provider_assurance: str = "A1"
    raw_export_requested: bool = False
    http_host: str | None = None
    http_scheme: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_request_body_bytes: int | None = None
    os_uid: int | None = None
    executable_path: str | None = None
    executable_sha256: str | None = None


def create_app(*, vault_path: str | Path, api_key: str | None = None) -> FastAPI:
    store = SQLiteVaultStore(vault_path)
    vault = LocalVault(store=store)
    broker = LocalBroker(store=store, vault=vault)
    expected_key = api_key or os.environ.get("HBSE_API_KEY")
    idempotency_cache: dict[str, dict[str, object]] = {}

    def require_auth(x_hbse_api_key: Annotated[str | None, Header()] = None) -> None:
        if expected_key and x_hbse_api_key != expected_key:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthorized")

    app = FastAPI(title="HBSE API", version="0.1.0", dependencies=[Depends(require_auth)])

    @app.middleware("http")
    async def request_id_middleware(request, call_next):
        response = await call_next(request)
        request_id = request.headers.get("X-Request-ID")
        if request_id:
            response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(PermissionError)
    def permission_error_handler(_request, exc: PermissionError):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": {"code": "DENY_POLICY", "message": f"policy denied: {exc}"}},
        )

    @app.exception_handler(TicketValidationError)
    def ticket_error_handler(_request, exc: TicketValidationError):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": {"code": "INVALID_TICKET", "message": f"ticket invalid: {exc}"}},
        )

    @app.exception_handler(ValueError)
    def value_error_handler(_request, exc: ValueError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": {"code": "INVALID_REQUEST", "message": str(exc)}},
        )

    @app.get("/v1/vault/status")
    def vault_status() -> dict[str, object]:
        try:
            return store.export_redacted()
        except VaultNotInitialized:
            return {"vault": {"initialized": False}, "secrets": []}

    @app.post("/v1/vault/backup")
    def vault_backup(
        request: BackupRequest,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, object]:
        return _idempotent(
            idempotency_cache,
            idempotency_key,
            lambda: create_backup(store, request.destination).__dict__,
        )

    @app.post("/v1/vault/restore")
    def vault_restore(request: RestoreRequest) -> dict[str, object]:
        manifest = restore_backup(request.source, store.path)
        return manifest.__dict__

    @app.post("/v1/vault/recovery-package")
    def vault_recovery_package(request: RecoveryCreateRequest) -> dict[str, object]:
        package = vault.create_recovery_package(
            passphrase=request.passphrase,
            recovery_secret=request.recovery_secret,
        )
        if request.destination:
            package.write(request.destination)
        return package.model_dump(mode="json")

    @app.post("/v1/vault/recover")
    def vault_recover(request: RecoveryUseRequest) -> dict[str, object]:
        package = RecoveryPackage.read(request.package_path)
        header = vault.recover_provider_from_package(
            package=package,
            recovery_secret=request.recovery_secret,
            new_provider=request.new_provider,
            new_passphrase=request.new_passphrase,
            tpm_device=request.tpm_device,
        )
        return {
            "vault_id": header.vault_id,
            "provider_id": header.provider_binding.get("provider_id"),
            "assurance_level": header.provider_binding.get("assurance_level"),
        }

    @app.post("/v1/vault/unlock")
    def vault_unlock(request: PassphraseRequest) -> dict[str, object]:
        # Stateless REST mode validates unlock but does not retain root material.
        vault.verify_audit(passphrase=request.passphrase)
        return {"unlocked": True, "mode": "stateless-validation"}

    @app.post("/v1/vault/lock")
    def vault_lock() -> dict[str, object]:
        return {"locked": True, "mode": "stateless-no-retained-root"}

    @app.get("/v1/secrets")
    def list_secrets() -> dict[str, object]:
        return {"secrets": [summary.__dict__ for summary in store.list_secrets()]}

    @app.get("/v1/secrets/{secret_ref:path}")
    def get_secret_metadata(secret_ref: str) -> dict[str, object]:
        ref = _decode_ref(secret_ref)
        record = store.load_latest_secret(ref)
        return {
            "secret_ref": record.secret_ref,
            "secret_id": record.secret_id,
            "namespace_id": record.namespace_id,
            "version": record.secret_version,
            "status": record.status.value,
            "secret_type": record.secret_type.value,
            "created_at": record.created_at.isoformat(),
        }

    @app.post("/v1/secrets")
    def put_secret(
        request: SecretPutRequest,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, object]:
        return _idempotent(
            idempotency_cache,
            idempotency_key,
            lambda: {
                "secret_ref": request.secret_ref,
                "version": vault.put_secret(
                    secret_ref=request.secret_ref,
                    plaintext=request.value.encode("utf-8"),
                    passphrase=request.passphrase,
                ),
            },
        )

    @app.post("/v1/secrets/{secret_ref:path}/rotate")
    def rotate_secret(secret_ref: str, request: SecretPutRequest) -> dict[str, object]:
        ref = _decode_ref(secret_ref)
        version = vault.put_secret(
            secret_ref=ref,
            plaintext=request.value.encode("utf-8"),
            passphrase=request.passphrase,
        )
        return {"secret_ref": ref, "version": version}

    @app.post("/v1/rotation/jobs")
    def rotation_start(request: RotationStartRequest) -> dict[str, object]:
        job = vault.start_rotation(
            secret_ref=request.secret_ref,
            new_plaintext=request.value.encode("utf-8"),
            passphrase=request.passphrase,
        )
        return job.model_dump(mode="json")

    @app.get("/v1/rotation/jobs")
    def rotation_list() -> dict[str, object]:
        return {"rotation_jobs": [json.loads(raw) for raw in store.list_rotation_job_json()]}

    @app.post("/v1/rotation/jobs/{job_id}/verify")
    def rotation_verify(job_id: str, request: PassphraseRequest) -> dict[str, object]:
        return vault.verify_rotation(job_id=job_id, passphrase=request.passphrase).model_dump(mode="json")

    @app.post("/v1/rotation/jobs/{job_id}/promote")
    def rotation_promote(job_id: str, request: PassphraseRequest) -> dict[str, object]:
        return vault.promote_rotation(job_id=job_id, passphrase=request.passphrase).model_dump(mode="json")

    @app.post("/v1/rotation/jobs/{job_id}/rollback")
    def rotation_rollback(job_id: str, request: PassphraseRequest) -> dict[str, object]:
        return vault.rollback_rotation(job_id=job_id, passphrase=request.passphrase).model_dump(mode="json")

    @app.post("/v1/secrets/{secret_ref:path}/disable")
    def disable_secret(secret_ref: str, request: PassphraseRequest) -> dict[str, object]:
        ref = _decode_ref(secret_ref)
        vault.disable_secret(secret_ref=ref, passphrase=request.passphrase)
        return {"secret_ref": ref, "status": "disabled"}

    @app.post("/v1/secrets/{secret_ref:path}/destroy")
    def destroy_secret(secret_ref: str, request: SecretDestroyRequest) -> dict[str, object]:
        ref = _decode_ref(secret_ref)
        vault.destroy_secret(secret_ref=ref, passphrase=request.passphrase, reason=request.reason)
        return {"secret_ref": ref, "status": "destroyed"}

    @app.post("/v1/policies")
    def create_policy(request: PolicyCreateRequest) -> dict[str, object]:
        policy = AccessPolicy(
            policy_id=request.policy_id,
            secret_refs=request.secret_refs,
            allowed_consumers=request.allowed_consumers,
            allowed_purposes=request.allowed_purposes,
            allowed_delivery_modes=request.allowed_delivery_modes,
            allowed_http_hosts=request.allowed_http_hosts,
            denied_http_hosts=request.denied_http_hosts,
            allowed_http_methods=request.allowed_http_methods,
            denied_http_methods=request.denied_http_methods,
            allowed_http_path_prefixes=request.allowed_http_path_prefixes,
            denied_http_path_prefixes=request.denied_http_path_prefixes,
            require_https_for_brokered_http=request.require_https_for_brokered_http,
            max_http_request_body_bytes=request.max_http_request_body_bytes,
            allowed_os_uids=request.allowed_os_uids,
            denied_os_uids=request.denied_os_uids,
            allowed_executable_paths=request.allowed_executable_paths,
            denied_executable_paths=request.denied_executable_paths,
            allowed_executable_sha256=request.allowed_executable_sha256,
            denied_executable_sha256=request.denied_executable_sha256,
            exportable=request.exportable,
            max_ticket_ttl_seconds=request.max_ticket_ttl_seconds,
            max_uses=request.max_uses,
        )
        vault.create_policy(policy)
        return {"policy_id": policy.policy_id}

    @app.post("/v1/policies/{policy_id}/test")
    def test_policy(policy_id: str, request: PolicyTestRequest) -> dict[str, object]:
        raw = store.load_policy_json(policy_id)
        if raw is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "policy not found")
        policy = AccessPolicy.model_validate_json(raw)
        result = PolicyEngine([policy]).evaluate(
            AccessRequest(
                secret_ref=request.secret_ref,
                consumer=request.consumer,
                purpose=request.purpose,
                delivery_mode=request.delivery_mode,
                provider_assurance=request.provider_assurance,
                raw_export_requested=request.raw_export_requested,
                http_host=request.http_host,
                http_scheme=request.http_scheme,
                http_method=request.http_method,
                http_path=request.http_path,
                http_request_body_bytes=request.http_request_body_bytes,
                os_uid=request.os_uid,
                executable_path=request.executable_path,
                executable_sha256=request.executable_sha256,
            )
        )
        return {"decision": result.decision.value, "reason": result.reason}

    @app.post("/v1/tickets")
    def issue_ticket(request: TicketIssueRequest) -> dict[str, object]:
        ticket = vault.issue_ticket(
            secret_ref=request.secret_ref,
            consumer=request.consumer,
            purpose=request.purpose,
            delivery_mode=request.delivery_mode,
            passphrase=request.passphrase,
            raw_export_requested=request.raw_export_requested,
        )
        return ticket.model_dump(mode="json")

    @app.get("/v1/tickets/{ticket_id}")
    def get_ticket(ticket_id: str) -> dict[str, object]:
        raw = store.load_ticket_json(ticket_id)
        if raw is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "ticket not found")
        return json.loads(raw)

    @app.post("/v1/tickets/{ticket_id}/consume")
    def consume_ticket(ticket_id: str, request: TicketIssueRequest) -> dict[str, object]:
        if request.delivery_mode in {DeliveryMode.RAW, DeliveryMode.TERMINAL_PRINT}:
            if not request.raw_export_requested:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "raw materialization requires explicit request")
        secret = vault.consume_ticket_for_secret(
            ticket_id=ticket_id,
            consumer=request.consumer,
            purpose=request.purpose,
            delivery_mode=request.delivery_mode,
            passphrase=request.passphrase,
        )
        return {"secret": secret.decode("utf-8")}

    @app.post("/v1/tickets/{ticket_id}/revoke")
    def revoke_ticket(ticket_id: str, request: PassphraseRequest) -> dict[str, object]:
        ticket = vault.revoke_ticket(ticket_id=ticket_id, passphrase=request.passphrase)
        return ticket.model_dump(mode="json")

    @app.post("/v1/materialize/callback")
    def materialize_callback(request: MaterializeRequest) -> dict[str, object]:
        if request.delivery_mode in {DeliveryMode.RAW, DeliveryMode.TERMINAL_PRINT}:
            if not request.raw_export_requested:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "raw materialization requires explicit request")
        secret = broker.materialize_bytes(
            secret_ref=request.secret_ref,
            consumer=request.consumer,
            purpose=request.purpose,
            delivery_mode=request.delivery_mode,
            passphrase=request.passphrase,
            raw_export_requested=request.raw_export_requested,
        )
        return {"secret": secret.decode("utf-8")}

    @app.post("/v1/materialize/pipe")
    def materialize_pipe(request: MaterializeRequest) -> StreamingResponse:
        secret = broker.materialize_bytes(
            secret_ref=request.secret_ref,
            consumer=request.consumer,
            purpose=request.purpose,
            delivery_mode=DeliveryMode.PIPE,
            passphrase=request.passphrase,
            raw_export_requested=False,
        )
        return StreamingResponse(iter([secret]), media_type="application/octet-stream")

    @app.post("/v1/provider-gateway/http")
    def brokered_http(request: BrokeredHttpRequest) -> dict[str, object]:
        response = broker.brokered_http_request(
            secret_ref=request.secret_ref,
            consumer=request.consumer,
            purpose=request.purpose,
            method=request.method,
            url=request.url,
            headers=request.headers,
            body=request.body,
            passphrase=request.passphrase,
            credential_header=request.credential_header,
            credential_prefix=request.credential_prefix,
            timeout_seconds=request.timeout_seconds,
            max_response_bytes=request.max_response_bytes,
        )
        return {
            "status_code": response.status_code,
            "headers": response.headers,
            "body": response.body,
            "redacted": response.redacted,
        }

    @app.get("/v1/providers")
    def providers() -> dict[str, object]:
        tpm2 = LinuxTPM2ToolsProvider().detect()
        return {"providers": [tpm2.__dict__]}

    @app.post("/v1/providers/{provider_id}/test")
    def provider_test(provider_id: str) -> dict[str, object]:
        if provider_id != "tpm2":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "provider not found")
        status_doc = LinuxTPM2ToolsProvider().self_test()
        return status_doc.__dict__

    @app.post("/v1/providers/{provider_id}/enroll")
    def provider_enroll(provider_id: str, request: ProviderEnrollRequest) -> dict[str, object]:
        if provider_id not in {"passphrase", "tpm2"}:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "provider not found")
        header = vault.rewrap_provider(
            current_passphrase=request.current_passphrase,
            new_provider=provider_id,
            new_passphrase=request.new_passphrase,
            tpm_device=request.tpm_device,
        )
        return {
            "vault_id": header.vault_id,
            "provider_id": header.provider_binding.get("provider_id"),
            "assurance_level": header.provider_binding.get("assurance_level"),
        }

    @app.get("/v1/audit")
    def audit_query() -> dict[str, object]:
        return {"events": [json.loads(raw) for raw in store.list_audit_event_json()]}

    @app.post("/v1/audit/verify")
    def audit_verify(passphrase: str | None = None) -> dict[str, object]:
        vault.verify_audit(passphrase=passphrase)
        return {"audit": "ok"}

    @app.get("/v1/doctor")
    def doctor() -> dict[str, object]:
        try:
            status_doc = store.export_redacted()
            return {"checks": {"vault": "initialized"}, "status": status_doc}
        except VaultNotInitialized:
            return {"checks": {"vault": "not_initialized"}}

    return app


def _decode_ref(value: str) -> str:
    return value if value.startswith("secret://") else f"secret://{value}"


def _idempotent(
    cache: dict[str, dict[str, object]],
    key: str | None,
    compute,
) -> dict[str, object]:
    if not key:
        return compute()
    if key not in cache:
        cache[key] = compute()
    return cache[key]


def app_from_env() -> FastAPI:
    path = os.environ.get("HBSE_VAULT_PATH", str(Path.home() / ".local/share/hbse/vault.db"))
    return create_app(vault_path=path)
