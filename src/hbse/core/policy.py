"""Deny-by-default policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class DeliveryMode(StrEnum):
    BROKERED_HTTP = "brokered_http"
    BROKERED_OPERATION = "brokered_operation"
    CALLBACK = "callback"
    PIPE = "pipe"
    FD = "fd"
    TEMP_FILE = "temp_file"
    CHILD_ENV = "child_env"
    RAW = "raw"
    TERMINAL_PRINT = "terminal_print"


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class AccessPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str
    secret_refs: list[str] = Field(default_factory=list)
    allowed_consumers: list[str] = Field(default_factory=list)
    denied_consumers: list[str] = Field(default_factory=list)
    allowed_purposes: list[str] = Field(default_factory=list)
    denied_purposes: list[str] = Field(default_factory=list)
    allowed_delivery_modes: list[DeliveryMode] = Field(default_factory=list)
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
    minimum_provider_assurance: str = "A1"
    expires_at: datetime | None = None


@dataclass(frozen=True)
class AccessRequest:
    secret_ref: str
    consumer: str
    purpose: str
    delivery_mode: DeliveryMode
    provider_assurance: str
    raw_export_requested: bool = False
    http_host: str | None = None
    http_scheme: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_request_body_bytes: int | None = None
    os_uid: int | None = None
    executable_path: str | None = None
    executable_sha256: str | None = None
    now: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class EvaluationResult:
    decision: PolicyDecision
    reason: str
    policy: AccessPolicy | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == PolicyDecision.ALLOW


class PolicyEngine:
    def __init__(self, policies: list[AccessPolicy] | None = None) -> None:
        self._policies = policies or []

    def evaluate(self, request: AccessRequest) -> EvaluationResult:
        for policy in self._policies:
            result = self._evaluate_policy(policy, request)
            if result.decision == PolicyDecision.ALLOW:
                return result
        return EvaluationResult(PolicyDecision.DENY, "no matching allow policy")

    def _evaluate_policy(self, policy: AccessPolicy, request: AccessRequest) -> EvaluationResult:
        if request.secret_ref not in policy.secret_refs and "*" not in policy.secret_refs:
            return EvaluationResult(PolicyDecision.DENY, "secret reference not covered", policy)
        if policy.expires_at and request.now > policy.expires_at.astimezone(UTC):
            return EvaluationResult(PolicyDecision.DENY, "policy expired", policy)
        if request.consumer in policy.denied_consumers:
            return EvaluationResult(PolicyDecision.DENY, "consumer explicitly denied", policy)
        if request.purpose in policy.denied_purposes:
            return EvaluationResult(PolicyDecision.DENY, "purpose explicitly denied", policy)
        if request.consumer not in policy.allowed_consumers and "*" not in policy.allowed_consumers:
            return EvaluationResult(PolicyDecision.DENY, "consumer not allowed", policy)
        if request.purpose not in policy.allowed_purposes and "*" not in policy.allowed_purposes:
            return EvaluationResult(PolicyDecision.DENY, "purpose not allowed", policy)
        if request.delivery_mode not in policy.allowed_delivery_modes:
            return EvaluationResult(PolicyDecision.DENY, "delivery mode not allowed", policy)
        if request.os_uid in policy.denied_os_uids:
            return EvaluationResult(PolicyDecision.DENY, "OS user explicitly denied", policy)
        if policy.allowed_os_uids and request.os_uid not in policy.allowed_os_uids:
            return EvaluationResult(PolicyDecision.DENY, "OS user not allowed", policy)
        if request.executable_path in policy.denied_executable_paths:
            return EvaluationResult(PolicyDecision.DENY, "executable path explicitly denied", policy)
        if policy.allowed_executable_paths and request.executable_path not in policy.allowed_executable_paths:
            return EvaluationResult(PolicyDecision.DENY, "executable path not allowed", policy)
        if request.executable_sha256 in policy.denied_executable_sha256:
            return EvaluationResult(PolicyDecision.DENY, "executable hash explicitly denied", policy)
        if policy.allowed_executable_sha256 and request.executable_sha256 not in policy.allowed_executable_sha256:
            return EvaluationResult(PolicyDecision.DENY, "executable hash not allowed", policy)
        if request.delivery_mode == DeliveryMode.BROKERED_HTTP:
            if request.http_host is None:
                return EvaluationResult(PolicyDecision.DENY, "HTTP host required for brokered_http", policy)
            if policy.require_https_for_brokered_http and request.http_scheme != "https":
                return EvaluationResult(PolicyDecision.DENY, "HTTPS required for brokered_http", policy)
            if request.http_host in policy.denied_http_hosts:
                return EvaluationResult(PolicyDecision.DENY, "HTTP host explicitly denied", policy)
            if policy.allowed_http_hosts and request.http_host not in policy.allowed_http_hosts and "*" not in policy.allowed_http_hosts:
                return EvaluationResult(PolicyDecision.DENY, "HTTP host not allowed", policy)
            if request.http_method is None:
                return EvaluationResult(PolicyDecision.DENY, "HTTP method required for brokered_http", policy)
            method = request.http_method.upper()
            allowed_methods = [item.upper() for item in policy.allowed_http_methods]
            denied_methods = [item.upper() for item in policy.denied_http_methods]
            if method in denied_methods:
                return EvaluationResult(PolicyDecision.DENY, "HTTP method explicitly denied", policy)
            if allowed_methods and method not in allowed_methods and "*" not in allowed_methods:
                return EvaluationResult(PolicyDecision.DENY, "HTTP method not allowed", policy)
            if request.http_path is None:
                return EvaluationResult(PolicyDecision.DENY, "HTTP path required for brokered_http", policy)
            if any(request.http_path.startswith(prefix) for prefix in policy.denied_http_path_prefixes):
                return EvaluationResult(PolicyDecision.DENY, "HTTP path explicitly denied", policy)
            if policy.allowed_http_path_prefixes and not any(
                request.http_path.startswith(prefix) for prefix in policy.allowed_http_path_prefixes
            ):
                return EvaluationResult(PolicyDecision.DENY, "HTTP path not allowed", policy)
            if (
                policy.max_http_request_body_bytes is not None
                and request.http_request_body_bytes is not None
                and request.http_request_body_bytes > policy.max_http_request_body_bytes
            ):
                return EvaluationResult(PolicyDecision.DENY, "HTTP request body too large", policy)
        if request.raw_export_requested and not policy.exportable:
            return EvaluationResult(PolicyDecision.DENY, "raw export not allowed", policy)
        if _assurance_rank(request.provider_assurance) < _assurance_rank(policy.minimum_provider_assurance):
            return EvaluationResult(PolicyDecision.DENY, "provider assurance too low", policy)
        return EvaluationResult(PolicyDecision.ALLOW, "allowed", policy)


def _assurance_rank(level: str) -> int:
    order = {"A0": 0, "A1": 1, "A2": 2, "A3": 3, "A4": 4, "A5": 5}
    return order.get(level, -1)
