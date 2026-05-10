from __future__ import annotations

from pathlib import Path


def test_grpc_proto_contract_contains_required_services_and_rpcs() -> None:
    proto = Path("proto/hbse/v1/hbse.proto").read_text(encoding="utf-8")

    for service in [
        "VaultService",
        "SecretService",
        "RotationService",
        "TicketService",
        "PolicyService",
        "ProviderService",
        "AuditService",
        "MaterializationService",
        "DiagnosticsService",
    ]:
        assert f"service {service}" in proto

    for rpc in [
        "rpc Status",
        "rpc Backup",
        "rpc Restore",
        "rpc Recover",
        "rpc Create",
        "rpc Rotate",
        "rpc Start",
        "rpc Verify",
        "rpc Promote",
        "rpc Rollback",
        "rpc Consume",
        "rpc Revoke",
        "rpc OpenPipe",
    ]:
        assert rpc in proto
