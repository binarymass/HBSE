"""HBSE MVP command-line interface."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from hbse.core.backup import create_backup, restore_backup
from hbse.core.broker import LocalBroker
from hbse.core.dotenv import parse_dotenv, scan_dotenv, split_dotenv_values
from hbse.core.models import SecretType
from hbse.core.policy import AccessPolicy, DeliveryMode
from hbse.core.provider import ProviderUnlockFailed
from hbse.core.provider import PASSPHRASE_PROVIDER_ID
from hbse.core.provider_tpm2 import LinuxTPM2ToolsProvider, TPM2ProviderError, TPM2_PROVIDER_ID
from hbse.core.store import (
    SecretNotFound,
    SQLiteVaultStore,
    VaultAlreadyInitialized,
    VaultNotInitialized,
    json_dumps_redacted,
)
from hbse.core.readiness import check_local_readiness
from hbse.core.recovery import RecoveryPackage
from hbse.core.release import (
    generate_release_evidence,
    generate_signing_keypair,
    sign_release_artifacts,
    verify_release_evidence,
)
from hbse.core.systemd import install_broker_service
from hbse.core.vault import LocalVault
from hbse.core.tickets import TicketValidationError


def default_store_path() -> Path:
    return Path(os.environ.get("HBSE_VAULT_PATH", Path.home() / ".local/share/hbse/vault.db"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hbse")
    parser.add_argument("--vault", type=Path, default=default_store_path(), help="Vault database path")
    parser.add_argument("--json", action="store_true", help="Emit redacted JSON where supported")
    subcommands = parser.add_subparsers(dest="top_command", required=True)

    vault = subcommands.add_parser("vault")
    vault_sub = vault.add_subparsers(dest="vault_command", required=True)
    vault_init = vault_sub.add_parser("init")
    vault_init.add_argument("--namespace", default="default")
    vault_init.add_argument("--provider", choices=["passphrase", "tpm2"], default="passphrase")
    vault_init.add_argument("--tpm-device", default="/dev/tpmrm0")
    vault_sub.add_parser("status")
    vault_backup = vault_sub.add_parser("backup")
    vault_backup.add_argument("destination", type=Path)
    vault_restore = vault_sub.add_parser("restore")
    vault_restore.add_argument("source", type=Path)
    recovery_create = vault_sub.add_parser("recovery-create")
    recovery_create.add_argument("destination", type=Path)
    recovery_use = vault_sub.add_parser("recover")
    recovery_use.add_argument("package", type=Path)
    recovery_use.add_argument("--new-provider", choices=["passphrase", "tpm2"], required=True)
    recovery_use.add_argument("--new-passphrase")
    recovery_use.add_argument("--tpm-device", default="/dev/tpmrm0")

    secret = subcommands.add_parser("secret")
    secret_sub = secret.add_subparsers(dest="secret_command", required=True)
    secret_put = secret_sub.add_parser("put")
    secret_put.add_argument("ref")
    secret_put.add_argument("--type", choices=[item.value for item in SecretType], default=SecretType.GENERIC.value)
    secret_put.add_argument("--value", help="Secret value. Prefer stdin or prompt for real use.")
    secret_put.add_argument("--stdin", action="store_true", help="Read secret value from stdin")
    secret_sub.add_parser("list")
    secret_inspect = secret_sub.add_parser("inspect")
    secret_inspect.add_argument("ref")
    secret_rotate = secret_sub.add_parser("rotate")
    secret_rotate.add_argument("ref")
    secret_rotate.add_argument("--value", help="New secret value. Prefer stdin or prompt for real use.")
    secret_rotate.add_argument("--stdin", action="store_true", help="Read new secret value from stdin")
    secret_disable = secret_sub.add_parser("disable")
    secret_disable.add_argument("ref")
    secret_destroy = secret_sub.add_parser("destroy")
    secret_destroy.add_argument("ref")
    secret_destroy.add_argument("--reason", required=True)
    secret_get = secret_sub.add_parser("get")
    secret_get.add_argument("ref")
    secret_get.add_argument("--raw", action="store_true", help="Print the raw secret value")
    secret_get.add_argument("--allow-secret-output", action="store_true", help="Required with --raw")
    secret_get.add_argument("--reason", help="Reason for raw output")

    rotation = subcommands.add_parser("rotation")
    rotation_sub = rotation.add_subparsers(dest="rotation_command", required=True)
    rotation_start = rotation_sub.add_parser("start")
    rotation_start.add_argument("ref")
    rotation_start.add_argument("--value")
    rotation_start.add_argument("--stdin", action="store_true")
    rotation_verify = rotation_sub.add_parser("verify")
    rotation_verify.add_argument("job_id")
    rotation_promote = rotation_sub.add_parser("promote")
    rotation_promote.add_argument("job_id")
    rotation_rollback = rotation_sub.add_parser("rollback")
    rotation_rollback.add_argument("job_id")
    rotation_sub.add_parser("list")

    policy = subcommands.add_parser("policy")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    policy_create = policy_sub.add_parser("create")
    policy_create.add_argument("policy_id")
    policy_create.add_argument("--secret-ref", required=True)
    policy_create.add_argument("--consumer", default="cli")
    policy_create.add_argument("--purpose", required=True)
    policy_create.add_argument(
        "--delivery-mode",
        choices=[item.value for item in DeliveryMode],
        default=DeliveryMode.TERMINAL_PRINT.value,
    )
    policy_create.add_argument("--exportable", action="store_true")
    policy_create.add_argument("--ttl", type=int, default=60)
    policy_create.add_argument("--max-uses", type=int, default=1)
    policy_create.add_argument("--http-host", action="append", default=[])
    policy_create.add_argument("--http-method", action="append", default=[])
    policy_create.add_argument("--http-path-prefix", action="append", default=[])
    policy_create.add_argument("--require-https", action="store_true")
    policy_create.add_argument("--max-http-request-body-bytes", type=int)
    policy_create.add_argument("--os-uid", action="append", type=int, default=[])
    policy_create.add_argument("--executable-path", action="append", default=[])
    policy_create.add_argument("--executable-sha256", action="append", default=[])

    ticket = subcommands.add_parser("ticket")
    ticket_sub = ticket.add_subparsers(dest="ticket_command", required=True)
    ticket_sub.add_parser("list")
    ticket_inspect = ticket_sub.add_parser("inspect")
    ticket_inspect.add_argument("ticket_id")
    ticket_issue = ticket_sub.add_parser("issue")
    ticket_issue.add_argument("ref")
    ticket_issue.add_argument("--consumer", default="cli")
    ticket_issue.add_argument("--purpose", required=True)
    ticket_issue.add_argument(
        "--delivery-mode",
        choices=[item.value for item in DeliveryMode],
        default=DeliveryMode.TERMINAL_PRINT.value,
    )
    ticket_issue.add_argument("--raw-export", action="store_true")
    ticket_revoke = ticket_sub.add_parser("revoke")
    ticket_revoke.add_argument("ticket_id")

    provider = subcommands.add_parser("provider")
    provider_sub = provider.add_subparsers(dest="provider_command", required=True)
    provider_detect = provider_sub.add_parser("detect")
    provider_detect.add_argument("--device", default="/dev/tpmrm0")
    provider_test = provider_sub.add_parser("test-tpm2")
    provider_test.add_argument("--device", default="/dev/tpmrm0")
    provider_enroll = provider_sub.add_parser("enroll")
    provider_enroll.add_argument("provider_id", choices=["passphrase", "tpm2"])
    provider_enroll.add_argument("--new-passphrase")
    provider_enroll.add_argument("--tpm-device", default="/dev/tpmrm0")

    audit = subcommands.add_parser("audit")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_list = audit_sub.add_parser("list")
    audit_list.add_argument("--limit", type=int)
    audit_list.add_argument("--event-type")
    audit_export = audit_sub.add_parser("export")
    audit_export.add_argument("destination", type=Path)
    audit_export.add_argument("--event-type")
    audit_sub.add_parser("verify")

    readiness = subcommands.add_parser("readiness")
    readiness_sub = readiness.add_subparsers(dest="readiness_command", required=True)
    readiness_check = readiness_sub.add_parser("check")
    readiness_check.add_argument("--target", default="A2", choices=["A1", "A2", "A3", "A4", "A5"])
    readiness_check.add_argument("--release-dir", default="release")
    readiness_check.add_argument("--verify-audit", action="store_true")

    release = subcommands.add_parser("release")
    release_sub = release.add_subparsers(dest="release_command", required=True)
    release_keygen = release_sub.add_parser("keygen")
    release_keygen.add_argument("--private-key", required=True, type=Path)
    release_keygen.add_argument("--public-key", required=True, type=Path)
    release_keygen.add_argument("--encrypted", action="store_true")
    release_evidence = release_sub.add_parser("evidence")
    release_evidence.add_argument("--output-dir", default="release")
    release_evidence.add_argument("--project-root", default=".")
    release_evidence.add_argument("--version", default="0.1.0")
    release_sign = release_sub.add_parser("sign")
    release_sign.add_argument("--release-dir", default="release")
    release_sign.add_argument("--private-key", required=True, type=Path)
    release_sign.add_argument("--public-key-out", type=Path)
    release_sign.add_argument("--key-passphrase-env", default="HBSE_RELEASE_KEY_PASSPHRASE")
    release_sign.add_argument("--artifact", action="append", default=[])
    release_sign.add_argument("--version", default="0.1.0")
    release_proto = release_sub.add_parser("export-proto")
    release_proto.add_argument("--output-dir", default="release/proto")
    release_proto.add_argument("--project-root", default=".")
    release_verify = release_sub.add_parser("verify")
    release_verify.add_argument("--release-dir", default="release")
    release_verify.add_argument("--public-key", type=Path)

    api = subcommands.add_parser("api")
    api_sub = api.add_subparsers(dest="api_command", required=True)
    api_serve = api_sub.add_parser("serve")
    api_serve.add_argument("--host", default="127.0.0.1")
    api_serve.add_argument("--port", type=int, default=8765)
    api_serve.add_argument("--api-key")
    api_export = api_sub.add_parser("export-openapi")
    api_export.add_argument("destination", type=Path)

    dotenv = subcommands.add_parser("dotenv")
    dotenv_sub = dotenv.add_subparsers(dest="dotenv_command", required=True)
    dotenv_scan = dotenv_sub.add_parser("scan")
    dotenv_scan.add_argument("path", type=Path)
    dotenv_run = dotenv_sub.add_parser("run")
    dotenv_run.add_argument("path", type=Path)
    dotenv_run.add_argument("--consumer", default="cli")
    dotenv_run.add_argument("--purpose", required=True)
    dotenv_run.add_argument("command", nargs=argparse.REMAINDER)

    run = subcommands.add_parser("run")
    run.add_argument("--secret-ref", required=True)
    run.add_argument("--env", required=True, dest="env_name")
    run.add_argument("--consumer", default="cli")
    run.add_argument("--purpose", required=True)
    run.add_argument("child_command", nargs=argparse.REMAINDER)

    broker_cmd = subcommands.add_parser("broker")
    broker_sub = broker_cmd.add_subparsers(dest="broker_command", required=True)
    broker_serve = broker_sub.add_parser("serve")
    broker_serve.add_argument("--socket", required=True)
    broker_serve.add_argument("--idle-timeout-seconds", type=float, default=0)
    broker_install = broker_sub.add_parser("install-service")
    broker_install.add_argument("--scope", choices=["user", "system"], default="user")
    broker_install.add_argument("--unit-dir", type=Path)
    broker_install.add_argument("--socket")
    broker_install.add_argument("--idle-timeout-seconds", type=float, default=900)
    broker_install.add_argument("--broker-executable")
    broker_install.add_argument("--service-user")
    broker_install.add_argument("--enable", action="store_true")
    broker_install.add_argument("--start", action="store_true")
    broker_install.add_argument("--dry-run", action="store_true")
    broker_status = broker_sub.add_parser("status")
    broker_status.add_argument("--socket", required=True)
    broker_unlock = broker_sub.add_parser("unlock")
    broker_unlock.add_argument("--socket", required=True)
    broker_lock = broker_sub.add_parser("lock")
    broker_lock.add_argument("--socket", required=True)
    broker_checkout = broker_sub.add_parser("checkout")
    broker_checkout.add_argument("--socket", required=True)
    broker_checkout.add_argument("--secret-ref", required=True)
    broker_checkout.add_argument("--consumer", default="cli")
    broker_checkout.add_argument("--purpose", required=True)
    broker_checkout.add_argument(
        "--delivery-mode",
        choices=[item.value for item in DeliveryMode],
        default=DeliveryMode.CALLBACK.value,
    )
    broker_checkout.add_argument("--method")
    broker_checkout.add_argument("--url")
    broker_materialize = broker_sub.add_parser("materialize")
    broker_materialize.add_argument("--socket", required=True)
    broker_materialize.add_argument("--secret-ref", required=True)
    broker_materialize.add_argument("--consumer", default="cli")
    broker_materialize.add_argument("--purpose", required=True)
    broker_materialize.add_argument(
        "--delivery-mode",
        choices=[item.value for item in DeliveryMode],
        default=DeliveryMode.CALLBACK.value,
    )
    broker_materialize.add_argument("--raw-export", action="store_true")
    broker_http = broker_sub.add_parser("provider-http")
    broker_http.add_argument("--socket", required=True)
    broker_http.add_argument("--secret-ref", required=True)
    broker_http.add_argument("--consumer", default="cli")
    broker_http.add_argument("--purpose", required=True)
    broker_http.add_argument("--method", default="GET")
    broker_http.add_argument("--url", required=True)
    broker_http.add_argument("--header", action="append", default=[])
    broker_http.add_argument("--body")
    broker_http.add_argument("--credential-header", default="Authorization")
    broker_http.add_argument("--credential-prefix", default="Bearer ")
    broker_http.add_argument("--timeout-seconds", type=float, default=30.0)
    broker_http.add_argument("--max-response-bytes", type=int, default=10 * 1024 * 1024)

    subcommands.add_parser("doctor")
    lockdown = subcommands.add_parser("lockdown")
    lockdown.add_argument("--reason", default="local lockdown")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = SQLiteVaultStore(args.vault)
    vault = LocalVault(store=store)

    try:
        if args.top_command == "vault":
            return _handle_vault(args, store, vault)
        if args.top_command == "secret":
            return _handle_secret(args, store, vault)
        if args.top_command == "policy":
            return _handle_policy(args, store, vault)
        if args.top_command == "ticket":
            return _handle_ticket(args, vault)
        if args.top_command == "rotation":
            return _handle_rotation(args, store, vault)
        if args.top_command == "provider":
            return _handle_provider(args, vault)
        if args.top_command == "audit":
            return _handle_audit(args, vault)
        if args.top_command == "readiness":
            return _handle_readiness(args, store, vault)
        if args.top_command == "release":
            return _handle_release(args)
        if args.top_command == "api":
            return _handle_api(args, store)
        if args.top_command == "dotenv":
            return _handle_dotenv(args)
        if args.top_command == "run":
            return _handle_run(args, store, vault)
        if args.top_command == "broker":
            return _handle_broker(args, store)
        if args.top_command == "doctor":
            return _handle_doctor(store, args.json)
        if args.top_command == "lockdown":
            return _handle_lockdown(args, store, vault)
    except VaultNotInitialized as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except VaultAlreadyInitialized as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ProviderUnlockFailed as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    except SecretNotFound as exc:
        print(f"error: secret not found: {exc.args[0]}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"error: policy denied: {exc}", file=sys.stderr)
        return 3
    except TicketValidationError as exc:
        print(f"error: ticket invalid: {exc}", file=sys.stderr)
        return 6
    except TPM2ProviderError as exc:
        print(f"error: TPM2 provider failed: {exc}", file=sys.stderr)
        return 4
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1


def _handle_vault(args: argparse.Namespace, store: SQLiteVaultStore, vault: LocalVault) -> int:
    if args.vault_command == "init":
        passphrase = _read_new_passphrase() if args.provider == "passphrase" else None
        header = vault.init(
            passphrase=passphrase,
            namespace_id=args.namespace,
            provider_id=args.provider,
            tpm_device=args.tpm_device,
        )
        if args.json:
            print(json_dumps_redacted(store.export_redacted()))
        else:
            print(f"Initialized HBSE vault {header.vault_id}")
            provider_id = header.provider_binding.get("provider_id")
            assurance = header.provider_binding.get("assurance_level")
            print(f"Provider: {provider_id} ({assurance})")
        return 0

    if args.vault_command == "status":
        status = store.export_redacted()
        if args.json:
            print(json_dumps_redacted(status))
        else:
            vault_info = status["vault"]
            print(f"Vault: {vault_info['vault_id']}")
            print(f"Namespace: {vault_info['namespace_id']}")
            print(f"Provider: {vault_info['provider_id']} ({vault_info['assurance_level']})")
            print(f"Secrets: {len(status['secrets'])}")
        return 0
    if args.vault_command == "backup":
        manifest = create_backup(store, args.destination)
        if args.json:
            print(manifest.to_json())
        else:
            print(f"Backup created: {args.destination}")
            print(f"Vault: {manifest.vault_id}")
        return 0
    if args.vault_command == "restore":
        manifest = restore_backup(args.source, store.path)
        if args.json:
            print(manifest.to_json())
        else:
            print(f"Backup restored for vault {manifest.vault_id}")
        return 0
    if args.vault_command == "recovery-create":
        passphrase = _read_unlock_passphrase(store)
        recovery_secret = getpass.getpass("Recovery secret: ")
        package = vault.create_recovery_package(
            passphrase=passphrase,
            recovery_secret=recovery_secret,
        )
        package.write(args.destination)
        print(f"Recovery package created: {args.destination}")
        return 0
    if args.vault_command == "recover":
        package = RecoveryPackage.read(args.package)
        recovery_secret = getpass.getpass("Recovery secret: ")
        new_passphrase = args.new_passphrase
        if args.new_provider == "passphrase" and new_passphrase is None:
            new_passphrase = _read_new_passphrase()
        header = vault.recover_provider_from_package(
            package=package,
            recovery_secret=recovery_secret,
            new_provider=args.new_provider,
            new_passphrase=new_passphrase,
            tpm_device=args.tpm_device,
        )
        print(
            f"Recovered vault {header.vault_id} to provider "
            f"{header.provider_binding.get('provider_id')}"
        )
        return 0
    return 1


def _handle_secret(args: argparse.Namespace, store: SQLiteVaultStore, vault: LocalVault) -> int:
    if args.secret_command == "put":
        value = _read_secret_input(args)
        passphrase = _read_unlock_passphrase(store)
        version = vault.put_secret(
            secret_ref=args.ref,
            plaintext=value,
            passphrase=passphrase,
            secret_type=SecretType(args.type),
        )
        print(f"Stored {args.ref} version {version}")
        return 0

    if args.secret_command == "list":
        summaries = store.list_secrets()
        if args.json:
            print(json_dumps_redacted({"secrets": [summary.__dict__ for summary in summaries]}))
        else:
            for summary in summaries:
                print(f"{summary.secret_ref}\tversion={summary.latest_version}\tstatus={summary.status}")
        return 0

    if args.secret_command == "inspect":
        summary = store.load_secret_metadata(args.ref)
        print(json_dumps_redacted(summary.__dict__))
        return 0

    if args.secret_command == "rotate":
        value = _read_secret_input(args)
        passphrase = _read_unlock_passphrase(store)
        version = vault.put_secret(secret_ref=args.ref, plaintext=value, passphrase=passphrase)
        print(f"Rotated {args.ref} to version {version}")
        return 0

    if args.secret_command == "disable":
        passphrase = _read_unlock_passphrase(store)
        vault.disable_secret(secret_ref=args.ref, passphrase=passphrase)
        print(f"Disabled {args.ref}")
        return 0

    if args.secret_command == "destroy":
        passphrase = _read_unlock_passphrase(store)
        vault.destroy_secret(secret_ref=args.ref, passphrase=passphrase, reason=args.reason)
        print(f"Destroyed {args.ref}")
        return 0

    if args.secret_command == "get":
        if not (args.raw and args.allow_secret_output and args.reason):
            print(
                "Secret retrieval is denied by default. Use --raw --allow-secret-output --reason <text>.",
                file=sys.stderr,
            )
            return 3
        passphrase = _read_unlock_passphrase(store)
        ticket = vault.issue_ticket(
            secret_ref=args.ref,
            consumer="cli",
            purpose=args.reason,
            delivery_mode=DeliveryMode.TERMINAL_PRINT,
            passphrase=passphrase,
            raw_export_requested=True,
        )
        secret = vault.consume_ticket_for_secret(
            ticket_id=ticket.ticket_id,
            consumer="cli",
            purpose=args.reason,
            delivery_mode=DeliveryMode.TERMINAL_PRINT,
            passphrase=passphrase,
        )
        sys.stdout.buffer.write(secret)
        sys.stdout.buffer.write(b"\n")
        return 0
    return 1


def _handle_policy(args: argparse.Namespace, store: SQLiteVaultStore, vault: LocalVault) -> int:
    if args.policy_command == "create":
        policy = AccessPolicy(
            policy_id=args.policy_id,
            secret_refs=[args.secret_ref],
            allowed_consumers=[args.consumer],
            allowed_purposes=[args.purpose],
            allowed_delivery_modes=[DeliveryMode(args.delivery_mode)],
            allowed_http_hosts=args.http_host,
            allowed_http_methods=args.http_method,
            allowed_http_path_prefixes=args.http_path_prefix,
            require_https_for_brokered_http=args.require_https,
            max_http_request_body_bytes=args.max_http_request_body_bytes,
            allowed_os_uids=args.os_uid,
            allowed_executable_paths=args.executable_path,
            allowed_executable_sha256=args.executable_sha256,
            exportable=args.exportable,
            max_ticket_ttl_seconds=args.ttl,
            max_uses=args.max_uses,
            minimum_provider_assurance="A1",
        )
        vault.create_policy(policy)
        if args.json:
            print(policy.model_dump_json())
        else:
            print(f"Created policy {policy.policy_id}")
        return 0
    return 1


def _handle_ticket(args: argparse.Namespace, vault: LocalVault) -> int:
    if args.ticket_command == "list":
        tickets = [__import__("json").loads(raw) for raw in vault.store.list_ticket_json()]
        print(json_dumps_redacted({"tickets": tickets}))
        return 0
    if args.ticket_command == "inspect":
        raw = vault.store.load_ticket_json(args.ticket_id)
        if raw is None:
            raise TicketValidationError("ticket not found")
        print(json_dumps_redacted(__import__("json").loads(raw)))
        return 0
    if args.ticket_command == "issue":
        passphrase = _read_unlock_passphrase(vault.store)
        ticket = vault.issue_ticket(
            secret_ref=args.ref,
            consumer=args.consumer,
            purpose=args.purpose,
            delivery_mode=DeliveryMode(args.delivery_mode),
            passphrase=passphrase,
            raw_export_requested=args.raw_export,
        )
        print(ticket.model_dump_json())
        return 0
    if args.ticket_command == "revoke":
        passphrase = _read_unlock_passphrase(vault.store)
        ticket = vault.revoke_ticket(ticket_id=args.ticket_id, passphrase=passphrase)
        print(ticket.model_dump_json())
        return 0
    return 1


def _handle_rotation(args: argparse.Namespace, store: SQLiteVaultStore, vault: LocalVault) -> int:
    if args.rotation_command == "start":
        value = _read_secret_input(args)
        passphrase = _read_unlock_passphrase(store)
        job = vault.start_rotation(secret_ref=args.ref, new_plaintext=value, passphrase=passphrase)
        print(job.model_dump_json())
        return 0
    if args.rotation_command == "verify":
        passphrase = _read_unlock_passphrase(store)
        print(vault.verify_rotation(job_id=args.job_id, passphrase=passphrase).model_dump_json())
        return 0
    if args.rotation_command == "promote":
        passphrase = _read_unlock_passphrase(store)
        print(vault.promote_rotation(job_id=args.job_id, passphrase=passphrase).model_dump_json())
        return 0
    if args.rotation_command == "rollback":
        passphrase = _read_unlock_passphrase(store)
        print(vault.rollback_rotation(job_id=args.job_id, passphrase=passphrase).model_dump_json())
        return 0
    if args.rotation_command == "list":
        jobs = [__import__("json").loads(raw) for raw in store.list_rotation_job_json()]
        print(json_dumps_redacted({"rotation_jobs": jobs}))
        return 0
    return 1


def _handle_provider(args: argparse.Namespace, vault: LocalVault) -> int:
    if args.provider_command == "detect":
        status = LinuxTPM2ToolsProvider(device_path=args.device).detect()
        print(json_dumps_redacted(status.__dict__))
        return 0 if status.available else 4
    if args.provider_command == "test-tpm2":
        status = LinuxTPM2ToolsProvider(device_path=args.device).self_test()
        print(json_dumps_redacted(status.__dict__))
        return 0 if status.available else 4
    if args.provider_command == "enroll":
        current_passphrase = _read_unlock_passphrase(vault.store)
        new_passphrase = args.new_passphrase
        if args.provider_id == "passphrase" and new_passphrase is None:
            new_passphrase = _read_new_passphrase()
        header = vault.rewrap_provider(
            current_passphrase=current_passphrase,
            new_provider=args.provider_id,
            new_passphrase=new_passphrase,
            tpm_device=args.tpm_device,
        )
        print(
            f"Enrolled provider {header.provider_binding.get('provider_id')} "
            f"({header.provider_binding.get('assurance_level')})"
        )
        return 0
    return 1


def _handle_audit(args: argparse.Namespace, vault: LocalVault) -> int:
    if args.audit_command == "list":
        events = _load_audit_events(vault.store, event_type=args.event_type)
        if args.limit is not None:
            events = events[-args.limit :]
        print(json_dumps_redacted({"events": events}))
        return 0
    if args.audit_command == "export":
        events = _load_audit_events(vault.store, event_type=args.event_type)
        args.destination.parent.mkdir(parents=True, exist_ok=True)
        args.destination.write_text(json_dumps_redacted({"events": events}) + "\n", encoding="utf-8")
        print(f"Audit exported: {args.destination}")
        return 0
    if args.audit_command == "verify":
        passphrase = _read_unlock_passphrase(vault.store)
        vault.verify_audit(passphrase=passphrase)
        print("audit: ok")
        return 0
    return 1


def _load_audit_events(store: SQLiteVaultStore, event_type: str | None = None) -> list[dict[str, object]]:
    events = [__import__("json").loads(raw) for raw in store.list_audit_event_json()]
    if event_type:
        events = [event for event in events if event.get("event_type") == event_type]
    return events


def _handle_readiness(args: argparse.Namespace, store: SQLiteVaultStore, vault: LocalVault) -> int:
    passphrase = None
    if args.verify_audit:
        passphrase = _read_unlock_passphrase(store)
    report = check_local_readiness(
        store=store,
        vault=vault,
        passphrase=passphrase,
        release_dir=args.release_dir,
        target=args.target,
    )
    print(json_dumps_redacted(report.as_dict()))
    return 0 if report.passed else 1


def _handle_release(args: argparse.Namespace) -> int:
    if args.release_command == "keygen":
        passphrase = _read_new_release_key_passphrase() if args.encrypted else None
        result = generate_signing_keypair(
            private_key_path=args.private_key,
            public_key_path=args.public_key,
            passphrase=passphrase,
        )
        print(json_dumps_redacted(result))
        return 0
    if args.release_command == "evidence":
        evidence = generate_release_evidence(
            output_dir=args.output_dir,
            project_root=args.project_root,
            version=args.version,
        )
        print(
            json_dumps_redacted(
                {
                    "output_dir": str(evidence.output_dir),
                    "source_digest": evidence.source_digest,
                    "signature_mode": evidence.signature_mode,
                }
            )
        )
        return 0
    if args.release_command == "sign":
        passphrase = os.environ.get(args.key_passphrase_env)
        result = sign_release_artifacts(
            release_dir=args.release_dir,
            artifact_paths=args.artifact,
            private_key_path=args.private_key,
            public_key_path=args.public_key_out,
            key_passphrase=passphrase,
            version=args.version,
        )
        print(
            json_dumps_redacted(
                {
                    "mode": result["signature"]["mode"],
                    "manifest": result["signature"]["manifest"],
                    "public_key_sha256": result["signature"]["public_key_sha256"],
                    "artifact_count": len(result["manifest"]["artifacts"]),
                }
            )
        )
        return 0
    if args.release_command == "export-proto":
        source = Path(args.project_root) / "proto"
        destination = Path(args.output_dir)
        if destination.exists():
            import shutil

            shutil.rmtree(destination)
        import shutil

        shutil.copytree(source, destination)
        print(f"Proto contract exported: {destination}")
        return 0
    if args.release_command == "verify":
        verification = verify_release_evidence(
            release_dir=args.release_dir,
            public_key_path=args.public_key,
        )
        print(json_dumps_redacted(verification.as_dict()))
        return 0 if verification.passed else 1
    return 1


def _handle_api(args: argparse.Namespace, store: SQLiteVaultStore) -> int:
    if args.api_command == "serve":
        try:
            import uvicorn
        except ImportError:
            print("error: install the api extra to use hbse api serve", file=sys.stderr)
            return 2
        from hbse.api import create_app

        app = create_app(vault_path=store.path, api_key=args.api_key)
        uvicorn.run(app, host=args.host, port=args.port)
        return 0
    if args.api_command == "export-openapi":
        from hbse.api import create_app

        app = create_app(vault_path=store.path)
        args.destination.parent.mkdir(parents=True, exist_ok=True)
        args.destination.write_text(json_dumps_redacted(app.openapi()), encoding="utf-8")
        print(f"OpenAPI schema written: {args.destination}")
        return 0
    return 1


def _handle_dotenv(args: argparse.Namespace) -> int:
    if args.dotenv_command == "scan":
        findings = scan_dotenv(args.path)
        if not findings:
            print("dotenv: ok")
            return 0
        print(json_dumps_redacted({"findings": [finding.__dict__ for finding in findings]}))
        return 1 if any(finding.kind == "likely_raw_secret" for finding in findings) else 0
    if args.dotenv_command == "run":
        command = args.command[1:] if args.command and args.command[0] == "--" else args.command
        if not command:
            print("error: use hbse dotenv run <file> -- <command>", file=sys.stderr)
            return 2
        findings = scan_dotenv(args.path)
        raw_findings = [finding for finding in findings if finding.kind == "likely_raw_secret"]
        if raw_findings:
            print(json_dumps_redacted({"error": "raw secrets detected", "findings": [finding.__dict__ for finding in raw_findings]}), file=sys.stderr)
            return 8
        plain, refs = split_dotenv_values(parse_dotenv(args.path))
        passphrase = _read_unlock_passphrase(SQLiteVaultStore(args.vault))
        broker = LocalBroker(store=SQLiteVaultStore(args.vault), vault=LocalVault(store=SQLiteVaultStore(args.vault)))
        result = broker.run_with_env_refs(
            refs=refs,
            plain_env=plain,
            command=command,
            consumer=args.consumer,
            purpose=args.purpose,
            passphrase=passphrase,
        )
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return result.returncode
    return 1


def _handle_run(args: argparse.Namespace, store: SQLiteVaultStore, vault: LocalVault) -> int:
    command = (
        args.child_command[1:]
        if args.child_command and args.child_command[0] == "--"
        else args.child_command
    )
    if not command:
        print("error: use hbse run ... -- <command>", file=sys.stderr)
        return 2
    passphrase = _read_unlock_passphrase(store)
    broker = LocalBroker(store=store, vault=vault)
    result = broker.run_with_env(
        secret_ref=args.secret_ref,
        env_name=args.env_name,
        command=command,
        consumer=args.consumer,
        purpose=args.purpose,
        passphrase=passphrase,
    )
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result.returncode


def _handle_broker(args: argparse.Namespace, store: SQLiteVaultStore) -> int:
    from hbse import broker_daemon

    if args.broker_command == "serve":
        broker_daemon.serve(
            vault_path=store.path,
            socket_path=args.socket,
            idle_timeout_seconds=args.idle_timeout_seconds,
        )
        return 0
    if args.broker_command == "install-service":
        result = install_broker_service(
            scope=args.scope,
            unit_dir=args.unit_dir,
            broker_executable=args.broker_executable,
            vault_path=str(store.path),
            socket_path=args.socket,
            idle_timeout_seconds=args.idle_timeout_seconds,
            service_user=args.service_user,
            enable=args.enable,
            start=args.start,
            dry_run=args.dry_run,
        )
        print(json_dumps_redacted(result.__dict__))
        return 0
    if args.broker_command == "status":
        print(json_dumps_redacted(broker_daemon.request(args.socket, {"command": "status"})))
        return 0
    if args.broker_command == "unlock":
        passphrase = _read_unlock_passphrase(store)
        response = broker_daemon.request(args.socket, {"command": "unlock", "passphrase": passphrase})
        print(json_dumps_redacted(response))
        return 0 if response.get("ok") else 1
    if args.broker_command == "lock":
        response = broker_daemon.request(args.socket, {"command": "lock"})
        print(json_dumps_redacted(response))
        return 0 if response.get("ok") else 1
    if args.broker_command == "checkout":
        response = broker_daemon.request(
            args.socket,
            {
                "command": "checkout",
                "secret_ref": args.secret_ref,
                "consumer": args.consumer,
                "purpose": args.purpose,
                "delivery_mode": args.delivery_mode,
                "method": args.method,
                "url": args.url,
            },
        )
        print(json_dumps_redacted(response))
        return 0 if response.get("ok") else 1
    if args.broker_command == "materialize":
        response = broker_daemon.request(
            args.socket,
            {
                "command": "materialize",
                "secret_ref": args.secret_ref,
                "consumer": args.consumer,
                "purpose": args.purpose,
                "delivery_mode": args.delivery_mode,
                "raw_export_requested": args.raw_export,
            },
        )
        print(json_dumps_redacted(response))
        return 0 if response.get("ok") else 1
    if args.broker_command == "provider-http":
        response = broker_daemon.request(
            args.socket,
            {
                "command": "provider_http",
                "secret_ref": args.secret_ref,
                "consumer": args.consumer,
                "purpose": args.purpose,
                "method": args.method,
                "url": args.url,
                "headers": _parse_headers(args.header),
                "body": args.body,
                "credential_header": args.credential_header,
                "credential_prefix": args.credential_prefix,
                "timeout_seconds": args.timeout_seconds,
                "max_response_bytes": args.max_response_bytes,
            },
        )
        print(json_dumps_redacted(response))
        return 0 if response.get("ok") else 1
    return 1


def _parse_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values:
        if ":" not in value:
            raise ValueError("--header must use 'Name: value' format")
        key, header_value = value.split(":", 1)
        headers[key.strip()] = header_value.strip()
    return headers


def _handle_lockdown(args: argparse.Namespace, store: SQLiteVaultStore, vault: LocalVault) -> int:
    passphrase = _read_unlock_passphrase(store)
    count = vault.revoke_all_tickets(passphrase=passphrase, reason=args.reason)
    if args.json:
        print(json_dumps_redacted({"revoked_tickets": count, "reason": args.reason}))
    else:
        print(f"Revoked {count} ticket(s)")
    return 0


def _handle_doctor(store: SQLiteVaultStore, emit_json: bool) -> int:
    checks: dict[str, object] = {"schema": "ok"}
    try:
        header = store.load_header()
        checks["vault"] = "initialized"
        checks["provider"] = str(header.provider_binding.get("provider_id"))
        checks["provider_assurance"] = str(header.provider_binding.get("assurance_level", "unknown"))
    except VaultNotInitialized:
        checks["vault"] = "not_initialized"
        if emit_json:
            print(json_dumps_redacted({"checks": checks}))
        else:
            for key, value in checks.items():
                print(f"{key}: {value}")
        return 0
    policies = store.list_policy_json()
    tickets = store.list_ticket_json()
    audit_events = store.list_audit_event_json()
    fingerprints = store.list_redaction_fingerprints()
    checks["store_integrity"] = store.integrity_check()
    checks["policies"] = len(policies)
    checks["tickets"] = len(tickets)
    checks["audit_events"] = len(audit_events)
    checks["redaction_fingerprints"] = len(fingerprints)
    checks["explicit_policy_configured"] = bool(policies)
    checks["audit_present"] = bool(audit_events)
    checks["redaction_ready"] = bool(fingerprints)
    if emit_json:
        print(json_dumps_redacted({"checks": checks}))
    else:
        for key, value in checks.items():
            print(f"{key}: {value}")
    return 0


def _read_new_passphrase() -> str:
    first = getpass.getpass("New vault passphrase: ")
    second = getpass.getpass("Confirm vault passphrase: ")
    if first != second:
        raise ValueError("passphrases did not match")
    return first


def _read_new_release_key_passphrase() -> str:
    first = getpass.getpass("New release key passphrase: ")
    second = getpass.getpass("Confirm release key passphrase: ")
    if first != second:
        raise ValueError("release key passphrases did not match")
    return first


def _read_unlock_passphrase(store: SQLiteVaultStore) -> str | None:
    header = store.load_header()
    provider_id = header.provider_binding.get("provider_id")
    if provider_id == PASSPHRASE_PROVIDER_ID:
        return getpass.getpass("Vault passphrase: ")
    if provider_id == TPM2_PROVIDER_ID:
        return None
    return getpass.getpass("Vault passphrase: ")


def _read_secret_input(args: argparse.Namespace) -> bytes:
    if args.stdin:
        return sys.stdin.buffer.read().rstrip(b"\n")
    if args.value is not None:
        return args.value.encode("utf-8")
    return getpass.getpass("Secret value: ").encode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
