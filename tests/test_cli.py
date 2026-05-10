from __future__ import annotations

import json
import subprocess
import sys


def run_cli(*args: str, input_text: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "hbse.cli", *args],
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def test_doctor_reports_uninitialized_vault(tmp_path) -> None:
    result = run_cli("--vault", str(tmp_path / "vault.db"), "--json", "doctor")

    assert result.returncode == 0
    assert '"vault": "not_initialized"' in result.stdout


def test_secret_get_requires_explicit_raw_flags(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    init_result = run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="passphrase\npassphrase\n",
    )
    assert init_result.returncode == 0

    put_result = run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "sk-test",
        input_text="passphrase\n",
    )
    assert put_result.returncode == 0

    get_result = run_cli("--vault", str(vault_path), "secret", "get", "secret://default/api")

    assert get_result.returncode == 3
    assert "denied by default" in get_result.stderr


def test_audit_list_export_and_verify_from_cli(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    export_path = tmp_path / "audit.json"
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="passphrase\npassphrase\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "sk-test",
        input_text="passphrase\n",
    ).returncode == 0

    listed = run_cli("--vault", str(vault_path), "audit", "list", "--limit", "1")
    assert listed.returncode == 0
    listed_payload = json.loads(listed.stdout)
    assert len(listed_payload["events"]) == 1
    assert "event_hash" in listed_payload["events"][0]
    assert "sk-test" not in listed.stdout

    stored_only = run_cli(
        "--vault",
        str(vault_path),
        "audit",
        "list",
        "--event-type",
        "secret.stored",
    )
    assert stored_only.returncode == 0
    assert {event["event_type"] for event in json.loads(stored_only.stdout)["events"]} == {"secret.stored"}

    exported = run_cli("--vault", str(vault_path), "audit", "export", str(export_path))
    assert exported.returncode == 0
    assert export_path.exists()
    assert "sk-test" not in export_path.read_text(encoding="utf-8")

    verified = run_cli("--vault", str(vault_path), "audit", "verify", input_text="passphrase\n")
    assert verified.returncode == 0
    assert "audit: ok" in verified.stdout


def test_secret_inspect_and_destroy_are_metadata_only_and_policy_enforced(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="passphrase\npassphrase\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "sk-test",
        input_text="passphrase\n",
    ).returncode == 0

    inspected = run_cli("--vault", str(vault_path), "secret", "inspect", "secret://default/api")
    assert inspected.returncode == 0
    metadata = json.loads(inspected.stdout)
    assert metadata["secret_ref"] == "secret://default/api"
    assert metadata["status"] == "active"
    assert "sk-test" not in inspected.stdout

    destroyed = run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "destroy",
        "secret://default/api",
        "--reason",
        "test destroy",
        input_text="passphrase\n",
    )
    assert destroyed.returncode == 0
    inspected_after = run_cli("--vault", str(vault_path), "secret", "inspect", "secret://default/api")
    assert json.loads(inspected_after.stdout)["status"] == "destroyed"

    assert run_cli(
        "--vault",
        str(vault_path),
        "policy",
        "create",
        "run",
        "--secret-ref",
        "secret://default/api",
        "--purpose",
        "run-test",
        "--delivery-mode",
        "child_env",
    ).returncode == 0
    denied = run_cli(
        "--vault",
        str(vault_path),
        "run",
        "--secret-ref",
        "secret://default/api",
        "--env",
        "TOKEN",
        "--purpose",
        "run-test",
        "--",
        sys.executable,
        "-c",
        "print('no materialization')",
        input_text="passphrase\n",
    )
    assert denied.returncode == 3
    assert "secret status is destroyed" in denied.stderr


def test_secret_get_raw_requires_reason_and_passphrase(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="passphrase\npassphrase\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "policy",
        "create",
        "cli-raw",
        "--secret-ref",
        "secret://default/api",
        "--purpose",
        "test retrieval",
        "--exportable",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "sk-test",
        input_text="passphrase\n",
    ).returncode == 0

    result = run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "get",
        "secret://default/api",
        "--raw",
        "--allow-secret-output",
        "--reason",
        "test retrieval",
        input_text="passphrase\npassphrase\n",
    )

    assert result.returncode == 0
    assert result.stdout == "sk-test\n"


def test_secret_get_raw_is_policy_denied_without_matching_policy(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="passphrase\npassphrase\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "sk-test",
        input_text="passphrase\n",
    ).returncode == 0

    result = run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "get",
        "secret://default/api",
        "--raw",
        "--allow-secret-output",
        "--reason",
        "test retrieval",
        input_text="passphrase\n",
    )

    assert result.returncode == 3
    assert "policy denied" in result.stderr


def test_run_injects_secret_only_when_policy_allows(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="passphrase\npassphrase\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "sk-test",
        input_text="passphrase\n",
    ).returncode == 0
    denied = run_cli(
        "--vault",
        str(vault_path),
        "run",
        "--secret-ref",
        "secret://default/api",
        "--env",
        "TOKEN",
        "--purpose",
        "run-test",
        "--",
        sys.executable,
        "-c",
        "import os; print(os.environ.get('TOKEN'))",
        input_text="passphrase\n",
    )
    assert denied.returncode == 3

    assert run_cli(
        "--vault",
        str(vault_path),
        "policy",
        "create",
        "run",
        "--secret-ref",
        "secret://default/api",
        "--purpose",
        "run-test",
        "--delivery-mode",
        "child_env",
    ).returncode == 0
    allowed = run_cli(
        "--vault",
        str(vault_path),
        "run",
        "--secret-ref",
        "secret://default/api",
        "--env",
        "TOKEN",
        "--purpose",
        "run-test",
        "--",
        sys.executable,
        "-c",
        "import os; print(os.environ['TOKEN'].replace('sk-', 'ok-'))",
        input_text="passphrase\n",
    )

    assert allowed.returncode == 0
    assert allowed.stdout.strip() == "ok-test"


def test_ticket_list_inspect_and_revoke_from_cli(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="passphrase\npassphrase\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "sk-test",
        input_text="passphrase\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "policy",
        "create",
        "callback",
        "--secret-ref",
        "secret://default/api",
        "--purpose",
        "callback-test",
        "--delivery-mode",
        "callback",
    ).returncode == 0
    issued = run_cli(
        "--vault",
        str(vault_path),
        "ticket",
        "issue",
        "secret://default/api",
        "--purpose",
        "callback-test",
        "--delivery-mode",
        "callback",
        input_text="passphrase\n",
    )
    assert issued.returncode == 0
    ticket_id = json.loads(issued.stdout)["ticket_id"]

    listed = run_cli("--vault", str(vault_path), "ticket", "list")
    assert listed.returncode == 0
    assert ticket_id in listed.stdout
    inspected = run_cli("--vault", str(vault_path), "ticket", "inspect", ticket_id)
    assert json.loads(inspected.stdout)["revoked"] is False

    revoked = run_cli(
        "--vault",
        str(vault_path),
        "ticket",
        "revoke",
        ticket_id,
        input_text="passphrase\n",
    )
    assert revoked.returncode == 0
    assert json.loads(revoked.stdout)["revoked"] is True


def test_dotenv_run_resolves_secret_refs_through_policy(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text("APP_ENV=dev\nTOKEN=secret://default/api\n", encoding="utf-8")
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="passphrase\npassphrase\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "sk-test",
        input_text="passphrase\n",
    ).returncode == 0
    denied = run_cli(
        "--vault",
        str(vault_path),
        "dotenv",
        "run",
        "--purpose",
        "dotenv-test",
        str(dotenv_path),
        "--",
        sys.executable,
        "-c",
        "import os; print(os.environ.get('TOKEN'))",
        input_text="passphrase\n",
    )
    assert denied.returncode == 3
    assert run_cli(
        "--vault",
        str(vault_path),
        "policy",
        "create",
        "dotenv",
        "--secret-ref",
        "secret://default/api",
        "--purpose",
        "dotenv-test",
        "--delivery-mode",
        "child_env",
    ).returncode == 0
    allowed = run_cli(
        "--vault",
        str(vault_path),
        "dotenv",
        "run",
        "--purpose",
        "dotenv-test",
        str(dotenv_path),
        "--",
        sys.executable,
        "-c",
        "import os; print(os.environ['APP_ENV'] + ':' + os.environ['TOKEN'].replace('sk-', 'ok-'))",
        input_text="passphrase\n",
    )
    assert allowed.returncode == 0
    assert allowed.stdout.strip() == "dev:ok-test"


def test_dotenv_run_blocks_raw_secret_values(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text("API_KEY=sk-1234567890abcdef\n", encoding="utf-8")
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="passphrase\npassphrase\n",
    ).returncode == 0
    result = run_cli(
        "--vault",
        str(vault_path),
        "dotenv",
        "run",
        "--purpose",
        "dotenv-test",
        str(dotenv_path),
        "--",
        sys.executable,
        "-c",
        "print('nope')",
        input_text="passphrase\n",
    )
    assert result.returncode == 8
    assert "raw secrets detected" in result.stderr


def test_api_export_openapi_writes_schema(tmp_path) -> None:
    destination = tmp_path / "openapi.json"
    result = run_cli(
        "--vault",
        str(tmp_path / "vault.db"),
        "api",
        "export-openapi",
        str(destination),
    )

    assert result.returncode == 0
    assert '"openapi"' in destination.read_text(encoding="utf-8")


def test_release_export_proto_copies_contract(tmp_path) -> None:
    destination = tmp_path / "proto"
    result = run_cli(
        "release",
        "export-proto",
        "--output-dir",
        str(destination),
        "--project-root",
        ".",
    )

    assert result.returncode == 0
    assert (destination / "hbse/v1/hbse.proto").exists()


def test_release_verify_reports_missing_artifacts(tmp_path) -> None:
    result = run_cli("release", "verify", "--release-dir", str(tmp_path / "missing-release"))

    assert result.returncode == 1
    assert "sbom.json" in result.stdout


def test_provider_enroll_rotates_passphrase_from_cli(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="old\nold\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "sk-test",
        input_text="old\n",
    ).returncode == 0
    enrolled = run_cli(
        "--vault",
        str(vault_path),
        "provider",
        "enroll",
        "passphrase",
        "--new-passphrase",
        "new",
        input_text="old\n",
    )
    assert enrolled.returncode == 0
    assert "passphrase-scrypt-aesgcm" in enrolled.stdout

    assert run_cli(
        "--vault",
        str(vault_path),
        "policy",
        "create",
        "cli-raw",
        "--secret-ref",
        "secret://default/api",
        "--purpose",
        "test",
        "--exportable",
    ).returncode == 0
    result = run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "get",
        "secret://default/api",
        "--raw",
        "--allow-secret-output",
        "--reason",
        "test",
        input_text="new\nnew\n",
    )
    assert result.returncode == 0
    assert result.stdout == "sk-test\n"


def test_cli_recovery_package_recovers_to_new_passphrase(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    recovery_path = tmp_path / "recovery.json"
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="old\nold\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "sk-test",
        input_text="old\n",
    ).returncode == 0
    created = run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "recovery-create",
        str(recovery_path),
        input_text="old\nrecovery\n",
    )
    assert created.returncode == 0
    recovered = run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "recover",
        str(recovery_path),
        "--new-provider",
        "passphrase",
        "--new-passphrase",
        "new",
        input_text="recovery\n",
    )
    assert recovered.returncode == 0

    assert run_cli(
        "--vault",
        str(vault_path),
        "policy",
        "create",
        "cli-raw",
        "--secret-ref",
        "secret://default/api",
        "--purpose",
        "test",
        "--exportable",
    ).returncode == 0
    result = run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "get",
        "secret://default/api",
        "--raw",
        "--allow-secret-output",
        "--reason",
        "test",
        input_text="new\nnew\n",
    )
    assert result.returncode == 0
    assert result.stdout == "sk-test\n"


def test_cli_staged_rotation_flow(tmp_path) -> None:
    vault_path = tmp_path / "vault.db"
    assert run_cli(
        "--vault",
        str(vault_path),
        "vault",
        "init",
        input_text="passphrase\npassphrase\n",
    ).returncode == 0
    assert run_cli(
        "--vault",
        str(vault_path),
        "secret",
        "put",
        "secret://default/api",
        "--value",
        "old",
        input_text="passphrase\n",
    ).returncode == 0
    started = run_cli(
        "--vault",
        str(vault_path),
        "rotation",
        "start",
        "secret://default/api",
        "--value",
        "new",
        input_text="passphrase\n",
    )
    assert started.returncode == 0
    job_id = json.loads(started.stdout)["job_id"]
    assert run_cli(
        "--vault",
        str(vault_path),
        "rotation",
        "verify",
        job_id,
        input_text="passphrase\n",
    ).returncode == 0
    promoted = run_cli(
        "--vault",
        str(vault_path),
        "rotation",
        "promote",
        job_id,
        input_text="passphrase\n",
    )
    assert promoted.returncode == 0
    assert json.loads(promoted.stdout)["status"] == "promoted"
