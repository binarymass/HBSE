"""Production readiness evidence checker."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hbse.core.store import SQLiteVaultStore, VaultNotInitialized
from hbse.core.vault import LocalVault


@dataclass(frozen=True)
class ReadinessItem:
    area: str
    status: str
    detail: str


@dataclass(frozen=True)
class ReadinessReport:
    target: str
    items: list[ReadinessItem]

    @property
    def passed(self) -> bool:
        return all(item.status != "fail" for item in self.items)

    def as_dict(self) -> dict[str, object]:
        return {"target": self.target, "passed": self.passed, "items": [item.__dict__ for item in self.items]}


def check_local_readiness(
    *,
    store: SQLiteVaultStore,
    vault: LocalVault,
    passphrase: str | None,
    release_dir: str | Path = "release",
    target: str = "A2",
) -> ReadinessReport:
    items: list[ReadinessItem] = []
    try:
        header = store.load_header()
        items.append(ReadinessItem("Vault", "pass", "vault initialized"))
        provider_level = str(header.provider_binding.get("assurance_level", "A0"))
        if provider_level >= "A1":
            items.append(ReadinessItem("Providers", "pass", f"provider assurance visible: {provider_level}"))
        else:
            items.append(ReadinessItem("Providers", "fail", "provider assurance below A1"))
    except VaultNotInitialized:
        return ReadinessReport(
            target=target,
            items=[ReadinessItem("Vault", "fail", "vault is not initialized")],
        )

    if store.list_policy_json():
        items.append(ReadinessItem("Policy", "pass", "at least one explicit policy exists"))
    else:
        items.append(ReadinessItem("Policy", "fail", "no explicit policies configured"))

    if store.list_audit_event_json():
        items.append(ReadinessItem("Audit", "pass", "audit events exist"))
    else:
        items.append(ReadinessItem("Audit", "fail", "no audit events recorded"))

    if store.list_redaction_fingerprints():
        items.append(ReadinessItem("Redaction", "pass", "secret fingerprints exist"))
    else:
        items.append(ReadinessItem("Redaction", "warn", "no active secret fingerprints yet"))

    if passphrase:
        try:
            vault.verify_audit(passphrase=passphrase)
            items.append(ReadinessItem("Audit", "pass", "audit chain verifies"))
        except Exception as exc:
            items.append(ReadinessItem("Audit", "fail", f"audit chain verification failed: {exc}"))
    else:
        items.append(ReadinessItem("Audit", "warn", "passphrase not supplied; audit MAC not verified"))

    release_path = Path(release_dir)
    items.extend(_release_items(release_path, target))
    if target in {"A4", "A5"}:
        items.append(
            ReadinessItem(
                "Review",
                "fail",
                "independent security review evidence is required and cannot be generated automatically",
            )
        )
        items.append(
            ReadinessItem(
                "Providers",
                "fail",
                "real hardware copied-vault tests require external TPM/provider evidence",
            )
        )
    return ReadinessReport(target=target, items=items)


def _release_items(release_path: Path, target: str) -> list[ReadinessItem]:
    required = {
        "SBOM": release_path / "sbom.json",
        "Provenance": release_path / "provenance.json",
        "Signature": release_path / "artifact.sig",
        "Checklist": release_path / "production_checklist.json",
    }
    items: list[ReadinessItem] = []
    for area, path in required.items():
        if path.exists():
            items.append(ReadinessItem(area, "pass", f"{path} exists"))
        else:
            status = "fail" if target in {"A4", "A5"} else "warn"
            items.append(ReadinessItem(area, status, f"{path} missing"))
    return items
