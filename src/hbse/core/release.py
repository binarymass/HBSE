"""Release evidence generation for readiness gates."""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from importlib.metadata import distributions
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from hbse.core.serialization import b64url_no_padding, utc_millis


@dataclass(frozen=True)
class ReleaseEvidence:
    output_dir: Path
    source_digest: str
    signature_mode: str


@dataclass(frozen=True)
class ReleaseCheck:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class ReleaseVerification:
    checks: list[ReleaseCheck]

    @property
    def passed(self) -> bool:
        return all(check.status == "pass" for check in self.checks)

    def as_dict(self) -> dict[str, object]:
        return {"passed": self.passed, "checks": [check.__dict__ for check in self.checks]}


def generate_release_evidence(
    *,
    output_dir: str | Path,
    project_root: str | Path,
    version: str = "0.1.0",
) -> ReleaseEvidence:
    output = Path(output_dir)
    root = Path(project_root)
    output.mkdir(parents=True, exist_ok=True)
    source_digest = _source_digest(root)

    sbom = {
        "bomFormat": "CycloneDX-lite",
        "specVersion": "1.0-local",
        "metadata": {"component": {"name": "hbse", "version": version}},
        "components": _installed_components(),
    }
    (output / "sbom.json").write_text(json.dumps(sbom, sort_keys=True, indent=2), encoding="utf-8")

    provenance = {
        "project": "hbse",
        "version": version,
        "created_at": utc_millis(datetime.now(UTC)),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "source_digest": source_digest,
    }
    (output / "provenance.json").write_text(
        json.dumps(provenance, sort_keys=True, indent=2), encoding="utf-8"
    )

    checklist = {
        "crypto_tests": "run-required",
        "policy_tests": "run-required",
        "ticket_tests": "run-required",
        "audit_tests": "run-required",
        "redaction_tests": "run-required",
        "backup_restore_tests": "run-required",
        "external_security_review": "required-for-A4-plus",
        "real_hardware_provider_matrix": "required-for-A4-plus",
    }
    (output / "production_checklist.json").write_text(
        json.dumps(checklist, sort_keys=True, indent=2), encoding="utf-8"
    )

    signature = {
        "mode": "unsigned-development-evidence",
        "source_digest": source_digest,
        "warning": "Run hbse release sign with an Ed25519 release key for production.",
    }
    signature_mode = "unsigned-development-evidence"
    (output / "artifact.sig").write_text(
        json.dumps(signature, sort_keys=True, indent=2), encoding="utf-8"
    )
    lock = {
        "project": "hbse",
        "version": version,
        "source_digest": source_digest,
        "components": sbom["components"],
    }
    (output / "dependency-lock.json").write_text(
        json.dumps(lock, sort_keys=True, indent=2), encoding="utf-8"
    )
    return ReleaseEvidence(output, source_digest, signature_mode)


def generate_signing_keypair(
    *,
    private_key_path: str | Path,
    public_key_path: str | Path,
    passphrase: str | None = None,
) -> dict[str, str]:
    private_key = Ed25519PrivateKey.generate()
    encryption_algorithm: serialization.KeySerializationEncryption
    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        encryption_algorithm = serialization.NoEncryption()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    _write_private_file(private_path, private_bytes)
    public_path.write_bytes(public_bytes)
    return {
        "private_key_path": str(private_path),
        "public_key_path": str(public_path),
        "public_key_sha256": _sha256_bytes(public_bytes),
    }


def sign_release_artifacts(
    *,
    release_dir: str | Path,
    artifact_paths: list[str | Path],
    private_key_path: str | Path,
    public_key_path: str | Path | None = None,
    key_passphrase: str | None = None,
    version: str = "0.1.0",
) -> dict[str, object]:
    release_path = Path(release_dir)
    release_path.mkdir(parents=True, exist_ok=True)
    private_key = _load_private_key(Path(private_key_path), key_passphrase)
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if public_key_path:
        public_path = Path(public_key_path)
        public_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.write_bytes(public_bytes)
    elif not (release_path / "signing_public_key.pem").exists():
        (release_path / "signing_public_key.pem").write_bytes(public_bytes)

    manifest = _artifact_manifest(
        release_dir=release_path,
        artifact_paths=[Path(path) for path in artifact_paths],
        version=version,
        public_key_sha256=_sha256_bytes(public_bytes),
    )
    manifest_path = release_path / "artifacts.json"
    manifest_path.write_text(_canonical_json_text(manifest), encoding="utf-8")
    signature_bytes = private_key.sign(_canonical_json_bytes(manifest))
    signature = {
        "mode": "ed25519",
        "manifest": "artifacts.json",
        "manifest_sha256": _sha256_bytes(manifest_path.read_bytes()),
        "public_key_sha256": _sha256_bytes(public_bytes),
        "signature": b64url_no_padding(signature_bytes),
        "signed_at": utc_millis(datetime.now(UTC)),
    }
    (release_path / "artifact.sig").write_text(
        json.dumps(signature, sort_keys=True, indent=2), encoding="utf-8"
    )
    return {"manifest": manifest, "signature": signature}


def verify_release_evidence(
    *,
    release_dir: str | Path,
    public_key_path: str | Path | None = None,
) -> ReleaseVerification:
    root = Path(release_dir)
    checks: list[ReleaseCheck] = []
    for name in [
        "sbom.json",
        "provenance.json",
        "production_checklist.json",
        "artifact.sig",
        "dependency-lock.json",
        "openapi.json",
        "proto/hbse/v1/hbse.proto",
        "artifacts.json",
    ]:
        path = root / name
        status = "pass" if path.exists() else "fail"
        if name == "artifacts.json" and not path.exists():
            status = "warn"
        checks.append(ReleaseCheck(name, status, "exists" if path.exists() else "missing"))
    for json_name in [
        "sbom.json",
        "provenance.json",
        "production_checklist.json",
        "artifact.sig",
        "dependency-lock.json",
        "openapi.json",
        "artifacts.json",
    ]:
        path = root / json_name
        if not path.exists():
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
            checks.append(ReleaseCheck(f"{json_name}:json", "pass", "valid JSON"))
        except json.JSONDecodeError as exc:
            checks.append(ReleaseCheck(f"{json_name}:json", "fail", str(exc)))
    signature_path = root / "artifact.sig"
    if signature_path.exists():
        signature = json.loads(signature_path.read_text(encoding="utf-8"))
        mode = signature.get("mode")
        if mode == "unsigned-development-evidence":
            checks.append(ReleaseCheck("artifact.sig:mode", "warn", str(mode)))
        elif mode == "ed25519":
            checks.append(ReleaseCheck("artifact.sig:mode", "pass", "ed25519"))
            checks.extend(_verify_ed25519_signature(root, signature, public_key_path))
        else:
            checks.append(ReleaseCheck("artifact.sig:mode", "fail", f"unsupported mode: {mode}"))
    return ReleaseVerification(checks)


def _artifact_manifest(
    *,
    release_dir: Path,
    artifact_paths: list[Path],
    version: str,
    public_key_sha256: str,
) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for path in [
        release_dir / "sbom.json",
        release_dir / "dependency-lock.json",
        release_dir / "provenance.json",
        release_dir / "production_checklist.json",
        release_dir / "openapi.json",
        release_dir / "proto/hbse/v1/hbse.proto",
        *artifact_paths,
    ]:
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(str(path))
        resolved = str(path.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        entries.append(_artifact_entry(path))
    provenance_path = release_dir / "provenance.json"
    source_digest = None
    if provenance_path.exists():
        source_digest = json.loads(provenance_path.read_text(encoding="utf-8")).get("source_digest")
    return {
        "schema": "hbse.release.artifacts.v1",
        "project": "hbse",
        "version": version,
        "created_at": utc_millis(datetime.now(UTC)),
        "source_digest": source_digest,
        "public_key_sha256": public_key_sha256,
        "artifacts": entries,
    }


def _artifact_entry(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {
        "path": path.as_posix(),
        "sha256": _sha256_bytes(data),
        "size": len(data),
    }


def _verify_ed25519_signature(
    release_dir: Path,
    signature: dict[str, object],
    public_key_path: str | Path | None,
) -> list[ReleaseCheck]:
    checks: list[ReleaseCheck] = []
    manifest_path = release_dir / str(signature.get("manifest", "artifacts.json"))
    if not manifest_path.exists():
        return [ReleaseCheck("artifacts.json:signature", "fail", "manifest missing")]
    manifest_bytes = manifest_path.read_bytes()
    expected_manifest_sha = signature.get("manifest_sha256")
    actual_manifest_sha = _sha256_bytes(manifest_bytes)
    checks.append(
        ReleaseCheck(
            "artifacts.json:sha256",
            "pass" if expected_manifest_sha == actual_manifest_sha else "fail",
            actual_manifest_sha,
        )
    )
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        checks.append(ReleaseCheck("artifacts.json:parse", "fail", str(exc)))
        return checks
    checks.extend(_verify_manifest_artifact_hashes(manifest))
    public_path = Path(public_key_path) if public_key_path else release_dir / "signing_public_key.pem"
    if not public_path.exists():
        checks.append(ReleaseCheck("artifact.sig:public_key", "fail", f"{public_path} missing"))
        return checks
    public_bytes = public_path.read_bytes()
    public_key_sha = _sha256_bytes(public_bytes)
    expected_public_sha = str(signature.get("public_key_sha256"))
    checks.append(
        ReleaseCheck(
            "artifact.sig:public_key",
            "pass" if public_key_sha == expected_public_sha else "fail",
            public_key_sha,
        )
    )
    if public_key_sha != expected_public_sha:
        return checks
    try:
        public_key = serialization.load_pem_public_key(public_bytes)
        if not isinstance(public_key, Ed25519PublicKey):
            checks.append(ReleaseCheck("artifact.sig:algorithm", "fail", "public key is not Ed25519"))
            return checks
        public_key.verify(_b64url_decode(str(signature["signature"])), _canonical_json_bytes(manifest))
        checks.append(ReleaseCheck("artifact.sig:signature", "pass", "valid Ed25519 signature"))
    except (InvalidSignature, ValueError, KeyError) as exc:
        checks.append(ReleaseCheck("artifact.sig:signature", "fail", str(exc) or exc.__class__.__name__))
    return checks


def _verify_manifest_artifact_hashes(manifest: dict[str, object]) -> list[ReleaseCheck]:
    checks: list[ReleaseCheck] = []
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return [ReleaseCheck("artifacts.json:artifacts", "fail", "artifacts must be a list")]
    for item in artifacts:
        if not isinstance(item, dict):
            checks.append(ReleaseCheck("artifacts.json:artifact", "fail", "artifact entry is not an object"))
            continue
        path = Path(str(item.get("path", "")))
        if not path.exists():
            checks.append(ReleaseCheck(f"artifact:{path}", "fail", "missing"))
            continue
        data = path.read_bytes()
        expected_sha = str(item.get("sha256"))
        expected_size = int(item.get("size", -1))
        actual_sha = _sha256_bytes(data)
        actual_size = len(data)
        status = "pass" if actual_sha == expected_sha and actual_size == expected_size else "fail"
        checks.append(
            ReleaseCheck(
                f"artifact:{path}",
                status,
                f"sha256={actual_sha} size={actual_size}",
            )
        )
    return checks


def _load_private_key(path: Path, passphrase: str | None) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(
        path.read_bytes(),
        password=passphrase.encode("utf-8") if passphrase else None,
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("release private key must be Ed25519")
    return key


def _write_private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _sha256_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()


def _canonical_json_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_json_bytes(value: object) -> bytes:
    return _canonical_json_text(value).encode("utf-8")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    import base64

    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _source_digest(root: Path) -> str:
    digest = sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(
            part in {".venv", ".pytest_cache", "__pycache__", "build", "dist", "release"}
            for part in path.parts
        ):
            continue
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return b64url_no_padding(digest.digest())


def _installed_components() -> list[dict[str, str]]:
    components: list[dict[str, str]] = []
    for dist in distributions():
        metadata = dist.metadata
        name = metadata.get("Name")
        version = metadata.get("Version")
        if name and version:
            components.append({"type": "library", "name": name, "version": version})
    return sorted(components, key=lambda item: item["name"].lower())
