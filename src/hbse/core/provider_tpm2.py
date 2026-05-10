"""Linux TPM 2.0 provider backed by tpm2-tools.

This provider intentionally shells out only as an integration bridge. The
production spec still prefers direct TPM bindings to reduce process and file
handling exposure.
"""

from __future__ import annotations

import os
import hashlib
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from hbse.core.keys import KEY_SIZE
from hbse.core.serialization import b64url_decode_no_padding, b64url_no_padding


TPM2_PROVIDER_ID = "linux-tpm2-tools-seal"


class TPM2ProviderError(RuntimeError):
    """Raised when the TPM provider cannot complete an operation."""


@dataclass(frozen=True)
class TPM2ProviderStatus:
    available: bool
    device_path: str
    tools_available: bool
    device_accessible: bool
    detail: str


@dataclass(frozen=True)
class LinuxTPM2ToolsProvider:
    device_path: str = "/dev/tpmrm0"

    def detect(self) -> TPM2ProviderStatus:
        tools = all(
            shutil.which(tool)
            for tool in ("tpm2_createprimary", "tpm2_create", "tpm2_load", "tpm2_unseal")
        )
        device = Path(self.device_path)
        accessible = device.exists() and os.access(device, os.R_OK | os.W_OK)
        if not device.exists():
            detail = f"{self.device_path} does not exist"
        elif not accessible:
            detail = f"{self.device_path} exists but is not readable/writable by this user"
        elif not tools:
            detail = "required tpm2-tools commands are not installed"
        else:
            detail = "TPM device and tpm2-tools are available"
        return TPM2ProviderStatus(
            available=bool(tools and accessible),
            device_path=self.device_path,
            tools_available=bool(tools),
            device_accessible=bool(accessible),
            detail=detail,
        )

    def wrap_root_key(self, *, vault_id: str, root_key: bytes) -> dict[str, object]:
        if len(root_key) != KEY_SIZE:
            raise ValueError("vault root key must be 32 bytes")
        self._require_available()
        with tempfile.TemporaryDirectory(prefix="hbse-tpm2-") as tmpdir:
            tmp = Path(tmpdir)
            secret_path = tmp / "root.key"
            primary_ctx = tmp / "primary.ctx"
            sealed_pub = tmp / "sealed.pub"
            sealed_priv = tmp / "sealed.priv"
            sealed_ctx = tmp / "sealed.ctx"
            secret_path.write_bytes(root_key)
            try:
                self._run("tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", str(primary_ctx))
                self._run(
                    "tpm2_create",
                    "-C",
                    str(primary_ctx),
                    "-i",
                    str(secret_path),
                    "-u",
                    str(sealed_pub),
                    "-r",
                    str(sealed_priv),
                )
                self._run(
                    "tpm2_load",
                    "-C",
                    str(primary_ctx),
                    "-u",
                    str(sealed_pub),
                    "-r",
                    str(sealed_priv),
                    "-c",
                    str(sealed_ctx),
                )
                public_info = self._run("tpm2_readpublic", "-c", str(sealed_ctx), capture=True)
            finally:
                secret_path.write_bytes(b"\x00" * KEY_SIZE)
            return {
                "provider_id": TPM2_PROVIDER_ID,
                "vault_id": vault_id,
                "device_path": self.device_path,
                "parent_hierarchy": "owner",
                "public": b64url_no_padding(sealed_pub.read_bytes()),
                "private": b64url_no_padding(sealed_priv.read_bytes()),
                "public_info_sha256": b64url_no_padding(hashlib.sha256(public_info).digest()),
                "assurance_level": "A2",
                "warning": "tpm2-tools bridge provider; direct TPM bindings are preferred for production.",
            }

    def unwrap_root_key(self, *, binding: dict[str, object]) -> bytes:
        if binding.get("provider_id") != TPM2_PROVIDER_ID:
            raise TPM2ProviderError("unsupported TPM provider binding")
        self._require_available()
        with tempfile.TemporaryDirectory(prefix="hbse-tpm2-") as tmpdir:
            tmp = Path(tmpdir)
            primary_ctx = tmp / "primary.ctx"
            sealed_pub = tmp / "sealed.pub"
            sealed_priv = tmp / "sealed.priv"
            sealed_ctx = tmp / "sealed.ctx"
            sealed_pub.write_bytes(b64url_decode_no_padding(str(binding["public"])))
            sealed_priv.write_bytes(b64url_decode_no_padding(str(binding["private"])))
            self._run("tpm2_createprimary", "-C", "o", "-G", "ecc", "-c", str(primary_ctx))
            self._run(
                "tpm2_load",
                "-C",
                str(primary_ctx),
                "-u",
                str(sealed_pub),
                "-r",
                str(sealed_priv),
                "-c",
                str(sealed_ctx),
            )
            public_info = self._run("tpm2_readpublic", "-c", str(sealed_ctx), capture=True)
            expected_public_hash = str(binding.get("public_info_sha256", ""))
            actual_public_hash = b64url_no_padding(hashlib.sha256(public_info).digest())
            if expected_public_hash and expected_public_hash != actual_public_hash:
                raise TPM2ProviderError("TPM sealed object identity mismatch")
            root_key = self._run("tpm2_unseal", "-c", str(sealed_ctx), capture=True)
        if len(root_key) != KEY_SIZE:
            raise TPM2ProviderError("TPM returned invalid root key length")
        return root_key

    def self_test(self) -> TPM2ProviderStatus:
        status = self.detect()
        if not status.available:
            return status
        root_key = os.urandom(KEY_SIZE)
        binding = self.wrap_root_key(vault_id="self-test", root_key=root_key)
        unwrapped = self.unwrap_root_key(binding=binding)
        if unwrapped != root_key:
            raise TPM2ProviderError("TPM seal/unseal self-test mismatch")
        return status

    def _require_available(self) -> None:
        status = self.detect()
        if not status.available:
            raise TPM2ProviderError(status.detail)

    def _run(self, *args: str, capture: bool = False) -> bytes:
        env = {**os.environ, "TPM2TOOLS_TCTI": f"device:{self.device_path}"}
        try:
            result = subprocess.run(
                args,
                env=env,
                check=True,
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise TPM2ProviderError(f"missing command: {args[0]}") from exc
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace").strip()
            raise TPM2ProviderError(f"{args[0]} failed: {stderr}") from exc
        return result.stdout if capture else b""
