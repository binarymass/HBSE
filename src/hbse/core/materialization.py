"""Controlled secret materialization modes."""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from hbse.core.policy import DeliveryMode


class MaterializationError(RuntimeError):
    """Raised when materialization cannot be completed safely."""


@dataclass(frozen=True)
class MaterializedSecret:
    mode: DeliveryMode
    value: bytes | None = None
    path: Path | None = None
    fd: int | None = None


class Materializer:
    def to_pipe(self, secret: bytes) -> tuple[int, int]:
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, secret)
        finally:
            os.close(write_fd)
        return read_fd, -1

    def to_temp_file(self, secret: bytes) -> Path:
        handle = tempfile.NamedTemporaryFile(prefix="hbse-secret-", delete=False)
        try:
            os.chmod(handle.name, 0o600)
            handle.write(secret)
            handle.flush()
            return Path(handle.name)
        finally:
            handle.close()

    def run_child_env(
        self,
        *,
        secret: bytes,
        env_name: str,
        command: list[str],
        base_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if not env_name.isidentifier():
            raise MaterializationError("environment variable name must be an identifier")
        env = dict(base_env or os.environ)
        env[env_name] = secret.decode("utf-8")
        return subprocess.run(command, env=env, text=True, capture_output=True, check=False)

    def cleanup_temp_file(self, path: Path) -> None:
        try:
            path.write_bytes(b"")
        except FileNotFoundError:
            return
        path.unlink(missing_ok=True)
