"""Systemd unit generation for the HBSE broker."""

from __future__ import annotations

import getpass
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SystemdInstallResult:
    scope: str
    unit_dir: str
    service_path: str
    socket_path: str
    service_name: str
    socket_name: str
    enabled: bool
    started: bool
    commands: list[list[str]]


def default_broker_executable() -> str:
    sibling = Path(sys.executable).parent / "hbse-broker"
    if sibling.exists():
        return str(sibling)
    found = shutil.which("hbse-broker")
    if found:
        return found
    return f"{sys.executable} -m hbse.broker_daemon"


def default_unit_dir(scope: str) -> Path:
    if scope == "user":
        return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "systemd/user"
    if scope == "system":
        return Path("/etc/systemd/system")
    raise ValueError("scope must be user or system")


def default_socket_path(scope: str) -> str:
    return "%t/hbse/broker.sock" if scope == "user" else "/run/hbse/broker.sock"


def default_vault_path(scope: str) -> str:
    if scope == "user":
        return str(Path.home() / ".local/share/hbse/vault.db")
    return "/var/lib/hbse/vault.db"


def render_broker_service(
    *,
    scope: str,
    broker_executable: str,
    vault_path: str,
    socket_path: str,
    idle_timeout_seconds: float,
    service_user: str | None = None,
) -> str:
    lines = [
        "[Unit]",
        "Description=HBSE local broker",
        "Documentation=file:/usr/share/doc/hbse/operations.md",
        "After=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"Environment=HBSE_VAULT_PATH={_systemd_escape_env(vault_path)}",
        f"ExecStart={broker_executable} --vault {vault_path} --socket {socket_path} --idle-timeout-seconds {idle_timeout_seconds:g}",
        "Restart=on-failure",
        "RestartSec=2",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
    ]
    if scope == "user":
        write_paths = [str(Path(vault_path).parent), str(Path(socket_path).parent)]
        if socket_path.startswith("%t/"):
            write_paths.append("%t/hbse")
        seen_write_paths = " ".join(dict.fromkeys(write_paths))
        lines.extend(
            [
                "ProtectHome=read-only",
                f"ReadWritePaths={seen_write_paths}",
            ]
        )
    else:
        if service_user:
            lines.append(f"User={service_user}")
        lines.extend(
            [
                "ProtectHome=true",
                f"StateDirectory={_state_directory_name(vault_path)}",
                "RuntimeDirectory=hbse",
                "RuntimeDirectoryMode=0700",
            ]
        )
    lines.extend(
        [
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "",
            "[Install]",
            "WantedBy=default.target" if scope == "user" else "WantedBy=multi-user.target",
            "",
        ]
    )
    return "\n".join(lines)


def render_broker_socket(*, scope: str, socket_path: str) -> str:
    return "\n".join(
        [
            "[Unit]",
            "Description=HBSE local broker socket",
            "",
            "[Socket]",
            f"ListenStream={socket_path}",
            "SocketMode=0600",
            "DirectoryMode=0700",
            "",
            "[Install]",
            "WantedBy=sockets.target",
            "",
        ]
    )


def install_broker_service(
    *,
    scope: str,
    unit_dir: str | Path | None,
    broker_executable: str | None,
    vault_path: str | None,
    socket_path: str | None,
    idle_timeout_seconds: float,
    service_user: str | None = None,
    enable: bool = False,
    start: bool = False,
    dry_run: bool = False,
) -> SystemdInstallResult:
    unit_path = Path(unit_dir) if unit_dir else default_unit_dir(scope)
    service_name = "hbse-broker.service"
    socket_name = "hbse-broker.socket"
    resolved_broker = broker_executable or default_broker_executable()
    resolved_vault = vault_path or default_vault_path(scope)
    resolved_socket = socket_path or default_socket_path(scope)
    resolved_user = service_user
    if scope == "system" and resolved_user is None:
        resolved_user = getpass.getuser()
    service_text = render_broker_service(
        scope=scope,
        broker_executable=resolved_broker,
        vault_path=resolved_vault,
        socket_path=resolved_socket,
        idle_timeout_seconds=idle_timeout_seconds,
        service_user=resolved_user,
    )
    socket_text = render_broker_socket(scope=scope, socket_path=resolved_socket)
    service_path = unit_path / service_name
    socket_unit_path = unit_path / socket_name
    commands: list[list[str]] = []
    if not dry_run:
        unit_path.mkdir(parents=True, exist_ok=True)
        service_path.write_text(service_text, encoding="utf-8")
        socket_unit_path.write_text(socket_text, encoding="utf-8")
        commands.append(_systemctl(scope, "daemon-reload"))
        _run(commands[-1])
        if enable:
            commands.append(_systemctl(scope, "enable", socket_name, service_name))
            _run(commands[-1])
        if start:
            commands.append(_systemctl(scope, "start", service_name))
            _run(commands[-1])
    return SystemdInstallResult(
        scope=scope,
        unit_dir=str(unit_path),
        service_path=str(service_path),
        socket_path=str(socket_unit_path),
        service_name=service_name,
        socket_name=socket_name,
        enabled=enable and not dry_run,
        started=start and not dry_run,
        commands=commands,
    )


def _systemctl(scope: str, *args: str) -> list[str]:
    command = ["systemctl"]
    if scope == "user":
        command.append("--user")
    command.extend(args)
    return command


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def _state_directory_name(vault_path: str) -> str:
    parent = Path(vault_path).parent
    if parent == Path("/var/lib/hbse"):
        return "hbse"
    return "hbse"


def _systemd_escape_env(value: str) -> str:
    return value.replace("%", "%%")
