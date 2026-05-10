"""Unix-socket local broker daemon for HBSE."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from hbse.core.broker import LocalBroker
from hbse.core.policy import DeliveryMode
from hbse.core.provider import PASSPHRASE_PROVIDER_ID
from hbse.core.provider_tpm2 import TPM2_PROVIDER_ID
from hbse.core.store import SQLiteVaultStore, json_dumps_redacted
from hbse.core.vault import LocalVault


SO_PEERCRED = 17


@dataclass
class BrokerState:
    vault_path: Path
    idle_timeout_seconds: float = 0
    unlocked_passphrase: str | None = None
    unlocked: bool = False
    last_activity: datetime | None = None

    @property
    def store(self) -> SQLiteVaultStore:
        return SQLiteVaultStore(self.vault_path)

    @property
    def vault(self) -> LocalVault:
        return LocalVault(store=self.store)


def serve(*, vault_path: str | Path, socket_path: str | Path, idle_timeout_seconds: float = 0) -> None:
    socket_path = Path(socket_path)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    state = BrokerState(vault_path=Path(vault_path), idle_timeout_seconds=idle_timeout_seconds)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        socket_path.chmod(0o600)
        server.listen(16)
        while True:
            conn, _ = server.accept()
            with conn:
                response = _handle_connection(conn, state)
                conn.sendall((json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))


def _handle_connection(conn: socket.socket, state: BrokerState) -> dict[str, Any]:
    try:
        request = json.loads(_read_line(conn))
        peer = _peer_identity(conn)
        command = request.get("command")
        _expire_idle_unlock(state)
        if command == "status":
            return {
                "ok": True,
                "unlocked": state.unlocked,
                "idle_timeout_seconds": state.idle_timeout_seconds,
                "last_activity": state.last_activity.isoformat() if state.last_activity else None,
                "peer": peer,
            }
        if command == "unlock":
            passphrase = request.get("passphrase")
            _validate_unlock(state, passphrase)
            state.unlocked_passphrase = passphrase
            state.unlocked = True
            _mark_activity(state)
            return {"ok": True, "unlocked": True}
        if command == "lock":
            state.unlocked_passphrase = None
            state.unlocked = False
            state.last_activity = None
            return {"ok": True, "unlocked": False}
        if command == "checkout":
            _require_unlocked(state)
            broker = LocalBroker(store=state.store, vault=state.vault)
            ticket = broker.checkout(
                secret_ref=request["secret_ref"],
                consumer=request.get("consumer") or f"uid:{peer['uid']}",
                purpose=request["purpose"],
                delivery_mode=DeliveryMode(request["delivery_mode"]),
                passphrase=state.unlocked_passphrase,
                url=request.get("url"),
                method=request.get("method"),
                os_uid=peer.get("uid"),
                executable_path=peer.get("exe_path"),
                executable_sha256=peer.get("exe_sha256"),
            )
            _mark_activity(state)
            return {"ok": True, "ticket": ticket.model_dump(mode="json"), "peer": peer}
        if command == "materialize":
            _require_unlocked(state)
            broker = LocalBroker(store=state.store, vault=state.vault)
            mode = DeliveryMode(request["delivery_mode"])
            secret = broker.materialize_bytes(
                secret_ref=request["secret_ref"],
                consumer=request.get("consumer") or f"uid:{peer['uid']}",
                purpose=request["purpose"],
                delivery_mode=mode,
                passphrase=state.unlocked_passphrase,
                raw_export_requested=bool(request.get("raw_export_requested", False)),
                os_uid=peer.get("uid"),
                executable_path=peer.get("exe_path"),
                executable_sha256=peer.get("exe_sha256"),
            )
            _mark_activity(state)
            return {"ok": True, "secret": secret.decode("utf-8"), "peer": peer}
        if command == "provider_http":
            _require_unlocked(state)
            broker = LocalBroker(store=state.store, vault=state.vault)
            response = broker.brokered_http_request(
                secret_ref=request["secret_ref"],
                consumer=request.get("consumer") or f"uid:{peer['uid']}",
                purpose=request["purpose"],
                method=request.get("method", "GET"),
                url=request["url"],
                headers=request.get("headers") or {},
                body=request.get("body"),
                passphrase=state.unlocked_passphrase,
                credential_header=request.get("credential_header", "Authorization"),
                credential_prefix=request.get("credential_prefix", "Bearer "),
                timeout_seconds=float(request.get("timeout_seconds", 30.0)),
                max_response_bytes=int(request.get("max_response_bytes", 10 * 1024 * 1024)),
                os_uid=peer.get("uid"),
                executable_path=peer.get("exe_path"),
                executable_sha256=peer.get("exe_sha256"),
            )
            _mark_activity(state)
            return {
                "ok": True,
                "status_code": response.status_code,
                "headers": response.headers,
                "body": response.body,
                "redacted": response.redacted,
                "peer": peer,
            }
        return {"ok": False, "error": {"code": "UNKNOWN_COMMAND", "message": str(command)}}
    except Exception as exc:
        return {"ok": False, "error": {"code": exc.__class__.__name__, "message": str(exc)}}


def _validate_unlock(state: BrokerState, passphrase: str | None) -> None:
    header = state.store.load_header()
    provider_id = header.provider_binding.get("provider_id")
    if provider_id == PASSPHRASE_PROVIDER_ID:
        state.vault.verify_audit(passphrase=passphrase)
        return
    if provider_id == TPM2_PROVIDER_ID:
        state.vault.verify_audit(passphrase=None)
        return
    raise ValueError(f"unsupported provider: {provider_id}")


def _require_unlocked(state: BrokerState) -> None:
    _expire_idle_unlock(state)
    if not state.unlocked:
        raise PermissionError("broker is locked")


def _mark_activity(state: BrokerState) -> None:
    state.last_activity = datetime.now(UTC)


def _expire_idle_unlock(state: BrokerState) -> None:
    if not state.unlocked or state.idle_timeout_seconds <= 0 or state.last_activity is None:
        return
    deadline = state.last_activity + timedelta(seconds=state.idle_timeout_seconds)
    if datetime.now(UTC) > deadline:
        state.unlocked_passphrase = None
        state.unlocked = False
        state.last_activity = None


def _read_line(conn: socket.socket) -> str:
    chunks: list[bytes] = []
    while True:
        data = conn.recv(4096)
        if not data:
            break
        chunks.append(data)
        if b"\n" in data:
            break
    return b"".join(chunks).split(b"\n", 1)[0].decode("utf-8")


def _peer_identity(conn: socket.socket) -> dict[str, Any]:
    creds = conn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", creds)
    identity: dict[str, Any] = {"pid": pid, "uid": uid, "gid": gid}
    identity.update(_linux_process_identity(pid))
    return identity


def _linux_process_identity(pid: int) -> dict[str, str]:
    proc = Path("/proc") / str(pid)
    identity: dict[str, str] = {}
    try:
        identity["exe_path"] = os.readlink(proc / "exe")
    except OSError:
        pass
    try:
        identity["comm"] = (proc / "comm").read_text(encoding="utf-8").strip()
    except OSError:
        pass
    exe_path = identity.get("exe_path")
    if exe_path:
        try:
            identity["exe_sha256"] = _sha256_file(Path(exe_path))
        except OSError:
            pass
    return identity


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def request(socket_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(socket_path))
        client.sendall((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
        return json.loads(_read_line(client))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hbse-broker")
    parser.add_argument("--vault", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--idle-timeout-seconds", type=float, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        serve(
            vault_path=args.vault,
            socket_path=args.socket,
            idle_timeout_seconds=args.idle_timeout_seconds,
        )
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
