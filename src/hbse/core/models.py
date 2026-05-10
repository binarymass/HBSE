"""Shared model primitives."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum


class SecretStatus(StrEnum):
    ACTIVE = "active"
    STAGED = "staged"
    DISABLED = "disabled"
    DESTROYED = "destroyed"


class SecretType(StrEnum):
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    SSH_KEY = "ssh_key"
    GENERIC = "generic"


def now_utc() -> datetime:
    return datetime.now(UTC)
