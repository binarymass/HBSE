"""Nonce generation and collision tracking."""

from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Callable


NONCE_SIZE = 12


class NonceCollisionError(RuntimeError):
    """Raised when a nonce collision cannot be avoided."""


class NonceRegistry:
    """Tracks generated nonces per key scope for the running process."""

    def __init__(self, random_bytes: Callable[[int], bytes] = os.urandom) -> None:
        self._random_bytes = random_bytes
        self._seen: dict[str, set[bytes]] = defaultdict(set)

    def generate(self, scope: str, *, max_attempts: int = 16) -> bytes:
        for _ in range(max_attempts):
            nonce = self._random_bytes(NONCE_SIZE)
            if len(nonce) != NONCE_SIZE:
                raise ValueError("random source returned an invalid nonce length")
            if nonce not in self._seen[scope]:
                self._seen[scope].add(nonce)
                return nonce
        raise NonceCollisionError(f"nonce collision limit exceeded for scope {scope!r}")
