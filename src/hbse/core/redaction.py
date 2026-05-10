"""Redaction primitives for controlled output and audit safety."""

from __future__ import annotations

import base64
import hmac
import re
from urllib.parse import quote
from hashlib import sha256

from hbse.core.serialization import b64url_no_padding


class RedactionLeakError(ValueError):
    """Raised when a controlled output still contains a known secret."""


class RedactionEngine:
    def __init__(self, fingerprint_key: bytes, fingerprints: list[str] | None = None) -> None:
        self._fingerprint_key = fingerprint_key
        self._fingerprints = set(fingerprints or [])
        self._known_values: dict[str, bytes] = {}

    def fingerprint(self, secret: bytes) -> str:
        digest = hmac.new(self._fingerprint_key, secret, sha256).digest()
        return b64url_no_padding(digest[:18])

    def learn(self, secret: bytes) -> str:
        fingerprint = self.fingerprint(secret)
        self._fingerprints.add(fingerprint)
        self._known_values[fingerprint] = secret
        return fingerprint

    def redact_text(self, text: str) -> str:
        redacted = text
        for fingerprint, secret in self._known_values.items():
            marker = f"[REDACTED:secret:{fingerprint}]"
            for representation in self._representations(secret):
                if representation:
                    redacted = redacted.replace(representation, marker)
        redacted = self._redact_structured_patterns(redacted)
        return redacted

    def assert_no_known_secret(self, text: str) -> None:
        redacted = self.redact_text(text)
        if redacted != text:
            raise RedactionLeakError("controlled output contains a known secret")

    @staticmethod
    def _representations(secret: bytes) -> set[str]:
        values: set[str] = set()
        try:
            secret_text = secret.decode("utf-8")
            values.add(secret_text)
            values.add(quote(secret_text, safe=""))
        except UnicodeDecodeError:
            pass
        values.add(base64.b64encode(secret).decode("ascii"))
        values.add(base64.urlsafe_b64encode(secret).decode("ascii").rstrip("="))
        return values

    @staticmethod
    def _redact_structured_patterns(text: str) -> str:
        patterns = [
            (re.compile(r"(?i)(Authorization:\s*Bearer\s+)[^\s,;]+"), r"\1[REDACTED:bearer]"),
            (re.compile(r'(?i)(password=)(["\']?)[^;&\s"\']+(\2)'), r"\1\2[REDACTED]\3"),
            (re.compile(r'(?i)(token=)(["\']?)[^;&\s"\']+(\2)'), r"\1\2[REDACTED]\3"),
            (re.compile(r'(?i)(api[_-]?key=)(["\']?)[^;&\s"\']+(\2)'), r"\1\2[REDACTED]\3"),
            (re.compile(r'(?i)("?(?:password|token|api[_-]?key)"?\s*:\s*")[^"]+(")'), r"\1[REDACTED]\2"),
        ]
        redacted = text
        for pattern, replacement in patterns:
            redacted = pattern.sub(replacement, redacted)
        return redacted
