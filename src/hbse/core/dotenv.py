"""Dotenv reference scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


SECRET_REF_PATTERN = re.compile(r"secret://[A-Za-z0-9_.:/@+-]+")
LIKELY_SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*=\s*['\"]?([^'\"\s#]{12,})"
)


@dataclass(frozen=True)
class DotenvFinding:
    line: int
    kind: str
    key: str | None
    detail: str


def scan_dotenv(path: str | Path) -> list[DotenvFinding]:
    findings: list[DotenvFinding] = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for match in SECRET_REF_PATTERN.finditer(stripped):
            key = stripped.split("=", 1)[0].strip() if "=" in stripped else None
            findings.append(DotenvFinding(line_no, "secret_ref", key, match.group(0)))
        secret_match = LIKELY_SECRET_PATTERN.search(stripped)
        if secret_match and "secret://" not in stripped:
            findings.append(
                DotenvFinding(
                    line_no,
                    "likely_raw_secret",
                    secret_match.group(1),
                    "dotenv value looks like raw secret material",
                )
            )
    return findings


def parse_dotenv(path: str | Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def split_dotenv_values(values: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    plain: dict[str, str] = {}
    refs: dict[str, str] = {}
    for key, value in values.items():
        if SECRET_REF_PATTERN.fullmatch(value):
            refs[key] = value
        else:
            plain[key] = value
    return plain, refs
