from __future__ import annotations

import pytest

from hbse.core.provider_tpm2 import LinuxTPM2ToolsProvider


def test_tpm2_provider_detects_unavailable_device(tmp_path) -> None:
    status = LinuxTPM2ToolsProvider(device_path=str(tmp_path / "missing-tpm")).detect()

    assert status.available is False
    assert status.device_accessible is False
    assert "does not exist" in status.detail


def test_tpm2_provider_rejects_identity_mismatch(monkeypatch, tmp_path) -> None:
    provider = LinuxTPM2ToolsProvider(device_path=str(tmp_path / "fake-tpm"))
    calls: list[str] = []

    monkeypatch.setattr(
        LinuxTPM2ToolsProvider,
        "detect",
        lambda self: type(
            "Status",
            (),
            {"available": True, "detail": "ok"},
        )(),
    )

    def fake_run(*args: str, capture: bool = False) -> bytes:
        calls.append(args[0])
        if args[0] == "tpm2_readpublic":
            return b"different-public-info"
        if args[0] == "tpm2_unseal":
            return b"x" * 32
        return b""

    monkeypatch.setattr(LinuxTPM2ToolsProvider, "_run", lambda self, *args, capture=False: fake_run(*args, capture=capture))

    from hbse.core.provider_tpm2 import TPM2ProviderError

    with pytest.raises(TPM2ProviderError, match="identity mismatch"):
        provider.unwrap_root_key(
            binding={
                "provider_id": "linux-tpm2-tools-seal",
                "public": "",
                "private": "",
                "public_info_sha256": "expected",
            }
        )
