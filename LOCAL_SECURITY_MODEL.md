# HBSE Local Security Model

This document describes the current local Rust implementation.

## What HBSE Protects

HBSE is designed to keep application secrets out of project files, shell history, logs, and long-lived environment files. Secrets stored in the vault are encrypted at rest with per-secret data encryption keys. Those data encryption keys are wrapped by keys derived from the vault root key.

The vault root key is protected by a local provider:

- `tpm2-direct`: native TPM2-TSS ESAPI sealed-object binding.
- `tpm2`: compatibility provider using `tpm2-tools`.
- `system-fingerprint`: local machine-identifier binding.
- `passphrase`: passphrase-derived root-key wrapping.

The broker is a same-machine communication facilitator. It validates policy and tickets, materializes credentials only for approved requests, and redacts HBSE-managed secret material from brokered HTTP responses.

## Provider Tradeoffs

`tpm2-direct` is the preferred local hardware-backed provider on Linux systems with a TPM resource manager device such as `/dev/tpmrm0`. A copied vault database should not unwrap on another machine without the original TPM hierarchy.

`tpm2` provides similar semantics through the external `tpm2-tools` command bridge. It remains useful as a compatibility fallback.

`system-fingerprint` improves copied-vault resistance on machines without TPM hardware, but it is not a hardware security boundary. A privileged attacker may be able to read or clone the same identifiers.

`passphrase` works everywhere. Its security depends on passphrase strength, local file permissions, and whether the host is already compromised.

## What HBSE Does Not Protect

HBSE does not protect secrets from a fully compromised live host that can control the requesting process, inspect process memory, modify HBSE binaries, or abuse an already unlocked broker session.

HBSE does not make unsafe downstream tools safe. If an approved tool logs credentials after receiving them, HBSE cannot retract those logs.

HBSE does not currently provide remote attestation, enterprise key escrow, production HSM/KMS provider bindings, or external security-review assurance.

## Audit And Redaction

Audit events are designed to describe security-relevant actions without containing raw secret values. Redaction fingerprints are keyed and truncated so the audit trail can support detection/redaction without becoming a secret database.

Use:

```bash
hbse audit verify
hbse audit export audit.json
hbse doctor
hbse readiness check --verify-audit
```

## Recovery

Recovery packages can rewrap the vault root key when paired with the recovery secret or mnemonic. Store recovery packages separately from the mnemonic/passphrase. The mnemonic alone is not enough; the package alone is not enough.

Inspect a package without printing secret material:

```bash
hbse vault recovery-inspect recovery-package.json
hbse vault recovery-inspect recovery-package.json --recovery-mnemonic '...'
```

## Local Hardening Checklist

- Prefer `tpm2-direct` on systems with TPM hardware.
- Keep plaintext export disabled except for short interactive maintenance windows.
- Enroll TOTP MFA before enabling plaintext export; `--allow-without-mfa` is an explicit emergency/no-MFA override.
- Keep the vault file under a user-private directory.
- Use `hbse broker install-service --scope user --enable --start` for a managed local broker.
- Keep broker sockets under a private runtime directory.
- Verify `hbse doctor` and `hbse readiness check --verify-audit`.
- Configure explicit policies before using broker materialization or brokered provider HTTP.
- Create and test a recovery package before relying on a vault for important secrets.
- Keep raw `.env` files free of credentials; use `secret://` references.
