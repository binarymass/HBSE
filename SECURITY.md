# HBSE Security Policy

This file defines security assumptions, supported usage boundaries, vulnerability reporting expectations, and unsafe modes for HBSE.

---

## Security Objective

HBSE protects software secrets by combining encrypted vault storage, hardware-bound root-key protection, per-secret encryption keys, policy-controlled access, short-lived access tickets, audit logging, and redaction.

The system is designed to reduce the blast radius of stolen project folders, copied vault databases, plaintext `.env` files, accidental logs, and unauthorized local or remote access attempts.

---

## Supported Secret Types

HBSE may store:

- API keys.
- OAuth tokens.
- Database credentials.
- SSH private keys.
- TLS private keys.
- Webhook signing secrets.
- Cloud provider credentials.
- Application-specific opaque secrets.
- Binary secret blobs.

HBSE should not be used as a general human password manager unless a dedicated product mode is designed for that purpose.

---

## Core Safety Rules

HBSE production builds must enforce the following:

- Raw secrets must not be written to disk.
- Raw secrets must not appear in audit logs.
- Raw secrets must not appear in CLI output unless explicitly authorized.
- Raw secrets must not be stored in `.env` files.
- Secret access tickets must not contain cryptographic storage keys.
- Every stored secret must have its own data encryption key.
- Provider downgrade must be visible and auditable.
- Recovery must be auditable.
- A copied vault file must not decrypt on an unauthorized host.

---

## Threats HBSE Reduces

| Threat | Mitigation |
|---|---|
| Copied project directory | `.env` files contain references, not values. |
| Copied encrypted vault database | Vault root key requires authorized provider or recovery path. |
| Accidental secret logging | Redaction filters controlled output. |
| Unauthorized consumer process | Broker policy and consumer identity checks deny access. |
| Ticket replay | Tickets are short-lived, scoped, and revocable. |
| Vault metadata tampering | Associated data and policy hashes detect tampering. |
| Backup leakage | Backups contain encrypted records only. |

---

## Residual Risks

HBSE cannot fully protect against:

- root or administrator compromise of a live, unlocked machine;
- memory scraping of authorized broker or consumer processes;
- malicious approved consumers that intentionally leak secrets;
- intentionally enabled raw export;
- supply-chain compromise in dependencies;
- unsafe operational policies;
- hardware provider vulnerabilities outside the system's control;
- physical attacks outside the selected provider's threat model.

These risks must be communicated in product documentation and deployment guidance.

---

## Unsafe Modes

The following modes are permitted only with explicit policy, audit, and warnings:

| Mode | Risk |
|---|---|
| Raw terminal printing | Highest leakage risk. |
| Raw REST response | High leakage risk. |
| Bulk raw export | High blast radius. |
| Child-process environment injection | Environment variables may leak via process inspection, child processes, dumps, or logs. |
| Long-lived tickets | Increased replay risk. |
| Passphrase-only provider | Susceptible to offline attack if vault material is copied. |
| Strict PCR mode without recovery | Legitimate firmware or boot updates can lock out access. |

---

## Vulnerability Reporting Template

When reporting a vulnerability, include:

- HBSE version and assurance level.
- Operating system and hardware provider.
- Deployment mode: CLI, broker, API, or SDK.
- Steps to reproduce.
- Expected result.
- Actual result.
- Whether raw secret material was exposed.
- Logs or traces with secrets redacted.
- Severity assessment if known.

---

## Severity Guide

| Severity | Example |
|---|---|
| Critical | Raw secret disclosure without authorization; vault decrypts on unauthorized machine; ticket decrypts secret by itself. |
| High | Policy bypass; audit tampering not detected; provider identity not verified. |
| Medium | Redaction miss in non-default path; unsafe downgrade warning missing. |
| Low | Documentation issue, non-sensitive metadata leakage, non-security crash. |

---

## Production Release Rule

A release must not be called production-grade until it satisfies the project's production assurance gates, including crypto protocol lock, test vectors, provider identity verification, backup recovery drill, signed artifacts, SBOM, and independent security review for high-assurance external releases.
