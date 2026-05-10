# HBSE Rust Port Plan

This tree contains the native HBSE implementation work.

The current Python implementation remains the executable reference while the native implementation is brought up to parity. The port should preserve protocol contracts first, then replace runtime surfaces incrementally.

## Current Milestone

Implemented:

- canonical JSON helpers;
- base64url helpers;
- policy model and deny-by-default evaluator;
- Secret Access Ticket issue/validate/consume/revoke;
- audit event append and hash-chain verification;
- keyed redaction fingerprint generation and persistence;
- redaction engine support for known secret encodings and structured token/password patterns;
- key hierarchy and secret encryption/decryption;
- passphrase provider root-key wrapping;
- TPM2 `tpm2-tools` bridge detect/test/seal/unseal provider;
- provider enrollment/rewrap between passphrase and TPM2 providers;
- backup/restore package with manifest hash verification;
- encrypted recovery package creation and provider rewrap recovery;
- SQLite vault store with the Python-compatible table layout;
- persisted audit chain with verification;
- `hbse version`;
- `hbse vault init/status`;
- `hbse vault init --provider tpm2`;
- `hbse vault backup/restore`;
- `hbse vault recovery-create/recover`;
- `hbse secret put/list/inspect/get/disable/destroy`;
- `hbse audit list/export/verify`;
- `hbse policy put/list/export/hash/test`;
- `hbse ticket issue/list/inspect/revoke/consume`;
- `hbse run` with policy-gated child environment, stdin pipe, inherited fd,
  and temp-file materialization;
- `hbse rotation start/verify/promote/rollback/list`;
- `hbse provider detect/test-tpm2/enroll`.
- separate `hbse-broker` daemon binary;
- `hbse broker status/unlock/lock/checkout/materialize` client commands;
- broker provider-HTTP credential injection and response redaction;
- `hbse broker install-service` systemd unit generation/install support;
- `hbse dotenv scan/run` with policy-gated `secret://` child environment materialization;
- `hbse release evidence/keygen/sign/verify` release evidence generation plus
  Ed25519 artifact manifest signing and verification, including encrypted
  private-key PEM support via `HBSE_RELEASE_KEY_PASSPHRASE`;
- `hbse doctor` local diagnostics for vault, provider, store, policy, ticket, audit,
  and redaction state;
- `hbse readiness check` local readiness gate report with optional audit-chain
  verification and release evidence checks;
- `hbse lockdown` emergency ticket revocation.

## Local Product Parity Target

The first native target is the current local product surface:

- vault init/status;
- passphrase provider;
- TPM provider;
- secret put/list/inspect/get/rotate/disable/destroy;
- policy create/evaluate;
- ticket list/inspect/issue/revoke;
- audit list/export/verify;
- child-process run command with environment, stdin pipe, inherited fd, and temp-file delivery;
- broker daemon over Unix socket;
- provider-gateway HTTP;
- dotenv scan/run;
- systemd service install;
- release signing and verification.
- diagnostics/readiness gates;
- emergency ticket lockdown.
- recovery package creation and rewrap.
- native Linux tarball packaging via `rust/package-local.sh`.

## Compatibility Rules

- Match canonical serialization semantics.
- Match KDF labels and protocol-bound payloads.
- Match policy decisions and denial reasons where practical.
- Match ticket payloads and MAC validation.
- Match audit event payloads, hash rules, and MAC validation.
- Match broker JSON IPC command shapes.
- Use Python-generated fixtures for cross-implementation tests.

## Deferred For Later

- enterprise remote API;
- multi-user/team administration;
- cloud KMS providers;
- production gRPC server;
- broader cross-platform provider matrix.
