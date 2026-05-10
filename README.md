# HBSE

Hardware Bound Secrets Enclave

HBSE is a local secrets vault and broker for protecting software credentials on a workstation or service host. It stores secrets encrypted at rest, binds vault unlock to a local provider such as Linux TPM2 or a passphrase fallback, and only materializes secrets through explicit policy.

HBSE is not specific to AI systems. It can be used by developer tools, local services, automation, CI jobs, desktop applications, and agent harnesses that need credentials without keeping raw API keys, tokens, or passwords in project files, shell history, logs, or long-lived environment files.

## Current Implementation

This repository contains:

- Native Rust CLI: `hbse`.
- Native Rust broker daemon: `hbse-broker`.
- Python package with CLI, broker daemon, SDK modules, and REST API code.
- Linux TPM2 provider support through native TPM2-TSS ESAPI bindings, with a `tpm2-tools` fallback provider retained for compatibility.
- System fingerprint provider support for machines without TPM hardware.
- YubiKey/PIV provider detection for hardware-token readiness checks.
- Passphrase provider fallback for systems without TPM hardware.
- TOTP MFA step-up support for authenticator apps.
- SQLite-backed encrypted local vault storage.
- Policy, ticket, audit, backup, recovery, rotation, dotenv, release, readiness, and systemd support.
- Versioned protobuf contract under `proto/`.
- Systemd service/socket templates under `packaging/systemd/`.
- Release evidence commands that generate artifacts into a local release directory.
- Local security model in `LOCAL_SECURITY_MODEL.md`.

The native local implementation is the primary runtime path. The Python package remains in the repository for API/SDK work and compatibility testing.

## What HBSE Provides

- Encrypted local vault storage.
- Per-secret random data encryption keys.
- Vault root key protection by TPM2, system fingerprint, or passphrase.
- Policy-controlled secret access by consumer, purpose, and delivery mode.
- Optional policy-level TOTP MFA requirement.
- Short-lived Secret Access Tickets.
- Local broker daemon for same-machine tools and services.
- Dotenv compatibility using `secret://` references.
- Secret delivery to child environment variables, temp files, file descriptors, stdin, broker materialization, and brokered provider HTTP.
- Audit chain export and verification without raw secret values.
- Backup, restore, encrypted recovery packages, provider rewrap, and staged rotation.
- Local diagnostics and readiness checks.
- Release evidence generation, Ed25519 signing, and release verification.
- Systemd service installation for the broker daemon.

## Security Model

HBSE is built around these rules:

- Secrets are encrypted at rest.
- `.env` files should contain references such as `secret://project/api-key`, not raw credentials.
- Policy defaults to deny.
- Secret Access Tickets authorize use but do not contain decryption keys.
- The broker facilitates approved credential use; it does not orchestrate application workflows.
- Audit records must not contain raw secrets.
- Recovery material must be protected separately from the vault.
- Passphrase mode works without TPM hardware, but it is not hardware-bound.

See [SECURITY.md](SECURITY.md) before using HBSE with sensitive credentials.
See [LOCAL_SECURITY_MODEL.md](LOCAL_SECURITY_MODEL.md) for the local threat model and provider tradeoffs.

## Repository Layout

| Path | Purpose |
|---|---|
| `README.md` | User-facing usage and operations manual. |
| `SECURITY.md` | Security assumptions, unsafe modes, and reporting guidance. |
| `MANIFEST.md` | Release repository contents. |
| `rust/` | Native Rust implementation and bundle script. |
| `src/hbse/` | Python package, API, SDK, and compatibility implementation. |
| `tests/` | Python test suite. |
| `proto/` | Versioned protobuf contract. |
| `packaging/systemd/` | Broker service/socket templates. |
| `release/` | Generated release evidence output. This directory is intentionally ignored. |

Working specifications, internal notes, chat history, local vaults, build output, and local environment files are intentionally not tracked.

## Build And Install

Install the native binaries for the current user:

```bash
rust/install.sh
```

Get a local setup recommendation:

```bash
hbse setup
hbse --json setup
```

Install the native binaries and enable the user broker service:

```bash
rust/install.sh --service user --enable-service --start-service
```

Install system-wide:

```bash
sudo rust/install.sh --prefix /usr/local
```

Install system-wide with a system broker service:

```bash
sudo rust/install.sh \
  --prefix /usr/local \
  --service system \
  --service-user hbse \
  --enable-service \
  --start-service
```

Build the native bundle from the repository root:

```bash
rust/package-local.sh 0.1.0
```

Expected artifact:

```text
rust/target/hbse-0.1.0-native-linux.tar.gz
```

Extract and verify:

```bash
tar -xzf rust/target/hbse-0.1.0-native-linux.tar.gz -C /tmp
cd /tmp/hbse-0.1.0-native-linux
sha256sum -c SHA256SUMS
bin/hbse --help
bin/hbse-broker --help
```

Use directly:

```bash
export PATH=/tmp/hbse-0.1.0-native-linux/bin:$PATH
hbse --help
```

Build native release binaries without packaging:

```bash
cd rust
cargo build --release
```

The resulting binaries are:

```text
rust/target/release/hbse
rust/target/release/hbse-broker
```

Uninstall user-level binaries and broker units:

```bash
rust/uninstall.sh
```

Uninstall system-level binaries and broker units:

```bash
sudo rust/uninstall.sh --prefix /usr/local --service system
```

The uninstaller does not delete vault data unless `--purge-vault` is supplied.

## Python Package

Create a virtual environment and install the Python package:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test,api]'
```

Run Python tests:

```bash
.venv/bin/python -m pytest -q
```

The Python package exposes console scripts:

```text
hbse
hbse-broker
```

The Python package also contains REST API and SDK modules. The native Rust binary is currently focused on local CLI and broker workflows.

## Command Overview

The native `hbse` command exposes these groups:

```text
version
vault
secret
audit
policy
ticket
rotation
provider
broker
dotenv
release
run
doctor
lockdown
readiness
```

Global options:

```text
--vault <path>    Vault database path.
--json            Emit JSON where supported.
```

The default vault path is:

```text
~/.local/share/hbse/vault.db
```

Override it per command:

```bash
hbse --vault /path/to/vault.db vault status
```

Or with an environment variable:

```bash
export HBSE_VAULT_PATH=/path/to/vault.db
```

Common environment variables:

| Variable | Purpose |
|---|---|
| `HBSE_VAULT_PATH` | Default vault path override. |
| `HBSE_PASSPHRASE` | Non-interactive passphrase-provider unlock. |
| `HBSE_RECOVERY_SECRET` | Non-interactive recovery package secret. |
| `HBSE_RELEASE_KEY_PASSPHRASE` | Release signing key passphrase. |

## Quick Start

Create a test vault:

```bash
export HBSE_TEST_DIR=/tmp/hbse-quickstart
export HBSE_TEST_VAULT="$HBSE_TEST_DIR/vault.db"
export HBSE_PASSPHRASE='change this local test passphrase'
mkdir -p "$HBSE_TEST_DIR"
```

Initialize with passphrase fallback:

```bash
hbse --vault "$HBSE_TEST_VAULT" vault init --provider passphrase
```

Store a secret:

```bash
printf 'example-secret-value' |
  hbse --vault "$HBSE_TEST_VAULT" secret put secret://demo/api-key --stdin
```

Create a policy allowing a local command to receive the secret through an environment variable:

```bash
cat > "$HBSE_TEST_DIR/policy.json" <<'JSON'
{
  "policy_id": "demo-child-env",
  "secret_refs": ["secret://demo/api-key"],
  "allowed_consumers": ["demo-tool"],
  "allowed_purposes": ["local-test"],
  "allowed_delivery_modes": ["child_env"],
  "minimum_provider_assurance": "A0",
  "max_ticket_ttl_seconds": 60,
  "max_uses": 1
}
JSON

hbse --vault "$HBSE_TEST_VAULT" policy put --file "$HBSE_TEST_DIR/policy.json"
```

Run a command with only that approved secret:

```bash
hbse --vault "$HBSE_TEST_VAULT" run \
  --consumer demo-tool \
  --purpose local-test \
  --secret-env TOKEN=secret://demo/api-key \
  -- sh -c 'printf "%s\n" "$TOKEN"'
```

Inspect health:

```bash
hbse --vault "$HBSE_TEST_VAULT" doctor
hbse --vault "$HBSE_TEST_VAULT" readiness check --verify-audit
```

## TPM2 Provider

Check native TPM availability:

```bash
hbse provider test-tpm2-direct --device /dev/tpmrm0
```

Check TPM availability through the compatibility `tpm2-tools` bridge:

```bash
hbse provider test-tpm2 --device /dev/tpmrm0
```

Initialize a TPM-backed vault using native TPM2-TSS ESAPI bindings:

```bash
hbse --vault vault.db vault init \
  --provider tpm2-direct \
  --tpm-device /dev/tpmrm0
```

Initialize a TPM-backed vault using the compatibility `tpm2-tools` provider:

```bash
hbse --vault vault.db vault init \
  --provider tpm2 \
  --tpm-device /dev/tpmrm0
```

Passphrase-backed vaults operate without TPM hardware:

```bash
hbse --vault vault.db vault init --provider passphrase
```

Provider detection:

```bash
hbse provider list
hbse --json provider list
hbse provider detect
```

`provider list` inventories the local provider surface. It reports whether each provider is available, whether it supports vault binding today, and whether it is hardware-backed. `provider detect` is retained as the `tpm2-tools` compatibility check.

Provider enrollment and rewrap:

```bash
hbse --vault vault.db provider enroll passphrase --new-passphrase 'new local passphrase'
hbse --vault vault.db provider enroll tpm2-direct --tpm-device /dev/tpmrm0
hbse --vault vault.db provider enroll tpm2 --tpm-device /dev/tpmrm0
hbse --vault vault.db provider enroll system-fingerprint
```

The `tpm2-direct` provider stores the vault root key as a TPM sealed object using native TPM2-TSS ESAPI calls. It requires a Linux TPM resource manager device such as `/dev/tpmrm0` and the system TPM2-TSS libraries. The `tpm2` provider remains available for systems where the direct provider is not usable but `tpm2-tools` works.

## Local Diagnostics

```bash
hbse setup
hbse doctor
hbse readiness check --verify-audit
```

`setup` recommends the best available local provider and prints commands to initialize the vault and install the broker service. `doctor` reports local vault, provider, broker socket, policy, ticket, audit, and redaction readiness without printing secret values.

## System Fingerprint Provider

The `system-fingerprint` provider binds the vault root key to stable local machine identifiers such as machine ID and DMI identifiers. It is intended for systems that do not have TPM hardware or an external hardware token, but still want copied-vault resistance beyond passphrase-only storage.

This provider is not a hardware security boundary. A privileged local attacker may be able to read or clone the same identifiers. It is assigned A1 assurance and should be treated as stronger than standalone passphrase ergonomically, but weaker than TPM-backed binding.

Check availability:

```bash
hbse provider test-system-fingerprint
```

Initialize a system-fingerprint-bound vault:

```bash
hbse --vault vault.db vault init --provider system-fingerprint
```

Recover or rewrap to this provider:

```bash
hbse --vault vault.db provider enroll system-fingerprint

hbse --vault recovered.db vault recover \
  --recovery-secret 'store separately' \
  --new-provider system-fingerprint \
  recovery-package.json
```

Because this binding depends on local system identity, motherboard replacement, VM cloning, OS machine-ID changes, or hardware inventory changes can prevent unlock. Keep a separate recovery package.

## External Hardware Token Providers

HBSE currently includes YubiKey/PIV readiness detection:

```bash
hbse provider test-yubikey-piv
```

This checks for common YubiKey/PIV tooling such as `ykman`, OpenSC `opensc-tool`/`pkcs11-tool`, or `piv-tool`, and reports whether a compatible token appears present. It does not yet wrap or unwrap the vault root key through a YubiKey/PIV private key.

The intended production direction for this provider is:

- generate or select a PIV key slot on the token;
- wrap the vault root key to the token-backed public key;
- require token presence and PIN/touch policy for unwrap;
- store only public key identity and wrapped vault material in the HBSE vault header.

Until that cryptographic path is implemented and tested against real hardware, use TPM2 for hardware-backed local binding or `system-fingerprint` for non-hardware copied-vault resistance.

## Vault Commands

Initialize:

```bash
hbse --vault vault.db vault init --provider passphrase
hbse --vault vault.db vault init --provider tpm2-direct --tpm-device /dev/tpmrm0
hbse --vault vault.db vault init --provider tpm2 --tpm-device /dev/tpmrm0
hbse --vault vault.db vault init --provider system-fingerprint
```

Status:

```bash
hbse --vault vault.db vault status
hbse --vault vault.db --json vault status
```

Backup:

```bash
hbse --vault vault.db vault backup /secure/backups/hbse-vault-backup.json
```

Restore:

```bash
hbse --vault restored.db vault restore /secure/backups/hbse-vault-backup.json
```

Create an encrypted recovery package:

```bash
hbse --vault vault.db vault recovery-create --recovery-secret 'store separately' recovery-package.json
```

Create a recovery package protected by a generated mnemonic phrase:

```bash
hbse --vault vault.db vault recovery-create --mnemonic recovery-package.json
```

The mnemonic is shown once. Store it separately from the recovery package. The mnemonic alone is not enough to recover the vault; it unlocks the recovery package, which can then rewrap the vault root key to a new provider.

Recover and rewrap to a new provider:

```bash
hbse --vault recovered.db vault recover \
  --recovery-secret 'store separately' \
  --new-provider passphrase \
  --new-passphrase 'new local passphrase' \
  recovery-package.json
```

Recover with a mnemonic:

```bash
hbse --vault recovered.db vault recover \
  --recovery-mnemonic 'anchor ... zircon' \
  --new-provider passphrase \
  --new-passphrase 'new local passphrase' \
  recovery-package.json
```

Inspect a recovery package without exposing the recovered root key:

```bash
hbse vault recovery-inspect recovery-package.json
hbse vault recovery-inspect recovery-package.json --recovery-mnemonic 'anchor ... zircon'
```

## Secret Commands

Store a secret from stdin:

```bash
printf 'secret-value' | hbse --vault vault.db secret put secret://app/api-key --stdin
```

Store with an explicit value:

```bash
hbse --vault vault.db secret put secret://app/api-key \
  --secret-type api_key \
  --value 'secret-value'
```

Supported secret types are `api_key`, `access_token`, `refresh_token`, `password`, `passphrase`, `token`, `mnemonic_phrase`, `ssh_key`, `private_key`, `certificate`, `credential`, `json_credential`, and `generic`.

List and inspect metadata:

```bash
hbse --vault vault.db secret list
hbse --vault vault.db secret inspect secret://app/api-key
```

Disable a secret:

```bash
hbse --vault vault.db secret disable secret://app/api-key
```

Destroy a secret record:

```bash
hbse --vault vault.db secret destroy \
  --reason 'credential revoked upstream' \
  secret://app/api-key
```

Raw secret retrieval is intentionally constrained. Prefer `hbse run`, broker materialization, or provider HTTP instead of printing raw secrets.

## Policy Commands

Policies authorize consumers to use specific secrets for specific purposes and delivery modes.

Example policy:

```json
{
  "policy_id": "app-local",
  "secret_refs": ["secret://app/api-key"],
  "allowed_consumers": ["app-cli"],
  "allowed_purposes": ["provider-call"],
  "allowed_delivery_modes": ["child_env", "brokered_http"],
  "minimum_provider_assurance": "A0",
  "require_mfa": false,
  "max_ticket_ttl_seconds": 60,
  "max_uses": 1
}
```

Set `"require_mfa": true` to require a verified authenticator-app TOTP code before the policy can issue tickets or materialize secrets.

Install a policy:

```bash
hbse --vault vault.db policy put --file policy.json
```

List policies:

```bash
hbse --vault vault.db policy list
```

Export policies:

```bash
hbse --vault vault.db policy export policies.json
```

Hash a policy file:

```bash
hbse policy hash --file policy.json
```

Test a policy decision:

```bash
hbse --vault vault.db policy test \
  --secret-ref secret://app/api-key \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode child_env
```

## MFA

HBSE supports TOTP MFA for authenticator apps such as Microsoft Authenticator, Google Authenticator, 1Password, or compatible TOTP clients. MFA is a step-up gate for policy and broker use; it is not a vault root-key provider.

Enroll TOTP:

```bash
hbse --vault vault.db mfa enroll-totp --issuer HBSE --account workstation
```

The enrollment output includes an `otpauth://` URI and Base32 seed. Add it to the authenticator app immediately. HBSE stores the TOTP seed encrypted inside the vault, not as clear database metadata.

Verify a code:

```bash
hbse --vault vault.db mfa verify-totp 123456
```

Check enrollment status:

```bash
hbse --vault vault.db mfa status
```

## Running Commands With Secrets

Deliver a secret as an environment variable:

```bash
hbse --vault vault.db run \
  --consumer app-cli \
  --purpose provider-call \
  --mfa-code 123456 \
  --secret-env API_KEY=secret://app/api-key \
  -- ./app
```

Deliver a secret path through an environment variable:

```bash
hbse --vault vault.db run \
  --consumer app-cli \
  --purpose provider-call \
  --secret-file-env API_KEY_FILE=secret://app/api-key \
  -- ./app
```

Deliver a file descriptor number through an environment variable:

```bash
hbse --vault vault.db run \
  --consumer app-cli \
  --purpose provider-call \
  --secret-fd-env API_KEY_FD=secret://app/api-key \
  -- ./app
```

Deliver one secret to child stdin:

```bash
hbse --vault vault.db run \
  --consumer app-cli \
  --purpose provider-call \
  --secret-stdin secret://app/api-key \
  -- ./app
```

Set ordinary non-secret environment variables:

```bash
hbse --vault vault.db run \
  --consumer app-cli \
  --purpose provider-call \
  --env APP_ENV=local \
  --secret-env API_KEY=secret://app/api-key \
  -- ./app
```

## Dotenv Workflows

`.env` files should hold references, not raw secrets:

```dotenv
APP_ENV=local
OPENAI_API_KEY=secret://providers/openai/api-key
```

Scan a dotenv file:

```bash
hbse dotenv scan .env
```

Run a command with references resolved through policy:

```bash
hbse --vault vault.db dotenv run \
  --consumer app-cli \
  --purpose provider-call \
  .env \
  -- ./app
```

If likely raw secrets are detected, the scanner fails so the file can be corrected.

## Tickets

Secret Access Tickets are short-lived authorization artifacts. They do not contain raw secrets, vault root key material, DEKs, or KEKs. Native tickets are MACed, scoped to a vault, secret reference, secret version, consumer, purpose, delivery mode, policy hash, and available local context such as OS user, executable identity, HTTP request context, and broker session.

Issue a ticket:

```bash
hbse --vault vault.db ticket issue \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode child_env \
  secret://app/api-key
```

List and inspect tickets:

```bash
hbse --vault vault.db ticket list
hbse --vault vault.db ticket inspect <ticket-id>
```

Validate a ticket without materializing the secret:

```bash
hbse --vault vault.db ticket validate <ticket-id> \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode child_env
```

Renew a valid ticket. Renewal issues a new ticket and revokes the old ticket:

```bash
hbse --vault vault.db ticket renew <ticket-id> \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode child_env
```

Revoke a ticket:

```bash
hbse --vault vault.db ticket revoke <ticket-id>
```

At consumption time HBSE re-validates the ticket MAC, expiration, revocation state, remaining uses, request context, active policy hash, and active secret version. If the policy changed incompatibly, the ticket is stale, or the secret has rotated to a newer active version, materialization is denied.

Emergency lockdown revokes active tickets and records a critical audit event:

```bash
hbse --vault vault.db lockdown --reason 'suspected credential exposure'
```

## Broker Daemon

Start the native broker:

```bash
hbse-broker \
  --vault "$HOME/.local/share/hbse/vault.db" \
  --socket /tmp/hbse.sock \
  --idle-timeout-seconds 900
```

If `--idle-timeout-seconds` is `0` or omitted, the broker does not auto-lock due to inactivity.

Unlock and inspect:

```bash
hbse broker unlock --socket /tmp/hbse.sock
hbse broker mfa-verify --socket /tmp/hbse.sock 123456
hbse broker status --socket /tmp/hbse.sock
```

When `--socket` is omitted, broker commands use `HBSE_BROKER_SOCKET`, then `$XDG_RUNTIME_DIR/hbse/broker.sock`, then `$HOME/.local/share/hbse/broker.sock`.

You can also supply the MFA code during unlock:

```bash
hbse broker unlock --socket /tmp/hbse.sock --mfa-code 123456
```

Request a checkout ticket:

```bash
hbse broker checkout \
  --socket /tmp/hbse.sock \
  --secret-ref secret://app/api-key \
  --purpose provider-call \
  --delivery-mode brokered_http
```

Materialize through the broker:

```bash
hbse broker materialize \
  --socket /tmp/hbse.sock \
  --secret-ref secret://app/api-key \
  --purpose provider-call
```

Provider HTTP facilitation injects the credential internally and redacts HBSE-managed secret material from returned response data:

```bash
hbse broker provider-http \
  --socket /tmp/hbse.sock \
  --secret-ref secret://providers/openai/api-key \
  --purpose provider-call \
  --url https://api.openai.com/v1/models
```

Lock the broker:

```bash
hbse broker lock --socket /tmp/hbse.sock
```

Remove a stale socket left behind by a broker process that is no longer reachable:

```bash
hbse broker cleanup-socket
hbse broker cleanup-socket --socket /tmp/hbse.sock
```

The broker captures local peer identity such as PID, UID, GID, executable path, executable hash, and command name on supported Linux systems. Policies can use this context to restrict access.

## Systemd Service

Install the broker as a user service:

```bash
hbse --vault "$HOME/.local/share/hbse/vault.db" broker install-service \
  --scope user \
  --enable \
  --start
```

Allow a user service to start at boot before login:

```bash
sudo loginctl enable-linger "$USER"
```

Install as a system service:

```bash
sudo hbse --vault /var/lib/hbse/vault.db broker install-service \
  --scope system \
  --socket /run/hbse/broker.sock \
  --service-user hbse \
  --enable \
  --start
```

The service starts the broker process. The vault must still be unlockable by the selected provider. TPM-backed vaults can unlock without a typed passphrase when TPM policy permits it; passphrase-backed vaults require an explicit unlock path.

## Audit

List audit events:

```bash
hbse --vault vault.db audit list
hbse --vault vault.db audit list --event-type secret.stored
hbse --vault vault.db audit list --limit 20
```

Export audit events:

```bash
hbse --vault vault.db audit export audit-export.json
hbse --vault vault.db audit export audit-secret-events.json --event-type secret.materialized
```

Verify the audit chain:

```bash
hbse --vault vault.db audit verify
```

Audit events are designed to record security-relevant activity without exposing secret values.

## Rotation

Start a staged rotation:

```bash
printf 'new-secret-value' |
  hbse --vault vault.db rotation start secret://app/api-key --stdin
```

List jobs:

```bash
hbse --vault vault.db rotation list
```

Verify, promote, or rollback:

```bash
hbse --vault vault.db rotation verify <job-id>
hbse --vault vault.db rotation promote <job-id>
hbse --vault vault.db rotation rollback <job-id>
```

## Diagnostics And Readiness

Run diagnostics:

```bash
hbse --vault vault.db doctor
```

Run readiness checks:

```bash
hbse --vault vault.db readiness check
hbse --vault vault.db readiness check --verify-audit
hbse --vault vault.db readiness check --target A2 --release-dir release
```

Readiness checks do not replace external assurance work such as independent security review, release key custody, or copied-hardware TPM evidence.

## Release Evidence And Signing

Generate release evidence:

```bash
hbse release evidence \
  --output-dir release \
  --project-root . \
  --version 0.1.0
```

Generate an encrypted Ed25519 release key:

```bash
export HBSE_RELEASE_KEY_PASSPHRASE='long signing key passphrase'

hbse release keygen \
  --private-key /secure/offline/hbse-release-ed25519.pem \
  --public-key release/signing_public_key.pem \
  --encrypted
```

Sign artifacts:

```bash
hbse release sign \
  --release-dir release \
  --private-key /secure/offline/hbse-release-ed25519.pem \
  --public-key-out release/signing_public_key.pem \
  --artifact rust/target/release/hbse \
  --artifact rust/target/release/hbse-broker \
  --artifact rust/target/hbse-0.1.0-native-linux.tar.gz
```

Verify signed release artifacts:

```bash
hbse release verify \
  --release-dir release \
  --public-key release/signing_public_key.pem
```

Treat the public signing key as a trust root. Pin it from a trusted channel, not only from a release archive.

## JSON Output

Most commands support global JSON output:

```bash
hbse --json vault status
hbse --json secret list
hbse --json audit list --limit 5
```

JSON output must still follow redaction rules and should not expose raw secret values.

## Common Failure Modes

`vault is not initialized`

Initialize a vault or point `--vault`/`HBSE_VAULT_PATH` at the intended vault database.

`policy denied`

Check that the policy covers the requested secret reference, consumer, purpose, delivery mode, provider assurance, and any broker HTTP or process identity constraints.

`TPM device or provider unavailable`

Run:

```bash
hbse provider test-tpm2-direct --device /dev/tpmrm0
hbse provider test-tpm2 --device /dev/tpmrm0
```

Then verify permissions for the TPM resource manager device. The direct provider requires TPM2-TSS libraries; the compatibility provider requires `tpm2-tools`.

`HBSE broker unavailable`

Start `hbse-broker`, verify the socket path, then run:

```bash
hbse broker status
hbse broker cleanup-socket
```

`audit verification failed`

Treat this as a potential tampering or storage integrity event. Stop using the vault until the cause is understood, preserve the vault and audit export, and restore from a known-good backup if needed.

## Development

Run Python tests:

```bash
python -m pytest -q
```

Run native tests:

```bash
cd rust
cargo test
```

Build native release binaries:

```bash
cd rust
cargo build --release
```

Build the native install bundle:

```bash
rust/package-local.sh 0.1.0
```

## Production Status

HBSE should not be represented as production-grade for high-sensitivity or external deployment until the appropriate production assurance gates pass and the release artifacts are verified.

Current local functionality includes encrypted vault storage, passphrase, system fingerprint, native TPM2-TSS, and TPM2 tools providers, YubiKey/PIV readiness detection, local broker facilitation, dotenv reference workflows, policy-controlled command execution, audit verification, backup/recovery, rotation, systemd installation, and release evidence/signing. Remaining higher-assurance work includes full external hardware-token vault bindings such as YubiKey/PIV unwrap, broader cross-platform provider support, production gRPC serving, signed provider profiles, parser-aware redaction expansion, and external security review.
