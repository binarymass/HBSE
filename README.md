# HBSE

**Hardware Bound Secrets Enclave**

HBSE is a Rust-native local secrets vault and broker for workstation and service-host credentials. It keeps raw API keys, tokens, passwords, and other credentials out of project files, shell history, logs, and long-lived `.env` files by storing encrypted secrets in a local SQLite vault and materializing them only through explicit policy.

> **Status:** HBSE is local-first security infrastructure for development and controlled evaluation. Do not market or operate it as production-grade for high-sensitivity deployments without independent review, release signing/key custody, hardware-provider testing, and the readiness evidence appropriate for your threat model.

---

## Contents

- [What HBSE Does](#what-hbse-does)
- [Repository Layout](#repository-layout)
- [Security Model In Brief](#security-model-in-brief)
- [Install And Build](#install-and-build)
- [Quick Start](#quick-start)
- [Command Overview](#command-overview)
- [Vaults And Providers](#vaults-and-providers)
- [Secrets](#secrets)
- [Policies](#policies)
- [Tickets](#tickets)
- [MFA And Plaintext Export](#mfa-and-plaintext-export)
- [Running Commands With Secrets](#running-commands-with-secrets)
- [Dotenv Workflows](#dotenv-workflows)
- [Broker Daemon](#broker-daemon)
- [Model Provider Gateway](#model-provider-gateway)
- [Backup Recovery And Rotation](#backup-recovery-and-rotation)
- [Audit Diagnostics And Readiness](#audit-diagnostics-and-readiness)
- [Release Evidence And Signing](#release-evidence-and-signing)
- [Development](#development)
- [Known Limitations](#known-limitations)

---

## What HBSE Does

HBSE provides:

- encrypted local vault storage backed by SQLite;
- per-secret-version encryption with random data encryption keys;
- local root-key wrapping through passphrase, system fingerprint, Linux TPM2 tools, or native Linux TPM2-TSS ESAPI;
- policy-controlled secret use by consumer, purpose, delivery mode, provider assurance, MFA state, peer identity, and HTTP constraints;
- short-lived Secret Access Tickets that authorize use without containing secret material;
- a local Unix-socket broker daemon for approved same-machine consumers;
- optional loopback HTTP gateway support for model-provider credentials;
- `.env` scanning and `secret://...` reference resolution workflows;
- TOTP MFA step-up for policies and plaintext export gates;
- audit chain verification, backup/restore, recovery packages, rotation, readiness checks, release evidence, and Ed25519 release signing.

HBSE is not a cloud KMS, password manager, remote multi-tenant vault, or protection against a fully compromised live host.

---

## Repository Layout

This GitHub branch is the Rust implementation:

| Path | Purpose |
|---|---|
| `Cargo.toml` | Rust workspace manifest. |
| `Cargo.lock` | Locked Rust dependency graph. |
| `hbse/Cargo.toml` | Native `hbse` crate manifest. |
| `hbse/src/main.rs` | `hbse` CLI entry point and command dispatch. |
| `hbse/src/bin/hbse-broker.rs` | `hbse-broker` daemon entry point. |
| `hbse/src/vault.rs` | Local vault operations and high-level workflows. |
| `hbse/src/store.rs` | SQLite storage schema and persistence. |
| `hbse/src/crypto.rs`, `hbse/src/keys.rs` | Secret encryption, DEK wrapping, and key hierarchy. |
| `hbse/src/policy.rs`, `hbse/src/tickets.rs` | Policy decisions and Secret Access Tickets. |
| `hbse/src/broker_daemon.rs` | Unix-socket broker and optional HTTP gateway. |
| `hbse/src/provider*.rs` | Passphrase, TPM2, system-fingerprint, and YubiKey/PIV provider code. |
| `hbse/src/mfa.rs` | TOTP MFA support. |
| `hbse/src/audit.rs` | Chained and MACed audit events. |
| `hbse/src/backup.rs`, `hbse/src/recovery.rs`, `hbse/src/rotation.rs` | Backup, recovery package, and rotation workflows. |
| `hbse/src/release.rs` | Release evidence and Ed25519 signing. |
| `install.sh`, `uninstall.sh`, `package-local.sh` | Local install, uninstall, and bundle scripts. |

---

## Security Model In Brief

HBSE's local security model is based on these rules:

- Raw secrets should not live in `.env`, source files, shell history, logs, issue trackers, or chat transcripts.
- Project configuration should store references such as `secret://providers/openai/api-key`.
- The vault root key is wrapped by a local provider; individual secrets are encrypted with per-version DEKs.
- Policies default to deny. Consumers must be explicitly allowed for a purpose and delivery mode.
- Secret Access Tickets are authorization records, not decryption keys.
- The broker can facilitate approved use, but it does not make an untrusted host safe.
- Audit records and diagnostics are designed not to print raw secrets.
- Plaintext export is deliberately gated and should be disabled except during short maintenance windows.

Implementation details visible in the Rust code:

- secret payload encryption: AES-256-GCM;
- per-secret-version random DEKs;
- DEK wrapping: AES-256-GCM under derived KEKs;
- root-key-derived subkeys: HMAC-SHA256 counter KDF with `HBSE:v1` domain-separated labels;
- passphrase and system-fingerprint wrapping: scrypt-derived wrapping keys plus AES-GCM;
- audit integrity: chained SHA-256 event hashes plus HMAC-SHA256 MACs;
- broker socket permissions: Unix socket created with private permissions where supported.

---

## Install And Build

### Prerequisites

- Rust toolchain with Cargo.
- Linux is the primary native target today.
- Native TPM2 direct mode requires a TPM resource-manager device such as `/dev/tpmrm0` and TPM2-TSS support.
- TPM2 tools compatibility mode requires `tpm2-tools`.
- systemd is needed only if installing the broker as a service.

### Build

From the repository root:

```bash
cargo build --release
```

Binaries:

```text
target/release/hbse
target/release/hbse-broker
```

### Install For Current User

```bash
./install.sh
```

Default install location:

```text
$HOME/.local/bin/hbse
$HOME/.local/bin/hbse-broker
```

If needed, add `$HOME/.local/bin` to `PATH`.

### Install System-Wide

```bash
sudo ./install.sh --prefix /usr/local
```

### Install Broker Service

User service:

```bash
./install.sh --service user --enable-service --start-service
```

System service:

```bash
sudo ./install.sh \
  --prefix /usr/local \
  --service system \
  --service-user hbse \
  --enable-service \
  --start-service
```

### Uninstall

```bash
./uninstall.sh
```

System-wide uninstall:

```bash
sudo ./uninstall.sh --prefix /usr/local --service system
```

Vault data is not removed unless the uninstall script is run with its purge option.

### Build A Local Bundle

```bash
./package-local.sh 0.1.0
```

Expected output:

```text
target/hbse-0.1.0-native-linux.tar.gz
```

---

## Quick Start

This example creates a temporary passphrase-backed vault for local testing.

```bash
export HBSE_TEST_DIR=/tmp/hbse-quickstart
export HBSE_TEST_VAULT="$HBSE_TEST_DIR/vault.db"
export HBSE_PASSPHRASE='change-this-demo-passphrase'
mkdir -p "$HBSE_TEST_DIR"
```

Initialize the vault:

```bash
hbse --vault "$HBSE_TEST_VAULT" vault init --provider passphrase
```

Store a secret:

```bash
printf '%s' 'demo-secret-value' |
  hbse --vault "$HBSE_TEST_VAULT" secret put secret://demo/api-key --stdin --secret-type api_key
```

Create a policy that allows one local consumer to receive the secret as a child environment variable:

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

Run a command with the approved secret injected into the child process:

```bash
hbse --vault "$HBSE_TEST_VAULT" run \
  --consumer demo-tool \
  --purpose local-test \
  --secret-env TOKEN=secret://demo/api-key \
  -- sh -c 'test -n "$TOKEN" && printf "secret delivered\n"'
```

Check health:

```bash
hbse --vault "$HBSE_TEST_VAULT" doctor
hbse --vault "$HBSE_TEST_VAULT" readiness check --verify-audit
```

Clean up:

```bash
rm -rf "$HBSE_TEST_DIR"
unset HBSE_TEST_DIR HBSE_TEST_VAULT HBSE_PASSPHRASE
```

---

## Command Overview

Global options:

```text
--vault <path>    Vault database path.
--json            Emit JSON where supported.
```

Default vault path resolution:

1. `--vault <path>`;
2. `HBSE_VAULT_PATH`;
3. `$HOME/.local/share/hbse/vault.db`;
4. `vault.db` if `HOME` is unavailable.

Top-level commands:

```text
version
vault
secret
audit
policy
config
ticket
rotation
provider
model-provider
mfa
broker
dotenv
release
run
resolve
doctor
setup
lockdown
readiness
```

Use built-in help for exact flags:

```bash
hbse --help
hbse vault --help
hbse secret --help
hbse-broker --help
```

Common environment variables:

| Variable | Purpose |
|---|---|
| `HBSE_VAULT_PATH` | Default vault path override. |
| `HBSE_PASSPHRASE` | Non-interactive passphrase unlock for passphrase-backed vaults. |
| `HBSE_RECOVERY_SECRET` | Non-interactive recovery package secret. |
| `HBSE_RELEASE_KEY_PASSPHRASE` | Passphrase for encrypted release signing keys. |

---

## Vaults And Providers

Initialize with passphrase fallback:

```bash
hbse --vault vault.db vault init --provider passphrase
```

Initialize with native Linux TPM2-TSS ESAPI:

```bash
hbse --vault vault.db vault init --provider tpm2-direct --tpm-device /dev/tpmrm0
```

Initialize with the `tpm2-tools` compatibility provider:

```bash
hbse --vault vault.db vault init --provider tpm2 --tpm-device /dev/tpmrm0
```

Initialize with system fingerprint binding:

```bash
hbse --vault vault.db vault init --provider system-fingerprint
```

Inspect status:

```bash
hbse --vault vault.db vault status
hbse --vault vault.db --json vault status
```

List and test local providers:

```bash
hbse provider list
hbse --json provider list
hbse provider test-tpm2-direct --device /dev/tpmrm0
hbse provider test-tpm2 --device /dev/tpmrm0
hbse provider test-system-fingerprint
hbse provider test-yubikey-piv
```

Provider summary:

| CLI provider | Provider behavior | Assurance | Notes |
|---|---|---:|---|
| `tpm2-direct` | Native Linux TPM2-TSS ESAPI sealed object | A2 | Preferred hardware-backed Linux path when available. |
| `tpm2` | TPM2 tools bridge | A2 | Compatibility path for systems where `tpm2-tools` works. |
| `system-fingerprint` | scrypt/AES-GCM binding to local machine identifiers | A1 | Not a hardware boundary; hardware/VM identity changes can break unlock. |
| `passphrase` | scrypt/AES-GCM wrapping from a passphrase | A1 | Works without hardware; depends on passphrase strength and file protection. |
| YubiKey/PIV | Readiness detection only | A2 target | Root-key wrap/unwrap through PIV is not implemented yet. |

Enroll or rewrap a provider:

```bash
hbse --vault vault.db provider enroll passphrase --new-passphrase '<new-local-passphrase>'
hbse --vault vault.db provider enroll tpm2-direct --tpm-device /dev/tpmrm0
hbse --vault vault.db provider enroll tpm2 --tpm-device /dev/tpmrm0
hbse --vault vault.db provider enroll system-fingerprint
```

---

## Secrets

Store from stdin:

```bash
printf '%s' 'secret-value' |
  hbse --vault vault.db secret put secret://app/api-key --stdin --secret-type api_key
```

Store from a command-line value:

```bash
hbse --vault vault.db secret put secret://app/api-key \
  --secret-type api_key \
  --value 'secret-value'
```

Prefer `--stdin` for real secrets so values do not appear in shell history.

Supported secret types:

```text
api_key, access_token, refresh_token, password, passphrase, token,
mnemonic_phrase, ssh_key, private_key, certificate, credential,
json_credential, generic
```

Inspect metadata without printing the secret:

```bash
hbse --vault vault.db secret list
hbse --vault vault.db secret inspect secret://app/api-key
```

Disable or destroy:

```bash
hbse --vault vault.db secret disable secret://app/api-key
hbse --vault vault.db secret destroy \
  --reason 'credential revoked upstream' \
  secret://app/api-key
```

Plaintext retrieval is intentionally constrained. Prefer `hbse run`, `hbse dotenv run`, broker materialization, or brokered HTTP over `secret get` or `resolve`.

---

## Policies

Policies authorize specific secret use. A request must match secret reference, consumer, purpose, delivery mode, provider assurance, and any additional constraints.

Example policy for child environment delivery:

```json
{
  "policy_id": "app-local",
  "secret_refs": ["secret://app/api-key"],
  "allowed_consumers": ["app-cli"],
  "allowed_purposes": ["provider-call"],
  "allowed_delivery_modes": ["child_env"],
  "minimum_provider_assurance": "A1",
  "require_mfa": false,
  "max_ticket_ttl_seconds": 60,
  "max_uses": 1
}
```

Example policy for brokered HTTP:

```json
{
  "policy_id": "provider-http-openai",
  "secret_refs": ["secret://providers/openai/api-key"],
  "allowed_consumers": ["hbse.http-gateway.openai"],
  "allowed_purposes": ["model.chat", "model.discovery"],
  "allowed_delivery_modes": ["brokered_http"],
  "allowed_http_hosts": ["api.openai.com"],
  "allowed_http_methods": ["GET", "POST"],
  "allowed_http_path_prefixes": ["/v1/"],
  "require_https_for_brokered_http": true,
  "max_http_request_body_bytes": 10485760,
  "exportable": false,
  "minimum_provider_assurance": "A1",
  "max_ticket_ttl_seconds": 60,
  "max_uses": 1
}
```

Policy commands:

```bash
hbse --vault vault.db policy put --file policy.json
hbse --vault vault.db policy list
hbse --vault vault.db policy export policies.json
hbse policy hash --file policy.json
hbse --vault vault.db policy test \
  --secret-ref secret://app/api-key \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode child_env
```

Supported delivery modes in policy JSON:

```text
brokered_http, brokered_operation, callback, pipe, fd,
temp_file, child_env, raw, terminal_print
```

Important policy fields include allow/deny consumers, purposes, HTTP hosts/methods/path prefixes, OS UIDs, executable paths, executable SHA-256 hashes, `exportable`, `allow_unbound_plaintext_export`, `minimum_provider_assurance`, `require_mfa`, `expires_at`, `max_ticket_ttl_seconds`, and `max_uses`.

---

## Tickets

Secret Access Tickets are scoped, MACed authorization artifacts. They do not contain raw secrets, DEKs, KEKs, or the vault root key.

```bash
hbse --vault vault.db ticket issue \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode child_env \
  secret://app/api-key

hbse --vault vault.db ticket list
hbse --vault vault.db ticket inspect <ticket-id>
hbse --vault vault.db ticket validate <ticket-id> \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode child_env
hbse --vault vault.db ticket renew <ticket-id> \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode child_env
hbse --vault vault.db ticket revoke <ticket-id>
```

Consume a ticket only when plaintext output is explicitly intended:

```bash
hbse --vault vault.db ticket consume <ticket-id> \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode terminal_print \
  --allow-plaintext
```

Emergency lockdown revokes active tickets and records a critical audit event:

```bash
hbse --vault vault.db lockdown --reason 'suspected credential exposure'
```

---

## MFA And Plaintext Export

HBSE supports TOTP MFA for authenticator apps. MFA is a step-up gate for policies, broker sessions, and plaintext export; it is not a vault root-key provider.

Enroll TOTP in a private terminal:

```bash
hbse --vault vault.db mfa enroll-totp \
  --issuer HBSE \
  --account workstation \
  --show-secret
```

Verify a code:

```bash
hbse --vault vault.db mfa verify-totp 123456
hbse --vault vault.db mfa status
```

Plaintext export is disabled by default:

```bash
hbse --vault vault.db config plaintext-export status
```

Enable only for short maintenance windows:

```bash
hbse --vault vault.db config plaintext-export enable --mfa-code 123456
# perform the needed plaintext operation
hbse --vault vault.db config plaintext-export disable --mfa-code 123456
```

Resolve a secret reference after export is enabled:

```bash
hbse --vault vault.db resolve --allow-plaintext secret://app/api-key
```

Use `--allow-without-mfa` only for intentional no-MFA or emergency deployments.

---

## Running Commands With Secrets

Deliver as a child environment variable:

```bash
hbse --vault vault.db run \
  --consumer app-cli \
  --purpose provider-call \
  --secret-env API_KEY=secret://app/api-key \
  -- ./app
```

Deliver as a temp-file path in an environment variable:

```bash
hbse --vault vault.db run \
  --consumer app-cli \
  --purpose provider-call \
  --secret-file-env API_KEY_FILE=secret://app/api-key \
  -- ./app
```

Deliver as a file descriptor number in an environment variable:

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

Environment-variable delivery is convenient but can leak through process inspection, crash dumps, child logs, and debugging tools. Prefer stdin, file descriptor, temp file with narrow lifetime, or brokered HTTP where possible.

---

## Dotenv Workflows

Use references, not raw secrets:

```dotenv
APP_ENV=local
PROVIDER_API_KEY=secret://providers/example/api-key
```

Scan a dotenv file for likely raw secrets:

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

---

## Broker Daemon

Start the native Unix-socket broker:

```bash
hbse-broker \
  --vault "$HOME/.local/share/hbse/vault.db" \
  --socket "${XDG_RUNTIME_DIR:-$HOME/.local/share}/hbse/broker.sock" \
  --idle-timeout-seconds 900
```

If `--idle-timeout-seconds` is `0`, idle auto-lock is disabled.

Default broker socket resolution for `hbse broker ...` commands:

1. `--socket <path>`;
2. `HBSE_BROKER_SOCKET`;
3. `$XDG_RUNTIME_DIR/hbse/broker.sock`;
4. `$HOME/.local/share/hbse/broker.sock`.

Broker commands:

```bash
hbse broker status
hbse broker unlock --mfa-code 123456
hbse broker mfa-verify 123456
hbse broker checkout \
  --secret-ref secret://app/api-key \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode brokered_http
hbse broker materialize \
  --secret-ref secret://app/api-key \
  --consumer app-cli \
  --purpose provider-call \
  --delivery-mode terminal_print \
  --allow-plaintext
hbse broker lock
hbse broker cleanup-socket
```

Install the broker service through the CLI:

```bash
hbse --vault "$HOME/.local/share/hbse/vault.db" broker install-service \
  --scope user \
  --enable \
  --start
```

For a system service:

```bash
sudo hbse --vault /var/lib/hbse/vault.db broker install-service \
  --scope system \
  --socket /run/hbse/broker.sock \
  --service-user hbse \
  --enable \
  --start
```

The broker captures local peer identity where supported, including PID, UID, GID, executable path, command name, and executable SHA-256.

---

## Model Provider Gateway

HBSE can broker local model-provider HTTP calls so unmodified tools can point at a loopback OpenAI-compatible endpoint while HBSE injects the real upstream credential only into approved requests.

List built-in presets:

```bash
hbse model-provider list
```

Built-in presets:

```text
openai, xai, openrouter, groq, mistral, deepseek, together,
perplexity, azure-openai, anthropic, amazon-bedrock
```

Store a provider credential from an environment variable and create a non-exportable brokered-HTTP policy:

```bash
hbse --vault vault.db model-provider setup openai \
  --api-key-env PROVIDER_API_KEY \
  --listen 127.0.0.1:8787
```

You can also read the credential from stdin:

```bash
printf '%s' "$PROVIDER_API_KEY" |
  hbse --vault vault.db model-provider setup openai --stdin --listen 127.0.0.1:8787
```

Start a local gateway:

```bash
hbse-broker \
  --vault "$HOME/.local/share/hbse/vault.db" \
  --socket "$XDG_RUNTIME_DIR/hbse/broker.sock" \
  --idle-timeout-seconds 900 \
  --http-listen 127.0.0.1:8787 \
  --http-upstream-base-url https://api.openai.com/v1 \
  --http-secret-ref secret://providers/openai/api-key \
  --http-consumer hbse.http-gateway.openai \
  --http-purpose model.chat \
  --http-model-discovery-purpose model.discovery
```

Configure an OpenAI-compatible client:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
export OPENAI_API_KEY=hbse-placeholder
```

The placeholder is ignored by HBSE; it exists because many clients require an API-key setting. The gateway strips client authorization, policy-checks the request, injects the real credential upstream, and redacts known HBSE-managed secret forms from response headers/body.

The gateway should bind to loopback. Remote listen addresses require explicit `--http-allow-remote` and should be avoided unless there is a strong external network boundary.

For direct brokered HTTP without the gateway:

```bash
hbse broker provider-http \
  --secret-ref secret://providers/openai/api-key \
  --consumer app-cli \
  --purpose provider-call \
  --url https://api.openai.com/v1/models
```

---

## Backup Recovery And Rotation

Backup and restore:

```bash
hbse --vault vault.db vault backup /secure/backups/hbse-vault.zip
hbse --vault restored.db vault restore /secure/backups/hbse-vault.zip
```

Create a recovery package:

```bash
hbse --vault vault.db vault recovery-create \
  --mnemonic \
  --show-recovery-secret \
  recovery-package.json
```

Inspect a recovery package without exposing root-key material:

```bash
hbse vault recovery-inspect recovery-package.json
hbse vault recovery-inspect recovery-package.json --recovery-mnemonic '<stored-mnemonic>'
```

Recover and rewrap to a new provider:

```bash
hbse --vault recovered.db vault recover \
  --recovery-mnemonic '<stored-mnemonic>' \
  --new-provider tpm2-direct \
  --tpm-device /dev/tpmrm0 \
  recovery-package.json
```

Stage and promote a rotation:

```bash
printf '%s' 'new-secret-value' |
  hbse --vault vault.db rotation start secret://app/api-key --stdin --secret-type api_key

hbse --vault vault.db rotation list
hbse --vault vault.db rotation verify <job-id>
hbse --vault vault.db rotation promote <job-id>
hbse --vault vault.db rotation rollback <job-id>
```

Store recovery packages separately from recovery secrets or mnemonics.

---

## Audit Diagnostics And Readiness

Audit commands:

```bash
hbse --vault vault.db audit list --limit 20
hbse --vault vault.db audit export audit-export.json
hbse --vault vault.db audit verify
```

Diagnostics:

```bash
hbse setup
hbse --json setup
hbse --vault vault.db doctor
hbse --vault vault.db readiness check --verify-audit
hbse --vault vault.db readiness check --target A2 --release-dir release
```

`setup` recommends the best available local provider and prints useful initialization/service commands. `doctor` checks vault, provider, broker socket, policy, ticket, audit, and redaction readiness without printing raw secrets. `readiness check` emits JSON and exits non-zero when required checks fail.

Readiness checks are local evidence. They do not replace independent security review, release key custody, or real hardware validation.

---

## Release Evidence And Signing

Generate release evidence:

```bash
hbse release evidence \
  --output-dir release \
  --project-root . \
  --version 0.1.0
```

Generate an Ed25519 release keypair:

```bash
export HBSE_RELEASE_KEY_PASSPHRASE='<release-key-passphrase>'

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
  --artifact target/release/hbse \
  --artifact target/release/hbse-broker \
  --artifact target/hbse-0.1.0-native-linux.tar.gz
```

Verify release artifacts:

```bash
hbse release verify \
  --release-dir release \
  --public-key release/signing_public_key.pem
```

Treat the public signing key as a trust root. Pin it from a trusted channel, not only from a release archive.

---

## Development

Run tests:

```bash
cargo test
```

Run strict linting if clippy is installed:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Format:

```bash
cargo fmt --all
```

Build release binaries:

```bash
cargo build --release
```

Smoke-check the CLIs:

```bash
target/release/hbse --help
target/release/hbse-broker --help
```

---

## Known Limitations

- Linux is the primary supported native target today.
- Passphrase mode is not hardware-bound.
- System-fingerprint mode is not a hardware security boundary and can break after hardware, VM, or machine-identity changes.
- YubiKey/PIV support is readiness detection only; vault root-key wrap/unwrap through PIV is not implemented yet.
- The broker and HTTP gateway are local-first components; do not expose them as public network services.
- Environment-variable delivery can leak through process inspection, crash dumps, child logs, or debugging tools.
- A fully compromised live host, malicious approved consumer, unsafe downstream logging, or memory scraping can still expose secrets.
- Readiness evidence is useful, but it is not a substitute for independent security review.

---

## License

MIT. See `hbse/Cargo.toml` for crate license metadata.
