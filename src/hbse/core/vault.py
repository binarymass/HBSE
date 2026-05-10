"""High-level local vault operations for the MVP CLI."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from hashlib import sha256

from hbse.core.audit import AuditEvent, AuditManager, verify_audit_chain
from hbse.core.crypto import CryptoEngine
from hbse.core.keys import KEY_SIZE, KeyHierarchy
from hbse.core.models import SecretStatus, SecretType, now_utc
from hbse.core.policy import AccessPolicy, AccessRequest, DeliveryMode, PolicyDecision, PolicyEngine
from hbse.core.provider import PassphraseProvider
from hbse.core.provider_tpm2 import LinuxTPM2ToolsProvider, TPM2_PROVIDER_ID
from hbse.core.recovery import RecoveryManager, RecoveryPackage
from hbse.core.rotation import RotationJob, RotationJobStatus
from hbse.core.redaction import RedactionEngine
from hbse.core.serialization import b64url_no_padding, utc_millis
from hbse.core.store import SQLiteVaultStore, VaultHeader
from hbse.core.tickets import SecretAccessTicket, TicketManager, TicketValidationError


def secret_id_from_ref(secret_ref: str) -> str:
    if not secret_ref.startswith("secret://"):
        raise ValueError("secret reference must start with secret://")
    digest = sha256(secret_ref.encode("utf-8")).digest()
    return b64url_no_padding(digest[:18])


@dataclass
class LocalVault:
    store: SQLiteVaultStore
    crypto: CryptoEngine = field(default_factory=CryptoEngine)
    provider: PassphraseProvider = field(default_factory=PassphraseProvider)

    def init(
        self,
        *,
        passphrase: str | None,
        namespace_id: str = "default",
        provider_id: str = "passphrase",
        tpm_device: str = "/dev/tpmrm0",
    ) -> VaultHeader:
        vault_id = str(uuid.uuid4())
        root_key = os.urandom(KEY_SIZE)
        if provider_id == "passphrase":
            if passphrase is None:
                raise ValueError("passphrase provider requires a passphrase")
            binding = self.provider.wrap_root_key(
                vault_id=vault_id, root_key=root_key, passphrase=passphrase
            )
        elif provider_id == "tpm2":
            binding = LinuxTPM2ToolsProvider(device_path=tpm_device).wrap_root_key(
                vault_id=vault_id, root_key=root_key
            )
        else:
            raise ValueError(f"unsupported provider: {provider_id}")
        header = VaultHeader(
            vault_id=vault_id,
            namespace_id=namespace_id,
            provider_binding=binding,
            created_at=utc_millis(now_utc()),
        )
        self.store.create_vault(header)
        keys = KeyHierarchy(vault_id=vault_id, root_key=root_key)
        self._audit(keys, header, known_secrets=[]).append(
            vault_id=vault_id,
            namespace_id=namespace_id,
            event_type="vault.initialized",
            severity="info",
            decision="allow",
            metadata={"provider_id": binding["provider_id"], "assurance_level": binding["assurance_level"]},
        )
        self._persist_last_audit_event()
        return header

    def create_policy(self, policy: AccessPolicy) -> None:
        self.store.save_policy_json(policy.policy_id, policy.model_dump_json())

    def rewrap_provider(
        self,
        *,
        current_passphrase: str | None,
        new_provider: str,
        new_passphrase: str | None = None,
        tpm_device: str = "/dev/tpmrm0",
    ) -> VaultHeader:
        header, keys = self._unlock(current_passphrase)
        if new_provider == "passphrase":
            if new_passphrase is None:
                raise ValueError("new passphrase is required for passphrase provider enrollment")
            binding = self.provider.wrap_root_key(
                vault_id=header.vault_id,
                root_key=keys.root_key,
                passphrase=new_passphrase,
            )
        elif new_provider == "tpm2":
            binding = LinuxTPM2ToolsProvider(device_path=tpm_device).wrap_root_key(
                vault_id=header.vault_id,
                root_key=keys.root_key,
            )
        else:
            raise ValueError(f"unsupported provider: {new_provider}")

        updated = header.model_copy(update={"provider_binding": binding})
        self.store.update_header(updated)
        self._audit(keys, header, known_secrets=[]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="provider.rewrapped",
            severity="high",
            decision="allow",
            metadata={
                "old_provider_id": header.provider_binding.get("provider_id"),
                "new_provider_id": binding.get("provider_id"),
                "assurance_level": binding.get("assurance_level"),
            },
        )
        self._persist_last_audit_event()
        return updated

    def create_recovery_package(
        self,
        *,
        passphrase: str | None,
        recovery_secret: str,
    ) -> RecoveryPackage:
        header, keys = self._unlock(passphrase)
        package = RecoveryManager().create_package(
            vault_id=header.vault_id,
            root_key=keys.root_key,
            recovery_secret=recovery_secret,
        )
        self._audit(keys, header, known_secrets=[]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="recovery.package_created",
            severity="critical",
            decision="allow",
            metadata={"recovery_id": package.recovery_id},
        )
        self._persist_last_audit_event()
        return package

    def recover_provider_from_package(
        self,
        *,
        package: RecoveryPackage,
        recovery_secret: str,
        new_provider: str,
        new_passphrase: str | None = None,
        tpm_device: str = "/dev/tpmrm0",
    ) -> VaultHeader:
        header = self.store.load_header()
        if package.vault_id != header.vault_id:
            raise ValueError("recovery package belongs to a different vault")
        root_key = RecoveryManager().unwrap_root_key(
            package=package,
            recovery_secret=recovery_secret,
        )
        keys = KeyHierarchy(vault_id=header.vault_id, root_key=root_key)
        if new_provider == "passphrase":
            if new_passphrase is None:
                raise ValueError("new passphrase is required for passphrase recovery")
            binding = self.provider.wrap_root_key(
                vault_id=header.vault_id,
                root_key=root_key,
                passphrase=new_passphrase,
            )
        elif new_provider == "tpm2":
            binding = LinuxTPM2ToolsProvider(device_path=tpm_device).wrap_root_key(
                vault_id=header.vault_id,
                root_key=root_key,
            )
        else:
            raise ValueError(f"unsupported provider: {new_provider}")

        updated = header.model_copy(update={"provider_binding": binding})
        self.store.update_header(updated)
        self._audit(keys, header, known_secrets=[]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="recovery.used",
            severity="critical",
            decision="allow",
            metadata={
                "recovery_id": package.recovery_id,
                "new_provider_id": binding.get("provider_id"),
            },
        )
        self._persist_last_audit_event()
        return updated

    def put_secret(
        self,
        *,
        secret_ref: str,
        plaintext: bytes,
        passphrase: str | None,
        secret_type: SecretType = SecretType.GENERIC,
    ) -> int:
        header, keys = self._unlock(passphrase)
        version = (self.store.latest_version(secret_ref) or 0) + 1
        record = self.crypto.encrypt_secret(
            key_hierarchy=keys,
            namespace_id=header.namespace_id,
            secret_id=secret_id_from_ref(secret_ref),
            secret_ref=secret_ref,
            version=version,
            plaintext=plaintext,
            secret_type=secret_type,
            policy_hash="mvp-default-deny-policy",
            metadata_hash=b64url_no_padding(sha256(secret_ref.encode("utf-8")).digest()),
        )
        self.store.save_secret_record(record)
        redaction = RedactionEngine(keys.redaction_fingerprint_key())
        fingerprint = redaction.learn(plaintext)
        self.store.save_redaction_fingerprint(secret_ref, version, fingerprint)
        self._audit(keys, header, known_secrets=[plaintext]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="secret.stored",
            severity="info",
            decision="allow",
            metadata={"secret_ref": secret_ref, "secret_version": version},
        )
        self._persist_last_audit_event()
        return version

    def start_rotation(
        self,
        *,
        secret_ref: str,
        new_plaintext: bytes,
        passphrase: str | None,
        secret_type: SecretType = SecretType.GENERIC,
    ) -> RotationJob:
        header, keys = self._unlock(passphrase)
        staged_version = (self.store.latest_version(secret_ref) or 0) + 1
        staged_record = self.crypto.encrypt_secret(
            key_hierarchy=keys,
            namespace_id=header.namespace_id,
            secret_id=secret_id_from_ref(secret_ref),
            secret_ref=secret_ref,
            version=staged_version,
            plaintext=new_plaintext,
            secret_type=secret_type,
            policy_hash="mvp-default-deny-policy",
            metadata_hash=b64url_no_padding(sha256(secret_ref.encode("utf-8")).digest()),
        ).model_copy(update={"status": SecretStatus.STAGED})
        job = RotationJob.create(
            vault_id=header.vault_id,
            secret_ref=secret_ref,
            staged_version=staged_version,
            staged_record=staged_record,
        )
        self.store.save_rotation_job_json(
            job.job_id, job.secret_ref, job.status.value, job.model_dump_json()
        )
        self._audit(keys, header, known_secrets=[new_plaintext]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="rotation.started",
            severity="info",
            decision="allow",
            metadata={"job_id": job.job_id, "secret_ref": secret_ref, "staged_version": staged_version},
        )
        self._persist_last_audit_event()
        return job

    def verify_rotation(self, *, job_id: str, passphrase: str | None) -> RotationJob:
        header, keys = self._unlock(passphrase)
        job = self._load_rotation_job(job_id)
        if job.status != RotationJobStatus.STAGED:
            raise ValueError(f"rotation job is not staged: {job.status.value}")
        # Verification hook: prove the staged record decrypts with its authenticated metadata.
        self.crypto.decrypt_secret(key_hierarchy=keys, record=job.staged_record)
        verified = job.transition(RotationJobStatus.VERIFIED)
        self.store.save_rotation_job_json(
            verified.job_id, verified.secret_ref, verified.status.value, verified.model_dump_json()
        )
        self._audit(keys, header, known_secrets=[]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="rotation.verified",
            severity="info",
            decision="allow",
            metadata={"job_id": job_id, "secret_ref": job.secret_ref},
        )
        self._persist_last_audit_event()
        return verified

    def promote_rotation(self, *, job_id: str, passphrase: str | None) -> RotationJob:
        header, keys = self._unlock(passphrase)
        job = self._load_rotation_job(job_id)
        if job.status != RotationJobStatus.VERIFIED:
            raise ValueError(f"rotation job must be verified before promotion: {job.status.value}")
        plaintext = self.crypto.decrypt_secret(key_hierarchy=keys, record=job.staged_record)
        active_record = job.staged_record.model_copy(update={"status": SecretStatus.ACTIVE})
        self.store.save_secret_record(active_record)
        fingerprint = RedactionEngine(keys.redaction_fingerprint_key()).learn(plaintext)
        self.store.save_redaction_fingerprint(job.secret_ref, job.staged_version, fingerprint)
        promoted = job.transition(RotationJobStatus.PROMOTED)
        self.store.save_rotation_job_json(
            promoted.job_id, promoted.secret_ref, promoted.status.value, promoted.model_dump_json()
        )
        self._audit(keys, header, known_secrets=[plaintext]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="rotation.promoted",
            severity="high",
            decision="allow",
            metadata={"job_id": job_id, "secret_ref": job.secret_ref, "version": job.staged_version},
        )
        self._persist_last_audit_event()
        return promoted

    def rollback_rotation(self, *, job_id: str, passphrase: str | None) -> RotationJob:
        header, keys = self._unlock(passphrase)
        job = self._load_rotation_job(job_id)
        if job.status not in {RotationJobStatus.STAGED, RotationJobStatus.VERIFIED}:
            raise ValueError(f"rotation job cannot be rolled back: {job.status.value}")
        rolled_back = job.transition(RotationJobStatus.ROLLED_BACK)
        self.store.save_rotation_job_json(
            rolled_back.job_id,
            rolled_back.secret_ref,
            rolled_back.status.value,
            rolled_back.model_dump_json(),
        )
        self._audit(keys, header, known_secrets=[]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="rotation.rolled_back",
            severity="critical",
            decision="allow",
            metadata={"job_id": job_id, "secret_ref": job.secret_ref},
        )
        self._persist_last_audit_event()
        return rolled_back

    def raw_get_secret(self, *, secret_ref: str, passphrase: str | None) -> bytes:
        header, keys = self._unlock(passphrase)
        record = self.store.load_latest_secret(secret_ref)
        return self.crypto.decrypt_secret(
            key_hierarchy=keys,
            record=record,
        )

    def disable_secret(self, *, secret_ref: str, passphrase: str | None) -> None:
        header, keys = self._unlock(passphrase)
        updated = self.store.save_updated_secret_status(secret_ref, "disabled")
        self._audit(keys, header, known_secrets=[]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="secret.disabled",
            severity="high",
            decision="allow",
            metadata={"secret_ref": secret_ref, "secret_version": updated.secret_version},
        )
        self._persist_last_audit_event()

    def destroy_secret(self, *, secret_ref: str, passphrase: str | None, reason: str) -> None:
        header, keys = self._unlock(passphrase)
        updated = self.store.save_updated_secret_status(secret_ref, "destroyed")
        self._audit(keys, header, known_secrets=[]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="secret.destroyed",
            severity="critical",
            decision="allow",
            metadata={
                "secret_ref": secret_ref,
                "secret_version": updated.secret_version,
                "reason": reason,
            },
        )
        self._persist_last_audit_event()

    def issue_ticket(
        self,
        *,
        secret_ref: str,
        consumer: str,
        purpose: str,
        delivery_mode: DeliveryMode,
        passphrase: str | None,
        raw_export_requested: bool = False,
        http_host: str | None = None,
        http_scheme: str | None = None,
        http_method: str | None = None,
        http_path: str | None = None,
        http_request_body_bytes: int | None = None,
        os_uid: int | None = None,
        executable_path: str | None = None,
        executable_sha256: str | None = None,
    ) -> SecretAccessTicket:
        header, keys = self._unlock(passphrase)
        request = AccessRequest(
            secret_ref=secret_ref,
            consumer=consumer,
            purpose=purpose,
            delivery_mode=delivery_mode,
            provider_assurance=str(header.provider_binding.get("assurance_level", "A0")),
            raw_export_requested=raw_export_requested,
            http_host=http_host,
            http_scheme=http_scheme,
            http_method=http_method,
            http_path=http_path,
            http_request_body_bytes=http_request_body_bytes,
            os_uid=os_uid,
            executable_path=executable_path,
            executable_sha256=executable_sha256,
        )
        policies = [AccessPolicy.model_validate_json(raw) for raw in self.store.list_policy_json()]
        result = PolicyEngine(policies).evaluate(request)
        audit = self._audit(keys, header, known_secrets=[])
        if result.decision == PolicyDecision.DENY or result.policy is None:
            audit.append(
                vault_id=header.vault_id,
                namespace_id=header.namespace_id,
                event_type="ticket.issue_denied",
                severity="high",
                decision="deny",
                metadata={"secret_ref": secret_ref, "consumer": consumer, "reason": result.reason},
            )
            self._persist_last_audit_event()
            raise PermissionError(result.reason)

        policy_hash = b64url_no_padding(sha256(result.policy.model_dump_json().encode("utf-8")).digest())
        ticket = TicketManager(keys.ticket_mac_key()).issue(
            vault_id=header.vault_id,
            request=request,
            policy=result.policy,
            policy_hash=policy_hash,
        )
        self.store.save_ticket_json(ticket.ticket_id, ticket.model_dump_json())
        audit.append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="ticket.issued",
            severity="info",
            decision="allow",
            metadata={
                "secret_ref": secret_ref,
                "consumer": consumer,
                "purpose": purpose,
                "delivery_mode": delivery_mode.value,
                "ticket_id": ticket.ticket_id,
                "http_host": http_host,
                "http_scheme": http_scheme,
                "http_method": http_method,
                "http_path": http_path,
                "http_request_body_bytes": http_request_body_bytes,
                "os_uid": os_uid,
                "executable_path": executable_path,
                "executable_sha256": executable_sha256,
            },
        )
        self._persist_last_audit_event()
        return ticket

    def consume_ticket_for_secret(
        self,
        *,
        ticket_id: str,
        consumer: str,
        purpose: str,
        delivery_mode: DeliveryMode,
        passphrase: str | None,
        http_host: str | None = None,
        http_scheme: str | None = None,
        http_method: str | None = None,
        http_path: str | None = None,
        http_request_body_bytes: int | None = None,
        os_uid: int | None = None,
        executable_path: str | None = None,
        executable_sha256: str | None = None,
    ) -> bytes:
        header, keys = self._unlock(passphrase)
        raw_ticket = self.store.load_ticket_json(ticket_id)
        if raw_ticket is None:
            raise TicketValidationError("ticket not found")
        ticket = SecretAccessTicket.model_validate_json(raw_ticket)
        request = AccessRequest(
            secret_ref=ticket.secret_ref,
            consumer=consumer,
            purpose=purpose,
            delivery_mode=delivery_mode,
            provider_assurance=str(header.provider_binding.get("assurance_level", "A0")),
            raw_export_requested=delivery_mode in {DeliveryMode.RAW, DeliveryMode.TERMINAL_PRINT},
            http_host=http_host,
            http_scheme=http_scheme,
            http_method=http_method,
            http_path=http_path,
            http_request_body_bytes=http_request_body_bytes,
            os_uid=os_uid,
            executable_path=executable_path,
            executable_sha256=executable_sha256,
        )
        manager = TicketManager(keys.ticket_mac_key())
        updated = manager.consume(ticket, request)
        record = self.store.load_latest_secret(ticket.secret_ref)
        if record.status != SecretStatus.ACTIVE:
            self._audit(keys, header, known_secrets=[]).append(
                vault_id=header.vault_id,
                namespace_id=header.namespace_id,
                event_type="secret.access_denied",
                severity="high",
                decision="deny",
                metadata={
                    "secret_ref": ticket.secret_ref,
                    "ticket_id": ticket.ticket_id,
                    "reason": f"secret status is {record.status.value}",
                },
            )
            self._persist_last_audit_event()
            raise PermissionError(f"secret status is {record.status.value}")
        plaintext = self.crypto.decrypt_secret(key_hierarchy=keys, record=record)
        self.store.save_ticket_json(updated.ticket_id, updated.model_dump_json())
        self._audit(keys, header, known_secrets=[plaintext]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="secret.materialized",
            severity="critical" if delivery_mode in {DeliveryMode.RAW, DeliveryMode.TERMINAL_PRINT} else "info",
            decision="allow",
            metadata={
                "secret_ref": ticket.secret_ref,
                "ticket_id": ticket.ticket_id,
                "consumer": consumer,
                "purpose": purpose,
                "delivery_mode": delivery_mode.value,
                "http_host": http_host,
                "http_scheme": http_scheme,
                "http_method": http_method,
                "http_path": http_path,
                "http_request_body_bytes": http_request_body_bytes,
                "os_uid": os_uid,
                "executable_path": executable_path,
                "executable_sha256": executable_sha256,
            },
        )
        self._persist_last_audit_event()
        return plaintext

    def revoke_ticket(self, *, ticket_id: str, passphrase: str | None) -> SecretAccessTicket:
        header, keys = self._unlock(passphrase)
        raw_ticket = self.store.load_ticket_json(ticket_id)
        if raw_ticket is None:
            raise TicketValidationError("ticket not found")
        ticket = SecretAccessTicket.model_validate_json(raw_ticket)
        revoked = TicketManager(keys.ticket_mac_key()).revoke(ticket)
        self.store.save_ticket_json(revoked.ticket_id, revoked.model_dump_json())
        self._audit(keys, header, known_secrets=[]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="ticket.revoked",
            severity="high",
            decision="allow",
            metadata={"ticket_id": ticket_id, "secret_ref": ticket.secret_ref},
        )
        self._persist_last_audit_event()
        return revoked

    def revoke_all_tickets(self, *, passphrase: str | None, reason: str = "local lockdown") -> int:
        header, keys = self._unlock(passphrase)
        manager = TicketManager(keys.ticket_mac_key())
        count = 0
        for raw_ticket in self.store.list_ticket_json():
            ticket = SecretAccessTicket.model_validate_json(raw_ticket)
            if ticket.revoked:
                continue
            revoked = manager.revoke(ticket)
            self.store.save_ticket_json(revoked.ticket_id, revoked.model_dump_json())
            count += 1
        self._audit(keys, header, known_secrets=[]).append(
            vault_id=header.vault_id,
            namespace_id=header.namespace_id,
            event_type="ticket.revoked_all",
            severity="critical",
            decision="allow",
            metadata={"count": count, "reason": reason},
        )
        self._persist_last_audit_event()
        return count

    def verify_audit(self, *, passphrase: str | None) -> None:
        _header, keys = self._unlock(passphrase)
        events = [AuditEvent.model_validate_json(raw) for raw in self.store.list_audit_event_json()]
        verify_audit_chain(events, keys.audit_integrity_key())

    def _unlock(self, passphrase: str | None) -> tuple[VaultHeader, KeyHierarchy]:
        header = self.store.load_header()
        provider_id = header.provider_binding.get("provider_id")
        if provider_id == TPM2_PROVIDER_ID:
            root_key = LinuxTPM2ToolsProvider(
                device_path=str(header.provider_binding.get("device_path", "/dev/tpmrm0"))
            ).unwrap_root_key(binding=header.provider_binding)
        else:
            if passphrase is None:
                raise ValueError("passphrase is required for this vault provider")
            root_key = self.provider.unwrap_root_key(
                vault_id=header.vault_id,
                binding=header.provider_binding,
                passphrase=passphrase,
            )
        return header, KeyHierarchy(vault_id=header.vault_id, root_key=root_key)

    def _audit(
        self, keys: KeyHierarchy, header: VaultHeader, known_secrets: list[bytes]
    ) -> AuditManager:
        redaction = RedactionEngine(
            keys.redaction_fingerprint_key(), self.store.list_redaction_fingerprints()
        )
        for secret in known_secrets:
            redaction.learn(secret)
        events = [AuditEvent.model_validate_json(raw) for raw in self.store.list_audit_event_json()]
        self._pending_audit = AuditManager(keys.audit_integrity_key(), redaction, events)
        return self._pending_audit

    def _load_rotation_job(self, job_id: str) -> RotationJob:
        raw = self.store.load_rotation_job_json(job_id)
        if raw is None:
            raise ValueError("rotation job not found")
        return RotationJob.model_validate_json(raw)

    def _persist_last_audit_event(self) -> None:
        manager = getattr(self, "_pending_audit", None)
        if not manager or not manager.existing_events:
            return
        event = manager.existing_events[-1]
        self.store.save_audit_event_json(event.event_id, event.model_dump_json())
