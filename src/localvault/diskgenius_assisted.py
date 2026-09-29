from __future__ import annotations

"""Assisted, identity-bound DiskGenius System Migration workflow."""

import hashlib
import hmac
import json
import os
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .config import load_config, paths
from .disk_clone import (
    CloneLock,
    DiskCloneBlocked,
    DiskIdentity,
    Enrollment,
    EnrollmentStore,
    VerificationResult,
    WindowsDiskInventory,
    WindowsProtectedPathResolver,
    resolved_protected_path_conflicts,
    windows_powershell_environment,
    windows_powershell_path,
)
from .clone_roles import EXPECTED_SIZE_BYTES, DiskRole, PROTECTED_ROLE, SOURCE_ROLE, TARGET_ROLE, matches_role as _matches_disk_role
from .utils import atomic_write_text


DISKGENIUS_EXE = Path(r"C:\Program Files\DiskGenius\DiskGenius.exe")
DISKGENIUS_VERSION = "6.1.1"
DISKGENIUS_PUBLISHER = "Qinhuangdao Yizhishu Software Development Co., Ltd."
CLONE_MODE = "system_migration_hot"
CLONE_MODE_LABEL = "System Migration · Hot Migration"
SESSION_FILE = "diskgenius_normal_clone_session.json"
ENROLLMENT_FILE = "diskgenius_clone_enrollment.json"
ENROLLMENT_SECRET_FILE = "diskgenius_clone_enrollment.secret"
EFI_GPT_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
BASIC_GPT_TYPE = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"


@dataclass(frozen=True)
class DiskGeniusCapabilities:
    available: bool
    executable: str
    version: str
    signature_status: str
    publisher: str
    sha256: str
    installed_edition: str = "not reported by local uninstall metadata"
    licensing: str = "System Migration is documented in DiskGenius Free Edition"
    mode: str = CLONE_MODE_LABEL
    snapshot: str = "vendor Hot Migration snapshot; VSS writer details are not exposed"
    reboot_required: bool = False
    automation: str = "assisted GUI"
    blocker: str = ""


@dataclass(frozen=True)
class DiskGeniusPreflight:
    source: DiskIdentity
    target: DiskIdentity
    protected: DiskIdentity
    source_layout_sha256: str
    protected_state_sha256: str
    inventory_at: str
    bitlocker_state: str


class DiskGeniusEnrollmentStore(EnrollmentStore):
    """Separate signed identity binding from the retired Clonezilla enrollment."""

    def __init__(self, root: Path):
        super().__init__(root)
        self.manifest_path = self.p.config / ENROLLMENT_FILE
        self.secret_path = self.p.config / ENROLLMENT_SECRET_FILE


class DiskGeniusSessionStore:
    def __init__(self, enrollment: DiskGeniusEnrollmentStore):
        self.enrollment = enrollment
        self.path = enrollment.p.logs / SESSION_FILE

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        secret = self.enrollment._secret()
        if not secret:
            raise DiskCloneBlocked("Chave de auditoria DiskGenius ausente; sessão bloqueada.", "blocked_identity")
        try:
            signed = json.loads(self.path.read_text(encoding="utf-8"))
            payload = signed["payload"]
            expected = hmac.new(secret, json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(signed.get("hmac", "")), expected):
                raise DiskCloneBlocked("Auditoria DiskGenius adulterada; nenhuma operação será iniciada.", "blocked_identity")
            if payload.get("schema") != 1 or not isinstance(payload.get("events"), list):
                raise DiskCloneBlocked("Auditoria DiskGenius inválida; nenhuma operação será iniciada.", "blocked_identity")
            return payload
        except DiskCloneBlocked:
            raise
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DiskCloneBlocked("Auditoria DiskGenius inválida; nenhuma operação será iniciada.", "blocked_identity") from exc

    def save(self, payload: dict[str, Any]) -> None:
        secret = self.enrollment._secret(create=True)
        assert secret is not None
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signed = {"payload": payload, "hmac": hmac.new(secret, body, hashlib.sha256).hexdigest()}
        atomic_write_text(self.path, json.dumps(signed, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass


class DiskGeniusNormalProvider:
    """L-vault binds persistent identities; DiskGenius performs the GUI migration."""

    def __init__(
        self,
        root: Path,
        *,
        inventory: Any | None = None,
        protected_path_resolver: Any | None = None,
        executable: Path = DISKGENIUS_EXE,
        metadata_reader: Callable[[Path], dict[str, Any]] | None = None,
        launcher: Callable[[Path], Any] | None = None,
        process_checker: Callable[[Path], bool] | None = None,
        file_verifier: Callable[[DiskIdentity], dict[str, Any]] | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.root = Path(root)
        self.p = paths(self.root)
        self.inventory = inventory or WindowsDiskInventory()
        self.protected_path_resolver = protected_path_resolver or WindowsProtectedPathResolver()
        self.executable = Path(executable)
        self.metadata_reader = metadata_reader or _read_executable_metadata
        self.launcher = launcher or _launch_elevated
        self.process_checker = process_checker or _diskgenius_is_running
        self.file_verifier = file_verifier or _verify_target_files
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.enrollment = DiskGeniusEnrollmentStore(self.root)
        self.sessions = DiskGeniusSessionStore(self.enrollment)

    def inspect_capabilities(self) -> DiskGeniusCapabilities:
        if not self.executable.is_file():
            return DiskGeniusCapabilities(False, str(self.executable), "", "NotFound", "", "", blocker="DiskGenius 6.1.1 não está instalado no caminho esperado.")
        try:
            metadata = self.metadata_reader(self.executable)
        except Exception as exc:
            return DiskGeniusCapabilities(False, str(self.executable), "", "Unknown", "", "", blocker=f"Não foi possível validar o executável DiskGenius: {type(exc).__name__}.")
        version = str(metadata.get("version", ""))
        signature = str(metadata.get("signature_status", ""))
        publisher = str(metadata.get("publisher", ""))
        sha256 = str(metadata.get("sha256", ""))
        if version != DISKGENIUS_VERSION:
            return DiskGeniusCapabilities(False, str(self.executable), version, signature, publisher, sha256, blocker=f"Versão DiskGenius divergente; esperada {DISKGENIUS_VERSION}.")
        if signature.casefold() != "valid" or DISKGENIUS_PUBLISHER.casefold() not in publisher.casefold():
            return DiskGeniusCapabilities(False, str(self.executable), version, signature, publisher, sha256, blocker="Assinatura ou publisher DiskGenius não corresponde ao esperado.")
        return DiskGeniusCapabilities(True, str(self.executable), version, signature, publisher, sha256)

    def resolve_source(self, disks: Iterable[DiskIdentity], enrollment: Enrollment | None = None) -> DiskIdentity:
        current = [disk for disk in disks if disk.is_system or disk.is_boot]
        if len(current) != 1:
            raise DiskCloneBlocked("Não foi possível identificar exatamente um disco Windows atual.", "blocked_identity")
        source = current[0]
        if not source.is_system or not source.is_boot or not _matches_role(source, SOURCE_ROLE):
            raise DiskCloneBlocked("O disco Windows atual não corresponde ao Kingston autorizado.", "blocked_identity")
        if source.identity_strength() != "strong":
            raise DiskCloneBlocked("A identidade persistente do Kingston é fraca.", "blocked_identity")
        if enrollment and not source.matches(enrollment.source):
            raise DiskCloneBlocked("A identidade persistente do Kingston mudou desde a inscrição.", "blocked_identity")
        _validate_known_kingston_layout(source)
        return source

    def resolve_target(self, disks: Iterable[DiskIdentity], source: DiskIdentity, enrollment: Enrollment | None = None) -> DiskIdentity:
        matches = [disk for disk in disks if _matches_role(disk, TARGET_ROLE)]
        if len(matches) != 1:
            raise DiskCloneBlocked("A identidade do Seagate autorizado está ausente ou ambígua.", "blocked_identity")
        target = matches[0]
        if target.identity_strength() != "strong":
            raise DiskCloneBlocked("A identidade persistente do Seagate é fraca.", "blocked_identity")
        if enrollment and not target.matches(enrollment.target):
            raise DiskCloneBlocked("A identidade persistente do Seagate mudou desde a inscrição.", "blocked_identity")
        if source.matches(target, require_strong=False) or target.number == source.number:
            raise DiskCloneBlocked("Origem e destino resolveram para o mesmo disco.", "blocked_identity")
        if any((target.is_system, target.is_boot, target.is_pagefile, target.is_crash_dump, target.is_clustered, target.is_virtual, target.is_removable, target.read_only)) or not target.online:
            raise DiskCloneBlocked("O Seagate está offline, em uso crítico, protegido ou somente leitura.", "blocked_identity")
        if target.size_bytes != source.size_bytes or target.size_bytes != EXPECTED_SIZE_BYTES:
            raise DiskCloneBlocked("A capacidade exata do Seagate não corresponde à autorização.", "blocked_size")
        if target.logical_sector_size != source.logical_sector_size or target.physical_sector_size != source.physical_sector_size:
            raise DiskCloneBlocked("A geometria lógica/física do Seagate difere da origem.", "blocked_size")
        return target

    def preflight(self) -> DiskGeniusPreflight:
        capabilities = self.inspect_capabilities()
        if not capabilities.available:
            raise DiskCloneBlocked(capabilities.blocker, "blocked_provider")
        disks = list(self.inventory.list_disks())
        enrollment = self.enrollment.load()
        if enrollment and (enrollment.provider != "diskgenius_normal" or enrollment.mode != CLONE_MODE):
            raise DiskCloneBlocked("A inscrição DiskGenius não corresponde ao modo System Migration.", "blocked_identity")
        source = self.resolve_source(disks, enrollment)
        target = self.resolve_target(disks, source, enrollment)
        protected = self._resolve_protected_disk(disks)
        if source.matches(protected, require_strong=False) or target.matches(protected, require_strong=False):
            raise DiskCloneBlocked("O disco protegido HGST foi resolvido como origem ou destino.", "blocked_protected_path")
        protected_paths = self._protected_paths()
        conflicts, _ = resolved_protected_path_conflicts(target, protected_paths, self.protected_path_resolver, inventory=disks)
        if conflicts:
            raise DiskCloneBlocked("O Seagate coincide com um caminho protegido ou uma identidade não resolvida.", "blocked_protected_path")
        return DiskGeniusPreflight(
            source=source,
            target=target,
            protected=protected,
            source_layout_sha256=_layout_hash(source),
            protected_state_sha256=_protected_state_hash(protected),
            inventory_at=self._now().isoformat(),
            bitlocker_state=source.bitlocker_state,
        )

    def launch(self) -> dict[str, Any]:
        lock = CloneLock(self.p.logs / "localvault_disk_clone.lock")
        lock.acquire(uuid.uuid4().hex)
        try:
            previous = self.sessions.load()
            if previous and previous.get("state") in {"launched", "ready_to_confirm", "clone_in_progress", "launch_unknown"}:
                raise DiskCloneBlocked("Há uma sessão DiskGenius não finalizada. Verifique o resultado antes de iniciar outra.", "blocked_identity")
            if previous and previous.get("state") == "failed_partial":
                raise DiskCloneBlocked("A tentativa anterior pode ter sobrescrito parte do Seagate. Inspecione-a antes de uma nova clonagem.", "blocked_identity")
            first = self.preflight()
            enrollment = self.enrollment.load()
            if enrollment is None:
                self.enrollment.save(first.source, first.target, "diskgenius_normal", CLONE_MODE)
            fresh = self.preflight()
            enrollment = self.enrollment.load()
            if enrollment is None or not fresh.source.matches(enrollment.source) or not fresh.target.matches(enrollment.target):
                raise DiskCloneBlocked("A revalidação após a inscrição DiskGenius falhou.", "blocked_identity")
            session = {
                "schema": 1,
                "session_id": uuid.uuid4().hex,
                "state": "launch_unknown",
                "mode": CLONE_MODE,
                "created_at": self._now().isoformat(),
                "source": _public_disk(fresh.source),
                "target": _public_disk(fresh.target),
                "protected": _public_disk(fresh.protected),
                "source_layout_sha256": fresh.source_layout_sha256,
                "protected_state_sha256": fresh.protected_state_sha256,
                "events": [],
            }
            self._event(session, "fresh_identity_preflight_passed")
            self.sessions.save(session)
            try:
                launched = self.launcher(self.executable)
            except Exception as exc:
                self._event(session, "DiskGenius_launch_failed", error=type(exc).__name__)
                self.sessions.save(session)
                raise DiskCloneBlocked("O DiskGenius não abriu. A sessão foi mantida pendente para impedir retry automático.", "blocked_provider") from exc
            session["state"] = "launched"
            session["process_id"] = int(getattr(launched, "pid", 0) or 0)
            self._event(session, "DiskGenius_opened_elevated")
            self.sessions.save(session)
            return self.monitor()
        finally:
            lock.release()

    def monitor(self) -> dict[str, Any]:
        session = self.sessions.load()
        if not session:
            return {"state": "ready", "session_id": "", "source": None, "target": None, "protected": None, "mode": CLONE_MODE_LABEL}
        state = session.get("state", "unknown")
        expires_at = session.get("overwrite_revalidation_expires_at", "")
        revalidation_expired = False
        if state == "ready_to_confirm" and expires_at:
            try:
                revalidation_expired = datetime.fromisoformat(expires_at) <= self._now()
            except ValueError:
                revalidation_expired = True
        return {
            "state": state,
            "revalidation_expired": revalidation_expired,
            "session_id": session.get("session_id", ""),
            "source": session.get("source"),
            "target": session.get("target"),
            "protected": session.get("protected"),
            "mode": CLONE_MODE_LABEL,
            "updated_at": session.get("updated_at", session.get("created_at", "")),
            "progress": "DiskGenius mostra o progresso; L-vault não infere conclusão pelo processo gráfico.",
            "verification": session.get("verification"),
        }

    def revalidate_before_overwrite(self, session_id: str, *, selected_devices_verified: bool) -> dict[str, Any]:
        lock = CloneLock(self.p.logs / "localvault_disk_clone.lock")
        lock.acquire(uuid.uuid4().hex)
        try:
            session = self.sessions.load()
            if not session or not hmac.compare_digest(str(session.get("session_id", "")), str(session_id)):
                raise DiskCloneBlocked("Sessão DiskGenius ausente ou desatualizada.", "blocked_identity")
            if session.get("state") != "launched":
                raise DiskCloneBlocked("A sessão não está pronta para revalidar o alvo.", "blocked_identity")
            if not selected_devices_verified:
                raise DiskCloneBlocked("Confirme visualmente a origem Kingston e o alvo Seagate no DiskGenius.", "blocked_identity")
            fresh = self.preflight()
            for role, disk in (("source", fresh.source), ("target", fresh.target), ("protected", fresh.protected)):
                prior = session.get(role) or {}
                current = _public_disk(disk)
                if (
                    disk.number != prior.get("disk_number")
                    or current.get("volumes") != prior.get("volumes")
                    or current.get("bitlocker_state") != prior.get("bitlocker_state")
                ):
                    raise DiskCloneBlocked("O mapeamento físico, os volumes ou o estado BitLocker mudaram desde que o DiskGenius foi aberto. Feche o assistente e recomece.", "blocked_identity")
            session["state"] = "ready_to_confirm"
            session["overwrite_revalidated_at"] = self._now().isoformat()
            session["overwrite_revalidation_expires_at"] = (self._now() + timedelta(minutes=2)).isoformat()
            self._event(session, "preoverwrite_identity_revalidated_and_gui_selection_owner_attested")
            self.sessions.save(session)
            return self.monitor()
        finally:
            lock.release()

    def cancel_before_overwrite(self, session_id: str, *, confirmed_not_started: bool) -> dict[str, Any]:
        lock = CloneLock(self.p.logs / "localvault_disk_clone.lock")
        lock.acquire(uuid.uuid4().hex)
        try:
            session = self.sessions.load()
            if not session or not hmac.compare_digest(str(session.get("session_id", "")), str(session_id)):
                raise DiskCloneBlocked("Sessão DiskGenius ausente ou desatualizada.", "blocked_identity")
            if session.get("state") not in {"launched", "ready_to_confirm", "launch_unknown"} or not confirmed_not_started:
                raise DiskCloneBlocked("Cancelamento só pode ser registrado com a sessão pendente e a confirmação de que nenhuma gravação começou.", "blocked_identity")
            try:
                if self.process_checker(self.executable):
                    raise DiskCloneBlocked("Feche o DiskGenius sem iniciar a gravação e tente registrar o cancelamento novamente.", "blocked_identity")
            except DiskCloneBlocked:
                raise
            except Exception as exc:
                raise DiskCloneBlocked("Não foi possível provar que o DiskGenius foi fechado; a sessão continua pendente.", "blocked_identity") from exc
            session["state"] = "cancelled_before_overwrite"
            self._event(session, "owner_attested_no_write_and_diskgenius_process_closed")
            self.sessions.save(session)
            return self.monitor()
        finally:
            lock.release()

    def verify(self, session_id: str, *, owner_confirmed_complete: bool) -> dict[str, Any]:
        lock = CloneLock(self.p.logs / "localvault_disk_clone.lock")
        lock.acquire(uuid.uuid4().hex)
        try:
            session = self.sessions.load()
            if not session or not hmac.compare_digest(str(session.get("session_id", "")), str(session_id)):
                raise DiskCloneBlocked("Sessão DiskGenius ausente ou desatualizada.", "blocked_identity")
            if session.get("state") not in {"ready_to_confirm", "failed_partial"}:
                raise DiskCloneBlocked("A operação precisa ter passado pela revalidação final antes da verificação.", "blocked_identity")
            if not owner_confirmed_complete:
                raise DiskCloneBlocked("Confirme que o DiskGenius informou a conclusão antes de verificar o clone.", "blocked_identity")
            try:
                if self.process_checker(self.executable):
                    raise DiskCloneBlocked("Feche o DiskGenius depois de confirmar a conclusão e reabra esta tela para verificar.", "blocked_identity")
            except DiskCloneBlocked:
                raise
            except Exception as exc:
                raise DiskCloneBlocked("Não foi possível confirmar que o DiskGenius terminou; resultado não registrado.", "blocked_identity") from exc
            fresh = self.preflight()
            source_unchanged = fresh.source_layout_sha256 == session.get("source_layout_sha256")
            protected_unchanged = fresh.protected_state_sha256 == session.get("protected_state_sha256")
            target_layout_changed = _layout_hash(fresh.target) != str((session.get("target") or {}).get("layout_sha256", ""))
            structural = verify_system_migration_layout(fresh.source, fresh.target)
            file_evidence = self.file_verifier(fresh.target) if structural.structurally_verified else {"verified": False, "reason": structural.evidence}
            success = owner_confirmed_complete and target_layout_changed and structural.structurally_verified and bool(file_evidence.get("verified")) and source_unchanged and protected_unchanged
            if success:
                state = "verified_structurally_bootable"
                bootability = "structurally_bootable"
                evidence = "Estrutura GPT, Windows, EFI, arquivos de boot, BCD e vínculo do carregador conferidos; boot físico não testado."
            else:
                state = "failed_partial"
                bootability = "unknown"
                evidence = "; ".join(item for item in (
                    "layout de origem alterado" if not source_unchanged else "",
                    "estado físico do HGST alterado" if not protected_unchanged else "",
                    "layout do alvo não difere do inventário inicial" if not target_layout_changed else "",
                    structural.evidence if not structural.structurally_verified else "",
                    str(file_evidence.get("reason", "verificação de arquivos/BCD incompleta")) if not file_evidence.get("verified") else "",
                ) if item)
            session["state"] = state
            session["verification"] = {
                "bootability": bootability,
                "source_layout_unchanged": source_unchanged,
                "protected_disk_unchanged": protected_unchanged,
                "target_layout_changed_from_preflight": target_layout_changed,
                "target_structurally_verified": structural.structurally_verified,
                "files_and_bcd_verified": bool(file_evidence.get("verified")),
                "diskgenius_completion_owner_attested": owner_confirmed_complete,
                "boot_tested": False,
                "evidence": evidence,
                "verified_at": self._now().isoformat(),
            }
            self._event(session, "post_clone_verification_completed", success=success)
            self.sessions.save(session)
            return self.monitor()
        finally:
            lock.release()

    def _resolve_protected_disk(self, disks: list[DiskIdentity]) -> DiskIdentity:
        matches = [disk for disk in disks if _matches_role(disk, PROTECTED_ROLE)]
        if len(matches) != 1 or matches[0].identity_strength() != "strong":
            raise DiskCloneBlocked("O HGST protegido está ausente, ambíguo ou sem identidade forte.", "blocked_protected_path")
        protected = matches[0]
        root_path = str(self.p.root)
        root_resolutions = [item for item in self.protected_path_resolver.resolve([Path(root_path)]) if _same_path(item.path, root_path)]
        if len(root_resolutions) != 1 or not root_resolutions[0].resolved:
            raise DiskCloneBlocked("O caminho do repositório não foi resolvido para um disco físico.", "blocked_protected_path")
        ids = {value.casefold() for value in root_resolutions[0].identifiers if value}
        path_disks = [disk for disk in disks if len(ids) >= 2 and ids.issubset({value.casefold() for value in disk.stable_identifiers()})]
        if len(path_disks) != 1 or not path_disks[0].matches(protected):
            raise DiskCloneBlocked("E:\\LocalVault não resolve para o HGST autorizado.", "blocked_protected_path")
        return protected

    def _protected_paths(self) -> list[Path]:
        config = load_config(self.root)
        clone_config = config.get("disk_clone", {})
        source_config = config.get("source_sync", {})
        values = [self.p.root]
        values.extend(Path(value) for value in clone_config.get("protected_paths", []) if str(value).strip())
        values.extend(Path(value) for value in source_config.get("google_takeout_sources", []) if str(value).strip())
        if os.name == "nt":
            system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            if system_root.exists():
                values.append(system_root)
        return values

    def _now(self) -> datetime:
        now = self.clock()
        return now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)

    def _event(self, session: dict[str, Any], name: str, **details: Any) -> None:
        allowed_details = {key: value for key, value in details.items() if key in {"success", "error"} and isinstance(value, (str, bool, int))}
        session.setdefault("events", []).append({"at": self._now().isoformat(), "event": name, **allowed_details})
        session["events"] = session["events"][-25:]
        session["updated_at"] = self._now().isoformat()


def verify_system_migration_layout(source: DiskIdentity, target: DiskIdentity) -> VerificationResult:
    if source.matches(target, require_strong=False):
        return VerificationResult(False, "origem e destino compartilham identidade persistente")
    if source.partition_style.casefold() != "gpt" or target.partition_style.casefold() != "gpt":
        return VerificationResult(False, "System Migration exige GPT na origem e no alvo neste fluxo UEFI")
    if target.size_bytes != EXPECTED_SIZE_BYTES or target.size_bytes < source.size_bytes:
        return VerificationResult(False, "capacidade final do alvo divergente")
    efi = [part for part in target.partitions if part.canonical_role == "efi" and part.filesystem.casefold() == "fat32"]
    windows = [part for part in target.partitions if part.canonical_role in {"windows", "basic_data"} and part.filesystem.casefold() == "ntfs"]
    if len(efi) != 1:
        return VerificationResult(False, "o alvo deve conter uma ESP FAT32, sem as ESPs históricas da origem")
    if len(windows) != 1:
        return VerificationResult(False, "o alvo deve conter uma partição Windows NTFS")
    return VerificationResult(True, "GPT, uma ESP FAT32 e uma partição Windows NTFS conferidos; WinRE não estava habilitado na origem", False)


def _matches_role(disk: DiskIdentity, role: DiskRole) -> bool:
    return _matches_disk_role(disk, role)


def _validate_known_kingston_layout(source: DiskIdentity) -> None:
    partitions = sorted(source.partitions, key=lambda item: item.number)
    windows = [part for part in partitions if part.number == 1 and part.canonical_role == "windows"]
    esp = [part for part in partitions if part.canonical_role == "efi"]
    if len(partitions) != 5 or len(windows) != 1 or len(esp) != 4:
        raise DiskCloneBlocked("O layout do Kingston mudou desde o boot audit; não é seguro reutilizar a decisão de migração.", "blocked_identity")
    if [part.number for part in esp] != [2, 3, 4, 5] or any(part.size_bytes != 104_857_600 for part in esp):
        raise DiskCloneBlocked("As quatro ESPs históricas do Kingston diferem do layout auditado.", "blocked_identity")
    if any(part.canonical_role in {"msr", "recovery"} for part in partitions):
        raise DiskCloneBlocked("O layout do Kingston ganhou MSR/Recovery; requer nova revisão do plano.", "blocked_identity")


def _layout_hash(disk: DiskIdentity) -> str:
    payload = {
        "partition_style": disk.partition_style,
        "disk_guid": disk.disk_guid,
        "partitions": [
            {
                "number": part.number,
                "offset_bytes": part.offset_bytes,
                "size_bytes": part.size_bytes,
                "gpt_type": part.gpt_type,
                "gpt_partition_id": part.gpt_partition_id,
                "filesystem": part.filesystem,
                "role": part.canonical_role,
            }
            for part in sorted(disk.partitions, key=lambda item: item.number)
        ],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _protected_state_hash(disk: DiskIdentity) -> str:
    payload = {
        "layout": _layout_hash(disk),
        "online": disk.online,
        "read_only": disk.read_only,
        "mount_points": sorted(disk.mount_points),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _public_disk(disk: DiskIdentity) -> dict[str, Any]:
    identity = "\n".join(disk.stable_identifiers()).encode("utf-8")
    return {
        "disk_number": disk.number,
        "model": disk.model,
        "masked_serial": disk.masked_serial,
        "size_bytes": disk.size_bytes,
        "bus_type": disk.bus_type,
        "bitlocker_state": disk.bitlocker_state,
        "volumes": sorted(disk.mount_points),
        "partition_count": len(disk.partitions),
        "identity_sha256": hashlib.sha256(identity).hexdigest(),
        "layout_sha256": _layout_hash(disk),
    }


def _same_path(left: str, right: str) -> bool:
    try:
        return os.path.normcase(str(Path(left).resolve(strict=False))) == os.path.normcase(str(Path(right).resolve(strict=False)))
    except OSError:
        return os.path.normcase(left) == os.path.normcase(right)


def _read_executable_metadata(path: Path) -> dict[str, Any]:
    request = json.dumps({"path": str(path.resolve(strict=True) if os.name == "nt" else path)}, ensure_ascii=False)
    script = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$inputObject = [Console]::In.ReadToEnd() | ConvertFrom-Json
$path = [string]$inputObject.path
$file = Get-Item -LiteralPath $path
$signature = Get-AuthenticodeSignature -LiteralPath $path
[pscustomobject]@{version=$file.VersionInfo.ProductVersion; signature_status=[string]$signature.Status; publisher=[string]$signature.SignerCertificate.Subject; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash} | ConvertTo-Json -Compress
"""
    result = subprocess.run([str(windows_powershell_path()), "-NoProfile", "-NonInteractive", "-Command", script], input=request, text=True, encoding="utf-8", errors="replace", capture_output=True, check=False, env=windows_powershell_environment())
    if result.returncode:
        raise OSError("DiskGenius file identity query failed")
    payload = json.loads(result.stdout or "{}")
    return payload if isinstance(payload, dict) else {}


def _launch_elevated(path: Path) -> Any:
    if os.name != "nt":
        raise OSError("DiskGenius launch requires Windows")
    os.startfile(str(path), "runas")
    return None


def _diskgenius_is_running(path: Path) -> bool:
    if os.name != "nt":
        raise OSError("DiskGenius process inspection requires Windows")
    env = windows_powershell_environment()
    env["LVAULT_DISKGENIUS_EXE"] = str(path.resolve(strict=True))
    script = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$expected = [IO.Path]::GetFullPath($env:LVAULT_DISKGENIUS_EXE)
$running = $false
foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='DiskGenius.exe'" -ErrorAction Stop)) {
  if (-not $process.ExecutablePath -or [string]::Equals([IO.Path]::GetFullPath([string]$process.ExecutablePath), $expected, [StringComparison]::OrdinalIgnoreCase)) { $running = $true }
}
[pscustomobject]@{running=$running} | ConvertTo-Json -Compress
"""
    result = subprocess.run([str(windows_powershell_path()), "-NoProfile", "-NonInteractive", "-Command", script], text=True, encoding="utf-8", errors="replace", capture_output=True, check=False, timeout=10, env=env)
    if result.returncode:
        raise OSError("DiskGenius process state query failed")
    payload = json.loads(result.stdout or "{}")
    if not isinstance(payload, dict) or not isinstance(payload.get("running"), bool):
        raise OSError("DiskGenius process state response is invalid")
    return payload["running"]


def _verify_target_files(target: DiskIdentity) -> dict[str, Any]:
    if os.name != "nt" or target.number is None:
        return {"verified": False, "reason": "verificação de ESP/BCD exige Windows e disco resolvido"}
    spec = {
        "number": target.number,
        "model": target.model,
        "serial": target.serial,
        "pnp": target.pnp_device_id,
        "unique_id": target.storage_unique_id,
        "size_bytes": target.size_bytes,
    }
    env = windows_powershell_environment()
    env["LVAULT_DISKGENIUS_TARGET"] = json.dumps(spec, ensure_ascii=False)
    script = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$spec = ConvertFrom-Json $env:LVAULT_DISKGENIUS_TARGET
$disk = Get-Disk -Number ([int]$spec.number) -ErrorAction Stop
$physical = Get-CimInstance Win32_DiskDrive | Where-Object Index -eq $disk.Number | Select-Object -First 1
function Same($left, $right) { return ([string]$left).Trim().ToLowerInvariant() -ceq ([string]$right).Trim().ToLowerInvariant() }
if (-not (Same $disk.FriendlyName $spec.model) -or -not (Same $disk.SerialNumber $spec.serial) -or -not (Same $disk.UniqueId $spec.unique_id) -or -not (Same $physical.PNPDeviceID $spec.pnp) -or [int64]$disk.Size -ne [int64]$spec.size_bytes) { throw 'Target identity changed' }
if ($disk.IsOffline) { throw 'Target is offline' }
$parts = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop)
$efi = @($parts | Where-Object { ([string]$_.GptType).Trim('{}').ToLowerInvariant() -eq 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b' })
$basic = @($parts | Where-Object { ([string]$_.GptType).Trim('{}').ToLowerInvariant() -eq 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' })
if ($efi.Count -ne 1) { throw 'Expected one target EFI System Partition' }
$available = @('Z','Y','X','W','V','U','T','S','R','Q','P')
$used = @((Get-Volume | Where-Object DriveLetter | ForEach-Object { [string]$_.DriveLetter }))
$added = @()
$windowsLetter = ''
$efiLetter = ''
try {
  foreach ($part in $basic) {
    $volume = Get-Volume -Partition $part -ErrorAction SilentlyContinue
    if (-not $volume -or [string]$volume.FileSystem -ne 'NTFS') { continue }
    $letter = [string]$part.DriveLetter
    if (-not $letter) {
      $letter = @($available | Where-Object { $_ -notin $used } | Select-Object -First 1)[0]
      if (-not $letter) { throw 'No temporary drive letter available for target Windows volume' }
      Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -DriveLetter $letter -ErrorAction Stop
      $added += [pscustomobject]@{partition=$part.PartitionNumber; letter=$letter}
      $used += $letter
    }
    if ((Test-Path "${letter}:\Windows\System32\winload.efi") -and (Test-Path "${letter}:\Windows\System32\config\SYSTEM")) { $windowsLetter=$letter; break }
  }
  if (-not $windowsLetter) { throw 'Target Windows directory or SYSTEM hive missing' }
  $efiLetter = [string]$efi[0].DriveLetter
  if (-not $efiLetter) {
    $efiLetter = @($available | Where-Object { $_ -notin $used } | Select-Object -First 1)[0]
    if (-not $efiLetter) { throw 'No temporary drive letter available for target EFI partition' }
    Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $efi[0].PartitionNumber -DriveLetter $efiLetter -ErrorAction Stop
    $added += [pscustomobject]@{partition=$efi[0].PartitionNumber; letter=$efiLetter}
  }
  $bootManager = "${efiLetter}:\EFI\Microsoft\Boot\bootmgfw.efi"
  $bcdPath = "${efiLetter}:\EFI\Microsoft\Boot\BCD"
  if (-not (Test-Path $bootManager) -or -not (Test-Path $bcdPath)) { throw 'Target EFI boot manager or BCD missing' }
  $bcdText = (& "$env:SystemRoot\System32\bcdedit.exe" /store $bcdPath /enum '{default}' /v 2>&1 | Out-String)
  $bcdReadable = ($LASTEXITCODE -eq 0)
  $devicePattern = "(?im)^\s*device\s+partition=$([regex]::Escape($windowsLetter)):`$"
  $osDevicePattern = "(?im)^\s*osdevice\s+partition=$([regex]::Escape($windowsLetter)):`$"
  $loader = ($bcdText -match '(?i)\\Windows\\System32\\winload\.efi')
  $bound = $bcdReadable -and ($bcdText -match $devicePattern) -and ($bcdText -match $osDevicePattern) -and $loader
  if (-not $bound) { throw 'Target BCD default loader does not resolve to the migrated Windows volume' }
  [pscustomobject]@{verified=$true; filesystem_visible=$true; efi_boot_files=$true; bcd_readable=$true; bcd_targets_migrated_windows=$true; temporary_mounts_removed=$true} | ConvertTo-Json -Compress
}
finally {
  $cleanupOk = $true
  foreach ($item in $added) {
    try { Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $item.partition -DriveLetter $item.letter -ErrorAction Stop } catch { $cleanupOk = $false }
  }
  if (-not $cleanupOk) { throw 'A temporary target volume mount could not be removed' }
}
"""
    result = subprocess.run([str(windows_powershell_path()), "-NoProfile", "-NonInteractive", "-Command", script], text=True, encoding="utf-8", errors="replace", capture_output=True, check=False, env=env)
    if result.returncode:
        return {"verified": False, "reason": "o sistema de arquivos, ESP ou vínculo do BCD do Seagate não passou na verificação"}
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return {"verified": False, "reason": "a verificação de arquivos DiskGenius retornou evidência inválida"}
    return payload if isinstance(payload, dict) else {"verified": False, "reason": "a verificação de arquivos DiskGenius retornou evidência inválida"}
