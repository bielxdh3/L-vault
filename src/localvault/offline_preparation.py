"""Windows-side production handoff preparation for the guarded clone path.

The adapter only prepares a signed, one-shot package.  It never changes disk
state and never starts Clonezilla.  All paths and trust material are explicit
configuration; an absent or unsafe prerequisite fails closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .config import load_config
from .clonezilla_artifacts import _gpg_fs_path
from .disk_clone import DiskIdentity, WindowsDiskInventory
from .offline_clone import (
    OfflineBlockDevice,
    OfflineCloneBlocked,
    OfflineJobStore,
    ProductionOfflineSignatureVerifier,
    build_offline_job,
    canonical_json,
)
from .offline_runtime import VirtualReturnChannel
from .utils import atomic_write_bytes, atomic_write_text


PREPARATION_SCHEMA = 1
DEFAULT_LOCAL_CONFIG = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "LocalVault" / "phase1" / "production-preparation-config.json"
_PRIVATE_MARKER = b"PRIVATE KEY"


def _regular_file(path: Path, label: str) -> Path:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise OfflineCloneBlocked(f"{label} path is unsafe", "offline_preparation_unconfigured")
    return path


def _directory(path: Path, label: str, *, create: bool = False) -> Path:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise OfflineCloneBlocked(f"{label} path is unsafe", "offline_preparation_unconfigured")
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise OfflineCloneBlocked(f"{label} path is unavailable", "offline_preparation_unconfigured")
    return path


def _read_json(path: Path, label: str) -> dict[str, Any]:
    _regular_file(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OfflineCloneBlocked(f"{label} is invalid", "offline_preparation_unconfigured") from exc
    if not isinstance(value, dict):
        raise OfflineCloneBlocked(f"{label} is invalid", "offline_preparation_unconfigured")
    return value


def _fingerprint(value: Any) -> str:
    text = "".join(str(value or "").split()).upper()
    if not text or any(char not in "0123456789ABCDEF" for char in text) or len(text) not in {40, 64}:
        raise OfflineCloneBlocked("production signer fingerprint is invalid", "offline_preparation_unconfigured")
    return text


def _persistent_hash(disk: DiskIdentity) -> str:
    raw = json.dumps(disk.persistent_identity_payload(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class _LoopbackGpgSigner:
    """Signer for a locally protected, deliberately empty-passphrase key."""

    def __init__(self, gpg_binary: Path, gnupg_home: Path, fingerprint: str):
        self.gpg_binary = Path(gpg_binary)
        self.gnupg_home = Path(gnupg_home)
        self.fingerprint = fingerprint

    def sign(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes) or len(payload) > 8 * 1024 * 1024:
            raise OfflineCloneBlocked("offline job payload is oversized", "offline_verification_failed")
        with tempfile.TemporaryDirectory(prefix="localvault-job-sign-") as temporary:
            root = Path(temporary)
            payload_path = root / "payload"
            payload_path.write_bytes(payload)
            argv = [
                str(self.gpg_binary),
                "--batch",
                "--no-options",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--homedir",
                _gpg_fs_path(str(self.gnupg_home)),
                "--local-user",
                self.fingerprint,
                "--detach-sign",
                "--output",
                "-",
                _gpg_fs_path(str(payload_path)),
            ]
            try:
                env = {
                    "LANG": "C",
                    "LC_ALL": "C",
                    "TZ": "UTC",
                    "PATH": "",
                    "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
                    "WINDIR": os.environ.get("WINDIR", r"C:\Windows"),
                    "COMSPEC": os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"),
                    "TEMP": os.environ.get("TEMP", tempfile.gettempdir()),
                    "TMP": os.environ.get("TMP", tempfile.gettempdir()),
                    "HOMEDRIVE": os.environ.get("HOMEDRIVE", "C:"),
                    "HOMEPATH": os.environ.get("HOMEPATH", r"\Users\bielx"),
                    "USERPROFILE": os.environ.get("USERPROFILE", str(Path.home())),
                }
                result = subprocess.run(argv, cwd=temporary, env=env, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                raise OfflineCloneBlocked("production job signing failed", "offline_verification_failed") from exc
            if result.returncode != 0 or not result.stdout or len(result.stdout) > 256 * 1024:
                raise OfflineCloneBlocked("production job signing failed", "offline_verification_failed")
            return bytes(result.stdout)


def _offline_device(disk: DiskIdentity) -> OfflineBlockDevice:
    roles = tuple(sorted({part.canonical_role for part in disk.partitions if part.canonical_role}))
    return OfflineBlockDevice(
        node=disk.runtime_selector or f"/dev/localvault-{disk.number}",
        model=disk.model,
        serial=disk.serial,
        wwn=disk.storage_unique_id,
        id_serial=disk.pnp_device_id,
        id_serial_short=disk.serial,
        transport=disk.bus_type,
        size_bytes=disk.size_bytes,
        logical_sector_size=disk.logical_sector_size,
        physical_sector_size=disk.physical_sector_size,
        partition_style=disk.partition_style,
        partition_roles=roles,
        mounted=bool(disk.mount_points or any(part.mount_point for part in disk.partitions)),
        live_root=disk.is_system,
        boot_medium=False,
        removable=disk.is_removable,
        read_only=disk.read_only,
    )


@dataclass(frozen=True)
class PreparationConfig:
    jobs_root: Path
    exchange_root: Path
    replay_state: Path
    audit_path: Path
    signer_gpg: Path
    signer_gnupg_home: Path
    signer_fingerprint: str
    verifier_gpgv: Path
    verifier_keyring: Path
    verifier_fingerprint: str
    runtime_report: Path
    source_enrollment: Path
    target_enrollment: Path
    excluded_enrollment: Path
    target_volume: str = "D:"
    lvault_volume: str = "E:"
    enrollment_secret: Path | None = None

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "PreparationConfig":
        if not isinstance(mapping, dict):
            raise OfflineCloneBlocked("production preparation adapter is not configured", "offline_preparation_unconfigured")
        names = {
            "jobs_root", "exchange_root", "replay_state", "audit_path", "signer_gpg",
            "signer_gnupg_home", "signer_fingerprint", "verifier_gpgv", "verifier_keyring",
            "verifier_fingerprint", "runtime_report", "source_enrollment", "target_enrollment",
            "excluded_enrollment",
        }
        if names - set(mapping):
            raise OfflineCloneBlocked("production preparation adapter is not configured", "offline_preparation_unconfigured")
        return cls(
            jobs_root=Path(str(mapping["jobs_root"])),
            exchange_root=Path(str(mapping["exchange_root"])),
            replay_state=Path(str(mapping["replay_state"])),
            audit_path=Path(str(mapping["audit_path"])),
            signer_gpg=Path(str(mapping["signer_gpg"])),
            signer_gnupg_home=Path(str(mapping["signer_gnupg_home"])),
            signer_fingerprint=_fingerprint(mapping["signer_fingerprint"]),
            verifier_gpgv=Path(str(mapping["verifier_gpgv"])),
            verifier_keyring=Path(str(mapping["verifier_keyring"])),
            verifier_fingerprint=_fingerprint(mapping["verifier_fingerprint"]),
            runtime_report=Path(str(mapping["runtime_report"])),
            source_enrollment=Path(str(mapping["source_enrollment"])),
            target_enrollment=Path(str(mapping["target_enrollment"])),
            excluded_enrollment=Path(str(mapping["excluded_enrollment"])),
            target_volume=str(mapping.get("target_volume", "D:")),
            lvault_volume=str(mapping.get("lvault_volume", "E:")),
            enrollment_secret=Path(str(mapping["enrollment_secret"])) if mapping.get("enrollment_secret") else None,
        )


class ProductionPreparationAdapter:
    """Prepare a real signed job without crossing the physical clone boundary."""

    def __init__(
        self,
        config: PreparationConfig,
        *,
        inventory: Any | None = None,
        clock: Callable[[], datetime] | None = None,
        signer: Any | None = None,
        verifier: Any | None = None,
    ):
        self.config = config
        self.inventory = inventory or WindowsDiskInventory()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.signer = signer
        self.verifier = verifier

    @classmethod
    def from_root(cls, root: Path) -> "ProductionPreparationAdapter":
        section = load_config(root).get("disk_clone", {}).get("production_preparation")
        if section is None and DEFAULT_LOCAL_CONFIG.is_file():
            section = _read_json(DEFAULT_LOCAL_CONFIG, "production preparation configuration")
        return cls(PreparationConfig.from_mapping(section or {}))

    def _validate_prerequisites(self) -> None:
        _directory(self.config.jobs_root, "jobs root", create=True)
        _directory(self.config.exchange_root, "exchange root", create=True)
        if self.config.replay_state.parent != self.config.jobs_root:
            raise OfflineCloneBlocked("replay state must be inside the jobs root", "offline_preparation_unconfigured")
        _regular_file(self.config.signer_gpg, "production signer GPG")
        _directory(self.config.signer_gnupg_home, "production signer key home")
        if str(self.config.signer_gnupg_home).casefold().startswith(str(Path(__file__).resolve().parents[2]).casefold()):
            raise OfflineCloneBlocked("production signer key home must be outside the repository", "offline_preparation_unconfigured")
        _regular_file(self.config.verifier_gpgv, "production verifier")
        keyring = _regular_file(self.config.verifier_keyring, "production public keyring")
        if keyring.read_bytes().find(_PRIVATE_MARKER) >= 0:
            raise OfflineCloneBlocked("production public keyring contains private key material", "offline_preparation_unconfigured")
        if keyring.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
            raise OfflineCloneBlocked("production public keyring must be read-only", "offline_preparation_unconfigured")
        _regular_file(self.config.runtime_report, "production runtime report")
        report = _read_json(self.config.runtime_report, "production runtime report")
        if report.get("state") != "offline_runtime_static_validation_passed" or report.get("blockers"):
            raise OfflineCloneBlocked("verified production static runtime is required", "offline_preparation_unconfigured")
        if self.config.signer_fingerprint != self.config.verifier_fingerprint:
            raise OfflineCloneBlocked("production signer and verifier fingerprints differ", "offline_preparation_unconfigured")
        _regular_file(self.config.source_enrollment, "source enrollment")
        _regular_file(self.config.target_enrollment, "target enrollment")
        _regular_file(self.config.excluded_enrollment, "protected exclusion enrollment")
        if self.config.enrollment_secret is not None:
            secret = _regular_file(self.config.enrollment_secret, "enrollment integrity secret")
            if secret.stat().st_size < 32 or secret.stat().st_size > 4096:
                raise OfflineCloneBlocked("enrollment integrity secret is invalid", "offline_preparation_unconfigured")

    def _enrolled(self, path: Path) -> DiskIdentity:
        value = _read_json(path, "disk enrollment")
        if self.config.enrollment_secret is not None:
            secret = self.config.enrollment_secret.read_bytes()
            payload = value.get("persistent_identity") or value.get("disk") or value
            expected = hmac.new(secret, canonical_json(payload), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(value.get("hmac", "")), expected):
                raise OfflineCloneBlocked("disk enrollment integrity check failed", "offline_identity_blocked")
        payload = value.get("persistent_identity") or value.get("disk") or value
        if not isinstance(payload, dict):
            raise OfflineCloneBlocked("disk enrollment is invalid", "offline_identity_blocked")
        return DiskIdentity.from_dict(payload)

    def _resolve(self) -> tuple[DiskIdentity, DiskIdentity, DiskIdentity, list[DiskIdentity]]:
        disks = list(self.inventory.list_disks())
        source_ref = self._enrolled(self.config.source_enrollment)
        target_ref = self._enrolled(self.config.target_enrollment)
        excluded_ref = self._enrolled(self.config.excluded_enrollment)
        sources = [d for d in disks if d.matches(source_ref, require_strong=True) and (d.is_system or d.is_boot)]
        targets = [d for d in disks if d.matches(target_ref, require_strong=True)]
        excluded = [d for d in disks if d.matches(excluded_ref, require_strong=True)]
        if len(sources) != 1 or len(targets) != 1 or len(excluded) != 1:
            raise OfflineCloneBlocked("source, target, or protected exclusion identity is ambiguous", "offline_identity_blocked")
        source, target, hgst = sources[0], targets[0], excluded[0]
        if source.matches(target, require_strong=False) or source.matches(hgst, require_strong=False) or target.matches(hgst, require_strong=False):
            raise OfflineCloneBlocked("source, target, and protected exclusion must be distinct", "offline_identity_blocked")
        if target.is_system or target.is_boot or target.is_pagefile or target.is_crash_dump or target.read_only:
            raise OfflineCloneBlocked("target is system-critical or read-only", "offline_identity_blocked")
        if isinstance(self.inventory, WindowsDiskInventory):
            target_number = self._volume_disk_number(self.config.target_volume)
            if target_number != target.number:
                raise OfflineCloneBlocked("target volume does not map to the enrolled physical identity", "offline_identity_blocked")
            lvault_number = self._volume_disk_number(self.config.lvault_volume)
            if lvault_number == target.number:
                raise OfflineCloneBlocked("active L-vault volume maps to the target", "offline_identity_blocked")
        if target.size_bytes < source.size_bytes or _normal(source.partition_style) != _normal(target.partition_style):
            raise OfflineCloneBlocked("target geometry is smaller or incompatible", "offline_identity_blocked")
        return source, target, hgst, disks

    @staticmethod
    def _volume_disk_number(volume: str) -> int:
        letter = str(volume or "").strip().rstrip(":")
        if len(letter) != 1 or not letter.isalpha():
            raise OfflineCloneBlocked("volume mapping is invalid", "offline_identity_blocked")
        script = f"Get-Partition -DriveLetter {letter.upper()} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DiskNumber | ConvertTo-Json -Compress"
        try:
            completed = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], text=True, capture_output=True, check=False, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OfflineCloneBlocked("volume mapping could not be read", "offline_identity_blocked") from exc
        if completed.returncode != 0:
            raise OfflineCloneBlocked("volume mapping could not be read", "offline_identity_blocked")
        try:
            value = json.loads(completed.stdout or "")
            values = value if isinstance(value, list) else [value]
            numbers = {int(item) for item in values if item is not None}
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OfflineCloneBlocked("volume mapping is ambiguous", "offline_identity_blocked") from exc
        if len(numbers) != 1:
            raise OfflineCloneBlocked("volume mapping is ambiguous", "offline_identity_blocked")
        return numbers.pop()

    def prepare(self, *, ttl: timedelta = timedelta(minutes=15), now: datetime | None = None) -> dict[str, Any]:
        self._validate_prerequisites()
        source, target, hgst, disks = self._resolve()
        signer = self.signer or _LoopbackGpgSigner(self.config.signer_gpg, self.config.signer_gnupg_home, self.config.signer_fingerprint)
        verifier = self.verifier or ProductionOfflineSignatureVerifier(self.config.verifier_gpgv, self.config.verifier_keyring, self.config.verifier_fingerprint)
        created = now or self.clock()
        source_offline, target_offline = _offline_device(source), _offline_device(target)
        job = build_offline_job(source_offline, target_offline, now=created, ttl=ttl, real_execution_authorized=True)
        channel = VirtualReturnChannel(self.config.exchange_root / "return-channel")
        channel_status = channel.initialize(job)
        store = OfflineJobStore(self.config.jobs_root)
        package = store.create(job, signer)
        loaded = store.load(job.job_id, verifier, now=created, consume=False)
        if loaded != job:
            raise OfflineCloneBlocked("signed offline job verification did not round-trip", "offline_verification_failed")
        handoff = self.config.exchange_root / f"job-{job.job_id}"
        if handoff.exists():
            raise OfflineCloneBlocked("exchange handoff already exists", "offline_verification_failed")
        temporary = Path(tempfile.mkdtemp(prefix=f".job-{job.job_id}-", dir=self.config.exchange_root))
        try:
            shutil.copy2(package / "manifest.json", temporary / "manifest.json")
            shutil.copy2(package / "manifest.sig", temporary / "manifest.sig")
            os.replace(temporary, handoff)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        # Public trust is intentionally copied; the signer home/private key is not.
        public_copy = self.config.exchange_root / "job-verifier-public.gpg"
        if public_copy.exists():
            raise OfflineCloneBlocked("exchange public key already exists", "offline_verification_failed")
        atomic_write_bytes(public_copy, self.config.verifier_keyring.read_bytes())
        try:
            public_copy.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pass
        replay_ready = not self.config.replay_state.exists()
        if self.config.replay_state.exists():
            try:
                state = json.loads(self.config.replay_state.read_text(encoding="utf-8"))
                replay_ready = state.get("schema") == 1 and isinstance(state.get("used_nonce_hashes"), list) and hashlib.sha256(job.nonce.encode()).hexdigest() not in state["used_nonce_hashes"]
            except (OSError, json.JSONDecodeError):
                replay_ready = False
        if not replay_ready:
            raise OfflineCloneBlocked("production replay state is unavailable or already consumed", "offline_verification_failed")
        manifest_sha = hashlib.sha256((handoff / "manifest.json").read_bytes()).hexdigest()
        result = {
            "schema": PREPARATION_SCHEMA,
            "state": "ready_for_offline_clone",
            "job_id": job.job_id,
            "created_at": job.created_at,
            "expires_at": job.expires_at,
            "nonce_masked": f"****{job.nonce[-4:]}",
            "source": {"model": source.model, "masked_identity": source.masked_serial, "size_bytes": source.size_bytes, "persistent_identity_sha256": _persistent_hash(source)},
            "target": {"model": target.model, "masked_identity": target.masked_serial, "size_bytes": target.size_bytes, "persistent_identity_sha256": _persistent_hash(target)},
            "excluded": {"model": hgst.model, "masked_identity": hgst.masked_serial, "persistent_identity_sha256": _persistent_hash(hgst)},
            "runtime": {"state": "offline_runtime_static_validation_passed", "report": str(self.config.runtime_report)},
            "signed_job": {"manifest_sha256": manifest_sha, "signature_verified": True, "real_execution_authorized": True},
            "return_channel": {"state": channel_status.state, "root": str(self.config.exchange_root / "return-channel"), "binding_verified": channel_status.state == "pending"},
            "replay_nonce": {"persistent_state": str(self.config.replay_state), "unconsumed": True},
            "secret_handling": {"private_key_outside_repository": True, "private_key_copied_to_exchange": False, "public_keyring_sha256": hashlib.sha256(self.config.verifier_keyring.read_bytes()).hexdigest()},
            "safety": {"rebooted": False, "physical_clone_performed": False, "source_mutated": False, "target_overwritten": False, "excluded_mutated": False, "disk_count_observed": len(disks)},
        }
        self.config.audit_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.config.audit_path, json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return result


def _normal(value: Any) -> str:
    return str(value or "").strip().casefold()
