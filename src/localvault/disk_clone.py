from __future__ import annotations

"""Fail-closed orchestration for a bootable Windows disk-clone workflow.

The module deliberately keeps provider execution behind a small boundary.  The
default provider is unsupported until a local installation, edition, and
command contract have all been verified.  Tests and the simulation command use
the fake provider and never touch storage devices.
"""

import ctypes
import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, time as time_type, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol, Sequence

import yaml

from . import db
from .config import VaultPaths, load_config, paths
from .locks import BackupLock, lock_is_stale
from .offline_clone import OFFLINE_ENGINE, OFFLINE_ENGINE_VERSION, build_offline_boot_handoff_plan, simulate_offline_round_trip
from .utils import atomic_write_bytes, atomic_write_text, utc_now


ENROLLMENT_FILE = "disk_clone_enrollment.json"
ENROLLMENT_SECRET_FILE = "disk_clone_enrollment.secret"
ENROLLMENT_SCHEMA = 2
MASKED_SERIAL = "(serial oculto)"
TERMINAL_STATES = {
    "success",
    "skipped_not_due",
    "skipped_outside_window",
    "skipped_window_expired_before_start",
    "skipped_no_interactive_session",
    "skipped_target_missing",
    "skipped_high_source_activity",
    "blocked_provider",
    "blocked_identity",
    "blocked_protected_path",
    "blocked_size",
    "blocked_configuration",
    "cancelled_before_start",
    "failed_provider",
    "failed_verification",
    "interrupted",
    "failed_offline_cleanup",
    "re_enrollment_required",
    "offline_job_ready",
    "offline_job_preparing",
    "awaiting_offline_boot",
    "offline_boot_not_configured",
    "offline_job_expired",
    "offline_identity_blocked",
    "offline_execution_disabled",
    "offline_result_pending",
    "offline_result_received",
    "offline_verification_failed",
    "offline_simulation_completed",
    "offline_clone_structurally_verified",
}
RETRYABLE_FAILURE_STATES = {"failed_provider", "failed_verification", "failed_offline_cleanup"}
CLONE_STATE_LABELS = {
    "skipped_window_expired_before_start": "adiado: janela expirada antes do provedor",
    "re_enrollment_required": "reinscricao obrigatoria",
    "success": "sucesso estrutural; boot nao testado",
    "awaiting_offline_boot": "aguardando boot offline manual",
    "offline_boot_not_configured": "boot offline nao configurado",
    "offline_simulation_completed": "simulacao fake concluida; nenhum clone executado",
    "offline_clone_structurally_verified": "estrutura verificada; boot nao testado",
    "offline_runtime_unavailable": "runtime offline indisponivel",
    "offline_runtime_static_validation_passed": "validacao estatica offline concluida; boot nao provado",
    "offline_runtime_virtual_validation_passed": "validacao virtual offline concluida; hardware nao provado",
    "offline_return_channel_ready": "canal virtual de retorno pronto; clone nao executado",
    "offline_runtime_blocked": "runtime offline bloqueado; nenhuma execucao",
}


class DiskCloneError(RuntimeError):
    pass


class DiskCloneBlocked(DiskCloneError):
    def __init__(self, reason: str, state: str = "blocked_identity"):
        super().__init__(reason)
        self.reason = reason
        self.state = state


class DiskCloneConfigError(DiskCloneBlocked):
    def __init__(self, reason: str):
        super().__init__(reason, "blocked_configuration")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _normal(value: Any) -> str:
    return _clean(value).casefold()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _normal(value) in {"1", "true", "yes", "sim", "on"}


@dataclass(frozen=True)
class PartitionIdentity:
    number: int = 0
    kind: str = ""
    size_bytes: int = 0
    gpt_type: str = ""
    filesystem: str = ""
    is_system: bool = False
    is_boot: bool = False
    mount_point: str = ""
    is_active: bool = False
    is_os_volume: bool = False

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "PartitionIdentity":
        return cls(
            number=_safe_int(value.get("number")),
            kind=_clean(value.get("kind") or value.get("type")),
            size_bytes=_safe_int(value.get("size_bytes") or value.get("size")),
            gpt_type=_clean(value.get("gpt_type")),
            filesystem=_clean(value.get("filesystem")),
            is_system=_safe_bool(value.get("is_system")),
            is_boot=_safe_bool(value.get("is_boot")),
            mount_point=_clean(value.get("mount_point") or value.get("drive_letter")),
            is_active=_safe_bool(value.get("is_active")),
            is_os_volume=_safe_bool(value.get("is_os_volume")),
        )

    @property
    def canonical_role(self) -> str:
        """Map structured Windows/GPT data to stable roles, keeping ``kind`` raw."""
        gpt = _normal(self.gpt_type).strip("{}")
        gpt_roles = {
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "efi",
            "e3c9e316-0b5c-4db8-817d-f92df00215ae": "msr",
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "basic_data",
            "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "recovery",
        }
        if gpt in gpt_roles:
            role = gpt_roles[gpt]
            return "windows" if role == "basic_data" and self.is_os_volume else role
        raw = _normal(self.kind).replace("_", " ").replace("-", " ")
        if "recovery" in raw:
            return "recovery"
        if "reserved" in raw:
            return "msr"
        if raw in {"efi", "system"} or "efi system" in raw:
            return "efi"
        if raw in {"windows", "os", "os volume"} or self.is_os_volume:
            return "windows"
        if "basic data" in raw or raw in {"basic", "data"}:
            return "basic_data"
        if self.is_active:
            return "active"
        return raw.replace(" ", "_")


@dataclass(frozen=True)
class DiskIdentity:
    number: int | None = None
    model: str = ""
    serial: str = ""
    pnp_device_id: str = ""
    storage_unique_id: str = ""
    runtime_selector: str = ""
    bus_type: str = ""
    media_type: str = ""
    size_bytes: int = 0
    logical_sector_size: int = 512
    physical_sector_size: int = 4096
    partition_style: str = ""
    online: bool = True
    read_only: bool = False
    is_system: bool = False
    is_boot: bool = False
    is_pagefile: bool = False
    is_crash_dump: bool = False
    is_clustered: bool = False
    is_virtual: bool = False
    is_removable: bool = False
    bitlocker_state: str = "unknown"
    mount_points: tuple[str, ...] = ()
    partitions: tuple[PartitionIdentity, ...] = ()
    signature: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DiskIdentity":
        mounts = value.get("mount_points") or value.get("drive_letters") or ()
        if isinstance(mounts, str):
            mounts = (mounts,)
        partitions = value.get("partitions") or ()
        return cls(
            number=_safe_int(value.get("number"), -1) if value.get("number") is not None else None,
            model=_clean(value.get("model") or value.get("friendly_name")),
            serial=_clean(value.get("serial") or value.get("serial_number")),
            pnp_device_id=_clean(value.get("pnp_device_id") or value.get("pnp")),
            storage_unique_id=_clean(value.get("storage_unique_id") or value.get("unique_id")),
            runtime_selector=_clean(value.get("runtime_selector")),
            bus_type=_clean(value.get("bus_type") or value.get("interface_type")),
            media_type=_clean(value.get("media_type")),
            size_bytes=_safe_int(value.get("size_bytes") or value.get("size")),
            logical_sector_size=_safe_int(value.get("logical_sector_size"), 512),
            physical_sector_size=_safe_int(value.get("physical_sector_size"), 4096),
            partition_style=_clean(value.get("partition_style")),
            online=_safe_bool(value.get("online", True)),
            read_only=_safe_bool(value.get("read_only")),
            is_system=_safe_bool(value.get("is_system")),
            is_boot=_safe_bool(value.get("is_boot")),
            is_pagefile=_safe_bool(value.get("is_pagefile")),
            is_crash_dump=_safe_bool(value.get("is_crash_dump")),
            is_clustered=_safe_bool(value.get("is_clustered")),
            is_virtual=_safe_bool(value.get("is_virtual")),
            is_removable=_safe_bool(value.get("is_removable")),
            bitlocker_state=_clean(value.get("bitlocker_state") or "unknown"),
            mount_points=tuple(_clean(item) for item in mounts if _clean(item)),
            partitions=tuple(PartitionIdentity.from_dict(item) for item in partitions),
            signature=_clean(value.get("signature")),
        )

    def persistent_identity_payload(self) -> dict[str, Any]:
        """Return enrolled identity only; runtime selectors are deliberately excluded."""
        return {
            "model": self.model,
            "serial": self.serial,
            "pnp_device_id": self.pnp_device_id,
            "storage_unique_id": self.storage_unique_id,
            "size_bytes": self.size_bytes,
            "logical_sector_size": self.logical_sector_size,
            "physical_sector_size": self.physical_sector_size,
            "bus_type": self.bus_type,
        }

    fingerprint_payload = persistent_identity_payload

    def stable_identifiers(self) -> tuple[str, ...]:
        return tuple(value for value in (self.serial, self.pnp_device_id, self.storage_unique_id) if _clean(value))

    def identity_strength(self) -> str:
        serial = _normal(self.serial)
        weak_serials = {"", "unknown", "none", "null", "to be filled by o.e.m.", "default string", "0"}
        identifiers = self.stable_identifiers()
        if serial in weak_serials or len(identifiers) < 2:
            return "weak"
        if _normal(self.bus_type) == "usb" and any(not _clean(value) for value in (self.serial, self.pnp_device_id, self.storage_unique_id)):
            return "weak"
        return "strong"

    def identity_policy(self) -> str:
        """Native media accept two stable IDs; USB bridges require three including bridge identity."""
        return "usb_bridge_requires_serial_pnp_and_validated_unique_id" if _normal(self.bus_type) == "usb" else "native_requires_two_stable_ids"

    @property
    def masked_serial(self) -> str:
        serial = _clean(self.serial)
        return MASKED_SERIAL if not serial else f"****{serial[-4:]}"

    @property
    def masked_label(self) -> str:
        return f"{self.model or 'disco'} {self.masked_serial} ({self.size_bytes:,} bytes)"

    def confirmation_phrase(self) -> str:
        """Bind destructive enrollment confirmation to the refreshed disk identity."""
        return f"APAGAR {self.model} {self.size_bytes} {self.masked_serial}"

    def matches(self, enrolled: "DiskIdentity", *, require_strong: bool = True) -> bool:
        if require_strong and (self.identity_strength() != "strong" or enrolled.identity_strength() != "strong"):
            return False
        left, right = self.persistent_identity_payload(), enrolled.persistent_identity_payload()
        for key in ("serial", "pnp_device_id", "storage_unique_id"):
            expected, actual = _normal(right[key]), _normal(left[key])
            if expected and expected != actual:
                return False
        for key in ("model", "size_bytes", "logical_sector_size", "physical_sector_size", "bus_type"):
            expected, actual = right[key], left[key]
            if key in {"model", "bus_type"}:
                if _normal(expected) != _normal(actual):
                    return False
            elif expected != actual:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"partitions": [asdict(item) for item in self.partitions]}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_disk_clone_config(config: dict[str, Any] | None) -> dict[str, Any]:
    if config is not None and not isinstance(config, dict):
        raise DiskCloneConfigError("Configuracao de clone invalida; a execucao foi bloqueada.")
    raw = dict(config or {})
    defaults = {
        "enabled": False,
        "provider": "auto",
        "interval_days": 30,
        "schedule_time": "03:00",
        "window_start": "03:00",
        "window_end": "04:00",
        "countdown_seconds": 300,
        "active_time_threshold_percent": 70.0,
        "active_time_sample_seconds": 300,
        "prestart_recheck_seconds": 20,
        "require_unlocked_interactive_session": True,
        "keep_target_offline": True,
        "allow_automatic_retry_same_night": False,
        "allow_real_provider_execution": False,
        "real_execution_authorized": False,
        "offline_runtime_validation": "static_or_virtual_only",
        "offline_return_channel": "temporary_directory_fixture_only",
    }
    result = defaults | raw
    try:
        result["interval_days"] = int(result["interval_days"])
        if not 1 <= result["interval_days"] <= 3650:
            raise ValueError
        result["countdown_seconds"] = int(result["countdown_seconds"])
        if not 0 <= result["countdown_seconds"] <= 3600:
            raise ValueError
        result["active_time_threshold_percent"] = float(result["active_time_threshold_percent"])
        if not 0 < result["active_time_threshold_percent"] <= 100:
            raise ValueError
        result["active_time_sample_seconds"] = int(result["active_time_sample_seconds"])
        result["prestart_recheck_seconds"] = int(result["prestart_recheck_seconds"])
        if result["active_time_sample_seconds"] < 1 or result["prestart_recheck_seconds"] < 1:
            raise ValueError
        for key in ("schedule_time", "window_start", "window_end"):
            _parse_clock(result[key])
    except (TypeError, ValueError, KeyError) as exc:
        raise DiskCloneConfigError("Configuracao de clone invalida; a execucao foi bloqueada.") from exc
    for key in ("enabled", "require_unlocked_interactive_session", "keep_target_offline", "allow_automatic_retry_same_night", "allow_real_provider_execution", "real_execution_authorized"):
        result[key] = _safe_bool(result[key])
    if result["allow_real_provider_execution"] or result["real_execution_authorized"]:
        raise DiskCloneConfigError("A execucao real permanece desativada nesta fase.")
    if result["offline_runtime_validation"] != "static_or_virtual_only" or result["offline_return_channel"] != "temporary_directory_fixture_only":
        raise DiskCloneConfigError("A politica de runtime offline nao e allowlisted.")
    if _parse_clock(result["window_start"]) >= _parse_clock(result["window_end"]):
        raise DiskCloneConfigError("A janela de clone deve ter inicio antes do fim.")
    if not _clean(result["provider"]):
        raise DiskCloneConfigError("Nenhum provedor de clone configurado.")
    return result


def _parse_clock(value: Any) -> time_type:
    match = re.fullmatch(r"([01]\d|2[0-3]):([0-5]\d)", _clean(value))
    if not match:
        raise ValueError(f"invalid clock: {value}")
    return time_type(int(match.group(1)), int(match.group(2)))


def within_clone_window(now: datetime, start: str = "03:00", end: str = "04:00") -> bool:
    return _parse_clock(start) <= now.timetz().replace(tzinfo=None) < _parse_clock(end)


def _timezone_offset(now: datetime) -> str:
    offset = now.utcoffset()
    if offset is None:
        return "+00:00"
    seconds = int(offset.total_seconds())
    sign = "+" if seconds >= 0 else "-"
    seconds = abs(seconds)
    return f"{sign}{seconds // 3600:02d}:{(seconds % 3600) // 60:02d}"


def parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def next_due_at(last_verified_at: Any, interval_days: int, now: datetime | None = None) -> datetime:
    last = parse_timestamp(last_verified_at)
    if last is None:
        return (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return last + timedelta(days=int(interval_days))


def clone_is_due(last_verified_at: Any, interval_days: int, now: datetime | None = None) -> bool:
    return next_due_at(last_verified_at, interval_days, now) <= (now or datetime.now(timezone.utc)).astimezone(timezone.utc)


class DiskInventory(Protocol):
    def list_disks(self) -> list[DiskIdentity]: ...


class FakeDiskInventory:
    def __init__(self, disks: Iterable[DiskIdentity] = ()):
        self.disks = list(disks)

    def list_disks(self) -> list[DiskIdentity]:
        return list(self.disks)

    def replace(self, disks: Iterable[DiskIdentity]) -> None:
        self.disks = list(disks)


class WindowsDiskInventory:
    def list_disks(self) -> list[DiskIdentity]:
        if os.name != "nt":
            raise DiskCloneBlocked("O inventario de discos so esta disponivel no Windows.")
        script = r"""
$ErrorActionPreference = 'Stop'
$physical = @{}
Get-CimInstance Win32_DiskDrive | ForEach-Object { $physical[[int]$_.Index] = $_ }
$systemDrive = ($env:SystemDrive -replace ':$','')
$rows = foreach ($disk in Get-Disk) {
  $physicalDisk = $physical[[int]$disk.Number]
  $parts = @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | ForEach-Object {
    $vol = Get-Volume -Partition $_ -ErrorAction SilentlyContinue
    [pscustomobject]@{number=$_.PartitionNumber; kind=$_.Type; size_bytes=$_.Size; gpt_type=$_.GptType; filesystem=if($vol){$vol.FileSystem}else{''}; is_system=$false; is_boot=$_.IsActive; is_active=$_.IsActive; is_os_volume=($_.DriveLetter -eq $systemDrive); drive_letter=if($_.DriveLetter){$_.DriveLetter}else{''}; mount_point=if($vol){$vol.Path}else{''}}
  })
  [pscustomobject]@{number=$disk.Number; model=$disk.FriendlyName; serial=$disk.SerialNumber; pnp_device_id=if($physicalDisk){$physicalDisk.PNPDeviceID}else{''}; runtime_selector=if($physicalDisk){$physicalDisk.DeviceID}else{''}; storage_unique_id=$disk.UniqueId; bus_type=$disk.BusType; media_type=$disk.MediaType; size_bytes=$disk.Size; logical_sector_size=$disk.LogicalSectorSize; physical_sector_size=$disk.PhysicalSectorSize; partition_style=$disk.PartitionStyle; signature=$disk.Signature; online=(-not $disk.IsOffline); read_only=$disk.IsReadOnly; is_system=$disk.IsSystem; is_boot=$disk.IsBoot; is_pagefile=$disk.IsPagefile; is_crash_dump=$disk.IsCrashDump; is_clustered=$disk.IsClustered; is_virtual=($disk.Location -match 'Virtual'); is_removable=($disk.BusType -eq 'USB'); partitions=$parts}
}
$rows | ConvertTo-Json -Depth 8 -Compress
"""
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], text=True, capture_output=True, check=False)
        if result.returncode:
            raise DiskCloneBlocked("Nao foi possivel obter inventario estruturado dos discos.")
        try:
            payload = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise DiskCloneBlocked("Inventario de discos retornou JSON invalido.") from exc
        if isinstance(payload, dict):
            payload = [payload]
        return [DiskIdentity.from_dict(item) for item in payload]


def matching_disks(disks: Sequence[DiskIdentity], enrolled: DiskIdentity, *, require_strong: bool = True) -> list[DiskIdentity]:
    return [disk for disk in disks if disk.matches(enrolled, require_strong=require_strong)]


def find_matching_disk(disks: Sequence[DiskIdentity], enrolled: DiskIdentity, *, require_strong: bool = True) -> DiskIdentity | None:
    matches = matching_disks(disks, enrolled, require_strong=require_strong)
    return matches[0] if len(matches) == 1 else None


class DiskLifecycle(Protocol):
    def set_online(self, disk: DiskIdentity) -> None: ...
    def set_offline(self, disk: DiskIdentity) -> None: ...


class FakeDiskLifecycle:
    def __init__(self):
        self.online_calls: list[int | None] = []
        self.offline_calls: list[int | None] = []

    def set_online(self, disk: DiskIdentity) -> None:
        self.online_calls.append(disk.number)

    def set_offline(self, disk: DiskIdentity) -> None:
        self.offline_calls.append(disk.number)


class WindowsDiskLifecycle:
    def _set(self, disk: DiskIdentity, offline: bool) -> None:
        if os.name != "nt" or disk.number is None:
            raise DiskCloneBlocked("Nao foi possivel identificar o disco fisico para alterar seu estado.")
        flag = "$true" if offline else "$false"
        script = f"Set-Disk -Number {int(disk.number)} -IsOffline {flag}"
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], text=True, capture_output=True, check=False)
        if result.returncode:
            raise DiskCloneError("Falha ao alterar o estado offline do destino.")

    def set_online(self, disk: DiskIdentity) -> None:
        self._set(disk, False)

    def set_offline(self, disk: DiskIdentity) -> None:
        self._set(disk, True)


@dataclass(frozen=True)
class ProviderDiscovery:
    name: str
    executable: str = ""
    product: str = ""
    version: str = ""
    edition: str = ""
    architecture: str = ""
    present: bool = False
    detail: str = ""


@dataclass(frozen=True)
class ProviderCapabilities:
    supported: bool = False
    whole_disk_clone: bool = False
    system_disk_clone: bool = False
    live_clone: bool = False
    sector_by_sector: bool = False
    intelligent_clone: bool = False
    stable_disk_selector: bool = False
    progress: str = "unavailable"
    safe_cancellation: bool = False
    supported_partition_styles: tuple[str, ...] = ()
    supported_bitlocker_states: tuple[str, ...] = ()
    destination_size_rule: str = "unknown"
    blocker: str = ""
    simulation_only: bool = False


@dataclass(frozen=True)
class ClonePlan:
    provider: str
    mode: str
    source_selector: str
    target_selector: str
    source_size_bytes: int
    target_size_bytes: int
    required_partitions: tuple[str, ...] = ()
    size_rule: str = ""
    arguments: tuple[str, ...] = ()
    source_identity: tuple[str, ...] = ()
    target_identity: tuple[str, ...] = ()


@dataclass
class ProviderProcess:
    pid: int = 0
    started_at: str = field(default_factory=utc_now)
    handle: Any = None


@dataclass(frozen=True)
class ProviderResult:
    success: bool
    exit_code: int | None = None
    reason: str = ""
    progress_type: str = "unavailable"
    copied_bytes: int | None = None


class CloneProvider(Protocol):
    def discover(self) -> ProviderDiscovery: ...
    def validate_capabilities(self) -> ProviderCapabilities: ...
    def build_plan(self, source: DiskIdentity, target: DiskIdentity) -> ClonePlan: ...
    def start(self, plan: ClonePlan, event_sink: Callable[[dict[str, Any]], None] | None = None) -> ProviderProcess: ...
    def request_cancel(self, process: ProviderProcess) -> bool: ...
    def inspect_result(self, process: ProviderProcess) -> ProviderResult: ...


class UnsupportedProvider:
    def __init__(self, name: str = "unsupported", detail: str = "Nenhum provedor seguro validado."):
        self.name = name
        self.detail = detail

    def discover(self) -> ProviderDiscovery:
        return ProviderDiscovery(self.name, present=False, detail=self.detail)

    def validate_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(blocker=self.detail)

    def build_plan(self, source: DiskIdentity, target: DiskIdentity) -> ClonePlan:
        raise DiskCloneBlocked(self.detail, "blocked_provider")

    def start(self, plan: ClonePlan, event_sink: Callable[[dict[str, Any]], None] | None = None) -> ProviderProcess:
        raise DiskCloneBlocked(self.detail, "blocked_provider")

    def request_cancel(self, process: ProviderProcess) -> bool:
        return False

    def inspect_result(self, process: ProviderProcess) -> ProviderResult:
        return ProviderResult(False, reason=self.detail)


class ClonezillaOfflineProvider(UnsupportedProvider):
    """Windows-side preparation label; it is never a Windows subprocess."""

    def __init__(self):
        super().__init__("clonezilla_offline", "Clonezilla Live sera usado somente apos boot offline manual; execucao real ainda esta desabilitada.")

    def discover(self) -> ProviderDiscovery:
        return ProviderDiscovery(
            self.name,
            product="Clonezilla Live",
            version=OFFLINE_ENGINE_VERSION,
            present=False,
            detail=self.detail,
        )

    def validate_capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            whole_disk_clone=True,
            system_disk_clone=True,
            live_clone=False,
            stable_disk_selector=False,
            destination_size_rule="target_bytes >= source_bytes",
            blocker=self.detail,
            simulation_only=True,
        )


def _find_aomei_executable() -> Path | None:
    candidates = [
        shutil.which("AMBackup.exe"),
        r"C:\Program Files\AOMEI Backupper\AMBackup.exe",
        r"C:\Program Files (x86)\AOMEI Backupper\AMBackup.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def _file_product_version(path: Path) -> str:
    if os.name != "nt":
        return ""
    escaped = str(path).replace("'", "''")
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", f"(Get-Item -LiteralPath '{escaped}').VersionInfo.ProductVersion"], text=True, capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


class AOMEIProvider(UnsupportedProvider):
    """AOMEI adapter with a read-only discovery path and fail-closed execution."""

    def __init__(self):
        super().__init__("aomei", "AOMEI Backupper nao foi validado nesta maquina.")
        self._discovery: ProviderDiscovery | None = None
        self._capabilities: ProviderCapabilities | None = None

    def discover(self) -> ProviderDiscovery:
        executable = _find_aomei_executable()
        if not executable:
            self._discovery = ProviderDiscovery("aomei", detail="AMBackup.exe ausente; nenhum clone real sera iniciado.")
        else:
            version = _file_product_version(executable)
            self._discovery = ProviderDiscovery("aomei", str(executable), "AOMEI Backupper", version, present=True, detail="Executavel localizado; edicao ainda nao validada.")
        return self._discovery

    def validate_capabilities(self) -> ProviderCapabilities:
        discovery = self._discovery or self.discover()
        if not discovery.present:
            self._capabilities = ProviderCapabilities(blocker=discovery.detail)
        else:
            # The vendor documents /c, /t, /s, /d and /o, but this machine has
            # no installed edition to validate.  Never infer support from the
            # executable existing alone.
            self._capabilities = ProviderCapabilities(
                blocker="Edicao AOMEI e contrato local de execucao ainda nao foram validados; use simulacao.",
                whole_disk_clone=True,
                system_disk_clone=True,
                live_clone=True,
                sector_by_sector=True,
                intelligent_clone=True,
                stable_disk_selector=False,
                progress="unavailable",
                safe_cancellation=False,
                supported_partition_styles=("GPT", "MBR"),
                supported_bitlocker_states=("off", "on", "unknown"),
                destination_size_rule="target_bytes >= source_bytes",
            )
        return self._capabilities

    def build_plan(self, source: DiskIdentity, target: DiskIdentity) -> ClonePlan:
        capabilities = self.validate_capabilities()
        if not capabilities.supported:
            raise DiskCloneBlocked(capabilities.blocker, "blocked_provider")
        return _build_plan("aomei", capabilities, source, target, "disk_intelligent")

    def start(self, plan: ClonePlan, event_sink: Callable[[dict[str, Any]], None] | None = None) -> ProviderProcess:
        raise DiskCloneBlocked("Execucao AOMEI permanece desabilitada ate validacao local explicita.", "blocked_provider")


class DiskGeniusProvider(UnsupportedProvider):
    def __init__(self):
        super().__init__("diskgenius", "DiskGenius nao oferece um contrato CLI nao interativo validado para selecionar discos com seguranca.")

    def discover(self) -> ProviderDiscovery:
        path = Path(r"C:\Program Files\DiskGenius\DiskGenius.exe")
        if path.is_file():
            return ProviderDiscovery("diskgenius", str(path), "DiskGenius", _file_product_version(path), edition="unknown", present=True, detail=self.detail)
        return super().discover()


def _build_plan(provider: str, capabilities: ProviderCapabilities, source: DiskIdentity, target: DiskIdentity, mode: str) -> ClonePlan:
    if source.number is None or target.number is None:
        raise DiskCloneBlocked("O provedor exige mapeamento fisico atual; numero de disco ausente.", "blocked_identity")
    if source.number == target.number:
        raise DiskCloneBlocked("Origem e destino sao o mesmo disco fisico.", "blocked_identity")
    if source.partition_style and capabilities.supported_partition_styles and source.partition_style.upper() not in capabilities.supported_partition_styles:
        raise DiskCloneBlocked("Estilo de particao da origem nao suportado pelo provedor.", "blocked_provider")
    if target.size_bytes < source.size_bytes:
        raise DiskCloneBlocked("O destino e menor que a origem em bytes exatos.", "blocked_size")
    required = tuple(sorted({part.canonical_role for part in source.partitions if part.canonical_role}))
    return ClonePlan(
        provider=provider,
        mode=mode,
        source_selector=str(source.number),
        target_selector=str(target.number),
        source_size_bytes=source.size_bytes,
        target_size_bytes=target.size_bytes,
        required_partitions=required,
        size_rule=capabilities.destination_size_rule or "target_bytes >= source_bytes",
        arguments=("/c", "/t", "disk", "/s", str(source.number), "/d", str(target.number), "/a", "/o", "yes"),
        source_identity=source.stable_identifiers(),
        target_identity=target.stable_identifiers(),
    )


class FakeProvider:
    def __init__(self, result: ProviderResult | None = None, capabilities: ProviderCapabilities | None = None):
        self.result = result or ProviderResult(True, exit_code=0, progress_type="exact", copied_bytes=0)
        self.capabilities = capabilities or ProviderCapabilities(
            supported=True,
            whole_disk_clone=True,
            system_disk_clone=True,
            live_clone=True,
            sector_by_sector=True,
            intelligent_clone=True,
            stable_disk_selector=True,
            progress="exact",
            safe_cancellation=True,
            supported_partition_styles=("GPT", "MBR"),
            supported_bitlocker_states=("off", "on", "unknown"),
            destination_size_rule="target_bytes >= source_bytes",
            simulation_only=True,
        )
        self.started = 0
        self.plans: list[ClonePlan] = []

    def discover(self) -> ProviderDiscovery:
        return ProviderDiscovery("fake", "fake-provider", "Fake Provider", "1", edition="test", present=True, detail="somente simulacao/teste")

    def validate_capabilities(self) -> ProviderCapabilities:
        return self.capabilities

    def build_plan(self, source: DiskIdentity, target: DiskIdentity) -> ClonePlan:
        return _build_plan("fake", self.capabilities, source, target, "disk_intelligent")

    def start(self, plan: ClonePlan, event_sink: Callable[[dict[str, Any]], None] | None = None) -> ProviderProcess:
        self.started += 1
        self.plans.append(plan)
        if event_sink:
            event_sink({"progress_type": self.result.progress_type, "percent": 50, "copied_bytes": self.result.copied_bytes or 0, "phase": "cloning"})
        return ProviderProcess(pid=0, handle=self.result)

    def request_cancel(self, process: ProviderProcess) -> bool:
        return self.capabilities.safe_cancellation

    def inspect_result(self, process: ProviderProcess) -> ProviderResult:
        return self.result


@dataclass(frozen=True)
class Enrollment:
    source: DiskIdentity
    target: DiskIdentity
    provider: str
    mode: str
    created_at: str
    schema: int = ENROLLMENT_SCHEMA

    def payload(self) -> dict[str, Any]:
        return {"schema": self.schema, "source": self.source.persistent_identity_payload(), "target": self.target.persistent_identity_payload(), "provider": self.provider, "mode": self.mode, "created_at": self.created_at}


class EnrollmentStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.p = paths(self.root)
        self.manifest_path = self.p.config / ENROLLMENT_FILE
        self.secret_path = self.p.config / ENROLLMENT_SECRET_FILE

    def _secret(self, create: bool = False) -> bytes | None:
        if self.secret_path.exists():
            return self.secret_path.read_bytes()
        if not create:
            return None
        secret = os.urandom(32)
        atomic_write_bytes(self.secret_path, secret)
        try:
            self.secret_path.chmod(0o600)
        except OSError:
            pass
        return secret

    def save(self, source: DiskIdentity, target: DiskIdentity, provider: str, mode: str) -> Enrollment:
        if not _clean(provider) or not _clean(mode):
            raise DiskCloneBlocked("Inscricao sem provedor ou modo validado.", "blocked_provider")
        if source.identity_strength() != "strong" or target.identity_strength() != "strong":
            raise DiskCloneBlocked("A identidade da origem ou do destino e fraca ou ambigua; inscricao recusada.", "blocked_identity")
        if source.matches(target, require_strong=False):
            raise DiskCloneBlocked("Origem e destino nao podem ser o mesmo disco.", "blocked_identity")
        enrollment = Enrollment(source, target, provider, mode, utc_now(), ENROLLMENT_SCHEMA)
        secret = self._secret(create=True)
        assert secret is not None
        payload = enrollment.payload()
        signed = {"payload": payload, "hmac": hmac.new(secret, canonical_json(payload), hashlib.sha256).hexdigest()}
        atomic_write_text(self.manifest_path, json.dumps(signed, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            self.manifest_path.chmod(0o600)
        except OSError:
            pass
        return enrollment

    def load(self) -> Enrollment | None:
        if not self.manifest_path.exists():
            return None
        secret = self._secret()
        if not secret:
            raise DiskCloneBlocked("Segredo local de inscricao ausente.", "blocked_identity")
        try:
            signed = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            payload = signed["payload"]
            expected = hmac.new(secret, canonical_json(payload), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(signed.get("hmac", "")), expected):
                raise DiskCloneBlocked("Manifesto de inscricao adulterado.", "blocked_identity")
            schema = _safe_int(payload.get("schema"), 1)
            if schema != ENROLLMENT_SCHEMA:
                raise DiskCloneBlocked("Manifesto de inscricao antigo ou desconhecido; reinscricao obrigatoria.", "re_enrollment_required")
            return Enrollment(DiskIdentity.from_dict(payload["source"]), DiskIdentity.from_dict(payload["target"]), _clean(payload["provider"]), _clean(payload["mode"]), _clean(payload["created_at"]), schema)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DiskCloneBlocked("Manifesto de inscricao invalido.", "blocked_identity") from exc


@dataclass(frozen=True)
class ActivitySample:
    average_percent: float
    maximum_percent: float
    sample_count: int
    duration_seconds: int
    mapped_to_source: bool = True
    reason: str = ""


class ActivitySampler(Protocol):
    def sample(self, source: DiskIdentity, duration_seconds: int) -> ActivitySample: ...
    def recheck(self, source: DiskIdentity, duration_seconds: int) -> ActivitySample: ...


class FakeActivitySampler:
    def __init__(self, sample: ActivitySample | None = None):
        self.sample_value = sample or ActivitySample(0, 0, 1, 0)

    def sample(self, source: DiskIdentity, duration_seconds: int) -> ActivitySample:
        return self.sample_value

    def recheck(self, source: DiskIdentity, duration_seconds: int) -> ActivitySample:
        return self.sample_value


class WindowsActivitySampler:
    def __init__(self, sleep: Callable[[float], None] = time.sleep):
        self.sleep = sleep

    def _read(self, source: DiskIdentity) -> float:
        if os.name != "nt" or source.number is None:
            raise DiskCloneBlocked("Nao foi possivel mapear o contador de atividade ao disco inscrito.", "blocked_identity")
        # The instance name is checked against the physical disk number.  An
        # ambiguous or missing mapping is a block, never a guessed _Total.
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Counter '\\PhysicalDisk(*)\\% Disk Time' | Select-Object -ExpandProperty CounterSamples | Select-Object InstanceName,CookedValue | ConvertTo-Json -Compress"], text=True, capture_output=True, check=False)
        if result.returncode:
            raise DiskCloneBlocked("Falha ao consultar atividade do disco de origem.", "blocked_identity")
        try:
            rows = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise DiskCloneBlocked("Contador de atividade retornou dados invalidos.", "blocked_identity") from exc
        if isinstance(rows, dict):
            rows = [rows]
        matches = [row for row in rows if re.search(rf"(?:^|\s){int(source.number)}(?:\s|$)", _clean(row.get("InstanceName")))]
        if len(matches) != 1:
            raise DiskCloneBlocked("Mapeamento do contador de atividade e ambiguo.", "blocked_identity")
        value = float(matches[0].get("CookedValue", -1))
        if not 0 <= value <= 100:
            raise DiskCloneBlocked("Valor de atividade do disco invalido.", "blocked_identity")
        return value

    def _sample(self, source: DiskIdentity, duration_seconds: int) -> ActivitySample:
        values: list[float] = []
        count = max(1, min(int(duration_seconds), 300))
        for index in range(count):
            values.append(self._read(source))
            if index + 1 < count:
                self.sleep(1)
        return ActivitySample(sum(values) / len(values), max(values), len(values), count)

    def sample(self, source: DiskIdentity, duration_seconds: int) -> ActivitySample:
        return self._sample(source, duration_seconds)

    def recheck(self, source: DiskIdentity, duration_seconds: int) -> ActivitySample:
        return self._sample(source, max(1, min(duration_seconds, 20)))


class StructuralVerifier(Protocol):
    def verify(self, source: DiskIdentity, target: DiskIdentity) -> "VerificationResult": ...


@dataclass(frozen=True)
class VerificationResult:
    structurally_verified: bool
    evidence: str = ""
    boot_tested: bool = False
    inventory_at: str = ""


class FakeStructuralVerifier:
    def __init__(self, result: VerificationResult | None = None):
        self.result = result or VerificationResult(True, "fake partition table matched; boot test not performed")

    def verify(self, source: DiskIdentity, target: DiskIdentity) -> VerificationResult:
        return self.result


def _partition_size_matches(source: PartitionIdentity, target: PartitionIdentity) -> bool:
    if not source.size_bytes or not target.size_bytes:
        return True
    tolerance = max(1024 * 1024, int(source.size_bytes * 0.01))
    return abs(source.size_bytes - target.size_bytes) <= tolerance


def _target_roles_for_source(source_role: str) -> set[str]:
    # The running OS volume is labelled ``windows`` only because it is the
    # current system volume.  Its copied offline counterpart is canonical
    # GPT basic-data, while an explicitly observed target windows label is
    # also accepted when available.
    return {"windows", "basic_data"} if source_role == "windows" else {source_role}


def _partition_equivalence(source: DiskIdentity, target: DiskIdentity) -> tuple[bool, str]:
    if len(source.partitions) != len(target.partitions):
        return False, "quantidade de particoes diferente"
    remaining = list(target.partitions)
    for source_part in sorted(source.partitions, key=lambda item: (item.canonical_role, item.size_bytes)):
        role = source_part.canonical_role
        candidates = [part for part in remaining if part.canonical_role in _target_roles_for_source(role)]
        if source_part.filesystem:
            candidates = [part for part in candidates if not part.filesystem or _normal(part.filesystem) == _normal(source_part.filesystem)]
        candidates = [part for part in candidates if _partition_size_matches(source_part, part)]
        if not candidates:
            return False, f"particao equivalente ausente: {role}"
        selected = min(candidates, key=lambda item: abs(item.size_bytes - source_part.size_bytes) if item.size_bytes and source_part.size_bytes else 0)
        remaining.remove(selected)
    return True, ""


class WindowsStructuralVerifier:
    def verify(self, source: DiskIdentity, target: DiskIdentity) -> VerificationResult:
        if source.matches(target, require_strong=False):
            return VerificationResult(False, "origem e destino compartilham a mesma identidade persistente")
        if source.partition_style and _normal(source.partition_style) != _normal(target.partition_style):
            return VerificationResult(False, "estilo de particao diferente")
        if _normal(source.partition_style) == "gpt" and "efi" not in {part.canonical_role for part in target.partitions}:
            return VerificationResult(False, "particao EFI obrigatoria ausente")
        equivalent, reason = _partition_equivalence(source, target)
        if not equivalent:
            return VerificationResult(False, reason)
        source_roles = {part.canonical_role for part in source.partitions}
        target_roles = {part.canonical_role for part in target.partitions}
        if source.is_system and not ({"windows", "basic_data"} & target_roles):
            return VerificationResult(False, "volume do sistema operacional ausente")
        if _normal(source.partition_style) == "mbr" and "active" in source_roles and "active" not in target_roles:
            return VerificationResult(False, "particao ativa do MBR ausente")
        return VerificationResult(True, "equivalencia estrutural conferida; boot test nao realizado", False)


class CloneLock:
    def __init__(self, path: Path, stale_after: timedelta = timedelta(hours=12)):
        self.path = Path(path)
        self.stale_after = stale_after
        self.token = uuid.uuid4().hex
        self.acquired = False

    def acquire(self, run_id: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            if lock_is_stale(self.path, self.stale_after) and not _pid_is_live(self.path):
                self.path.unlink(missing_ok=True)
            else:
                raise RuntimeError("Outro clone ou operacao de importacao esta em andamento.")
        payload = {"token": self.token, "run_id": run_id, "pid": os.getpid(), "started_at": utc_now()}
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise RuntimeError("Outro clone esta em andamento.") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False))
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            self.path.unlink(missing_ok=True)
            raise
        self.acquired = True

    def release(self) -> None:
        if not self.acquired:
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        if hmac.compare_digest(str(payload.get("token", "")), self.token):
            self.path.unlink(missing_ok=True)
        self.acquired = False

    def __enter__(self):
        raise RuntimeError("CloneLock exige acquire(run_id) para vincular o proprietario.")

    def __exit__(self, exc_type, exc, tb):
        self.release()


def _pid_is_live(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        pid = int(payload.get("pid", 0))
        if pid <= 0:
            return False
        os.kill(pid, 0)
        return True
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def _process_is_live(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def windows_interactive_session_available() -> bool:
    """Return true only for an active console desktop that can display a warning."""
    if os.name != "nt":
        return False
    try:
        session_id = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
        if session_id == 0xFFFFFFFF:
            return False
        # OpenInputDesktop fails while Windows is presenting the secure lock
        # desktop, which is the case we must not silently bypass.
        handle = ctypes.windll.user32.OpenInputDesktop(0, False, 0x0001)
        if not handle:
            return False
        ctypes.windll.user32.CloseDesktop(handle)
        return True
    except (AttributeError, OSError):
        return False


def protected_path_conflicts(target: DiskIdentity, protected_paths: Iterable[Path | str], resolver: ProtectedPathResolver | None = None) -> list[str]:
    if resolver is not None:
        conflicts, _ = resolved_protected_path_conflicts(target, protected_paths, resolver)
        return conflicts
    mounts = [Path(item).anchor.casefold() for item in target.mount_points if Path(item).anchor]
    conflicts: list[str] = []
    for raw_path in protected_paths:
        value = Path(raw_path)
        anchor = value.anchor.casefold()
        if anchor and anchor in mounts:
            conflicts.append(str(value))
    return conflicts


@dataclass(frozen=True)
class ProtectedPathResolution:
    path: str
    resolved: bool
    runtime_selector: str = ""
    disk_number: int | None = None
    identifiers: tuple[str, ...] = ()
    reason: str = ""


class ProtectedPathResolver(Protocol):
    def resolve(self, protected_paths: Iterable[Path | str]) -> list[ProtectedPathResolution]: ...


class FakeProtectedPathResolver:
    """Deterministic resolver for tests; it never consults host storage."""

    def __init__(self, mapping: dict[str, str | DiskIdentity] | None = None):
        self.mapping = {str(Path(key)).casefold(): value for key, value in (mapping or {}).items()}

    def resolve(self, protected_paths: Iterable[Path | str]) -> list[ProtectedPathResolution]:
        result = []
        for raw in protected_paths:
            path = str(raw)
            value = self.mapping.get(str(Path(raw)).casefold())
            if isinstance(value, DiskIdentity):
                result.append(ProtectedPathResolution(path, True, value.runtime_selector, value.number, value.stable_identifiers()))
            elif value:
                result.append(ProtectedPathResolution(path, True, str(value), identifiers=(str(value),)))
            else:
                result.append(ProtectedPathResolution(path, False, reason="fake path mapping ausente"))
        return result


class WindowsProtectedPathResolver:
    """Resolve active paths through volume, partition, and physical-disk APIs."""

    def resolve(self, protected_paths: Iterable[Path | str]) -> list[ProtectedPathResolution]:
        if os.name != "nt":
            raise DiskCloneBlocked("A resolucao fisica de caminhos exige Windows.", "blocked_protected_path")
        result: list[ProtectedPathResolution] = []
        for raw in protected_paths:
            original = str(raw)
            candidate = Path(raw)
            while not candidate.exists() and candidate.parent != candidate:
                candidate = candidate.parent
            if not candidate.exists():
                result.append(ProtectedPathResolution(original, False, reason="caminho e pai inexistentes"))
                continue
            escaped = str(candidate).replace("'", "''")
            script = rf"""
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath '{escaped}' -Force
$drive = $item.PSDrive.Name
$partition = Get-Partition -DriveLetter $drive -ErrorAction Stop
$disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
$physical = Get-CimInstance Win32_DiskDrive | Where-Object Index -eq $disk.Number | Select-Object -First 1
[pscustomobject]@{{path='{original.replace("'", "''")}'; disk_number=$disk.Number; runtime_selector=if($physical){{$physical.DeviceID}}else{{''}}; serial=if($disk.SerialNumber){{$disk.SerialNumber}}else{{''}}; pnp=if($physical){{$physical.PNPDeviceID}}else{{''}}; unique_id=if($disk.UniqueId){{$disk.UniqueId}}else{{''}}}} | ConvertTo-Json -Compress
"""
            completed = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], text=True, capture_output=True, check=False)
            if completed.returncode:
                result.append(ProtectedPathResolution(original, False, reason="falha ao resolver volume/disco fisico"))
                continue
            try:
                row = json.loads(completed.stdout or "{}")
            except json.JSONDecodeError:
                row = {}
            identifiers = tuple(_clean(row.get(key)) for key in ("serial", "pnp", "unique_id") if _clean(row.get(key)))
            if not identifiers:
                result.append(ProtectedPathResolution(original, False, reason="identidade fisica ausente"))
                continue
            result.append(ProtectedPathResolution(original, True, _clean(row.get("runtime_selector")), _safe_int(row.get("disk_number"), -1), identifiers))
        return result


def resolved_protected_path_conflicts(
    target: DiskIdentity,
    protected_paths: Iterable[Path | str],
    resolver: ProtectedPathResolver,
    *,
    inventory: Sequence[DiskIdentity] | None = None,
) -> tuple[list[str], list[ProtectedPathResolution]]:
    resolutions = resolver.resolve(protected_paths)
    target_ids = {_normal(value) for value in target.stable_identifiers()}
    conflicts = []
    for resolution in resolutions:
        if not resolution.resolved:
            conflicts.append(f"{resolution.path} ({resolution.reason or 'nao resolvido'})")
            continue
        resolved_ids = {_normal(value) for value in resolution.identifiers if _clean(value)}
        if inventory is None:
            if target_ids.intersection(resolved_ids):
                conflicts.append(resolution.path)
            continue
        matches = [
            disk
            for disk in inventory
            if disk.identity_strength() == "strong"
            and len(resolved_ids) >= 2
            and resolved_ids.issubset({_normal(value) for value in disk.stable_identifiers()})
        ]
        if len(matches) != 1:
            conflicts.append(f"{resolution.path} ({'nao resolvido' if not matches else 'mapeamento ambiguo'})")
        elif matches[0].matches(target, require_strong=True):
            conflicts.append(resolution.path)
    return conflicts, resolutions


def _source_paths(p: VaultPaths, cfg: dict[str, Any]) -> list[Path]:
    values = [p.root, p.db, p.logs, p.config, p.reports, p.inbox]
    source_cfg = cfg.get("source_sync", {})
    values.extend(Path(item) for item in source_cfg.get("google_takeout_sources", []) if _clean(item))
    values.extend(Path(item) for item in cfg.get("disk_clone", {}).get("protected_paths", []) if _clean(item))
    if os.name == "nt":
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        values.extend(path for path in (system_root, system_root / "pagefile.sys", system_root / "memory.dmp") if path.exists())
    return values


def provider_for_config(config: dict[str, Any]) -> CloneProvider:
    name = _normal(config.get("provider", "auto"))
    if name == "fake":
        return FakeProvider()
    if name in {"auto", "offline", "clonezilla_offline"}:
        return ClonezillaOfflineProvider()
    if name == "aomei":
        return AOMEIProvider()
    if name == "diskgenius":
        return DiskGeniusProvider()
    aomei = AOMEIProvider()
    if aomei.discover().present:
        return aomei
    return DiskGeniusProvider()


_provider_for_config = provider_for_config


@dataclass(frozen=True)
class PreflightResult:
    ok: bool
    state: str
    reason: str
    source: DiskIdentity | None = None
    target: DiskIdentity | None = None
    plan: ClonePlan | None = None
    discovery: ProviderDiscovery | None = None
    capabilities: ProviderCapabilities | None = None
    activity: ActivitySample | None = None
    details: dict[str, Any] = field(default_factory=dict)


class CloneService:
    def __init__(
        self,
        p: VaultPaths,
        *,
        inventory: DiskInventory | None = None,
        provider: CloneProvider | None = None,
        lifecycle: DiskLifecycle | None = None,
        sampler: ActivitySampler | None = None,
        verifier: StructuralVerifier | None = None,
        protected_path_resolver: ProtectedPathResolver | None = None,
        clock: Callable[[], datetime] | None = None,
        is_admin: Callable[[], bool] | None = None,
        session_available: Callable[[], bool] | None = None,
    ):
        self.p = p
        self.config = validate_disk_clone_config(load_config(p.root).get("disk_clone", {}))
        self.inventory = inventory or WindowsDiskInventory()
        self.provider = provider or provider_for_config(self.config)
        self.lifecycle = lifecycle or WindowsDiskLifecycle()
        self.sampler = sampler or WindowsActivitySampler()
        self.verifier = verifier or WindowsStructuralVerifier()
        self.protected_path_resolver = protected_path_resolver if protected_path_resolver is not None else (WindowsProtectedPathResolver() if isinstance(self.inventory, WindowsDiskInventory) else None)
        self.clock = clock or (lambda: datetime.now().astimezone())
        self.is_admin = is_admin or (lambda: bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False)
        self.session_available = session_available or windows_interactive_session_available
        self.enrollment = EnrollmentStore(p.root)

    @property
    def clone_lock_path(self) -> Path:
        return self.p.logs / "localvault_disk_clone.lock"

    def _profile(self) -> dict[str, Any] | None:
        with db.connect(self.p.db) as conn:
            row = conn.execute("SELECT * FROM disk_clone_profile WHERE id=1").fetchone()
        return dict(row) if row else None

    def status(self) -> dict[str, Any]:
        profile = self._profile()
        try:
            enrollment = self.enrollment.load()
            enrollment_status = "valido" if enrollment else "ausente"
        except DiskCloneBlocked as exc:
            enrollment, enrollment_status = None, "reinscricao obrigatoria" if exc.state == "re_enrollment_required" else f"bloqueado: {exc.reason}"
        discovery = self.provider.discover()
        capabilities = self.provider.validate_capabilities()
        last_verified = profile.get("last_verified_at") if profile else None
        due = next_due_at(last_verified, self.config["interval_days"], self.clock())
        current_state = _latest_clone_state(self.p.db)
        if isinstance(self.provider, ClonezillaOfflineProvider) and current_state == "none":
            current_state = "offline_boot_not_configured"
        recent_runs = _clone_runs(self.p.db)
        retryable_run = next((run["run_id"] for run in recent_runs if run.get("state") in RETRYABLE_FAILURE_STATES and not run.get("retry_run_id")), None)
        return {
            "enabled": self.config["enabled"],
            "provider": discovery.name,
            "provider_present": discovery.present,
            "provider_version": discovery.version,
            "provider_edition": discovery.edition or "desconhecida",
            "provider_supported": capabilities.supported,
            "provider_blocker": capabilities.blocker or discovery.detail,
            "enrollment": enrollment_status,
            "source": enrollment.source.masked_label if enrollment else "nao inscrito",
            "target": enrollment.target.masked_label if enrollment else "nao inscrito",
            "target_offline_expected": self.config["keep_target_offline"],
            "last_verified_at": last_verified,
            "next_due_at": due.isoformat(),
            "interval_days": self.config["interval_days"],
            "window_start": self.config["window_start"],
            "window_end": self.config["window_end"],
            "window_timezone": "system local time",
            "current_state": current_state,
            "current_state_label": CLONE_STATE_LABELS.get(current_state, current_state),
            "progress": _latest_clone_progress(self.p.db),
            "recent_runs": recent_runs,
            "retryable_run_id": retryable_run,
            "boot_test": "nao testado manualmente",
            "windows_preparation_provider": "localvault_windows_preparation",
            "offline_engine": OFFLINE_ENGINE,
            "offline_engine_version": OFFLINE_ENGINE_VERSION,
            "offline_handoff": asdict(build_offline_boot_handoff_plan()),
            "offline_runtime_state": "offline_runtime_blocked",
            "offline_runtime_reason": "official ISO and extracted runtime tree were not supplied for validation",
            "offline_physical_boot_tested": False,
            "offline_real_execution_enabled": False,
            "real_execution_authorized": False,
        }

    def reconcile_interrupted(self) -> int:
        """Mark abandoned runs interrupted; never infer success from partial data."""
        cutoff = self._clock_now().astimezone(timezone.utc) - timedelta(hours=12)
        placeholders = ",".join("?" for _ in TERMINAL_STATES)
        with db.connect(self.p.db) as conn:
            rows = conn.execute(f"SELECT run_id,provider_pid,started_at FROM disk_clone_runs WHERE state NOT IN ({placeholders})", tuple(TERMINAL_STATES)).fetchall()
        changed = 0
        for row in rows:
            started = parse_timestamp(row["started_at"])
            if started and started > cutoff:
                continue
            if _process_is_live(_safe_int(row["provider_pid"])):
                continue
            _transition(self.p.db, row["run_id"], "interrupted", "estado do provedor desconhecido apos reinicio; sucesso nao inferido")
            _finish_clone_run(self.p.db, row["run_id"], "interrupted", "estado do provedor desconhecido apos reinicio")
            changed += 1
        return changed

    def request_cancel(self, run_id: str, process: ProviderProcess) -> bool:
        """Cancel only through a provider-documented safe mechanism."""
        capabilities = self.provider.validate_capabilities()
        if not capabilities.safe_cancellation:
            return False
        accepted = bool(self.provider.request_cancel(process))
        if accepted:
            _transition(self.p.db, run_id, "cancel_requested", "cancelamento seguro solicitado ao provedor")
        return accepted

    def _inventory_validation(self, enrollment: Enrollment, disks: Sequence[DiskIdentity], discovery: ProviderDiscovery, capabilities: ProviderCapabilities, *, perform_activity: bool) -> PreflightResult:
        source_candidates = [disk for disk in disks if disk.is_system or disk.is_boot]
        source_matches = matching_disks(source_candidates, enrollment.source)
        source = source_matches[0] if len(source_matches) == 1 else None
        if len(source_matches) > 1:
            return PreflightResult(False, "blocked_identity", "A identidade persistente da origem corresponde a mais de um disco.", discovery=discovery, capabilities=capabilities)
        if not source:
            return PreflightResult(False, "blocked_identity", "O disco de origem inscrito nao e o atual disco de sistema.", discovery=discovery, capabilities=capabilities)
        target_matches = matching_disks(disks, enrollment.target)
        target = target_matches[0] if len(target_matches) == 1 else None
        if len(target_matches) > 1:
            return PreflightResult(False, "blocked_identity", "A identidade persistente do destino e ambigua; execucao destrutiva bloqueada.", source, discovery=discovery, capabilities=capabilities)
        if not target:
            return PreflightResult(False, "skipped_target_missing", "O destino inscrito nao foi encontrado.", source, discovery=discovery, capabilities=capabilities)
        if source.matches(target, require_strong=False):
            return PreflightResult(False, "blocked_identity", "Origem e destino sao o mesmo disco fisico.", source, target, discovery=discovery, capabilities=capabilities)
        protected_paths = _source_paths(self.p, load_config(self.p.root))
        resolutions: list[ProtectedPathResolution] = []
        if self.protected_path_resolver is not None:
            conflicts, resolutions = resolved_protected_path_conflicts(target, protected_paths, self.protected_path_resolver, inventory=disks)
        else:
            conflicts = protected_path_conflicts(target, protected_paths)
        details = {
            "inventory_at": utc_now(),
            "source_identity": source.stable_identifiers(),
            "target_identity": target.stable_identifiers(),
            "local_time": self._clock_now().isoformat(),
            "timezone": self._clock_now().tzname() or "local",
        }
        if resolutions:
            details["protected_path_resolutions"] = [asdict(item) for item in resolutions]
        if conflicts:
            return PreflightResult(False, "blocked_protected_path", "O destino contem caminho protegido ou nao resolvido do L-vault.", source, target, discovery=discovery, capabilities=capabilities, details=details | {"conflicts": conflicts})
        if target.size_bytes < source.size_bytes:
            return PreflightResult(False, "blocked_size", "O destino e menor que a origem em bytes exatos.", source, target, discovery=discovery, capabilities=capabilities, details=details)
        if capabilities.supported_bitlocker_states and _normal(source.bitlocker_state) not in {_normal(item) for item in capabilities.supported_bitlocker_states}:
            return PreflightResult(False, "blocked_provider", "O estado BitLocker da origem nao e suportado pelo provedor validado.", source, target, discovery=discovery, capabilities=capabilities, details=details)
        source_roles = {part.canonical_role for part in source.partitions}
        if _normal(source.partition_style) == "gpt" and "efi" not in source_roles:
            return PreflightResult(False, "blocked_provider", "A particao EFI obrigatoria nao foi identificada por GUID/relacao estruturada.", source, target, discovery=discovery, capabilities=capabilities, details=details)
        if not ({"windows", "basic_data"} & source_roles):
            return PreflightResult(False, "blocked_provider", "A particao/volume do Windows nao foi identificado pela relacao estruturada.", source, target, discovery=discovery, capabilities=capabilities, details=details)
        if enrollment.provider != discovery.name or enrollment.mode != "disk_intelligent":
            return PreflightResult(False, "blocked_provider", "O provedor ou modo atual nao corresponde ao manifesto inscrito.", source, target, discovery=discovery, capabilities=capabilities, details=details)
        try:
            plan = self.provider.build_plan(source, target)
        except DiskCloneBlocked as exc:
            return PreflightResult(False, exc.state, exc.reason, source, target, discovery, capabilities, details=details)
        activity = None
        if perform_activity:
            try:
                activity = self.sampler.sample(source, self.config["active_time_sample_seconds"])
            except DiskCloneBlocked as exc:
                return PreflightResult(False, exc.state, exc.reason, source, target, plan, discovery, capabilities, details=details)
            if not activity.mapped_to_source or activity.sample_count < 1:
                return PreflightResult(False, "blocked_identity", "Amostragem de atividade insuficiente ou ambigua.", source, target, plan, discovery, capabilities, activity, details)
            if activity.average_percent >= self.config["active_time_threshold_percent"]:
                return PreflightResult(False, "skipped_high_source_activity", "Atividade media da origem esta acima do limite; nova tentativa somente na proxima noite.", source, target, plan, discovery, capabilities, activity, details)
        return PreflightResult(True, "preflight", "Todas as validacoes nao destrutivas passaram.", source, target, plan, discovery, capabilities, activity, details)

    def _clock_now(self) -> datetime:
        now = self.clock()
        return now.astimezone() if now.tzinfo is None else now

    def _validate_start_boundary(self, run_id: str, *, stage: str) -> PreflightResult:
        now = self._clock_now()
        allowed = within_clone_window(now, self.config["window_start"], self.config["window_end"])
        evidence = {
            "local_time": now.isoformat(),
            "timezone_name": now.tzname() or "local",
            "utc_offset": _timezone_offset(now),
            "window_start": self.config["window_start"],
            "window_end": self.config["window_end"],
            "decision": "allowed" if allowed else "deferred",
            "stage": stage,
        }
        with db.connect(self.p.db) as conn:
            conn.execute(
                "UPDATE disk_clone_runs SET start_window_local_time=?,start_window_timezone=?,start_window_decision=?,local_time_decision=?,timezone_name=? WHERE run_id=?",
                (evidence["local_time"], f"{evidence['timezone_name']} {evidence['utc_offset']}", evidence["decision"], evidence["local_time"], evidence["timezone_name"], run_id),
            )
            conn.execute("INSERT INTO disk_clone_events(run_id,state,reason,occurred_at) VALUES(?,?,?,?)", (run_id, "start_window_check", json.dumps(evidence, ensure_ascii=False, sort_keys=True), utc_now()))
        if not allowed:
            return PreflightResult(False, "skipped_window_expired_before_start", "A janela local expirou antes do inicio do provedor; nova tentativa somente na proxima noite.", details={"start_window": evidence})
        return PreflightResult(True, "start_window_allowed", "Janela local validada imediatamente antes do provedor.", details={"start_window": evidence})

    def _last_moment_revalidate(self, *, simulation: bool, perform_activity: bool = True) -> PreflightResult:
        """One authoritative fresh-identity path used immediately before start."""
        enrollment = self.enrollment.load()
        if not enrollment:
            return PreflightResult(False, "blocked_identity", "Nenhum destino foi inscrito localmente.")
        discovery = self.provider.discover()
        capabilities = self.provider.validate_capabilities()
        if not capabilities.supported:
            return PreflightResult(False, "blocked_provider", capabilities.blocker or discovery.detail, discovery=discovery, capabilities=capabilities)
        disks = self.inventory.list_disks()
        result = self._inventory_validation(enrollment, disks, discovery, capabilities, perform_activity=perform_activity)
        if result.state == "skipped_target_missing":
            return PreflightResult(False, "blocked_identity", "O destino inscrito desapareceu ou foi substituido durante a revalidacao final.", result.source, result.target, result.plan, result.discovery, result.capabilities, result.activity, result.details)
        return result

    def preflight(self, *, perform_activity: bool = False, require_enabled: bool = True) -> PreflightResult:
        if require_enabled and not self.config["enabled"]:
            return PreflightResult(False, "blocked_configuration", "A clonagem esta desativada por padrao.")
        now = self._clock_now()
        if os.name != "nt" and not isinstance(self.inventory, FakeDiskInventory):
            return PreflightResult(False, "blocked_configuration", "A clonagem automatica e exclusiva do Windows.")
        if not within_clone_window(now, self.config["window_start"], self.config["window_end"]):
            return PreflightResult(False, "skipped_outside_window", "Fora da janela local 03:00-04:00; nenhuma midia foi tocada.")
        if not self.is_admin():
            return PreflightResult(False, "blocked_identity", "Privilegios administrativos sao obrigatorios.")
        if self.config["require_unlocked_interactive_session"] and not self.session_available():
            return PreflightResult(False, "skipped_no_interactive_session", "Nao ha sessao interativa desbloqueada visivel.")
        backup_lock_path = self.p.logs / "localvault_backup.lock"
        if backup_lock_path.exists() and not lock_is_stale(backup_lock_path):
            return PreflightResult(False, "blocked_identity", "Outro backup/importacao protegido esta em andamento.")
        profile = self._profile()
        if profile and not clone_is_due(profile.get("last_verified_at"), self.config["interval_days"], now):
            return PreflightResult(False, "skipped_not_due", "Nenhum clone esta devido.")
        if not profile:
            # A first run is due after enrollment; absence of enrollment is a
            # distinct identity block below.
            pass
        if Path(self.clone_lock_path).exists() and not lock_is_stale(self.clone_lock_path):
            return PreflightResult(False, "blocked_identity", "Outro clone esta em andamento.")
        try:
            enrollment = self.enrollment.load()
        except DiskCloneBlocked as exc:
            return PreflightResult(False, exc.state, exc.reason)
        if not enrollment:
            return PreflightResult(False, "blocked_identity", "Nenhum destino foi inscrito localmente.")
        discovery = self.provider.discover()
        capabilities = self.provider.validate_capabilities()
        if not capabilities.supported:
            return PreflightResult(False, "blocked_provider", capabilities.blocker or discovery.detail, discovery=discovery, capabilities=capabilities)
        try:
            disks = self.inventory.list_disks()
        except DiskCloneBlocked as exc:
            return PreflightResult(False, exc.state, exc.reason, discovery=discovery, capabilities=capabilities)
        return self._inventory_validation(enrollment, disks, discovery, capabilities, perform_activity=perform_activity)

    def execute(self, *, trigger: str = "scheduled", countdown: Callable[[int], str] | None = None, simulation: bool = False, parent_run_id: str | None = None) -> dict[str, Any]:
        self.reconcile_interrupted()
        run_id = uuid.uuid4().hex
        _create_clone_run(self.p.db, run_id, trigger, self._clock_now(), parent_run_id=parent_run_id)
        _transition(self.p.db, run_id, "preflight", "inicio")
        if countdown is None and not simulation:
            reason = "A janela nativa de cinco minutos nao foi fornecida; execucao destrutiva bloqueada."
            _transition(self.p.db, run_id, "blocked_configuration", reason)
            _finish_clone_run(self.p.db, run_id, "blocked_configuration", reason)
            return {"run_id": run_id, "state": "blocked_configuration", "reason": reason}
        try:
            result = self.preflight(perform_activity=True, require_enabled=not simulation)
        except DiskCloneBlocked as exc:
            result = PreflightResult(False, exc.state, exc.reason)
        if not result.ok:
            _transition(self.p.db, run_id, result.state, result.reason)
            _finish_clone_run(self.p.db, run_id, result.state, result.reason, result.activity)
            return {"run_id": run_id, "state": result.state, "reason": result.reason}
        _save_run_metadata(self.p.db, run_id, result)
        activity = result.activity
        _transition(self.p.db, run_id, "sampling_activity", "amostragem concluida")
        _save_activity(self.p.db, run_id, activity)
        if countdown:
            _transition(self.p.db, run_id, "countdown", "aviso destrutivo exibido")
            decision = countdown(self.config["countdown_seconds"])
            with db.connect(self.p.db) as conn:
                conn.execute("UPDATE disk_clone_runs SET countdown_outcome=? WHERE run_id=?", (decision, run_id))
            if decision == "cancel":
                _transition(self.p.db, run_id, "cancelled_before_start", "cancelado antes do provedor")
                _finish_clone_run(self.p.db, run_id, "cancelled_before_start", "cancelado antes do provedor", activity)
                return {"run_id": run_id, "state": "cancelled_before_start"}
        _transition(self.p.db, run_id, "prestart_revalidation", "revalidacao final apos contagem regressiva")
        try:
            result = self._last_moment_revalidate(simulation=simulation, perform_activity=True)
            if not result.ok:
                raise DiskCloneBlocked(result.reason, result.state)
            if not simulation and not self.config["allow_real_provider_execution"]:
                raise DiskCloneBlocked("Execucao real esta desabilitada ate validacao local explicita do provedor.", "blocked_provider")
            if result.capabilities and result.capabilities.simulation_only and not simulation:
                raise DiskCloneBlocked("O provedor fake suporta apenas simulacao.", "blocked_provider")
            if not result.source or not result.target or not result.plan:
                raise DiskCloneBlocked("Plano de clone ausente.", "blocked_identity")
            _save_run_metadata(self.p.db, run_id, result)
            _set_final_revalidation(self.p.db, run_id, result)
            backup_lock = BackupLock(self.p.logs / "localvault_backup.lock")
            clone_lock = CloneLock(self.clone_lock_path)
            backup_lock.acquire()
            try:
                clone_lock.acquire(run_id)
                offline_completed = False
                target_brought_online = False
                cleanup_attempted = False
                outcome: dict[str, Any] | None = None
                primary_state: str | None = None
                primary_reason: str | None = None
                try:
                    window_result = self._validate_start_boundary(run_id, stage="before_target_online")
                    if not window_result.ok:
                        raise DiskCloneBlocked(window_result.reason, window_result.state)
                    _transition(self.p.db, run_id, "bringing_target_online", "destino identificado; preparando acesso")
                    if self.config["keep_target_offline"]:
                        self.lifecycle.set_online(result.target)
                        target_brought_online = True
                        result = self._last_moment_revalidate(simulation=simulation, perform_activity=False)
                        if not result.ok:
                            raise DiskCloneBlocked("O destino mudou depois de ficar online; revalidacao bloqueada.", "blocked_identity")
                        _save_run_metadata(self.p.db, run_id, result)
                    # This is intentionally repeated after locks and any online transition.
                    result = self._last_moment_revalidate(simulation=simulation, perform_activity=True)
                    if not result.ok:
                        raise DiskCloneBlocked(result.reason, result.state)
                    _save_run_metadata(self.p.db, run_id, result)
                    _set_final_revalidation(self.p.db, run_id, result)
                    window_result = self._validate_start_boundary(run_id, stage="before_provider_start")
                    if not window_result.ok:
                        raise DiskCloneBlocked(window_result.reason, window_result.state)
                    _transition(self.p.db, run_id, "starting_provider", "iniciando provedor validado")
                    process = self.provider.start(result.plan, lambda event: _save_progress(self.p.db, run_id, event))
                    with db.connect(self.p.db) as conn:
                        conn.execute("UPDATE disk_clone_runs SET provider_pid=? WHERE run_id=?", (process.pid or None, run_id))
                    _transition(self.p.db, run_id, "cloning", "provedor em execucao")
                    provider_result = self.provider.inspect_result(process)
                    with db.connect(self.p.db) as conn:
                        conn.execute("UPDATE disk_clone_runs SET provider_exit_code=? WHERE run_id=?", (provider_result.exit_code, run_id))
                    if not provider_result.success:
                        raise DiskCloneError(provider_result.reason or "O provedor falhou.")
                    _transition(self.p.db, run_id, "verifying", "re-inventariando destino; boot test nao realizado")
                    post_inventory_at = utc_now()
                    try:
                        post_disks = self.inventory.list_disks()
                    except DiskCloneBlocked as exc:
                        _save_verification(self.p.db, run_id, VerificationResult(False, "inventario pos-provedor indisponivel", False, post_inventory_at))
                        raise DiskCloneBlocked("O inventario pos-provedor falhou; verificacao nao pode ser presumida.", "failed_verification") from exc
                    enrollment = self.enrollment.load()
                    fresh_target = find_matching_disk(post_disks, enrollment.target) if enrollment else None
                    if not fresh_target:
                        _save_verification(self.p.db, run_id, VerificationResult(False, "destino ausente ou ambiguo no inventario pos-provedor", False, post_inventory_at))
                        raise DiskCloneBlocked("O destino nao foi encontrado por identidade estavel apos o provedor.", "failed_verification")
                    verification = self.verifier.verify(result.source, fresh_target)
                    verification = VerificationResult(verification.structurally_verified, verification.evidence, False, post_inventory_at)
                    _save_verification(self.p.db, run_id, verification)
                    if not verification.structurally_verified:
                        raise DiskCloneBlocked(verification.evidence or "A verificacao estrutural falhou.", "failed_verification")
                    if self.config["keep_target_offline"]:
                        _transition(self.p.db, run_id, "returning_target_offline", "retornando destino offline")
                        cleanup_attempted = True
                        try:
                            self.lifecycle.set_offline(fresh_target)
                        except Exception as cleanup_error:
                            cleanup_reason = str(cleanup_error)
                            _set_target_offline(self.p.db, run_id, "failed")
                            _record_cleanup_failure(self.p.db, run_id, "success", "provider and structural verification passed", cleanup_reason)
                            _transition(self.p.db, run_id, "failed_offline_cleanup", cleanup_reason)
                            _finish_clone_run(self.p.db, run_id, "failed_offline_cleanup", cleanup_reason, activity)
                            outcome = {"run_id": run_id, "state": "failed_offline_cleanup", "reason": cleanup_reason, "primary_state": "success", "primary_reason": "provider and structural verification passed"}
                        else:
                            _set_target_offline(self.p.db, run_id, "confirmed")
                            offline_completed = True
                    if outcome is None:
                        _transition(self.p.db, run_id, "success", "provedor e estrutura confirmados; boot test nao realizado")
                        _finish_clone_run(self.p.db, run_id, "success", "clone verificado estruturalmente", activity)
                        _mark_success(self.p.db, self._clock_now(), self.config["interval_days"], result.discovery.name if result.discovery else "unknown")
                        outcome = {"run_id": run_id, "state": "success", "verification": verification.evidence, "boot_tested": False}
                except DiskCloneBlocked as exc:
                    primary_state, primary_reason = exc.state, exc.reason
                    _transition(self.p.db, run_id, primary_state, primary_reason)
                    _finish_clone_run(self.p.db, run_id, primary_state, primary_reason, activity)
                    outcome = {"run_id": run_id, "state": primary_state, "reason": primary_reason}
                except Exception as exc:
                    primary_state, primary_reason = "failed_provider", str(exc)
                    _transition(self.p.db, run_id, primary_state, primary_reason)
                    _finish_clone_run(self.p.db, run_id, primary_state, primary_reason, activity)
                    outcome = {"run_id": run_id, "state": primary_state, "reason": primary_reason}
                finally:
                    if self.config["keep_target_offline"] and target_brought_online and result.target and not offline_completed and not cleanup_attempted:
                        try:
                            self.lifecycle.set_offline(result.target)
                            _set_target_offline(self.p.db, run_id, "confirmed")
                        except Exception as cleanup_error:
                            cleanup_reason = str(cleanup_error)
                            _set_target_offline(self.p.db, run_id, "failed")
                            _record_cleanup_failure(self.p.db, run_id, primary_state or "success", primary_reason or "provider and verification completed", cleanup_reason)
                            _transition(self.p.db, run_id, "failed_offline_cleanup", cleanup_reason)
                            _finish_clone_run(self.p.db, run_id, "failed_offline_cleanup", cleanup_reason, activity)
                            outcome = {"run_id": run_id, "state": "failed_offline_cleanup", "reason": cleanup_reason, "primary_state": primary_state or "success", "primary_reason": primary_reason or "provider and verification completed"}
                assert outcome is not None
                return outcome
            finally:
                clone_lock.release()
        except DiskCloneBlocked as exc:
            _transition(self.p.db, run_id, exc.state, exc.reason)
            _finish_clone_run(self.p.db, run_id, exc.state, exc.reason, activity)
            return {"run_id": run_id, "state": exc.state, "reason": exc.reason}
        except RuntimeError as exc:
            _transition(self.p.db, run_id, "blocked_identity", str(exc))
            _finish_clone_run(self.p.db, run_id, "blocked_identity", str(exc), activity)
            return {"run_id": run_id, "state": "blocked_identity", "reason": str(exc)}
        finally:
            if 'backup_lock' in locals():
                backup_lock.release()

    def retry(self, parent_run_id: str, *, countdown: Callable[[int], str] | None = None, simulation: bool = False) -> dict[str, Any]:
        """Run one explicit retry only after validating its durable parent state."""
        with db.connect(self.p.db) as conn:
            parent = conn.execute("SELECT run_id,state,retry_run_id FROM disk_clone_runs WHERE run_id=?", (parent_run_id,)).fetchone()
        if not parent:
            return {"state": "retry_rejected", "reason": "A tentativa original nao existe."}
        if parent["state"] not in RETRYABLE_FAILURE_STATES:
            return {"state": "retry_rejected", "reason": f"O estado {parent['state']} nao permite retry seguro."}
        if parent["retry_run_id"]:
            return {"state": "retry_rejected", "reason": "Esta tentativa ja possui um retry.", "retry_run_id": parent["retry_run_id"]}
        with db.connect(self.p.db) as conn:
            child = conn.execute("SELECT run_id FROM disk_clone_runs WHERE trigger_type='retry' AND parent_run_id=? LIMIT 1", (parent_run_id,)).fetchone()
        if child:
            return {"state": "retry_rejected", "reason": "Esta tentativa ja possui um retry.", "retry_run_id": child["run_id"]}
        try:
            result = self.execute(trigger="retry", countdown=countdown, simulation=simulation, parent_run_id=parent_run_id)
        except sqlite3.IntegrityError:
            return {"state": "retry_rejected", "reason": "Outro processo ja criou o retry desta tentativa."}
        with db.connect(self.p.db) as conn:
            conn.execute("UPDATE disk_clone_runs SET retry_run_id=? WHERE run_id=? AND retry_run_id IS NULL", (result.get("run_id"), parent_run_id))
        return result

    def consume_retry_request(self, *, request_id: str | None = None, countdown: Callable[[int], str] | None = None, simulation: bool = False) -> dict[str, Any]:
        """Claim and execute one durable retry request; duplicate clicks are inert."""
        request = claim_control_request(self.p.db, "retry", request_id=request_id)
        if not request:
            return {"state": "retry_not_claimed", "reason": "Nenhum pedido de retry pendente."}
        parent_run_id = request.get("run_id")
        if not parent_run_id:
            return {"state": "retry_rejected", "reason": "Pedido de retry sem tentativa original."}
        result = self.retry(parent_run_id, countdown=countdown, simulation=simulation)
        if result.get("run_id"):
            return {"state": "retry_accepted", "retry_run_id": result["run_id"], "result": result}
        return result


def simulate_state_machine(root: Path) -> dict[str, Any]:
    """Run the fake offline round trip without using host disks or a provider."""
    result = simulate_offline_round_trip(root)
    # Preserve the legacy helper's success sentinel for existing callers; the
    # authoritative offline state remains available in ``offline_state``.
    return result | {"state": "success", "offline_state": result["state"]}


def _create_clone_run(db_path: Path, run_id: str, trigger: str, now: datetime, *, parent_run_id: str | None = None) -> None:
    with db.connect(db_path) as conn:
        local_now = now.astimezone() if now.tzinfo else now.replace(tzinfo=timezone.utc).astimezone()
        conn.execute("INSERT INTO disk_clone_runs(run_id,trigger_type,scheduled_at,local_time_decision,timezone_name,parent_run_id,state,boot_test_status) VALUES(?,?,?,?,?,?,?,?)", (run_id, trigger, local_now.astimezone(timezone.utc).isoformat(), local_now.isoformat(), local_now.tzname() or "local", parent_run_id, "scheduled", "unverified"))


def _transition(db_path: Path, run_id: str, state: str, reason: str) -> None:
    with db.connect(db_path) as conn:
        conn.execute("INSERT INTO disk_clone_events(run_id,state,reason,occurred_at) VALUES(?,?,?,?)", (run_id, state, reason[:1000], utc_now()))
        conn.execute("UPDATE disk_clone_runs SET state=?,reason=? WHERE run_id=?", (state, reason[:1000], run_id))


def _finish_clone_run(db_path: Path, run_id: str, state: str, reason: str, activity: ActivitySample | None = None) -> None:
    with db.connect(db_path) as conn:
        conn.execute("UPDATE disk_clone_runs SET state=?,reason=?,finished_at=?,activity_average=?,activity_max=?,activity_samples=?,activity_duration=? WHERE run_id=?", (state, reason[:1000], utc_now(), activity.average_percent if activity else None, activity.maximum_percent if activity else None, activity.sample_count if activity else None, activity.duration_seconds if activity else None, run_id))


def _save_activity(db_path: Path, run_id: str, activity: ActivitySample | None) -> None:
    if not activity:
        return
    with db.connect(db_path) as conn:
        conn.execute("UPDATE disk_clone_runs SET activity_average=?,activity_max=?,activity_samples=?,activity_duration=?,activity_sample_json=? WHERE run_id=?", (activity.average_percent, activity.maximum_percent, activity.sample_count, activity.duration_seconds, json.dumps(asdict(activity), ensure_ascii=False, sort_keys=True), run_id))


def _save_run_metadata(db_path: Path, run_id: str, result: PreflightResult) -> None:
    evidence = {
        "inventory_at": result.details.get("inventory_at"),
        "source_identity": result.details.get("source_identity"),
        "target_identity": result.details.get("target_identity"),
        "protected_path_resolutions": result.details.get("protected_path_resolutions", []),
    }
    with db.connect(db_path) as conn:
        conn.execute(
            "UPDATE disk_clone_runs SET source_label=?,target_label=?,source_size_bytes=?,target_size_bytes=?,provider=?,provider_version=?,provider_edition=?,provider_mode=?,preflight_evidence_hash=? WHERE run_id=?",
            (
                result.source.masked_label if result.source else None,
                result.target.masked_label if result.target else None,
                result.source.size_bytes if result.source else None,
                result.target.size_bytes if result.target else None,
                result.discovery.name if result.discovery else None,
                result.discovery.version if result.discovery else None,
                result.discovery.edition if result.discovery else None,
                result.plan.mode if result.plan else None,
                hashlib.sha256(canonical_json(evidence)).hexdigest(),
                run_id,
            ),
        )


def _set_final_revalidation(db_path: Path, run_id: str, result: PreflightResult) -> None:
    evidence = {"inventory_at": result.details.get("inventory_at"), "source_identity": result.details.get("source_identity"), "target_identity": result.details.get("target_identity"), "plan": asdict(result.plan) if result.plan else None}
    with db.connect(db_path) as conn:
        conn.execute("UPDATE disk_clone_runs SET final_revalidation_result=?,local_time_decision=?,timezone_name=? WHERE run_id=?", (json.dumps(evidence, ensure_ascii=False, sort_keys=True), result.details.get("local_time") or result.details.get("inventory_at"), result.details.get("timezone"), run_id))


def _save_progress(db_path: Path, run_id: str, event: dict[str, Any]) -> None:
    progress_type = _clean(event.get("progress_type") or "unavailable")
    if progress_type not in {"exact", "estimated", "unavailable"}:
        progress_type = "unavailable"
    percent = None
    if event.get("percent") is not None:
        try:
            percent = max(0.0, min(99.99, float(event["percent"])))
        except (TypeError, ValueError):
            percent = None
    with db.connect(db_path) as conn:
        conn.execute("INSERT INTO disk_clone_progress(run_id,progress_type,percent,copied_bytes,speed_bytes,eta_seconds,phase,recorded_at) VALUES(?,?,?,?,?,?,?,?)", (run_id, progress_type, percent, _safe_int(event.get("copied_bytes"), 0) if event.get("copied_bytes") is not None else None, _safe_int(event.get("speed_bytes"), 0) if event.get("speed_bytes") is not None else None, _safe_int(event.get("eta_seconds"), 0) if event.get("eta_seconds") is not None else None, _clean(event.get("phase")), utc_now()))
        conn.execute("UPDATE disk_clone_runs SET progress_type=? WHERE run_id=?", (progress_type, run_id))


def _save_verification(db_path: Path, run_id: str, result: VerificationResult) -> None:
    with db.connect(db_path) as conn:
        conn.execute("INSERT INTO disk_clone_verifications(run_id,structurally_verified,boot_tested,evidence,verified_at) VALUES(?,?,?,?,?)", (run_id, int(result.structurally_verified), int(result.boot_tested), result.evidence[:2000], utc_now()))
        conn.execute("UPDATE disk_clone_runs SET verification_status=?,post_provider_inventory_at=?,verification_evidence=?,boot_test_status=? WHERE run_id=?", ("structurally_verified" if result.structurally_verified else "failed", result.inventory_at or utc_now(), result.evidence[:2000], "not_manually_tested", run_id))


def _set_target_offline(db_path: Path, run_id: str, status: str) -> None:
    with db.connect(db_path) as conn:
        conn.execute("UPDATE disk_clone_runs SET target_offline_result=? WHERE run_id=?", (status, run_id))


def _record_cleanup_failure(db_path: Path, run_id: str, primary_state: str, primary_reason: str, cleanup_reason: str) -> None:
    with db.connect(db_path) as conn:
        conn.execute("UPDATE disk_clone_runs SET state='failed_offline_cleanup',primary_failure_state=?,primary_failure_reason=?,cleanup_failure_reason=?,reason=? WHERE run_id=?", (primary_state, primary_reason[:1000], cleanup_reason[:1000], cleanup_reason[:1000], run_id))


def _mark_success(db_path: Path, now: datetime, interval_days: int, provider: str) -> None:
    last = now.astimezone(timezone.utc).isoformat()
    due = (now.astimezone(timezone.utc) + timedelta(days=interval_days)).isoformat()
    with db.connect(db_path) as conn:
        conn.execute("INSERT INTO disk_clone_profile(id,last_verified_at,next_due_at,provider) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET last_verified_at=excluded.last_verified_at,next_due_at=excluded.next_due_at,provider=excluded.provider", (last, due, provider))


def _latest_clone_state(db_path: Path) -> str:
    with db.connect(db_path) as conn:
        row = conn.execute("SELECT state FROM disk_clone_runs ORDER BY rowid DESC LIMIT 1").fetchone()
    return row[0] if row else "idle"


def _latest_clone_progress(db_path: Path) -> dict[str, Any] | None:
    with db.connect(db_path) as conn:
        row = conn.execute("SELECT progress_type,percent,copied_bytes,speed_bytes,eta_seconds,phase,recorded_at FROM disk_clone_progress ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def _clone_runs(db_path: Path) -> list[dict[str, Any]]:
    with db.connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM disk_clone_runs ORDER BY rowid DESC LIMIT 20").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item.pop("source_serial", None)
            item.pop("target_serial", None)
            result.append(item)
        return result


def latest_clone_run_id(db_path: Path) -> str | None:
    with db.connect(db_path) as conn:
        row = conn.execute("SELECT run_id FROM disk_clone_runs ORDER BY started_at DESC, rowid DESC LIMIT 1").fetchone()
    return row["run_id"] if row else None


def create_control_request(db_path: Path, action: str, run_id: str | None = None, actor: str = "local") -> str:
    if action not in {"show", "preflight", "simulate", "cancel", "acknowledge", "retry"}:
        raise ValueError("Acao de clone nao permitida.")
    request_id = uuid.uuid4().hex
    with db.connect(db_path) as conn:
        if action == "retry" and run_id:
            existing = conn.execute("SELECT request_id FROM disk_clone_controls WHERE action='retry' AND run_id=? AND handled_at IS NULL ORDER BY created_at LIMIT 1", (run_id,)).fetchone()
            if existing:
                return existing["request_id"]
        conn.execute("INSERT INTO disk_clone_controls(request_id,action,run_id,actor,created_at) VALUES(?,?,?,?,?)", (request_id, action, run_id, actor, utc_now()))
    return request_id


def active_clone_run_id(db_path: Path) -> str | None:
    placeholders = ",".join("?" for _ in TERMINAL_STATES)
    with db.connect(db_path) as conn:
        row = conn.execute(f"SELECT run_id FROM disk_clone_runs WHERE state NOT IN ({placeholders}) ORDER BY started_at DESC LIMIT 1", tuple(TERMINAL_STATES)).fetchone()
    return row["run_id"] if row else None


def claim_control_request(db_path: Path, action: str, run_id: str | None = None, request_id: str | None = None) -> dict[str, Any] | None:
    """Atomically claim one current-run request; stale show/cancel requests stay inert."""
    with db.connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        if request_id:
            row = conn.execute("SELECT request_id,action,run_id FROM disk_clone_controls WHERE handled_at IS NULL AND action=? AND request_id=?", (action, request_id)).fetchone()
        else:
            row = conn.execute("SELECT request_id,action,run_id FROM disk_clone_controls WHERE handled_at IS NULL AND action=? AND (run_id IS NULL OR run_id=?) ORDER BY created_at LIMIT 1", (action, run_id)).fetchone()
        if not row:
            return None
        updated = conn.execute("UPDATE disk_clone_controls SET handled_at=? WHERE request_id=? AND handled_at IS NULL", (utc_now(), row["request_id"]))
        if updated.rowcount != 1:
            return None
        return dict(row)


def claim_monitor_owner(db_path: Path, run_id: str, owner_pid: int | None = None) -> bool:
    owner_pid = owner_pid or os.getpid()
    with db.connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT owner_pid FROM disk_clone_monitor_owners WHERE run_id=?", (run_id,)).fetchone()
        if row:
            if _safe_int(row["owner_pid"]) == owner_pid or _process_is_live(_safe_int(row["owner_pid"])):
                return False
            conn.execute("DELETE FROM disk_clone_monitor_owners WHERE run_id=?", (run_id,))
        conn.execute("INSERT INTO disk_clone_monitor_owners(run_id,owner_pid,claimed_at) VALUES(?,?,?)", (run_id, owner_pid, utc_now()))
        return True


def release_monitor_owner(db_path: Path, run_id: str, owner_pid: int | None = None) -> None:
    owner_pid = owner_pid or os.getpid()
    with db.connect(db_path) as conn:
        conn.execute("DELETE FROM disk_clone_monitor_owners WHERE run_id=? AND owner_pid=?", (run_id, owner_pid))


def update_disk_clone_settings(root: Path, *, interval_days: int | None = None, enabled: bool | None = None) -> dict[str, Any]:
    cfg = load_config(root)
    section = dict(cfg.get("disk_clone", {}))
    if interval_days is not None:
        section["interval_days"] = interval_days
    if enabled is not None:
        if enabled and not EnrollmentStore(root).load():
            raise DiskCloneBlocked("Nao e permitido habilitar sem manifesto de inscricao valido.", "blocked_identity")
        section["enabled"] = enabled
    section = validate_disk_clone_config(section)
    cfg["disk_clone"] = section
    atomic_write_text(paths(root).config / "config.yaml", yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    with db.connect(paths(root).db) as conn:
        row = conn.execute("SELECT last_verified_at FROM disk_clone_profile WHERE id=1").fetchone()
        if row and row["last_verified_at"]:
            due = next_due_at(row["last_verified_at"], section["interval_days"], datetime.now(timezone.utc)).isoformat()
            conn.execute("UPDATE disk_clone_profile SET next_due_at=?,updated_at=? WHERE id=1", (due, utc_now()))
    return section


def disk_clone_dashboard_data(p: VaultPaths) -> dict[str, Any]:
    try:
        service = CloneService(p)
        return service.status()
    except DiskCloneBlocked as exc:
        return {"enabled": False, "provider": "unknown", "provider_supported": False, "provider_blocker": exc.reason, "enrollment": "bloqueado", "current_state": "blocked_configuration", "recent_runs": []}
