"""Elevated execution worker for the first-party Windows data clone."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

from .clone_roles import PROTECTED_ROLE, SOURCE_ROLE, TARGET_ROLE, matches_role
from .config import paths
from .disk_clone import CloneLock, DiskCloneBlocked, DiskIdentity, WindowsDiskInventory, WindowsProtectedPathResolver, windows_powershell_path, windows_system_directory, windows_system_environment
from .first_party_data_clone import (
    ACTIVE_STATES,
    MODE_LABEL,
    REPARSE_TAG_SYMLINK,
    SNAPSHOT_REVALIDATE_SECONDS,
    CloneJobStore,
    CloneVolume,
    DataCloneError,
    ManifestEntry,
    _identity_digest,
    _is_reparse_path,
    _layout_digest,
    _public_disk,
    _protected_worker_path,
    _utc_now,
    build_manifest,
    compare_manifests,
    parse_vss_shadowstorage,
    resolve_clone_roles,
    robocopy_arguments,
    verify_protected_repository,
)


VOLUME_PATH_RE = re.compile(r"\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\")
SNAPSHOT_DEVICE_RE = re.compile(r"\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\d+\\?\Z", re.IGNORECASE)
COPY_TIMEOUT_SECONDS = 48 * 60 * 60
SNAPSHOT_TIMEOUT_SECONDS = 15 * 60
MANIFEST_SAFETY_MARGIN = 1024 * 1024 * 1024
MAX_SAMPLE_HASH_BYTES = 512 * 1024 * 1024
FULL_SAMPLE_FILE_LIMIT = 16 * 1024 * 1024
LARGE_FILE_SAMPLE_BYTES = 1024 * 1024


def _encode_json(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _clone_process_environment() -> dict[str, str]:
    worker = _protected_worker_path()
    if worker is None:
        raise DataCloneError("O runtime protegido da L-vault não está instalado.", "blocked_backend")
    environment = windows_system_environment(temp_directory=worker.parent / "Temp")
    if _is_reparse_path(worker.parent / "Temp") or not (worker.parent / "Temp").is_dir():
        raise DataCloneError("A pasta temporária protegida do runtime não está disponível.", "blocked_backend")
    return environment


def _system_executable(name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.exe", name):
        raise DataCloneError("Um nome de ferramenta interna do Windows é inválido.", "blocked_backend")
    executable = windows_system_directory() / name
    if not executable.is_file():
        raise DataCloneError("Uma ferramenta interna necessária do Windows não está disponível.", "blocked_backend")
    return executable


def _run_powershell(script: str, *, timeout: int = 120) -> str:
    if os.name != "nt":
        raise DataCloneError("A clonagem exige Windows.", "blocked_backend")
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    result = subprocess.run(
        [str(windows_powershell_path()), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        env=_clone_process_environment(),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise DataCloneError("Uma verificação nativa do Windows falhou; o destino não foi alterado.", "blocked_precheck")
    return result.stdout.strip()


def _powershell_json(body: str, input_value: Any | None = None, *, timeout: int = 120) -> Any:
    prelude = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop';"
    if input_value is not None:
        prelude += f"$lvData=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{_encode_json(input_value)}')) | ConvertFrom-Json;"
    script = prelude + body
    output = _run_powershell(script, timeout=timeout)
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise DataCloneError("Uma consulta estruturada do Windows retornou dados inválidos.", "blocked_precheck") from exc


def _all_volumes() -> list[dict[str, Any]]:
    body = r"""
$rows = [System.Collections.Generic.List[object]]::new()
$systemLetter = $env:SystemDrive.TrimEnd(':')
foreach ($disk in @(Get-Disk -ErrorAction Stop)) {
  $physical = Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Where-Object { [int]$_.Index -eq [int]$disk.Number } | Select-Object -First 1
  foreach ($partition in @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop)) {
    $volume = $null; $volumeError = ''
    try {
      $found = @(Get-Volume -Partition $partition -ErrorAction Stop)
      if ($found.Count -gt 1) { throw 'partition maps to multiple volumes' }
      if ($found.Count -eq 1) { $volume = $found[0] }
    } catch { $volumeError = $_.Exception.GetType().Name }
    $volumeGuid = ''
    if ($volume) {
      $paths = @($partition.AccessPaths) + @($volume.UniqueId) + @($volume.Path)
      $guidPath = $paths | Where-Object { $_ -match 'Volume\{[0-9A-Fa-f-]{36}\}' } | Select-Object -First 1
      if ($guidPath) {
        $match = [regex]::Match($guidPath, 'Volume\{([0-9A-Fa-f-]{36})\}')
        if ($match.Success) { $volumeGuid = '\\?\Volume{' + $match.Groups[1].Value.ToLowerInvariant() + '}\' }
      }
      if (-not $volumeGuid -and -not $volumeError) { $volumeError = 'MissingVolumeGuid' }
    }
    $rows.Add([pscustomobject]@{
      VolumeGuid=$volumeGuid; DiskUniqueId=[string]$disk.UniqueId; DiskNumber=[int]$disk.Number
      PnpDeviceId=[string]$(if($physical){$physical.PNPDeviceID}else{''})
      PartitionNumber=[int]$partition.PartitionNumber; PartitionType=[string]$partition.Type
      GptType=[string]$partition.GptType; PartitionSizeBytes=[long]$partition.Size
      FileSystem=[string]$(if($volume){$volume.FileSystem}else{''})
      Label=[string]$(if($volume){$volume.FileSystemLabel}else{''})
      SizeBytes=[long]$(if($volume){$volume.Size}else{0})
      FreeBytes=[long]$(if($volume){$volume.SizeRemaining}else{0})
      DriveLetter=[string]$(if($volume){$volume.DriveLetter}else{''})
      VolumeLookupError=$volumeError
      IsSystemVolume=($partition.DriveLetter -eq $systemLetter)
      IsDiskSystem=[bool]$disk.IsSystem; IsDiskBoot=[bool]$disk.IsBoot
    })
  }
}
ConvertTo-Json -InputObject @($rows) -Depth 5 -Compress
"""
    payload = _powershell_json(body, timeout=180)
    if payload is None:
        return []
    return payload if isinstance(payload, list) else [payload]


def _source_volumes(source: DiskIdentity, all_volumes: list[dict[str, Any]]) -> tuple[list[CloneVolume], list[dict[str, str]]]:
    source_id = source.storage_unique_id.casefold()
    identity_rows = [row for row in all_volumes if str(row.get("DiskUniqueId", "")).casefold() == source_id]
    if any(
        int(row.get("DiskNumber", -1)) != source.number
        or str(row.get("PnpDeviceId", "")).casefold() != source.pnp_device_id.casefold()
        for row in identity_rows
    ):
        raise DataCloneError("O identificador de armazenamento do Kingston também apareceu ligado a outro dispositivo físico.", "blocked_source_volume")
    rows = [row for row in identity_rows if int(row.get("DiskNumber", -1)) == source.number]
    if not rows:
        raise DataCloneError("Não foi possível enumerar as partições do Kingston; nenhum volume será omitido.", "blocked_source_volume")
    selected: list[CloneVolume] = []
    excluded: list[dict[str, str]] = []
    for row in rows:
        gpt = str(row.get("GptType", "")).strip("{} ").casefold()
        if gpt in {"c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "e3c9e316-0b5c-4db8-817d-f92df00215ae", "de94bba4-06d1-4d40-a16a-bfd50179d6ac"}:
            excluded.append({"path": f"partition:{row.get('PartitionNumber', '?')}", "reason": "boot_or_recovery_partition_not_in_data_clone"})
            continue
        if gpt != "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7":
            raise DataCloneError("O Kingston contém uma partição não reconhecida; ela não será omitida da cópia.", "blocked_source_volume")
        if str(row.get("VolumeLookupError", "")):
            raise DataCloneError("Uma partição de dados do Kingston não pôde ser associada a um único volume legível.", "blocked_source_volume")
        fs = str(row.get("FileSystem", "")).casefold()
        if fs != "ntfs":
            raise DataCloneError("O Kingston contém um volume de dados fora do NTFS; a cópia segura não pode omiti-lo.", "blocked_filesystem")
        try:
            size = int(row.get("SizeBytes") or 0)
            free = int(row.get("FreeBytes") or 0)
            part_number = int(row.get("PartitionNumber") or 0)
            partition_size = int(row.get("PartitionSizeBytes") or 0)
            disk_number = int(row.get("DiskNumber"))
        except (TypeError, ValueError) as exc:
            raise DataCloneError("Um volume do Kingston tem geometria incompleta.", "blocked_source_volume") from exc
        volume_guid = str(row.get("VolumeGuid", ""))
        if not re.fullmatch(r"\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\", volume_guid) or size <= 0 or partition_size <= 0 or size > partition_size:
            raise DataCloneError("Um volume de dados do Kingston não tem identidade/capacidade estável.", "blocked_source_volume")
        selected.append(CloneVolume(
            volume_guid=volume_guid,
            disk_unique_id=str(row.get("DiskUniqueId", "")),
            disk_number=disk_number,
            partition_number=part_number,
            filesystem=fs,
            label=str(row.get("Label", "")),
            size_bytes=size,
            free_bytes=free,
            drive_letter=str(row.get("DriveLetter", "")),
            is_system_volume=bool(row.get("IsSystemVolume")),
        ))
    if sum(volume.is_system_volume for volume in selected) != 1:
        raise DataCloneError("O volume Windows ativo não foi resolvido de forma única no Kingston.", "blocked_source_volume")
    selected.sort(key=lambda volume: (not volume.is_system_volume, volume.partition_number, volume.volume_guid.casefold()))
    selected = [CloneVolume(**(volume.__dict__ | {"role": "windows" if volume.is_system_volume else "data"})) for volume in selected]
    return selected, excluded


def _validate_bitlocker(volumes: list[CloneVolume]) -> dict[str, str]:
    body = r"""
$rows = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{MountPoint=[string]$_.MountPoint; LockStatus=[string]$_.LockStatus; VolumeStatus=[string]$_.VolumeStatus; ProtectionStatus=[string]$_.ProtectionStatus}
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
"""
    payload = _powershell_json(body, timeout=90)
    rows = payload if isinstance(payload, list) else ([payload] if payload else [])
    normalized = {str(row.get("MountPoint", "")).rstrip("\\/").casefold(): row for row in rows if isinstance(row, dict)}
    states: dict[str, str] = {}
    for volume in volumes:
        keys = []
        if volume.drive_letter:
            keys.append(volume.drive_letter.rstrip(":") + ":")
        keys.append(volume.volume_guid.rstrip("\\"))
        match = next((normalized[key.casefold()] for key in keys if key.casefold() in normalized), None)
        if match is None:
            if volume.is_system_volume:
                raise DataCloneError("O estado de criptografia do volume Windows não pôde ser determinado.", "blocked_encryption")
            states[volume.volume_guid] = "unknown_not_reported"
            continue
        lock = str(match.get("LockStatus", "")).casefold()
        if lock not in {"unlocked", "0"}:
            raise DataCloneError("Um volume de dados do Kingston está bloqueado pelo BitLocker.", "blocked_encryption")
        states[volume.volume_guid] = ":".join(str(match.get(key, "")) for key in ("VolumeStatus", "ProtectionStatus", "LockStatus"))
    return states


def _query_shadowstorage() -> dict[str, str]:
    executable = _system_executable("vssadmin.exe")
    result = subprocess.run([str(executable), "list", "shadowstorage"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, env=_clone_process_environment(), cwd=str(executable.parent), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise DataCloneError("A associação VSS não pôde ser lida com privilégios suficientes; nenhum disco foi alterado.", "blocked_vss")
    return parse_vss_shadowstorage(result.stdout)


def _query_shadow_copies() -> list[dict[str, str]]:
    body = r"""
$rows = @(Get-CimInstance -Namespace root/cimv2 -ClassName Win32_ShadowCopy -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{Id=[string]$_.ID; VolumeName=[string]$_.VolumeName; DeviceObject=[string]$_.DeviceObject; State=[string]$_.State}
})
ConvertTo-Json -InputObject $rows -Depth 3 -Compress
"""
    payload = _powershell_json(body, timeout=90)
    if payload is None:
        return []
    rows = payload if isinstance(payload, list) else [payload]
    result = []
    for row in rows:
        if not isinstance(row, dict) or not re.fullmatch(r"\{?[0-9a-fA-F-]{36}\}?", str(row.get("Id", ""))):
            raise DataCloneError("O inventário VSS retornou identidades de snapshot inválidas.", "blocked_snapshot")
        result.append({key: str(row.get(key, "")) for key in ("Id", "VolumeName", "DeviceObject", "State")})
    return result


def _snapshot_id_set(copies: list[dict[str, str]]) -> set[str]:
    return {row["Id"].strip("{}").casefold() for row in copies}


def _volume_key(value: str) -> str:
    match = re.search(r"Volume\{([0-9a-fA-F-]{36})\}", value)
    return match.group(1).casefold() if match else ""


def _device_key(value: str) -> str:
    match = re.search(r"\\device\\harddiskvolumeshadowcopy\d+", value, re.IGNORECASE)
    return match.group(0).casefold() if match else ""


def _snapshot_root(device_object: str) -> Path:
    device = str(device_object).rstrip("\\")
    if not SNAPSHOT_DEVICE_RE.fullmatch(device):
        raise DataCloneError("O dispositivo VSS não tem um caminho GlobalRoot válido.", "blocked_snapshot")
    # The VSS device object is a stable kernel path. Reading it directly avoids
    # a mutable drive-letter mapping that could be reassigned to another disk.
    return Path(device + "\\")


def _assert_snapshot_mapping(mapping: dict[str, str], snapshots: list[dict[str, str]] | None = None) -> None:
    volume_key = _volume_key(str(mapping.get("volume_guid", "")))
    snapshot_id = str(mapping.get("snapshot_id", "")).strip("{}").casefold()
    device_object = str(mapping.get("device_object", ""))
    if not volume_key or not re.fullmatch(r"[0-9a-f-]{36}", snapshot_id) or not SNAPSHOT_DEVICE_RE.fullmatch(device_object.rstrip("\\")):
        raise DataCloneError("O plano de snapshot contém uma identidade inválida.", "blocked_snapshot")
    observed = snapshots if snapshots is not None else _query_shadow_copies()
    rows = [row for row in observed if str(row.get("Id", "")).strip("{}").casefold() == snapshot_id]
    if len(rows) != 1 or _volume_key(str(rows[0].get("VolumeName", ""))) != volume_key:
        raise DataCloneError("O snapshot persistente não corresponde à partição Kingston esperada.", "blocked_snapshot")
    if _device_key(str(rows[0].get("DeviceObject", ""))) != _device_key(str(mapping.get("device_object", ""))):
        raise DataCloneError("O dispositivo VSS mudou após a validação do snapshot.", "blocked_snapshot")


def _validate_shadow_placement(volumes: list[CloneVolume], all_volumes: list[dict[str, Any]], source: DiskIdentity) -> None:
    associations = _query_shadowstorage()
    volume_to_disk = {str(row.get("VolumeGuid", "")).casefold().rstrip("\\"): str(row.get("DiskUniqueId", "")).casefold() for row in all_volumes}
    if not associations:
        raise DataCloneError("O Windows não tem uma associação VSS pré-configurada e segura para o Kingston; nenhum snapshot foi criado e o destino permanece intacto.", "blocked_vss_placement")
    for volume in volumes:
        source_match = VOLUME_GUID_RE.search(volume.volume_guid)
        if not source_match:
            raise DataCloneError("Um volume de origem não tem GUID VSS válido.", "blocked_vss_placement")
        diff_guid = associations.get(source_match.group(1).casefold())
        if not diff_guid:
            raise DataCloneError("Um volume de dados do Kingston não tem associação de armazenamento VSS; nenhum destino foi alterado.", "blocked_vss_placement")
        disk_id = volume_to_disk.get(f"\\\\?\\volume{{{diff_guid}}}".casefold())
        if not disk_id or disk_id != source.storage_unique_id.casefold():
            raise DataCloneError("O VSS não está vinculado a um volume do Kingston; HGST/Seagate não serão usados como armazenamento de snapshot.", "blocked_vss_placement")


def _vss_helper_path() -> Path:
    worker = _protected_worker_path()
    if worker is None:
        raise DataCloneError("O runtime VSS protegido da L-vault não está instalado.", "blocked_backend")
    helper = worker.with_name("LVaultVssSnapshot.exe")
    if not helper.is_file():
        raise DataCloneError("O solicitante VSS first-party não está instalado.", "blocked_backend")
    return helper


def _run_vss_helper(arguments: list[str], *, timeout: int = SNAPSHOT_TIMEOUT_SECONDS) -> dict[str, Any]:
    helper = _vss_helper_path()
    result = subprocess.run(
        [str(helper), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        cwd=str(helper.parent),
        env=_clone_process_environment(),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise DataCloneError("O solicitante VSS first-party não conseguiu concluir a operação.", "blocked_vss")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DataCloneError("O solicitante VSS retornou um resultado inválido.", "blocked_vss") from exc
    if not isinstance(payload, dict):
        raise DataCloneError("O solicitante VSS retornou um resultado inválido.", "blocked_vss")
    return payload


def _destination_name(volume: CloneVolume) -> str:
    if volume.is_system_volume:
        return "WindowsVolume"
    label = re.sub(r"[^A-Za-z0-9_-]", "_", volume.label or "data")[:40]
    return f"DataVolumes\\Partition-{volume.partition_number:02d}-{label}"


def _create_snapshots(
    volumes: list[CloneVolume],
    baseline_ids: set[str],
    store: CloneJobStore,
    job_id: str,
) -> tuple[list[dict[str, str]], list[str]]:
    if not volumes:
        raise DataCloneError("Não há volumes NTFS da origem para criar snapshot.", "blocked_snapshot")
    if any(volume.disk_unique_id.casefold() != SOURCE_ROLE.storage_unique_id.casefold() for volume in volumes):
        raise DataCloneError("Um volume a copiar não pertence ao Kingston autorizado.", "blocked_identity")
    if any(not VOLUME_PATH_RE.fullmatch(volume.volume_guid) for volume in volumes):
        raise DataCloneError("O plano VSS contém um GUID de volume inválido.", "blocked_snapshot")
    requested = [volume.volume_guid for volume in volumes]
    state = store.load() or {}
    state.update(snapshot_cleanup_confirmed=False, vss_snapshot_ids=[], snapshot_map=[], vss_helper_started=True)
    store.new_job(state)
    journal_path = store.job_directory(job_id) / "vss_snapshot_journal.json"
    expected = {_volume_key(value) for value in requested}
    try:
        arguments = ["snapshot", "--journal", str(journal_path)]
        arguments.extend(item for volume in requested for item in ("--volume", volume))
        payload = _run_vss_helper(arguments, timeout=SNAPSHOT_TIMEOUT_SECONDS)
    except Exception:
        _recover_journaled_snapshots(requested, baseline_ids, store, job_id)
        raise
    snapshots = payload.get("snapshots")
    if not isinstance(snapshots, list) or len(snapshots) != len(volumes):
        _recover_journaled_snapshots(requested, baseline_ids, store, job_id)
        raise DataCloneError("O VSS não retornou um snapshot único para cada volume Kingston.", "blocked_snapshot")
    valid_ids = [
        str(row.get("snapshot_id", "")).strip("{}")
        for row in snapshots
        if isinstance(row, dict) and re.fullmatch(r"\{?[0-9a-fA-F-]{36}\}?", str(row.get("snapshot_id", "")))
    ]
    store.update(job_id, vss_snapshot_ids=valid_ids, snapshot_cleanup_confirmed=False)
    try:
        journal_ids = _read_vss_journal(journal_path)
    except DataCloneError:
        _recover_journaled_snapshots(requested, baseline_ids, store, job_id)
        raise
    if {value.casefold() for value in journal_ids} != {value.casefold() for value in valid_ids}:
        _recover_journaled_snapshots(requested, baseline_ids, store, job_id)
        raise DataCloneError("O registro protegido de snapshots difere do resultado VSS.", "blocked_snapshot")
    by_source: dict[str, dict[str, str]] = {}
    snapshot_ids: list[str] = []
    try:
        for row in snapshots:
            if not isinstance(row, dict):
                raise DataCloneError("O VSS retornou uma identidade de snapshot inválida.", "blocked_snapshot")
            snapshot_id = str(row.get("snapshot_id", ""))
            original = str(row.get("original_volume", ""))
            device = str(row.get("device_object", ""))
            source_key = _volume_key(original)
            if not re.fullmatch(r"\{?[0-9a-fA-F-]{36}\}?", snapshot_id) or not VOLUME_PATH_RE.fullmatch(original) or not _device_key(device):
                raise DataCloneError("O VSS retornou uma identidade de snapshot inválida.", "blocked_snapshot")
            if source_key in by_source or source_key not in expected:
                raise DataCloneError("Um snapshot VSS não corresponde de forma única a um volume Kingston.", "blocked_snapshot")
            by_source[source_key] = {"snapshot_id": snapshot_id.strip("{}"), "volume_guid": original, "device_object": device}
            snapshot_ids.append(snapshot_id.strip("{}"))
        if set(by_source) != expected or len({item.casefold() for item in snapshot_ids}) != len(volumes):
            raise DataCloneError("O VSS não confirmou snapshots únicos para todos os volumes Kingston.", "blocked_snapshot")
        observed = {row["Id"].strip("{}").casefold(): row for row in _query_shadow_copies()}
        for source_key, record in by_source.items():
            snapshot_id = record["snapshot_id"].casefold()
            row = observed.get(snapshot_id)
            if snapshot_id in baseline_ids or row is None:
                raise DataCloneError("Um snapshot VSS não é novo ou não está presente no inventário independente.", "blocked_snapshot")
            if _volume_key(row.get("VolumeName", "")) != source_key or _device_key(row.get("DeviceObject", "")) != _device_key(record["device_object"]):
                raise DataCloneError("O inventário Windows não confirma a origem física do snapshot VSS.", "blocked_snapshot")
        store.update(job_id, vss_snapshot_ids=snapshot_ids, snapshot_cleanup_confirmed=False)
    except Exception:
        _recover_journaled_snapshots(requested, baseline_ids, store, job_id)
        raise
    snapshot_map: list[dict[str, str]] = []
    try:
        for volume in volumes:
            record = by_source[_volume_key(volume.volume_guid)]
            _assert_snapshot_mapping(record, list(observed.values()))
            source_path = _snapshot_root(record["device_object"])
            if not source_path.is_dir():
                raise DataCloneError("Um snapshot VSS não está acessível para leitura.", "blocked_snapshot")
            snapshot_map.append({
                "volume_guid": volume.volume_guid,
                "snapshot_id": record["snapshot_id"],
                "device_object": record["device_object"],
                "destination": _destination_name(volume),
            })
            store.update(job_id, snapshot_map=list(snapshot_map))
        return snapshot_map, snapshot_ids
    except Exception:
        cleanup_ok = _cleanup_snapshots(snapshot_ids, requested, baseline_ids)
        store.update(
            job_id,
            vss_snapshot_ids=[] if cleanup_ok else snapshot_ids,
            snapshot_cleanup_confirmed=cleanup_ok,
            vss_recovery_required=not cleanup_ok,
            vss_helper_started=False if cleanup_ok else True,
        )
        raise


def _read_vss_journal(journal_path: Path) -> list[str]:
    if _is_reparse_path(journal_path):
        raise DataCloneError("O registro VSS protegido não é seguro.", "blocked_audit")
    try:
        if journal_path.stat().st_size > 16_384:
            raise DataCloneError("O registro VSS protegido excede o limite esperado.", "blocked_snapshot")
        payload = json.loads(journal_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DataCloneError("O registro protegido de snapshots não foi criado.", "blocked_snapshot") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise DataCloneError("O registro protegido de snapshots está inválido.", "blocked_snapshot") from exc
    ids = payload.get("snapshot_ids") if isinstance(payload, dict) else None
    if not isinstance(ids, list) or len(ids) > 64 or any(not re.fullmatch(r"\{?[0-9a-fA-F-]{36}\}?", str(value)) for value in ids):
        raise DataCloneError("O registro VSS protegido contém IDs inválidos.", "blocked_snapshot")
    normalized = [str(value).strip("{}") for value in ids]
    if len({value.casefold() for value in normalized}) != len(normalized):
        raise DataCloneError("O registro VSS protegido contém IDs repetidos.", "blocked_snapshot")
    return normalized


def _cleanup_snapshots(snapshot_ids: list[str], expected_volumes: list[str], baseline_ids: set[str]) -> bool:
    expected = {_volume_key(value) for value in expected_volumes}
    try:
        copies = {row["Id"].strip("{}").casefold(): row for row in _query_shadow_copies()}
    except Exception:
        return False
    for snapshot_id in snapshot_ids:
        key = snapshot_id.strip("{}").casefold()
        if key in baseline_ids:
            return False
        row = copies.get(key)
        if row and _volume_key(row.get("VolumeName", "")) not in expected:
            return False
        if row is None:
            continue
        try:
            _run_vss_helper(["cleanup", "--snapshot-id", snapshot_id], timeout=120)
        except Exception:
            pass
    try:
        remaining = _snapshot_id_set(_query_shadow_copies())
    except Exception:
        return False
    return not any(snapshot_id.strip("{}").casefold() in remaining for snapshot_id in snapshot_ids)


def _recover_journaled_snapshots(
    requested_volumes: list[str],
    baseline_ids: set[str],
    store: CloneJobStore,
    job_id: str,
) -> None:
    """Clean up only GUIDs durably journaled by this protected helper invocation."""
    journal_path = store.job_directory(job_id) / "vss_snapshot_journal.json"
    try:
        ids = _read_vss_journal(journal_path)
    except DataCloneError:
        current_ids = _snapshot_id_set(_query_shadow_copies())
        new_ids = current_ids - baseline_ids
        store.update(
            job_id,
            snapshot_cleanup_confirmed=not new_ids,
            vss_recovery_required=bool(new_ids),
            vss_snapshot_ids=[],
        )
        return
    store.update(job_id, vss_snapshot_ids=ids, snapshot_cleanup_confirmed=False)
    if _cleanup_snapshots(ids, requested_volumes, baseline_ids):
        store.update(job_id, vss_snapshot_ids=[], snapshot_cleanup_confirmed=True, vss_recovery_required=False)
    else:
        store.update(job_id, snapshot_cleanup_confirmed=False, vss_recovery_required=True)


def _terminate_tree(pid: int) -> None:
    taskkill = _system_executable("taskkill.exe")
    subprocess.run([str(taskkill), "/PID", str(int(pid)), "/T", "/F"], capture_output=True, check=False, env=_clone_process_environment(), cwd=str(taskkill.parent), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _run_clone_job(root: Path, job_id: str) -> None:
    store = CloneJobStore(root, protected=True)
    cancel_gate = store.cancel_gate(job_id, create=False)
    lock = CloneLock(store.job_root / "worker.lock")
    try:
        lock.acquire(job_id)
    except Exception:
        cancel_gate.close()
        raise
    snapshot_ids: list[str] = []
    snapshot_baseline: set[str] = set()
    try:
        prior = store.load()
        prior_needs_review = bool(
            prior
            and prior.get("phase") in {"SNAPSHOT", "TARGET_PREPARE", "COPY", "VERIFY", "CLEANUP"}
            and prior.get("snapshot_cleanup_confirmed") is not True
        )
        if prior and (prior.get("state") in ACTIVE_STATES | {"partial"} or prior_needs_review):
            raise DataCloneError("Há uma operação anterior ativa ou parcial; nenhuma nova preparação foi iniciada.", "blocked_active_job")
        store.create_job_directory(job_id)
        created = _utc_now()
        store.new_job({
            "schema": 1,
            "job_id": job_id,
            "state": "starting",
            "phase": "PRECHECK",
            "created_at": created,
            "updated_at": created,
            "mode": MODE_LABEL,
            "bootable": False,
            "target_destroyed": False,
            "progress": {"files": 0, "bytes": 0},
            "result": None,
            "error": "",
            "worker_pid": os.getpid(),
        })
    except Exception:
        lock.release()
        cancel_gate.close()
        raise
    try:
        store.update(job_id, state="precheck", phase="PRECHECK", updated_at=_utc_now())
        inventory = WindowsDiskInventory()
        source, target, protected = resolve_clone_roles(inventory.list_disks())
        verify_protected_repository(root, protected, WindowsProtectedPathResolver())
        if source.is_system is not True or not source.is_boot:
            raise DataCloneError("O Kingston autorizado não é o disco Windows/sistema atual.", "blocked_identity")
        state = store.load() or {}
        state.update(
            source=_public_disk(source),
            target=_public_disk(target),
            protected=_public_disk(protected),
            source_layout_sha256=_layout_digest(source),
            protected_layout_sha256=_layout_digest(protected),
        )
        store.new_job(state)
        all_volumes = _all_volumes()
        source_volumes, excluded_partitions = _source_volumes(source, all_volumes)
        bitlocker = _validate_bitlocker(source_volumes)
        _validate_shadow_placement(source_volumes, all_volumes, source)
        snapshot_baseline = _snapshot_id_set(_query_shadow_copies())
        store.update(
            job_id,
            state="snapshot",
            phase="SNAPSHOT",
            source_volumes=[volume.__dict__ for volume in source_volumes],
            source_encryption=bitlocker,
            excluded_partitions=excluded_partitions,
            snapshot_ids_before=len(snapshot_baseline),
            snapshot_ids_before_set=sorted(snapshot_baseline),
            vss_helper_started=False,
            snapshot_cleanup_confirmed=False,
        )
        try:
            snapshot_map, snapshot_ids = _create_snapshots(source_volumes, snapshot_baseline, store, job_id)
            store.update(job_id, snapshot_map=snapshot_map)
            _copy_stage(root, job_id, snapshot_map, cancel_gate=cancel_gate)
        finally:
            if snapshot_ids:
                cleanup_ok = _cleanup_snapshots(snapshot_ids, [volume.volume_guid for volume in source_volumes], snapshot_baseline)
                state = store.load() or {}
                if cleanup_ok:
                    state.update(
                        vss_snapshot_ids=[],
                        snapshot_cleanup_confirmed=True,
                        vss_recovery_required=False,
                        vss_helper_started=False,
                        updated_at=_utc_now(),
                    )
                    if state.get("state") == "cleanup":
                        state.update(state="complete", phase="COMPLETE", error="")
                    store.new_job(state)
                else:
                    state.update(
                        state="partial" if state.get("target_destroyed") else "failed",
                        phase="CLEANUP",
                        snapshot_cleanup_confirmed=False,
                        vss_recovery_required=True,
                        vss_helper_started=True,
                        error="O Windows não confirmou a remoção de todos os snapshots VSS criados para esta clonagem.",
                        updated_at=_utc_now(),
                    )
                    store.new_job(state)
            else:
                state = store.load() or {}
                if state.get("snapshot_cleanup_confirmed") is None:
                    store.update(job_id, snapshot_cleanup_confirmed=True)
    except DiskCloneBlocked as exc:
        state = store.load() or {}
        result_state = "partial" if state.get("target_destroyed") else "blocked"
        state.update(state=result_state, phase=state.get("phase", "PRECHECK"), error=exc.reason, updated_at=_utc_now())
        store.new_job(state)
    except DataCloneError as exc:
        state = store.load() or {}
        result_state = "partial" if state.get("target_destroyed") and exc.state not in {"cancelled"} else exc.state
        if state.get("vss_recovery_required"):
            result_state = "partial" if state.get("target_destroyed") else "failed"
            exc.reason += " Uma limpeza VSS ficou pendente; não inicie outra clonagem antes da revisão."
        state.update(state=result_state, phase=state.get("phase", "PRECHECK"), error=exc.reason, updated_at=_utc_now())
        store.new_job(state)
    except Exception as exc:
        state = store.load() or {}
        state.update(state="partial" if state.get("target_destroyed") else "failed", error=f"Falha interna da operação ({type(exc).__name__}).", updated_at=_utc_now())
        store.new_job(state)
    finally:
        lock.release()
        cancel_gate.close()


def _recover_vss_job(root: Path, job_id: str) -> bool:
    """Remove only this job's journaled VSS snapshots after fresh role checks."""
    store = CloneJobStore(root, protected=True)
    lock = CloneLock(store.job_root / "worker.lock", stale_after=timedelta(0))
    lock.acquire(f"vss-recovery-{job_id}")
    try:
        state = store.load()
        snapshot_phase = bool(state and state.get("phase") in {"SNAPSHOT", "TARGET_PREPARE", "COPY", "VERIFY", "CLEANUP"})
        recovery_pending = bool(
            state
            and (
                state.get("vss_recovery_required") is True
                or (snapshot_phase and state.get("snapshot_cleanup_confirmed") is not True)
            )
        )
        if not state or state.get("job_id") != job_id or not recovery_pending:
            raise DataCloneError("Não há uma limpeza VSS pendente para esta operação.", "blocked_audit")

        inventory = WindowsDiskInventory().list_disks()
        source_matches = [disk for disk in inventory if matches_role(disk, SOURCE_ROLE)]
        protected_matches = [disk for disk in inventory if matches_role(disk, PROTECTED_ROLE)]
        if len(source_matches) != 1 or len(protected_matches) != 1:
            raise DataCloneError("As identidades Kingston/HGST não puderam ser revalidadas; nenhum snapshot foi removido.", "blocked_identity")
        source, protected = source_matches[0], protected_matches[0]
        if (
            not source.is_system
            or not source.is_boot
            or source.storage_unique_id.casefold() == protected.storage_unique_id.casefold()
            or _identity_digest(source) != (state.get("source") or {}).get("identity_sha256")
            or _identity_digest(protected) != (state.get("protected") or {}).get("identity_sha256")
            or _layout_digest(source) != state.get("source_layout_sha256")
            or _layout_digest(protected) != state.get("protected_layout_sha256")
        ):
            raise DataCloneError("O estado físico Kingston/HGST mudou desde a operação interrompida; nenhum snapshot foi removido.", "blocked_identity")
        verify_protected_repository(root, protected, WindowsProtectedPathResolver())

        saved_volumes = state.get("source_volumes")
        if not isinstance(saved_volumes, list) or not saved_volumes or len(saved_volumes) > 64:
            raise DataCloneError("A origem da limpeza VSS não tem um inventário protegido válido.", "blocked_audit")
        saved_guids = set()
        for row in saved_volumes:
            if not isinstance(row, dict):
                raise DataCloneError("O inventário protegido de volumes VSS é inválido.", "blocked_audit")
            volume = CloneVolume(**row)
            if (
                volume.disk_unique_id.casefold() != SOURCE_ROLE.storage_unique_id.casefold()
                or not VOLUME_PATH_RE.fullmatch(volume.volume_guid)
            ):
                raise DataCloneError("Um volume do registro VSS não pertence ao Kingston autorizado.", "blocked_identity")
            saved_guids.add(_volume_key(volume.volume_guid))
        current_volumes, _ = _source_volumes(source, _all_volumes())
        if {_volume_key(volume.volume_guid) for volume in current_volumes} != saved_guids:
            raise DataCloneError("As partições de dados Kingston mudaram desde a operação interrompida.", "blocked_identity")

        raw_baseline = state.get("snapshot_ids_before_set")
        if not isinstance(raw_baseline, list) or any(
            not re.fullmatch(r"\{?[0-9a-fA-F-]{36}\}?", str(value)) for value in raw_baseline
        ):
            raise DataCloneError("A linha de base VSS protegida está ausente ou inválida; limpeza recusada.", "blocked_audit")
        baseline_ids = {str(value).strip("{}").casefold() for value in raw_baseline}
        if len(baseline_ids) != len(raw_baseline):
            raise DataCloneError("A linha de base VSS protegida contém identidades repetidas.", "blocked_audit")

        job_directory = store.job_directory(job_id)
        journal_path = job_directory / "vss_snapshot_journal.json"
        helper_started = state.get("vss_helper_started") is True
        if not helper_started and journal_path.exists():
            raise DataCloneError("O registro VSS contradiz o estado protegido da operação; limpeza recusada.", "blocked_audit")
        snapshot_ids = _read_vss_journal(journal_path) if helper_started else []
        volume_guids = [volume.volume_guid for volume in current_volumes]
        store.update(job_id, state="cleanup", phase="CLEANUP", worker_pid=os.getpid(), error="")
        if not _cleanup_snapshots(snapshot_ids, volume_guids, baseline_ids):
            raise DataCloneError("O Windows ainda mostra um snapshot pendente; a limpeza deve ser repetida.", "failed")

        final_state = "partial" if state.get("target_destroyed") else "failed"
        store.update(
            job_id,
            state=final_state,
            phase="CLEANUP",
            worker_pid=os.getpid(),
            vss_snapshot_ids=[],
            snapshot_cleanup_confirmed=True,
            vss_recovery_required=False,
            vss_helper_started=False,
            vss_recovery_completed_at=_utc_now(),
            error="A limpeza VSS terminou. O clone anterior continua incompleto e requer nova revisão." if state.get("target_destroyed") else "A limpeza VSS terminou; a operação anterior não alterou o destino.",
        )
        return True
    except Exception as exc:
        state = store.load() or {}
        if state.get("job_id") == job_id:
            state.update(
                state="partial" if state.get("target_destroyed") else "failed",
                phase="CLEANUP",
                worker_pid=os.getpid(),
                snapshot_cleanup_confirmed=False,
                vss_recovery_required=True,
                error=getattr(exc, "reason", "A limpeza VSS ainda precisa de atenção."),
                updated_at=_utc_now(),
            )
            store.new_job(state)
        return False
    finally:
        lock.release()


def _copy_stage(root: Path, job_id: str, snapshot_map: list[dict[str, str]], *, cancel_gate: Any | None = None) -> None:
    store = CloneJobStore(root, protected=True)
    directory = store.job_directory(job_id)
    state = store.load() or {}
    source_volumes = [CloneVolume(**row) for row in state.get("source_volumes", [])]
    if _cancel_requested(cancel_gate):
        store.update(job_id, state="cancelled", phase="SNAPSHOT", error="Cancelada antes de apagar o destino.")
        return
    if not isinstance(snapshot_map, list) or len(snapshot_map) != len(source_volumes):
        store.update(job_id, state="blocked", phase="SNAPSHOT", error="A identidade do snapshot VSS ficou ambígua; o destino não foi alterado.")
        return
    snapshots = _query_shadow_copies()
    expected_source_keys = {_volume_key(volume.volume_guid) for volume in source_volumes}
    if len({_volume_key(str(mapping.get("volume_guid", ""))) for mapping in snapshot_map}) != len(source_volumes):
        raise DataCloneError("O plano de leitura contém volumes duplicados.", "blocked_snapshot")
    for volume, mapping in zip(source_volumes, snapshot_map, strict=True):
        if _volume_key(str(mapping.get("volume_guid", ""))) != _volume_key(volume.volume_guid) or _volume_key(volume.volume_guid) not in expected_source_keys:
            raise DataCloneError("Um snapshot não corresponde ao volume Kingston autorizado.", "blocked_snapshot")
        _assert_snapshot_mapping(mapping, snapshots)
    if _cancel_requested(cancel_gate):
        store.update(job_id, state="cancelled", phase="SNAPSHOT", error="Cancelada antes de apagar o destino.")
        return
    source_manifests: dict[str, Any] = {}
    for volume, mapping in zip(source_volumes, snapshot_map, strict=True):
        _assert_snapshot_mapping(mapping)
        source_path = _snapshot_root(mapping["device_object"])
        if not source_path.is_dir():
            raise DataCloneError("Um dispositivo snapshot do Windows não está acessível; o destino não foi alterado.", "blocked_snapshot")
        source_manifests[volume.volume_guid] = build_manifest(
            source_path,
            cancel_check=lambda: _cancel_requested(cancel_gate),
            snapshot_guard=lambda current=mapping: _assert_snapshot_mapping(current),
            exclude_windows_runtime_artifacts=volume.is_system_volume,
        )
    expected_bytes = sum(manifest.logical_bytes for manifest in source_manifests.values())
    required = expected_bytes + max(MANIFEST_SAFETY_MARGIN, expected_bytes // 50)
    if required > TARGET_ROLE.size_bytes - MANIFEST_SAFETY_MARGIN:
        raise DataCloneError("Os dados lógicos e a margem de espaço não cabem com segurança no Seagate; ele não foi alterado.", "blocked_capacity")
    # Re-resolve all physical roles and source/protected layouts immediately before the first destructive step.
    disks = WindowsDiskInventory().list_disks()
    source, target, protected = resolve_clone_roles(disks)
    verify_protected_repository(root, protected, WindowsProtectedPathResolver())
    if _identity_digest(source) != (state.get("source") or {}).get("identity_sha256") or _identity_digest(target) != (state.get("target") or {}).get("identity_sha256") or _identity_digest(protected) != (state.get("protected") or {}).get("identity_sha256"):
        raise DataCloneError("Uma identidade física mudou imediatamente antes de apagar o Seagate.", "blocked_identity")
    if _layout_digest(source) != state.get("source_layout_sha256") or _layout_digest(protected) != state.get("protected_layout_sha256"):
        raise DataCloneError("O layout do Kingston ou do HGST mudou antes de apagar o Seagate.", "blocked_identity")
    if _cancel_requested(cancel_gate):
        store.update(job_id, state="cancelled", phase="PRECHECK", error="Cancelada antes de apagar o destino.")
        return
    destruction_marker = directory / "target_clear_started"
    if cancel_gate is None:
        raise DataCloneError("A trava protegida de cancelamento não foi aberta; o destino não foi alterado.", "blocked_cancel_gate")
    with cancel_gate.locked():
        if _cancel_requested(cancel_gate):
            store.update(job_id, state="cancelled", phase="PRECHECK", error="Cancelada antes de apagar o destino.")
            return
        # This persisted boundary and the UI cancel request are serialized by
        # one owner-restricted mutex. Once this phase is visible, the UI refuses
        # cancellation; if cancellation won first, the event above prevents
        # target preparation.
        store.update(job_id, state="target_prepare", phase="TARGET_PREPARE", target_destroyed=False, progress={"files": 0, "bytes": 0, "expected_files": sum(item.file_count for item in source_manifests.values()), "expected_bytes": expected_bytes})
    try:
        target_volume = _prepare_target(target, destruction_marker)
    except DataCloneError as exc:
        destructive = destruction_marker.exists()
        raise DataCloneError(exc.reason, "partial" if destructive else "blocked_identity") from exc
    store.update(job_id, state="target_prepare", phase="TARGET_PREPARE", target_destroyed=True)
    if required > int(target_volume.get("free_bytes") or 0):
        raise DataCloneError("O espaço NTFS efetivamente disponível no Seagate é menor que a margem exigida; o destino está vazio e a cópia não começou.", "partial")
    target_root = Path(target_volume["volume_guid"])
    _assert_target_volume(target_volume["volume_guid"], target)
    data_root = target_root / "CloneData"
    data_root.mkdir(parents=False, exist_ok=False)
    store.update(job_id, state="copy", phase="COPY", target_volume={key: target_volume[key] for key in ("volume_guid", "partition_number", "filesystem", "label", "free_bytes")})
    copy_results = []
    for volume, mapping in zip(source_volumes, snapshot_map, strict=True):
        if _cancel_requested(cancel_gate):
            raise DataCloneError("A clonagem foi cancelada depois que o destino começou a ser preparado.", "partial")
        _assert_snapshot_mapping(mapping)
        source_path = _snapshot_root(mapping["device_object"])
        destination = data_root / mapping["destination"]
        destination.mkdir(parents=True, exist_ok=False)
        _assert_snapshot_mapping(mapping)
        _assert_target_volume(target_volume["volume_guid"], target)
        result = _copy_tree(
            source_path,
            destination,
            source_manifests[volume.volume_guid],
            store,
            job_id,
            cancel_gate,
            snapshot_guard=lambda current=mapping: _assert_snapshot_mapping(current),
        )
        _assert_target_volume(target_volume["volume_guid"], target)
        copy_results.append({"volume_guid": volume.volume_guid, "destination": str(Path(mapping["destination"]).as_posix()), **result})
    store.update(job_id, state="verify", phase="VERIFY", copy_results=copy_results)
    verified, verification = _verify_tree(source_manifests, snapshot_map, data_root, store, job_id, cancel_gate)
    inventory_after = WindowsDiskInventory().list_disks()
    source_after, target_after, protected_after = resolve_clone_roles(inventory_after)
    if _layout_digest(source_after) != state.get("source_layout_sha256"):
        raise DataCloneError("O layout do Kingston mudou durante a clonagem.", "partial")
    if _layout_digest(protected_after) != state.get("protected_layout_sha256"):
        raise DataCloneError("O estado de partições do HGST mudou durante a clonagem.", "partial")
    if not verified:
        verification["verified"] = False
        store.update(job_id, state="partial", phase="VERIFY", result=verification, error="A comparação de manifesto encontrou diferenças; não tente novamente sem nova inspeção.")
        return
    _assert_target_volume(target_volume["volume_guid"], target)
    target_encryption = _target_encryption_state(target_volume["volume_guid"])
    store.update(job_id, state="cleanup", phase="CLEANUP", result=verification)
    for mapping in snapshot_map:
        _clear_data_root_attributes(data_root / mapping["destination"])
    store.update(job_id, state="cleanup", phase="CLEANUP", result=verification | {"verified": True, "bootability": "not_applicable_data_clone", "target_encryption": target_encryption, "metadata_limits": ["NTFS hard-link relationships are copied as independent files.", "ACL, owner, audit data, alternate streams, and extended attributes are requested from Robocopy's backup mode but are not independently read back.", "Filesystem compression state is compared through attributes; compression allocation is not independently inspected."]}, error="")


def _cancel_requested(control: Any) -> bool:
    if control is None:
        return False
    if callable(control):
        return bool(control())
    is_cancelled = getattr(control, "is_cancelled", None)
    if callable(is_cancelled):
        return bool(is_cancelled())
    raise DataCloneError("A trava protegida de cancelamento está inválida.", "blocked_cancel_gate")


def _assert_target_volume(volume_guid: str, target: DiskIdentity) -> None:
    role_data = {
        "source": _role_payload(SOURCE_ROLE),
        "target": _role_payload(TARGET_ROLE),
        "protected": _role_payload(PROTECTED_ROLE),
        "target_unique_id": target.storage_unique_id,
        "volume_guid": volume_guid,
    }
    script = r"""$roles=$lvData
function Resolve-Role([object]$role) {
  $matches=@(Get-Disk -ErrorAction Stop | Where-Object { [string]$_.UniqueId -ieq [string]$role.storage_unique_id })
  if($matches.Count -ne 1){throw 'persistent disk identity is missing or ambiguous'}
  $disk=$matches[0]
  $physical=Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Where-Object { [int]$_.Index -eq [int]$disk.Number } | Select-Object -First 1
  if(-not $physical -or [string]$disk.FriendlyName -ine [string]$role.model -or -not ([string]$disk.SerialNumber).Trim().EndsWith([string]$role.serial_suffix,[StringComparison]::OrdinalIgnoreCase) -or [string]$physical.PNPDeviceID -ine [string]$role.pnp_device_id -or [long]$disk.Size -ne [long]$role.size_bytes -or [string]$disk.BusType -ine [string]$role.bus_type){throw 'persistent disk attributes changed'}
  return $disk
}
$s=Resolve-Role $roles.source; $t=Resolve-Role $roles.target; $p=Resolve-Role $roles.protected
if(-not $s.IsSystem -or -not $s.IsBoot -or $t.IsSystem -or $t.IsBoot -or $t.IsPagefile -or $t.IsCrashDump -or $t.IsReadOnly -or -not $t.IsOnline){throw 'disk roles changed'}
if([string]$s.UniqueId -ieq [string]$t.UniqueId -or [string]$p.UniqueId -ieq [string]$t.UniqueId -or [string]$p.UniqueId -ieq [string]$s.UniqueId -or [string]$t.UniqueId -ine [string]$roles.target_unique_id){throw 'disk identities overlap'}
$guid=[string]$roles.volume_guid
$parts=@(Get-Partition -ErrorAction Stop | Where-Object { @($_.AccessPaths | ForEach-Object { ([string]$_).TrimEnd('\\') }) -contains $guid.TrimEnd('\\') })
if($parts.Count -ne 1 -or [string]$parts[0].DiskId -ine [string]$t.UniqueId -or [long]$parts[0].Size -lt 900000000000){throw 'target volume no longer maps uniquely to the authorized disk'}
$vol=Get-Volume -Partition $parts[0] -ErrorAction Stop
if([string]$vol.FileSystem -ine 'NTFS' -or [string]$vol.FileSystemLabel -ine 'LVAULT_CLONE'){throw 'target volume identity changed'}
'true'
"""
    if _run_powershell(_encode_script(script, role_data), timeout=120).strip().casefold() != "true":
        raise DataCloneError("O volume de destino deixou de corresponder ao Seagate autorizado.", "partial")


def _encode_script(script: str, input_value: Any) -> str:
    prelude = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop';"
    prelude += f"$lvData=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{_encode_json(input_value)}')) | ConvertFrom-Json;"
    return prelude + script


def _target_encryption_state(volume_guid: str) -> str:
    try:
        script = r"""$volume=Get-Volume -ErrorAction Stop | Where-Object { ([string]$_.UniqueId).TrimEnd('\\') -ieq ([string]$lvData.volume_guid).TrimEnd('\\') } | Select-Object -First 1
if(-not $volume){throw 'target volume disappeared'}
try { $b=Get-BitLockerVolume -MountPoint $volume.Path -ErrorAction Stop; [pscustomobject]@{volume=[string]$b.VolumeStatus;protection=[string]$b.ProtectionStatus;lock=[string]$b.LockStatus} | ConvertTo-Json -Compress }
catch { [pscustomobject]@{volume='unknown';protection='unknown';lock='unknown'} | ConvertTo-Json -Compress }
"""
        payload = _powershell_json(script, {"volume_guid": volume_guid}, timeout=60)
        if isinstance(payload, dict):
            status = str(payload.get("volume", "unknown")).casefold().replace(" ", "")
            if status in {"fullydecrypted", "decrypted"}:
                return "unencrypted"
            if status in {"fullyencrypted", "encryptioninprogress", "decryptioninprogress", "encryptionpaused", "decryptionpaused"}:
                return "encrypted"
    except Exception:
        pass
    return "unknown"


def _robocopy_relative_path(line: str, source_root: Path) -> str:
    normalized = line.rstrip("\r\n")
    marker = str(source_root).rstrip("\\/") + "\\"
    folded = normalized.casefold()
    index = folded.find(marker.casefold())
    if index < 0:
        return ""
    return normalized[index + len(marker):].strip().replace("/", "\\").casefold()


def _prepare_target(target: DiskIdentity, destruction_marker: Path) -> dict[str, Any]:
    role_data = {
        "source": _role_payload(SOURCE_ROLE),
        "target": _role_payload(TARGET_ROLE),
        "protected": _role_payload(PROTECTED_ROLE),
        "target_unique_id": target.storage_unique_id,
        "destruction_marker": str(destruction_marker),
    }
    script = r"""$roles=$lvData
function Resolve-Role([object]$role) {
  $matches=@(Get-Disk -ErrorAction Stop | Where-Object { [string]$_.UniqueId -ieq [string]$role.storage_unique_id })
  if($matches.Count -ne 1){throw 'persistent disk identity is missing or ambiguous'}
  $disk=$matches[0]
  $physical=Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Where-Object { [int]$_.Index -eq [int]$disk.Number } | Select-Object -First 1
  if(-not $physical){throw 'physical disk binding is missing'}
  if([string]$disk.FriendlyName -ine [string]$role.model -or -not ([string]$disk.SerialNumber).Trim().EndsWith([string]$role.serial_suffix,[StringComparison]::OrdinalIgnoreCase) -or [string]$physical.PNPDeviceID -ine [string]$role.pnp_device_id -or [long]$disk.Size -ne [long]$role.size_bytes -or [string]$disk.BusType -ine [string]$role.bus_type){throw 'persistent disk attributes changed'}
  return $disk
}
function Assert-Roles {
  $s=Resolve-Role $roles.source; $t=Resolve-Role $roles.target; $p=Resolve-Role $roles.protected
  if(-not $s.IsSystem -or -not $s.IsBoot){throw 'authorized source is not the current system disk'}
  if($t.IsSystem -or $t.IsBoot -or $t.IsPagefile -or $t.IsCrashDump -or $t.IsReadOnly -or -not $t.IsOnline){throw 'target acquired a protected Windows role'}
  if([string]$s.UniqueId -ieq [string]$t.UniqueId -or [string]$p.UniqueId -ieq [string]$t.UniqueId -or [string]$p.UniqueId -ieq [string]$s.UniqueId){throw 'source, target, and protected disk overlap'}
  if([string]$t.UniqueId -ine [string]$roles.target_unique_id){throw 'authorized target UniqueId changed'}
  return $t
}
$target=Assert-Roles
if($target.IsOffline){throw 'authorized target is offline'}
Set-Content -LiteralPath $roles.destruction_marker -Value 'Clear-Disk is about to run' -Encoding ASCII -Force
Clear-Disk -UniqueId $roles.target_unique_id -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop | Out-Null
$target=Assert-Roles
Initialize-Disk -UniqueId $roles.target_unique_id -PartitionStyle GPT -ErrorAction Stop | Out-Null
$target=Assert-Roles
$partition=New-Partition -DiskId $roles.target_unique_id -UseMaximumSize -ErrorAction Stop
if([string]$partition.DiskId -ine [string]$roles.target_unique_id -or [long]$partition.Size -lt 900000000000){throw 'new partition does not belong to authorized target or is too small'}
$target=Assert-Roles
$partition=Get-Partition -DiskId $roles.target_unique_id -ErrorAction Stop | Where-Object { $_.PartitionNumber -eq $partition.PartitionNumber }
if(@($partition).Count -ne 1 -or [string]$partition.DiskId -ine [string]$roles.target_unique_id){throw 'new partition identity is ambiguous'}
Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'LVAULT_CLONE' -Force -Confirm:$false -ErrorAction Stop | Out-Null
$target=Assert-Roles
$volume=Get-Volume -Partition $partition -ErrorAction Stop
$paths=@($partition.AccessPaths)+@($volume.UniqueId)+@($volume.Path)
$path=$paths | Where-Object { $_ -match 'Volume\{[0-9A-Fa-f-]{36}\}' } | Select-Object -First 1
$m=[regex]::Match([string]$path,'Volume\{([0-9A-Fa-f-]{36})\}')
if(-not $m.Success -or [string]$volume.FileSystem -ine 'NTFS' -or [string]$volume.FileSystemLabel -ine 'LVAULT_CLONE'){throw 'formatted target volume failed verification'}
$guid='\\?\Volume{' + $m.Groups[1].Value.ToLowerInvariant() + '}\'
[pscustomobject]@{volume_guid=$guid;partition_number=[int]$partition.PartitionNumber;filesystem=[string]$volume.FileSystem;label=[string]$volume.FileSystemLabel;free_bytes=[long]$volume.SizeRemaining;size_bytes=[long]$volume.Size} | ConvertTo-Json -Compress
"""
    payload = _powershell_json(script, role_data, timeout=20 * 60)
    if not isinstance(payload, dict) or not str(payload.get("volume_guid", "")).startswith(r"\\?\Volume{"):
        raise DataCloneError("A preparação do Seagate não retornou uma identidade de volume válida.", "partial")
    return payload


def _role_payload(role) -> dict[str, Any]:
    return {
        "model": role.model,
        "serial_suffix": role.serial_suffix,
        "pnp_device_id": role.pnp_device_id,
        "storage_unique_id": role.storage_unique_id,
        "size_bytes": role.size_bytes,
        "bus_type": role.bus_type,
    }


def _copy_tree(
    source: Path,
    destination: Path,
    manifest,
    store: CloneJobStore,
    job_id: str,
    cancel_control: Any,
    *,
    snapshot_guard=None,
) -> dict[str, Any]:
    robocopy = _system_executable("robocopy.exe")
    runtime_exclusions = [
        Path(item["path"]).name
        for item in manifest.excluded
        if item.get("reason") == "windows_runtime_file"
    ]
    args = [str(robocopy), *robocopy_arguments(source, destination, runtime_exclusions=runtime_exclusions)]
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1, env=_clone_process_environment(), cwd=str(robocopy.parent), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), shell=False)
    lines: queue.Queue[str | None] = queue.Queue()

    def read_output() -> None:
        try:
            assert process.stdout is not None
            for line in process.stdout:
                lines.put(line)
        finally:
            lines.put(None)

    reader = threading.Thread(target=read_output, name="lvault-robocopy-output", daemon=True)
    reader.start()
    start = time.monotonic()
    observed_lines = 0
    completed = False
    source_entries = {entry.path.replace("/", "\\").casefold(): entry for entry in manifest.entries}
    processed_files: set[str] = set()
    processed_bytes = 0
    last_progress = 0.0
    while process.poll() is None or not completed:
        try:
            line = lines.get(timeout=0.25)
        except queue.Empty:
            line = ""
        if line is None:
            completed = True
        elif line:
            observed_lines += 1
            relative = _robocopy_relative_path(line, source)
            entry = source_entries.get(relative)
            if entry and entry.kind == "file" and relative not in processed_files:
                processed_files.add(relative)
                processed_bytes += entry.size_bytes
        if snapshot_guard is not None and time.monotonic() - last_progress >= SNAPSHOT_REVALIDATE_SECONDS:
            try:
                snapshot_guard()
            except Exception as exc:
                _terminate_tree(process.pid)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    pass
                reader.join(timeout=5)
                raise DataCloneError("A unidade de leitura deixou de corresponder ao snapshot; o destino está parcial.", "partial") from exc
        if _cancel_requested(cancel_control) and process.poll() is None:
            _terminate_tree(process.pid)
        if time.monotonic() - start > COPY_TIMEOUT_SECONDS and process.poll() is None:
            _terminate_tree(process.pid)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
            reader.join(timeout=5)
            raise DataCloneError("Robocopy excedeu o limite de tempo; o destino está parcial.", "partial")
        if process.poll() is None and _cancel_requested(cancel_control):
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                _terminate_tree(process.pid)
        if time.monotonic() - last_progress >= 1.0:
            elapsed = max(time.monotonic() - start, 0.001)
            speed = int(processed_bytes / elapsed)
            remaining = max(0, manifest.logical_bytes - processed_bytes)
            state = store.load() or {}
            progress = dict(state.get("progress") or {})
            progress.update({
                "files": len(processed_files),
                "bytes": processed_bytes,
                "expected_files": manifest.file_count,
                "expected_bytes": manifest.logical_bytes,
                "speed_bytes_per_second": speed,
                "eta_seconds": int(remaining / speed) if speed else 0,
            })
            store.update(job_id, state="copy", phase="COPY", progress=progress)
            last_progress = time.monotonic()
    reader.join(timeout=2)
    exit_code = int(process.wait())
    if _cancel_requested(cancel_control):
        raise DataCloneError("A clonagem foi cancelada depois que o destino começou a ser preparado.", "partial")
    if exit_code >= 8 or exit_code & 4:
        raise DataCloneError(f"Robocopy informou erro de arquivo ou metadados (código {exit_code}); o destino está parcial.", "partial")
    return {"exit_code": exit_code, "source_files": manifest.file_count, "source_logical_bytes": manifest.logical_bytes, "robocopy_output_lines": observed_lines, "metadata_mode": "COPYALL+BACKUP+SPARSE+EFSRAW"}


def _verify_tree(source_manifests: dict[str, Any], snapshot_map: list[dict[str, Any]], data_root: Path, store: CloneJobStore, job_id: str, cancel_control: Any) -> tuple[bool, dict[str, Any]]:
    results = []
    all_verified = True
    total_files = total_bytes = 0
    sample_hashes = []
    sample_budget = MAX_SAMPLE_HASH_BYTES
    for mapping in snapshot_map:
        _assert_snapshot_mapping(mapping)
        source = _snapshot_root(mapping["device_object"])
        target = data_root / mapping["destination"]
        expected = source_manifests[mapping["volume_guid"]]
        observed = build_manifest(target, cancel_check=lambda: _cancel_requested(cancel_control))
        comparison = compare_manifests(expected, observed)
        all_verified = all_verified and bool(comparison["verified"])
        total_files += comparison["file_count"]
        total_bytes += comparison["logical_bytes"]
        volume_samples = _verify_sample_hashes(
            source,
            target,
            expected,
            cancel_control,
            max_sample_bytes=sample_budget,
            snapshot_guard=lambda current=mapping: _assert_snapshot_mapping(current),
        )
        sample_hashes.extend(volume_samples)
        sample_budget -= sum(int(item.get("bytes_hashed_per_copy", 0)) for item in volume_samples)
        results.append({"volume": mapping["destination"], **comparison})
    if any(not item.get("match") for item in sample_hashes):
        all_verified = False
    return all_verified, {
        "verified": all_verified,
        "file_count": total_files,
        "logical_bytes": total_bytes,
        "volumes": results,
        "exclusions": (store.load() or {}).get("excluded_partitions", []) + [item for manifest in source_manifests.values() for item in manifest.excluded],
        "content_hash_samples": sample_hashes,
        "verification_scope": "deterministic path/type/size/mtime/attributes plus bounded selected SHA-256 content readback (up to 512 MiB per source and target); ACL/owner/SACL/ADS not independently re-read",
        "bootability": "not_applicable_data_clone",
    }


def _verify_sample_hashes(
    source: Path,
    target: Path,
    manifest,
    cancel_control: Any,
    *,
    max_sample_bytes: int = MAX_SAMPLE_HASH_BYTES,
    snapshot_guard=None,
) -> list[dict[str, Any]]:
    files = [entry for entry in manifest.entries if entry.kind == "file" and entry.size_bytes > 0]
    if not files:
        return []
    ordered = sorted(files, key=lambda entry: entry.path.casefold())
    selected = {ordered[0].path, ordered[len(ordered) // 2].path, ordered[-1].path}
    selected.update(entry.path for entry in sorted(files, key=lambda entry: (-entry.size_bytes, entry.path.casefold()))[:5])
    stride = max(1, len(ordered) // 12)
    selected.update(entry.path for entry in ordered[::stride][:12])
    results = []
    sampled_bytes = 0
    by_path = {entry.path: entry for entry in files}
    for relative in sorted(selected, key=str.casefold):
        if _cancel_requested(cancel_control):
            raise DataCloneError("A verificação foi cancelada; o destino está parcial.", "partial")
        entry = by_path.get(relative)
        if entry is None:
            continue
        ranges = _sample_ranges(entry.size_bytes)
        cost = sum(length for _, length in ranges)
        if sampled_bytes + cost > max_sample_bytes:
            continue
        left = _sha256_file_ranges(source / Path(relative), ranges, cancel_control, snapshot_guard=snapshot_guard)
        right = _sha256_file_ranges(target / Path(relative), ranges, cancel_control)
        sampled_bytes += cost
        results.append({
            "path": relative,
            "size_bytes": entry.size_bytes,
            "bytes_hashed_per_copy": cost,
            "method": "full" if len(ranges) == 1 and ranges[0] == (0, entry.size_bytes) else "head_tail",
            "match": left == right,
            "sha256": left,
        })
    return results


def _sample_ranges(size: int) -> list[tuple[int, int]]:
    if size <= FULL_SAMPLE_FILE_LIMIT:
        return [(0, size)]
    sample = min(LARGE_FILE_SAMPLE_BYTES, size // 2)
    return [(0, sample), (size - sample, sample)]


def _sha256_file_ranges(path: Path, ranges: list[tuple[int, int]], cancel_control: Any, *, snapshot_guard=None) -> str:
    digest = hashlib.sha256()
    last_snapshot_guard = 0.0
    if snapshot_guard is not None:
        snapshot_guard()
        last_snapshot_guard = time.monotonic()
    with path.open("rb") as handle:
        for offset, length in ranges:
            handle.seek(offset)
            digest.update(offset.to_bytes(8, "little"))
            remaining = length
            while remaining:
                if _cancel_requested(cancel_control):
                    raise DataCloneError("A verificação foi cancelada; o destino está parcial.", "partial")
                if snapshot_guard is not None and time.monotonic() - last_snapshot_guard >= SNAPSHOT_REVALIDATE_SECONDS:
                    snapshot_guard()
                    last_snapshot_guard = time.monotonic()
                block = handle.read(min(1024 * 1024, remaining))
                if not block:
                    raise DataCloneError("Um arquivo terminou durante a verificação de conteúdo.", "partial")
                digest.update(block)
                remaining -= len(block)
    return digest.hexdigest()


def _clear_data_root_attributes(path: Path) -> None:
    if os.name != "nt":
        return
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_attrs = kernel32.GetFileAttributesW
    get_attrs.argtypes = [ctypes.c_wchar_p]
    get_attrs.restype = ctypes.c_uint32
    set_attrs = kernel32.SetFileAttributesW
    set_attrs.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    set_attrs.restype = ctypes.c_int
    attrs = int(get_attrs(str(path)))
    if attrs == 0xFFFFFFFF:
        raise DataCloneError("A pasta raiz copiada não pôde ser lida para verificação.", "partial")
    attrs &= ~0x6  # Clear HIDDEN and SYSTEM inherited from a volume root.
    if not set_attrs(str(path), attrs or 0x80):
        raise DataCloneError("Não foi possível normalizar os atributos da pasta CloneData.", "partial")


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    import ctypes
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--job-id", required=True)
    args = parser.parse_args()
    if os.name != "nt":
        return 2
    protected_worker = _protected_worker_path()
    if protected_worker is None or Path(sys.executable).resolve() != protected_worker:
        return 3
    if not _is_admin():
        return 4
    try:
        _run_clone_job(args.root.resolve(), args.job_id)
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
