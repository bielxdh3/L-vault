"""Identity-bound Windows data cloning owned by L-vault.

Windows storage, VSS, and file-copy operations are delegated only to inbox
Windows facilities by :mod:`first_party_clone_worker`; no clone product is
required.  The module in this file owns policy, job state, and verification.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .clone_roles import PROTECTED_ROLE, SOURCE_ROLE, TARGET_ROLE, DiskRole, matches_role
from .clone_control import CloneCancelGate, CloneCancelGateError
from .clone_runtime_security import verify_clone_runtime_security
from .config import paths
from .disk_clone import (
    CloneLock,
    DiskCloneBlocked,
    DiskIdentity,
    WindowsDiskInventory,
    WindowsProtectedPathResolver,
    windows_powershell_path,
    windows_system_directory,
    windows_system_environment,
)
from .utils import atomic_write_text


MODE_LABEL = "L-vault Data Clone"
CONFIRMATION = "CLONE"
SNAPSHOT_REVALIDATE_SECONDS = 15.0
ACTIVE_STATES = {"starting", "precheck", "snapshot", "target_prepare", "copy", "verify", "cleanup", "cancelling"}
TERMINAL_STATES = {"complete", "failed", "blocked", "cancelled", "partial"}
SYSTEM_METADATA_EXCLUSIONS = {"system volume information"}
REPARSE_POINT_ATTRIBUTE = 0x400
REPARSE_TAG_MOUNT_POINT = 0xA0000003
REPARSE_TAG_SYMLINK = 0xA000000C
VOLUME_GUID_RE = re.compile(r"Volume\{([0-9a-fA-F-]{36})\}")


class DataCloneError(RuntimeError):
    def __init__(self, reason: str, state: str = "failed"):
        super().__init__(reason)
        self.reason = reason
        self.state = state


@dataclass(frozen=True)
class CloneVolume:
    volume_guid: str
    disk_unique_id: str
    disk_number: int
    partition_number: int
    filesystem: str
    label: str
    size_bytes: int
    free_bytes: int
    drive_letter: str = ""
    is_system_volume: bool = False
    role: str = "data"


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    kind: str
    size_bytes: int
    mtime_ns: int
    attributes: int
    reparse_tag: int = 0
    link_target: str = ""


@dataclass(frozen=True)
class ManifestResult:
    entries: tuple[ManifestEntry, ...]
    excluded: tuple[dict[str, str], ...]
    logical_bytes: int
    file_count: int
    sha256: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _identity_digest(disk: DiskIdentity) -> str:
    value = json.dumps(disk.persistent_identity_payload(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _layout_digest(disk: DiskIdentity) -> str:
    value = {
        "size_bytes": disk.size_bytes,
        "partition_style": disk.partition_style,
        "disk_guid": disk.disk_guid,
        "signature": disk.signature,
        "online": disk.online,
        "read_only": disk.read_only,
        "partitions": [asdict(part) for part in sorted(disk.partitions, key=lambda part: (part.offset_bytes, part.number))],
    }
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _safe_role_disk(disks: Iterable[DiskIdentity], role: DiskRole) -> DiskIdentity:
    matches = [disk for disk in disks if matches_role(disk, role)]
    if len(matches) != 1:
        raise DiskCloneBlocked(f"A identidade persistente de {role.model} está ausente ou ambígua.", "blocked_identity")
    return matches[0]


def resolve_clone_roles(disks: Iterable[DiskIdentity]) -> tuple[DiskIdentity, DiskIdentity, DiskIdentity]:
    rows = list(disks)
    source = _safe_role_disk(rows, SOURCE_ROLE)
    target = _safe_role_disk(rows, TARGET_ROLE)
    protected = _safe_role_disk(rows, PROTECTED_ROLE)
    if not source.is_system or not source.is_boot:
        raise DiskCloneBlocked("O Kingston autorizado não é o disco Windows/sistema atual.", "blocked_identity")
    if any((source.is_pagefile, source.is_crash_dump, source.is_clustered, source.is_virtual, source.is_removable)):
        raise DiskCloneBlocked("O Kingston apresenta um papel de disco incompatível com a origem autorizada.", "blocked_identity")
    if any((target.is_system, target.is_boot, target.is_pagefile, target.is_crash_dump, target.is_clustered, target.is_virtual, target.is_removable, target.read_only)) or not target.online:
        raise DiskCloneBlocked("O Seagate está ausente, em uso crítico, offline, protegido ou somente leitura.", "blocked_identity")
    if source.number == target.number or source.matches(target, require_strong=False):
        raise DiskCloneBlocked("Origem e destino resolveram para o mesmo disco.", "blocked_identity")
    if source.matches(protected, require_strong=False) or target.matches(protected, require_strong=False):
        raise DiskCloneBlocked("O HGST protegido coincide com a origem ou o destino.", "blocked_protected_path")
    for disk in (source, target):
        if disk.size_bytes != SOURCE_ROLE.size_bytes:
            raise DiskCloneBlocked(f"A capacidade de {disk.model} difere da autorização física exata.", "blocked_size")
    return source, target, protected


def verify_protected_repository(root: Path, protected: DiskIdentity, resolver: Any) -> None:
    resolutions = resolver.resolve([root])
    if len(resolutions) != 1 or not resolutions[0].resolved:
        raise DiskCloneBlocked("Não foi possível mapear E:\\LocalVault ao HGST protegido.", "blocked_protected_path")
    ids = {value.strip().casefold() for value in resolutions[0].identifiers if value.strip()}
    protected_ids = {value.strip().casefold() for value in protected.stable_identifiers() if value.strip()}
    if len(ids) < 2 or not ids.issubset(protected_ids):
        raise DiskCloneBlocked("O caminho do repositório não corresponde de forma única ao HGST protegido.", "blocked_protected_path")


def parse_vss_shadowstorage(text: str) -> dict[str, str]:
    """Parse volume-GUID pairs from vssadmin output independent of UI language."""
    ids: list[str] = []
    for line in text.splitlines():
        match = VOLUME_GUID_RE.search(line)
        if match:
            ids.append(match.group(1).casefold())
    if len(ids) % 2:
        raise DataCloneError("A associação VSS retornou dados ambíguos; nenhum disco foi alterado.", "blocked_vss")
    pairs: dict[str, str] = {}
    for index in range(0, len(ids), 2):
        source, diff = ids[index], ids[index + 1]
        if source in pairs:
            raise DataCloneError("Há associações VSS duplicadas para um volume de origem.", "blocked_vss")
        pairs[source] = diff
    return pairs


def _native_reparse_tag(path: Path) -> int:
    if os.name != "nt":
        return REPARSE_TAG_SYMLINK if path.is_symlink() else 0
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create_file.restype = ctypes.c_void_p
    handle = create_file(str(path), 0x80, 0x7, None, 3, 0x00200000 | 0x02000000, None)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise OSError(ctypes.get_last_error(), "Cannot open reparse point safely", str(path))
    try:
        buffer = ctypes.create_string_buffer(16_384)
        returned = ctypes.c_uint32()
        device_io = kernel32.DeviceIoControl
        device_io.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        device_io.restype = ctypes.c_int
        ok = device_io(handle, 0x000900A8, None, 0, buffer, len(buffer), ctypes.byref(returned), None)
        if not ok or returned.value < 4:
            raise OSError(ctypes.get_last_error(), "Cannot inspect reparse tag safely", str(path))
        return int.from_bytes(buffer.raw[:4], "little")
    finally:
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        close_handle(handle)


def build_manifest(
    root: Path,
    *,
    reparse_tag_reader: Callable[[Path], int] = _native_reparse_tag,
    cancel_check: Callable[[], bool] | None = None,
    snapshot_guard: Callable[[], None] | None = None,
    exclude_windows_runtime_artifacts: bool = False,
) -> ManifestResult:
    """Build a stable, no-follow manifest. Unknown reparse tags fail closed."""
    root = Path(root)
    if not root.is_dir():
        raise DataCloneError("A origem consistente não está acessível como diretório.", "blocked_snapshot")
    entries: list[ManifestEntry] = []
    excluded: list[dict[str, str]] = []
    queue = [root]
    last_snapshot_guard = 0.0
    if snapshot_guard:
        snapshot_guard()
        last_snapshot_guard = time.monotonic()
    while queue:
        if cancel_check and cancel_check():
            raise DataCloneError("A clonagem foi cancelada pelo proprietário.", "cancelled")
        if snapshot_guard and time.monotonic() - last_snapshot_guard >= SNAPSHOT_REVALIDATE_SECONDS:
            snapshot_guard()
            last_snapshot_guard = time.monotonic()
        directory = queue.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
        except OSError as exc:
            raise DataCloneError(f"Não foi possível enumerar a origem consistente ({type(exc).__name__}).", "blocked_source_read") from exc
        for child in children:
            if cancel_check and cancel_check():
                raise DataCloneError("A clonagem foi cancelada pelo proprietário.", "cancelled")
            if snapshot_guard and time.monotonic() - last_snapshot_guard >= SNAPSHOT_REVALIDATE_SECONDS:
                snapshot_guard()
                last_snapshot_guard = time.monotonic()
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            folded_name = child.name.casefold()
            if relative.count("/") == 0 and child.is_dir(follow_symlinks=False) and folded_name in SYSTEM_METADATA_EXCLUSIONS:
                excluded.append({"path": relative, "reason": "windows_vss_metadata"})
                continue
            try:
                info = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise DataCloneError(f"Não foi possível inspecionar um item da origem ({type(exc).__name__}).", "blocked_source_read") from exc
            attributes = int(getattr(info, "st_file_attributes", 0))
            if (
                exclude_windows_runtime_artifacts
                and relative.count("/") == 0
                and child.is_file(follow_symlinks=False)
                and folded_name in {"pagefile.sys", "hiberfil.sys", "swapfile.sys"}
            ):
                excluded.append({"path": relative, "reason": "windows_runtime_file"})
                continue
            is_reparse = bool(attributes & REPARSE_POINT_ATTRIBUTE) or child.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(path))
            if is_reparse:
                tag = reparse_tag_reader(path)
                if tag == REPARSE_TAG_MOUNT_POINT:
                    excluded.append({"path": relative, "reason": "reparse_mount_point_not_followed"})
                    continue
                if tag != REPARSE_TAG_SYMLINK:
                    raise DataCloneError(f"A origem contém um tipo de reparse point não suportado com segurança: {relative}.", "blocked_reparse")
                try:
                    link_target = os.readlink(path)
                except OSError as exc:
                    raise DataCloneError(f"Não foi possível ler um link simbólico sem segui-lo: {relative}.", "blocked_reparse") from exc
                entries.append(ManifestEntry(relative, "symlink", 0, int(info.st_mtime_ns), attributes, tag, link_target))
                continue
            if child.is_dir(follow_symlinks=False):
                entries.append(ManifestEntry(relative, "directory", 0, int(info.st_mtime_ns), attributes))
                queue.append(path)
            elif child.is_file(follow_symlinks=False):
                entries.append(ManifestEntry(relative, "file", int(info.st_size), int(info.st_mtime_ns), attributes))
            else:
                raise DataCloneError(f"A origem contém um objeto de sistema de arquivos não suportado: {relative}.", "blocked_source_object")
    entries.sort(key=lambda row: (row.path.casefold(), row.path))
    folded_paths: set[str] = set()
    for row in entries:
        folded = row.path.casefold()
        if folded in folded_paths:
            raise DataCloneError("A origem contém caminhos que diferem apenas por maiúsculas/minúsculas; não é possível verificar a cópia sem perda.", "blocked_case_sensitive_path")
        folded_paths.add(folded)
    payload = [asdict(row) for row in entries]
    digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return ManifestResult(
        entries=tuple(entries),
        excluded=tuple(excluded),
        logical_bytes=sum(row.size_bytes for row in entries if row.kind == "file"),
        file_count=sum(row.kind == "file" for row in entries),
        sha256=digest,
    )


def compare_manifests(source: ManifestResult, target: ManifestResult) -> dict[str, Any]:
    left = {row.path.casefold(): row for row in source.entries}
    right = {row.path.casefold(): row for row in target.entries}
    missing = sorted(set(left) - set(right))
    unexpected = sorted(set(right) - set(left))
    differences = []
    for key in sorted(set(left) & set(right)):
        a, b = left[key], right[key]
        if (a.kind, a.size_bytes, a.mtime_ns, a.attributes, a.reparse_tag, a.link_target) != (b.kind, b.size_bytes, b.mtime_ns, b.attributes, b.reparse_tag, b.link_target):
            differences.append(a.path)
    return {
        "verified": not missing and not unexpected and not differences,
        "missing_count": len(missing),
        "unexpected_count": len(unexpected),
        "metadata_or_size_difference_count": len(differences),
        "file_count": sum(row.kind == "file" for row in right.values()),
        "logical_bytes": sum(row.size_bytes for row in right.values() if row.kind == "file"),
        "target_manifest_sha256": target.sha256,
    }


def robocopy_arguments(source: Path, target: Path, *, runtime_exclusions: Iterable[str] = ()) -> list[str]:
    exclusions = [str(Path(source) / name) for name in sorted(SYSTEM_METADATA_EXCLUSIONS)]
    arguments = [
        str(source), str(target), "/E", "/B", "/COPYALL", "/DCOPY:DATE", "/SPARSE:Y", "/SL", "/XJ", "/EFSRAW", "/R:1", "/W:1", "/BYTES", "/ETA", "/FP", "/XD", exclusions[0],
    ]
    runtime_paths = [str(Path(source) / name) for name in sorted(set(runtime_exclusions))]
    if runtime_paths:
        arguments.extend(("/XF", *runtime_paths))
    return arguments


class CloneJobStore:
    def __init__(self, root: Path, *, protected: bool = False):
        self.protected = protected
        self.root = Path(root)
        if protected:
            common_data = _known_program_data()
            if common_data is None:
                raise DataCloneError("O local protegido de auditoria não está disponível.", "blocked_audit")
            self.job_root = common_data / "L-vault" / "clone-state"
        else:
            self.job_root = paths(root).logs / "first_party_data_clone"
            self.job_root.mkdir(parents=True, exist_ok=True)
        self.active_path = self.job_root / "active.json"

    def new_job(self, state: dict[str, Any]) -> None:
        atomic_write_text(self.active_path, json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

    def load(self) -> dict[str, Any] | None:
        try:
            value = json.loads(self.active_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise DataCloneError("O registro local de clonagem está inválido; não inicie outra operação.", "blocked_audit") from exc
        return value if isinstance(value, dict) else None

    def update(self, job_id: str, **fields: Any) -> dict[str, Any]:
        state = self.load()
        if not state or state.get("job_id") != job_id:
            raise DataCloneError("O registro de clonagem não corresponde à operação ativa.", "blocked_audit")
        state.update(fields)
        state["updated_at"] = _utc_now()
        self.new_job(state)
        return state

    def job_directory(self, job_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise DataCloneError("O identificador da operação é inválido.", "blocked_audit")
        directory = self.job_root / job_id
        if self.protected:
            if _is_reparse_path(self.job_root) or not self.job_root.is_dir() or _is_reparse_path(directory) or not directory.is_dir():
                raise DataCloneError("O diretório protegido da clonagem está ausente ou não é seguro.", "blocked_audit")
        else:
            directory.mkdir(parents=True, exist_ok=True)
        return directory

    def create_job_directory(self, job_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise DataCloneError("O identificador da operação é inválido.", "blocked_audit")
        if not self.protected:
            return self.job_directory(job_id)
        if _is_reparse_path(self.job_root) or not self.job_root.is_dir():
            raise DataCloneError("O diretório protegido da clonagem está ausente ou não é seguro.", "blocked_audit")
        directory = self.job_root / job_id
        directory.mkdir(exist_ok=False)
        return directory

    def cancel_gate(self, job_id: str, *, create: bool) -> CloneCancelGate:
        if not self.protected:
            raise DataCloneError("A trava de cancelamento protegida não está disponível.", "blocked_cancel_gate")
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise DataCloneError("O identificador da operação é inválido.", "blocked_audit")
        common_data = _known_program_data()
        if common_data is None:
            raise DataCloneError("O local protegido da operação não está disponível.", "blocked_audit")
        owner_file = common_data / "L-vault" / "clone-state" / "owner.sid"
        try:
            if _is_reparse_path(owner_file) or not owner_file.is_file() or owner_file.stat().st_size > 128:
                raise OSError("owner binding is missing or unsafe")
            owner_sid = owner_file.read_text(encoding="ascii").strip()
            if not re.fullmatch(r"S-1-\d+(?:-\d+)+", owner_sid):
                raise OSError("owner binding is malformed")
            return CloneCancelGate(job_id, owner_sid, create=create)
        except (OSError, UnicodeError, CloneCancelGateError) as exc:
            raise DataCloneError("A trava protegida de cancelamento não pôde ser validada.", "blocked_cancel_gate") from exc


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _known_program_data() -> Path | None:
    return _known_folder_path("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97")


def _known_folder_path(folder_id: str) -> Path | None:
    if os.name != "nt":
        return None
    try:
        class GUID(ctypes.Structure):
            _fields_ = [("data", ctypes.c_ubyte * 16)]

        known_folder_id = GUID.from_buffer_copy(uuid.UUID(folder_id).bytes_le)
        pointer = ctypes.c_void_p()
        shell32 = ctypes.windll.shell32
        shell32.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(GUID), ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        shell32.SHGetKnownFolderPath.restype = ctypes.c_long
        result = shell32.SHGetKnownFolderPath(ctypes.byref(known_folder_id), 0, None, ctypes.byref(pointer))
        if result < 0 or not pointer.value:
            return None
        try:
            return Path(ctypes.wstring_at(pointer.value))
        finally:
            ctypes.windll.ole32.CoTaskMemFree(pointer)
    except (AttributeError, OSError, ValueError):
        return None


def _is_reparse_path(path: Path) -> bool:
    try:
        parts = [path, *path.parents]
        return any(int(getattr(part.lstat(), "st_file_attributes", 0)) & 0x400 for part in parts)
    except OSError:
        return True


def _protected_worker_path() -> Path | None:
    common_data = _known_program_data()
    if common_data is None:
        return None
    runtime_dir = common_data / "L-vault" / "clone-runtime"
    worker = runtime_dir / "LocalVaultCloneWorker.exe"
    snapshot_helper = runtime_dir / "LVaultVssSnapshot.exe"
    state_root = common_data / "L-vault" / "clone-state" if common_data else None
    try:
        if state_root is None or not state_root.is_dir() or any(_is_reparse_path(path) for path in (runtime_dir, worker, snapshot_helper, state_root)) or not worker.is_file() or not snapshot_helper.is_file():
            return None
        if os.path.commonpath((str(runtime_dir.resolve()), str(worker.resolve()))).casefold() != str(runtime_dir.resolve()).casefold():
            return None
        if os.path.commonpath((str(runtime_dir.resolve()), str(snapshot_helper.resolve()))).casefold() != str(runtime_dir.resolve()).casefold():
            return None
        return worker.resolve()
    except (OSError, ValueError):
        return None


def _process_is_running(pid: Any) -> bool | None:
    try:
        process_id = int(pid)
    except (TypeError, ValueError):
        return None
    if process_id <= 0:
        return False
    if os.name != "nt":
        return None
    kernel32 = ctypes.windll.kernel32
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    open_process.restype = ctypes.c_void_p
    handle = open_process(0x1000, False, process_id)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        error = ctypes.get_last_error()
        if error == 5:  # ERROR_ACCESS_DENIED: cannot prove that it exited.
            return None
        return False
    try:
        code = ctypes.c_uint32()
        get_exit = kernel32.GetExitCodeProcess
        get_exit.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        get_exit.restype = ctypes.c_int
        if not get_exit(handle, ctypes.byref(code)):
            return None
        return code.value == 259  # STILL_ACTIVE
    finally:
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        close_handle(handle)
def _launch_elevated_worker(root: Path, job_id: str, *, recover_vss: bool = False) -> None:
    if os.name != "nt":
        raise DataCloneError("A clonagem local exige Windows.", "blocked_backend")
    if not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise DataCloneError("O identificador da operação é inválido.", "blocked_audit")
    executable = _protected_worker_path()
    if executable is None:
        raise DataCloneError("O runtime first-party protegido ainda não foi instalado.", "blocked_backend")
    runtime_security = verify_clone_runtime_security()
    if not runtime_security.ready:
        raise DataCloneError("As permissões do runtime protegido não passaram pela verificação de segurança do Windows.", "blocked_backend")
    args = ["--job-id", job_id]
    if recover_vss:
        args.append("--recover-vss")
    if _is_admin():
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.Popen([str(executable), *args], cwd=str(executable.parent), env=windows_system_environment(temp_directory=executable.parent / "Temp"), creationflags=flags, close_fds=True)
        return
    command_line = subprocess.list2cmdline(args)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", str(executable), command_line, str(executable.parent), 0)
    if result <= 32:
        raise DataCloneError("A elevação do Windows foi cancelada ou não pôde ser iniciada; o destino não foi alterado.", "blocked_elevation")


class FirstPartyDataCloneProvider:
    """Owner-facing provider. Destructive work runs only in its elevated worker."""

    def __init__(
        self,
        root: Path,
        *,
        inventory: Any | None = None,
        protected_path_resolver: Any | None = None,
        worker_launcher: Callable[[Path, str], None] | None = None,
        recovery_launcher: Callable[[Path, str], None] | None = None,
    ):
        self.root = Path(root).resolve()
        self.inventory = inventory or WindowsDiskInventory()
        self.protected_path_resolver = protected_path_resolver or WindowsProtectedPathResolver()
        self.worker_launcher = worker_launcher or _launch_elevated_worker
        self.recovery_launcher = recovery_launcher or (lambda root, job_id: _launch_elevated_worker(root, job_id, recover_vss=True))
        self.store = CloneJobStore(self.root, protected=True)
        self._pending_state: dict[str, Any] | None = None
        self._cancel_pending = False
        self._cancel_gate: CloneCancelGate | None = None
        self._cancel_gate_job_id: str | None = None

    def inspect_capabilities(self) -> dict[str, Any]:
        blockers = []
        try:
            powershell = windows_powershell_path()
            system_directory = windows_system_directory() if os.name == "nt" else None
        except OSError:
            powershell = Path("powershell.exe")
            system_directory = None
            blockers.append("O diretório de sistema do Windows não pôde ser resolvido com segurança.")
        robocopy = system_directory / "robocopy.exe" if system_directory is not None else Path("robocopy.exe")
        protected_worker = _protected_worker_path()
        if os.name != "nt":
            blockers.append("Windows é necessário.")
        if not powershell.is_file() or not robocopy.is_file():
            blockers.append("Uma ferramenta nativa necessária do Windows não está disponível.")
        if protected_worker is None:
            blockers.append("O runtime first-party protegido ainda não foi instalado.")
        else:
            runtime_security = verify_clone_runtime_security()
            if not runtime_security.ready:
                blockers.append("As permissões do runtime protegido não passaram pela verificação de segurança do Windows.")
        return {
            "available": not blockers,
            "backend": MODE_LABEL,
            "version": "Windows inbox VSS / Storage / Robocopy",
            "bootable": False,
            "blocker": " ".join(blockers),
            "elevation_required": not _is_admin(),
        }

    def _roles(self) -> tuple[DiskIdentity, DiskIdentity, DiskIdentity, list[DiskIdentity]]:
        disks = list(self.inventory.list_disks())
        source, target, protected = resolve_clone_roles(disks)
        verify_protected_repository(self.root, protected, self.protected_path_resolver)
        return source, target, protected, disks

    def inspect_source(self) -> dict[str, Any]:
        source, _, _, _ = self._roles()
        return _public_role(SOURCE_ROLE, _public_disk(source))

    def inspect_target(self) -> dict[str, Any]:
        _, target, _, _ = self._roles()
        return _public_role(TARGET_ROLE, _public_disk(target))

    def preflight(self) -> dict[str, Any]:
        source, target, protected, _ = self._roles()
        capabilities = self.inspect_capabilities()
        return {
            "ready": bool(capabilities["available"]),
            "source": _public_role(SOURCE_ROLE, _public_disk(source)),
            "target": _public_role(TARGET_ROLE, _public_disk(target)),
            "protected": _public_role(PROTECTED_ROLE, _public_disk(protected)),
            "mode": MODE_LABEL,
            "bootable": False,
            "confirmation": CONFIRMATION,
            "blocker": capabilities["blocker"],
        }

    def launch(self, *, confirmation: str) -> dict[str, Any]:
        if confirmation != CONFIRMATION:
            raise DiskCloneBlocked("Digite CLONE para autorizar o apagamento do ST1000VM002-1CT162.", "blocked_confirmation")
        capabilities = self.inspect_capabilities()
        if not capabilities["available"]:
            raise DiskCloneBlocked(capabilities["blocker"], "blocked_backend")
        prior = self.store.load()
        prior_needs_review = bool(
            prior
            and prior.get("phase") in {"SNAPSHOT", "TARGET_PREPARE", "COPY", "VERIFY", "CLEANUP"}
            and prior.get("snapshot_cleanup_confirmed") is not True
        )
        if prior and (prior.get("state") in ACTIVE_STATES | {"partial"} or prior_needs_review):
            raise DiskCloneBlocked("Há uma operação anterior ativa ou parcial. Revise o resultado antes de tentar novamente.", "blocked_active_job")
        source, target, protected, _ = self._roles()
        job_id = uuid.uuid4().hex
        state = {
            "schema": 1,
            "job_id": job_id,
            "state": "starting",
            "phase": "PRECHECK",
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "mode": MODE_LABEL,
            "bootable": False,
            "source": _public_disk(source),
            "target": _public_disk(target),
            "protected": _public_disk(protected),
            "source_layout_sha256": _layout_digest(source),
            "protected_layout_sha256": _layout_digest(protected),
            "target_destroyed": False,
            "progress": {"files": 0, "bytes": 0},
            "result": None,
            "error": "",
        }
        self._pending_state = state
        try:
            # Pre-create the per-job mutex with a DACL restricted to the
            # installed owner SID. Keep this handle open until the worker has
            # exited so the named object cannot disappear in the launch race.
            self._cancel_gate = self.store.cancel_gate(job_id, create=True)
            self._cancel_gate_job_id = job_id
            self.worker_launcher(self.root, job_id)
        except Exception as exc:
            if self._cancel_gate is not None:
                self._cancel_gate.close()
                self._cancel_gate = None
                self._cancel_gate_job_id = None
            state.update(state="blocked", phase="PRECHECK", error=getattr(exc, "reason", "Não foi possível iniciar o trabalhador elevado."))
            if isinstance(exc, DiskCloneBlocked):
                raise
            raise DiskCloneBlocked("Não foi possível iniciar o trabalhador elevado; o destino não foi alterado.", "blocked_elevation") from exc
        return self.monitor()

    def monitor(self) -> dict[str, Any]:
        state = self.store.load()
        if state is None and self._pending_state is not None:
            state = dict(self._pending_state)
        if state:
            if state.get("state") in ACTIVE_STATES and state.get("worker_pid"):
                running = _process_is_running(state.get("worker_pid"))
                if running is False:
                    directory = self.store.job_directory(str(state.get("job_id", "")))
                    target_started = bool(state.get("target_destroyed")) or (directory / "target_clear_started").exists()
                    snapshot_phase = state.get("phase") in {"SNAPSHOT", "TARGET_PREPARE", "COPY", "VERIFY", "CLEANUP"}
                    state.update(
                        state="partial" if target_started else "failed",
                        phase="CLEANUP" if snapshot_phase else state.get("phase", "PRECHECK"),
                        target_destroyed=target_started,
                        snapshot_cleanup_confirmed=False if snapshot_phase else state.get("snapshot_cleanup_confirmed"),
                        vss_recovery_required=True if snapshot_phase else state.get("vss_recovery_required", False),
                        error="O trabalhador terminou inesperadamente; revise a operação e os temporários locais.",
                        updated_at=_utc_now(),
                    )
            if self._cancel_pending and self._pending_state and state.get("job_id") == self._pending_state.get("job_id") and state.get("state") in ACTIVE_STATES:
                state = dict(state)
                state["state"] = "cancelling"
            elif state.get("state") not in ACTIVE_STATES:
                self._pending_state = None
                self._cancel_pending = False
                if self._cancel_gate is not None and state.get("job_id") == self._cancel_gate_job_id:
                    self._cancel_gate.close()
                    self._cancel_gate = None
                    self._cancel_gate_job_id = None
            return {
                "state": str(state.get("state", "failed")),
                "phase": str(state.get("phase", "PRECHECK")),
                "created_at": state.get("created_at", ""),
                "updated_at": state.get("updated_at", ""),
                "mode": MODE_LABEL,
                "bootable": False,
                "source": _public_role(SOURCE_ROLE, state.get("source")),
                "target": _public_role(TARGET_ROLE, state.get("target")),
                "protected": _public_role(PROTECTED_ROLE, state.get("protected")),
                "progress": _public_progress(state.get("progress")),
                "result": _public_result(state.get("result"), state),
                "error": _owner_error(state.get("state", ""), state.get("error", "")),
                "target_destroyed": bool(state.get("target_destroyed")),
                "snapshot_cleanup_confirmed": state.get("snapshot_cleanup_confirmed"),
                "vss_recovery_required": bool(state.get("vss_recovery_required")),
            }
        return {
            "state": "ready", "phase": "PRECHECK", "mode": MODE_LABEL, "bootable": False,
            "source": None, "target": None, "protected": None, "progress": {}, "result": None, "error": "",
            "vss_recovery_required": False,
        }

    def recover_vss(self) -> dict[str, Any]:
        state = self.store.load()
        if not state:
            raise DiskCloneBlocked("Não há uma limpeza VSS pendente para recuperar.", "blocked_active_job")
        status = self.monitor()
        state = self.store.load() or state
        snapshot_phase = state.get("phase") in {"SNAPSHOT", "TARGET_PREPARE", "COPY", "VERIFY", "CLEANUP"}
        recovery_pending = state.get("vss_recovery_required") is True or (
            snapshot_phase and state.get("snapshot_cleanup_confirmed") is not True
        )
        if not state.get("job_id") or not recovery_pending or status.get("state") == "unknown":
            raise DiskCloneBlocked("A operação mudou antes da recuperação VSS.", "blocked_active_job")
        pid = state.get("worker_pid")
        if pid and _process_is_running(pid) is not False:
            raise DiskCloneBlocked("A operação anterior ainda está em execução.", "blocked_active_job")
        self.recovery_launcher(self.root, str(state["job_id"]))
        return self.monitor()

    def cancel(self) -> dict[str, Any]:
        state = self.store.load()
        if not state or state.get("state") not in ACTIVE_STATES:
            raise DiskCloneBlocked("Não há uma clonagem ativa para cancelar.", "blocked_active_job")
        job_id = str(state["job_id"])
        try:
            gate = self.store.cancel_gate(job_id, create=False)
        except DataCloneError as exc:
            raise DiskCloneBlocked("A trava segura da operação não está disponível; não foi solicitado cancelamento.", exc.state) from exc
        with gate:
            with gate.locked():
                fresh = self.store.load()
                if (
                    not fresh
                    or fresh.get("job_id") != job_id
                    or fresh.get("state") not in ACTIVE_STATES
                    or fresh.get("phase") in {"TARGET_PREPARE", "CLEANUP"}
                ):
                    raise DiskCloneBlocked("A clonagem avançou para uma etapa que não pode ser cancelada com segurança.", "blocked_cancel_too_late")
                gate.signal_cancel()
                self._cancel_pending = True
        return self.monitor()

    def verify(self) -> dict[str, Any]:
        state = self.monitor()
        result = state.get("result") or {}
        if state.get("state") != "complete" or not result.get("verified"):
            raise DiskCloneBlocked("O resultado não passou pela verificação estrutural e de manifesto.", "failed_verification")
        return result


def _public_disk(disk: DiskIdentity) -> dict[str, Any]:
    return {
        "model": disk.model,
        "masked_serial": disk.masked_serial,
        "size_bytes": disk.size_bytes,
        "disk_number": disk.number,
        "identity_sha256": _identity_digest(disk),
        "is_system": disk.is_system,
        "is_boot": disk.is_boot,
        "partition_style": disk.partition_style,
        "volume_labels": [part.mount_point for part in disk.partitions if part.mount_point],
    }


def _public_role(role: DiskRole, observed: Any) -> dict[str, Any]:
    observed = observed if isinstance(observed, dict) else {}
    return {
        "model": role.model,
        "masked_serial": "****" + role.serial_suffix,
        "size_bytes": role.size_bytes,
        "is_system": bool(observed.get("is_system", role.name == "source")),
    }


def _public_progress(value: Any) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    return {
        key: max(0, int(value.get(key) or 0))
        for key in ("files", "bytes", "expected_files", "expected_bytes", "speed_bytes_per_second", "eta_seconds")
        if str(value.get(key, "")).isdigit()
    }


def _public_result(value: Any, state: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    exclusions = value.get("exclusions", [])
    exclusion_counts: dict[str, int] = {}
    runtime_names = {"pagefile.sys", "hiberfil.sys", "swapfile.sys"}
    if isinstance(exclusions, list):
        for item in exclusions:
            if not isinstance(item, dict):
                continue
            reason = str(item.get("reason", "other"))
            name = Path(str(item.get("path", ""))).name.casefold()
            category = name if name in runtime_names else reason
            exclusion_counts[category] = exclusion_counts.get(category, 0) + 1
    return {
        "verified": bool(value.get("verified")),
        "file_count": _nonnegative_int(value.get("file_count")),
        "logical_bytes": _nonnegative_int(value.get("logical_bytes")),
        "exclusion_count": sum(exclusion_counts.values()),
        "exclusions": exclusion_counts,
        "bootability": "not_applicable_data_clone",
        "target_encryption": str(value.get("target_encryption", "unknown")),
        "metadata_limits": [str(item) for item in value.get("metadata_limits", []) if isinstance(item, str)],
        "verification_scope": str(value.get("verification_scope", "")),
    }


def _nonnegative_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _owner_error(state: Any, value: Any) -> str:
    messages = {
        "blocked_confirmation": "Digite CLONE para autorizar o apagamento do Seagate.",
        "blocked_identity": "Uma das identidades dos discos está ausente, mudou ou ficou ambígua. Nenhum destino foi alterado.",
        "blocked_protected_path": "O disco de dados do L-vault não pôde ser excluído com segurança. Nenhum destino foi alterado.",
        "blocked_size": "As capacidades ou geometrias dos discos não correspondem à operação autorizada.",
        "blocked_capacity": "Os dados da origem não cabem com a margem exigida. Nenhum destino foi alterado.",
        "blocked_vss_placement": "O Windows não garante armazenamento do snapshot no Kingston. Nenhum destino foi alterado.",
        "blocked_vss": "O Windows não pôde criar uma leitura consistente da origem. Nenhum destino foi alterado.",
        "blocked_encryption": "O estado de criptografia impede uma leitura segura da origem. Nenhum destino foi alterado.",
        "blocked_filesystem": "Um volume de dados da origem usa um formato não suportado. Nenhum destino foi alterado.",
        "blocked_source_volume": "Um volume de dados da origem não pôde ser identificado com segurança.",
        "blocked_snapshot": "A leitura consistente da origem não pôde ser confirmada. Nenhum destino foi alterado.",
        "blocked_backend": "Um componente nativo necessário do Windows não está disponível.",
        "blocked_cancel_too_late": "A preparação destrutiva do destino já começou. A clonagem não pode ser cancelada com segurança neste estágio.",
        "blocked_elevation": "A permissão administrativa do Windows não foi concedida. Nenhum destino foi alterado.",
        "blocked_active_job": "Há uma clonagem anterior ativa ou incompleta. Revise-a antes de iniciar outra.",
        "blocked_audit": "O registro local da clonagem está inválido. Não inicie outra operação.",
        "blocked_source_read": "Um item da origem não pôde ser lido com segurança. Nenhum destino foi alterado.",
        "blocked_reparse": "A origem contém um tipo de link NTFS não suportado com segurança. Nenhum destino foi alterado.",
        "partial": "A clonagem foi interrompida após o início da preparação do Seagate. O destino está incompleto; revise antes de tentar novamente.",
        "cancelled": "A clonagem foi cancelada antes de alterar o Seagate.",
        "failed": "A clonagem não foi concluída. Revise o estado antes de iniciar outra operação.",
    }
    if isinstance(state, str) and state in messages:
        return messages[state]
    if isinstance(value, str) and value:
        return "A clonagem não foi concluída. Revise o estado antes de iniciar outra operação."
    return ""
