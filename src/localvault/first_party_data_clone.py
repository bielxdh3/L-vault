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
import shutil
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
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
# This pins the only script elevated during first-use setup to the exact
# installer reviewed with the application. Update it only with that script.
TRUSTED_INSTALLER_SHA256 = "fd28c3dda919f7732fee7f58a5e6ff594ee1231b873cd66854cdfc0d42ffd9b5"


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
    partitions = []
    for part in disk.partitions:
        payload = asdict(part)
        payload.pop("mount_point", None)
        partitions.append(payload)
    value = {
        "size_bytes": disk.size_bytes,
        "partition_style": disk.partition_style,
        "disk_guid": disk.disk_guid,
        "signature": disk.signature,
        "online": disk.online,
        "read_only": disk.read_only,
        "partitions": sorted(partitions, key=lambda part: (part["offset_bytes"], part["number"])),
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

    def cancel_gate(self, job_id: str, *, create: bool, owner_sid_override: str | None = None) -> CloneCancelGate:
        if not self.protected:
            raise DataCloneError("A trava de cancelamento protegida não está disponível.", "blocked_cancel_gate")
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise DataCloneError("O identificador da operação é inválido.", "blocked_audit")
        common_data = _known_program_data()
        if common_data is None:
            raise DataCloneError("O local protegido da operação não está disponível.", "blocked_audit")
        owner_file = common_data / "L-vault" / "clone-state" / "owner.sid"
        try:
            if (owner_file.parent.exists() and _is_reparse_path(owner_file.parent)) or (owner_file.exists() and _is_reparse_path(owner_file)):
                raise OSError("owner binding is unsafe")
            if owner_file.is_file():
                if owner_file.stat().st_size > 128:
                    raise OSError("owner binding is oversized")
                owner_sid = owner_file.read_text(encoding="ascii").strip()
                if owner_sid_override and owner_sid.casefold() != owner_sid_override.casefold():
                    raise OSError("owner override does not match protected binding")
            elif create and owner_sid_override:
                # First-use bootstrap: the current Windows SID comes from the
                # read-only ACL inventory and is pinned by the elevated local
                # installer before it launches the worker.
                owner_sid = owner_sid_override
            else:
                raise OSError("owner binding is missing")
            if not re.fullmatch(r"S-1-\d+(?:-\d+)+", owner_sid):
                raise OSError("owner binding is malformed")
            if owner_sid in {"S-1-1-0", "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545"}:
                raise OSError("owner binding is not an interactive user SID")
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


def _clone_runtime_paths(root: Path) -> tuple[Path, Path, Path, Path, Path]:
    repository = Path(root).resolve()
    installer = repository / "tools" / "install_clone_worker.ps1"
    bundle = repository / ".build" / "clone-runtime-stage" / "bundle"
    manifest = bundle / "build-manifest.json"
    worker = bundle / "LocalVaultCloneWorker.exe"
    helper = bundle / "LVaultVssSnapshot.exe"
    return installer, bundle, manifest, worker, helper


_BUILD_INPUT_GIT_PATHS = ("tools/clone_worker_entry.py", "src/localvault", "native/vss_snapshot")


def _runtime_build_inputs(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    repository = Path(root).resolve(strict=True)
    python_package = repository / "src" / "localvault"
    rust_project = repository / "native" / "vss_snapshot"
    if not python_package.is_dir() or not rust_project.is_dir():
        raise OSError("required first-party build sources are missing")
    directories = (
        repository,
        repository / "tools",
        repository / "src",
        python_package,
        repository / "native",
        rust_project,
        rust_project / "src",
    )
    files = {
        repository / "tools" / "clone_worker_entry.py",
        repository / "tools" / "install_clone_worker.ps1",
        *python_package.rglob("*.py"),
        *rust_project.rglob("*.rs"),
        rust_project / "Cargo.toml",
        rust_project / "Cargo.lock",
        rust_project / "build.rs",
    }
    return directories, tuple(sorted(files, key=lambda path: str(path).casefold()))


def _runtime_build_inputs_are_clean(git: str, repository: str) -> bool:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(name, None)
    try:
        diff = subprocess.run(
            [git, "-C", repository, "diff", "--quiet", "HEAD", "--", *_BUILD_INPUT_GIT_PATHS],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if diff.returncode:
            return False
        status = subprocess.run(
            [git, "-C", repository, "status", "--porcelain=v1", "--untracked-files=all", "--", *_BUILD_INPUT_GIT_PATHS],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return status.returncode == 0 and not status.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _installer_sha256(path: Path) -> str:
    # Git may check the reviewed PowerShell source out with either newline
    # convention. Pin its decoded code bytes so a platform line-ending
    # conversion does not invalidate the app's embedded hash.
    content = path.read_bytes().decode("utf-8-sig")
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _stage_path_hashes(value: dict[str, Any]) -> tuple[str, str, str] | None:
    hashes = tuple(str(value.get(key, "")).casefold() for key in ("installer_sha256", "worker_sha256", "vss_helper_sha256"))
    if any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in hashes):
        return None
    return hashes  # type: ignore[return-value]


def _runtime_stage_is_valid(root: Path) -> bool:
    installer, bundle, manifest_path, worker_path, helper_path = _clone_runtime_paths(root)
    try:
        for path in (installer, bundle, manifest_path, worker_path, helper_path):
            if _is_reparse_path(path) or not path.exists():
                return False
        if not installer.is_file() or not manifest_path.is_file() or not worker_path.is_file() or not helper_path.is_file():
            return False
        if manifest_path.stat().st_size < 2 or manifest_path.stat().st_size > 32_768:
            return False
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema") != 2 or value.get("status") != "local-integrity-install-bootstrap":
            return False
        if str(value.get("repository", "")).casefold() != str(Path(root).resolve()).casefold():
            return False
        if value.get("worker_artifact") != worker_path.name or value.get("vss_helper_artifact") != helper_path.name:
            return False
        commit = str(value.get("commit", ""))
        if not re.fullmatch(r"[a-fA-F0-9]{40,64}", commit):
            return False
        repository = str(Path(root).resolve())
        if str(value.get("repository", "")).casefold() != repository.casefold():
            return False
        git = shutil.which("git.exe") or shutil.which("git")
        if not git or not _runtime_build_inputs_are_clean(git, repository):
            return False
        current = subprocess.run(
            [git, "-C", repository, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if current.returncode or current.stdout.strip().casefold() != commit.casefold():
            return False
        expected_hashes = _stage_path_hashes(value)
        if expected_hashes is None or not re.fullmatch(r"[a-fA-F0-9]{64}", TRUSTED_INSTALLER_SHA256):
            return False
        if expected_hashes[0] != TRUSTED_INSTALLER_SHA256.casefold():
            return False
        for index, (expected, path) in enumerate(zip(expected_hashes, (installer, worker_path, helper_path), strict=True)):
            actual = _installer_sha256(path) if index == 0 else _file_sha256(path)
            if actual != expected:
                return False
        return True
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError, RuntimeError):
        return False


def _open_runtime_stage_lock(path: Path) -> int:
    if os.name != "nt":
        raise OSError("Windows file sharing is required to pin the clone runtime")
    if _is_reparse_path(path):
        raise OSError("clone runtime path contains a reparse point")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create_file.restype = ctypes.c_void_p
    flags = 0x00200000  # OPEN_REPARSE_POINT
    handle = create_file(str(path), 0x80000000, 0x00000001, None, 3, flags, None)
    invalid = ctypes.c_void_p(-1).value
    if not handle or handle == invalid:
        raise OSError(ctypes.get_last_error(), "could not pin clone runtime path", str(path))
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int

    class _FileTime(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

    class _ByHandleInfo(ctypes.Structure):
        _fields_ = [
            ("attributes", ctypes.c_uint32),
            ("creation_time", _FileTime),
            ("access_time", _FileTime),
            ("write_time", _FileTime),
            ("volume_serial", ctypes.c_uint32),
            ("file_size_high", ctypes.c_uint32),
            ("file_size_low", ctypes.c_uint32),
            ("links", ctypes.c_uint32),
            ("file_index_high", ctypes.c_uint32),
            ("file_index_low", ctypes.c_uint32),
        ]

    try:
        info = _ByHandleInfo()
        get_info = kernel32.GetFileInformationByHandle
        get_info.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ByHandleInfo)]
        get_info.restype = ctypes.c_int
        if not get_info(handle, ctypes.byref(info)):
            raise OSError(ctypes.get_last_error(), "could not inspect pinned clone runtime path", str(path))
        is_directory = bool(info.attributes & 0x10)
        if info.attributes & REPARSE_POINT_ATTRIBUTE or is_directory:
            raise OSError("clone runtime file changed type while it was being pinned")
        get_final_path = kernel32.GetFinalPathNameByHandleW
        get_final_path.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
        get_final_path.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_final_path(handle, buffer, len(buffer), 0)
        if length == 0 or length >= len(buffer):
            raise OSError(ctypes.get_last_error(), "could not resolve pinned clone runtime path", str(path))
        actual = buffer.value
        if actual.startswith("\\\\?\\UNC\\"):
            actual = "\\\\" + actual[8:]
        elif actual.startswith("\\\\?\\"):
            actual = actual[4:]
        expected = os.path.abspath(str(path))
        if os.path.normcase(actual.rstrip("\\")).casefold() != os.path.normcase(expected.rstrip("\\")).casefold():
            raise OSError("clone runtime path resolved to a different filesystem object")
        return int(handle)
    except Exception:
        close_handle(handle)
        raise


@contextmanager
def _locked_runtime_build_inputs(root: Path):
    """Pin existing build inputs and require a clean checkout during build."""
    repository = Path(root).resolve(strict=True)
    directories, files = _runtime_build_inputs(repository)
    handles: list[int] = []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    try:
        for path in directories:
            if _is_reparse_path(path) or not path.is_dir():
                raise OSError("clone runtime source directory changed or is unsafe")
        for path in files:
            handles.append(_open_runtime_stage_lock(path))
        git = shutil.which("git.exe") or shutil.which("git")
        if not git or not _runtime_build_inputs_are_clean(git, str(repository)):
            raise DataCloneError("Os arquivos-fonte do clone foram alterados; o runtime não será elevado.", "blocked_backend")
        installer = repository / "tools" / "install_clone_worker.ps1"
        if _installer_sha256(installer) != TRUSTED_INSTALLER_SHA256.casefold():
            raise DataCloneError("O instalador local não corresponde à versão aprovada pelo L-vault.", "blocked_backend")
        commit = subprocess.run(
            [git, "-C", str(repository), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if commit.returncode or not re.fullmatch(r"[a-fA-F0-9]{40,64}", commit.stdout.strip()):
            raise DataCloneError("L-vault não conseguiu fixar a revisão dos arquivos-fonte do clone.", "blocked_backend")
        yield commit.stdout.strip().casefold()
        if not _runtime_build_inputs_are_clean(git, str(repository)):
            raise DataCloneError("Os arquivos-fonte mudaram durante a preparação do runtime.", "blocked_backend")
    except DataCloneError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise DataCloneError("L-vault não conseguiu bloquear os arquivos-fonte durante a compilação.", "blocked_backend") from exc
    finally:
        for handle in reversed(handles):
            close_handle(ctypes.c_void_p(handle))


@contextmanager
def _locked_runtime_stage(root: Path):
    """Pin every path used by the elevated bootstrap against replacement."""
    if os.name != "nt":
        raise DataCloneError("A primeira instalação protegida do runtime exige Windows.", "blocked_backend")
    repository = Path(root).resolve(strict=True)
    original = os.path.abspath(str(root))
    if os.path.normcase(str(repository)).casefold() != os.path.normcase(original).casefold():
        raise DataCloneError("O caminho do repositório foi redirecionado e não pode ser elevado.", "blocked_backend")
    installer, bundle, manifest_path, worker_path, helper_path = _clone_runtime_paths(repository)
    stage_root = bundle.parent
    directories = (repository, repository / "tools", repository / ".build", stage_root, bundle)
    files = (installer, manifest_path, worker_path, helper_path)
    handles: list[int] = []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    try:
        for path in directories:
            if _is_reparse_path(path) or not path.is_dir():
                raise OSError("clone runtime directory changed or is unsafe")
        for path in files:
            handles.append(_open_runtime_stage_lock(path))
        if not _runtime_stage_is_valid(repository):
            raise DataCloneError("Os arquivos locais do runtime não passaram pela validação antes da elevação.", "blocked_backend")
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
        recorded_hashes = _stage_path_hashes(value)
        actual_hashes = (_installer_sha256(installer), _file_sha256(worker_path), _file_sha256(helper_path))
        if recorded_hashes != actual_hashes or actual_hashes[0] != TRUSTED_INSTALLER_SHA256.casefold():
            raise DataCloneError("O instalador local não corresponde à versão aprovada pelo L-vault.", "blocked_backend")
        # The elevated command line is pinned from hashes measured here while
        # the files and their containing directories deny write/delete access.
        yield {"manifest": value, "hashes": actual_hashes}
    except DataCloneError:
        raise
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise DataCloneError("L-vault não conseguiu manter os arquivos do runtime estáveis para a autorização do Windows.", "blocked_backend") from exc
    finally:
        for handle in reversed(handles):
            close_handle(handle)


def _prepare_runtime_stage(root: Path) -> None:
    if os.name != "nt":
        raise DataCloneError("L-vault could not prepare its protected Windows clone runtime.", "blocked_backend")
    installer, _, _, _, _ = _clone_runtime_paths(root)
    if _is_reparse_path(installer) or not installer.is_file():
        raise DataCloneError("L-vault could not prepare its protected Windows clone runtime.", "blocked_backend")
    try:
        with _locked_runtime_build_inputs(root):
            powershell = windows_powershell_path()
            environment = os.environ.copy()
            for name in (
                "PYTHONPATH",
                "PYTHONHOME",
                "PYTHONSTARTUP",
                "RUSTC_WRAPPER",
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "GIT_DIR",
                "GIT_WORK_TREE",
                "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            ):
                environment.pop(name, None)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            completed = subprocess.run(
                [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(installer), "-BuildOnly"],
                cwd=str(Path(root).resolve()),
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=3600,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if completed.returncode or not _runtime_stage_is_valid(root):
                raise OSError("runtime build failed its validation")
    except Exception as exc:
        raise DataCloneError("L-vault could not prepare its protected Windows clone runtime. No disks were changed.", "blocked_backend") from exc


class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("fMask", ctypes.c_uint32),
        ("hwnd", ctypes.c_void_p),
        ("lpVerb", ctypes.c_wchar_p),
        ("lpFile", ctypes.c_wchar_p),
        ("lpParameters", ctypes.c_wchar_p),
        ("lpDirectory", ctypes.c_wchar_p),
        ("nShow", ctypes.c_int),
        ("hInstApp", ctypes.c_void_p),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", ctypes.c_wchar_p),
        ("hkeyClass", ctypes.c_void_p),
        ("dwHotKey", ctypes.c_uint32),
        ("hIconOrMonitor", ctypes.c_void_p),
        ("hProcess", ctypes.c_void_p),
    ]


def _launch_elevated_runtime_installer(root: Path, job_id: str, owner_sid: str) -> None:
    if os.name != "nt":
        raise DataCloneError("A protected Windows clone runtime requires Windows.", "blocked_backend")
    if not re.fullmatch(r"[a-f0-9]{32}", job_id) or not re.fullmatch(r"S-1-\d+(?:-\d+)+", owner_sid):
        raise DataCloneError("L-vault refused an invalid protected clone request.", "blocked_audit")
    installer, _, _, _, _ = _clone_runtime_paths(root)
    if _is_reparse_path(installer) or not installer.is_file():
        raise DataCloneError("L-vault could not locate its protected runtime installer.", "blocked_backend")
    powershell = windows_powershell_path()
    with _locked_runtime_stage(root) as pinned:
        hashes = pinned["hashes"]
        arguments = [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(installer),
            "-Install",
            "-LaunchJobId",
            job_id,
            "-LaunchOwnerSid",
            owner_sid,
            "-ExpectedInstallerSha256",
            hashes[0],
            "-ExpectedWorkerSha256",
            hashes[1],
            "-ExpectedVssHelperSha256",
            hashes[2],
        ]
        if _is_admin():
            try:
                completed = subprocess.run(
                    [str(powershell), *arguments],
                    cwd=str(Path(root).resolve()),
                    env=windows_system_environment(),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=180,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except subprocess.TimeoutExpired as exc:
                raise DataCloneError("Runtime setup is taking longer than expected. Check clone status in L-vault before retrying.", "blocked_elevation") from exc
            if completed.returncode:
                raise DataCloneError("L-vault could not finish its protected runtime setup. The target was not started.", "blocked_backend")
            return

        execute = _ShellExecuteInfo()
        execute.cbSize = ctypes.sizeof(_ShellExecuteInfo)
        execute.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
        execute.lpVerb = "runas"
        execute.lpFile = str(powershell)
        execute.lpParameters = subprocess.list2cmdline(arguments)
        execute.lpDirectory = str(Path(root).resolve())
        execute.nShow = 0
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell_execute = shell32.ShellExecuteExW
        shell_execute.argtypes = [ctypes.POINTER(_ShellExecuteInfo)]
        shell_execute.restype = ctypes.c_int
        if not shell_execute(ctypes.byref(execute)):
            error = ctypes.get_last_error()
            if error == 1223:  # ERROR_CANCELLED
                raise DataCloneError("Windows permission was not granted. The target was not changed.", "blocked_elevation")
            raise DataCloneError("Windows could not start L-vault's protected clone setup.", "blocked_elevation")
        if not execute.hProcess:
            raise DataCloneError("Windows did not return the protected setup process handle.", "blocked_elevation")
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            wait = kernel32.WaitForSingleObject
            wait.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            wait.restype = ctypes.c_uint32
            result = wait(execute.hProcess, 180_000)
            if result != 0:
                raise DataCloneError("Protected clone setup did not report completion in time. Check clone status in L-vault before retrying.", "blocked_elevation")
            exit_code = ctypes.c_uint32()
            get_exit = kernel32.GetExitCodeProcess
            get_exit.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
            get_exit.restype = ctypes.c_int
            if not get_exit(execute.hProcess, ctypes.byref(exit_code)) or exit_code.value != 0:
                raise DataCloneError("L-vault could not finish its protected runtime setup. Check clone status before retrying.", "blocked_backend")
        finally:
            close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
            close_handle.argtypes = [ctypes.c_void_p]
            close_handle.restype = ctypes.c_int
            close_handle(execute.hProcess)


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


def _wait_for_worker_ack(root: Path, job_id: str, process_id: int, is_running: Callable[[], bool | None], *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    store = CloneJobStore(root, protected=True)
    while True:
        state = store.load()
        if state and state.get("job_id") == job_id and str(state.get("worker_pid", "")) == str(process_id):
            return
        running = is_running()
        if running is False:
            raise DataCloneError("The protected clone worker exited before acknowledging startup.", "blocked_backend")
        if time.monotonic() >= deadline:
            raise DataCloneError("The protected clone worker did not acknowledge startup. L-vault requested cancellation before target preparation.", "blocked_elevation")
        time.sleep(0.25)


def _process_handle_is_running(handle: int) -> bool | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_exit = kernel32.GetExitCodeProcess
    get_exit.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    get_exit.restype = ctypes.c_int
    code = ctypes.c_uint32()
    if not get_exit(ctypes.c_void_p(handle), ctypes.byref(code)):
        return None
    return code.value == 259
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
        try:
            process = subprocess.Popen([str(executable), *args], cwd=str(executable.parent), env=windows_system_environment(temp_directory=executable.parent / "Temp"), creationflags=flags, close_fds=True)
        except OSError as exc:
            raise DataCloneError("Windows could not start the protected clone worker.", "blocked_backend") from exc
        _wait_for_worker_ack(root, job_id, process.pid, lambda: None if process.poll() is None else False)
        return
    execute = _ShellExecuteInfo()
    execute.cbSize = ctypes.sizeof(_ShellExecuteInfo)
    execute.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
    execute.lpVerb = "runas"
    execute.lpFile = str(executable)
    execute.lpParameters = subprocess.list2cmdline(args)
    execute.lpDirectory = str(executable.parent)
    execute.nShow = 0
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell_execute = shell32.ShellExecuteExW
    shell_execute.argtypes = [ctypes.POINTER(_ShellExecuteInfo)]
    shell_execute.restype = ctypes.c_int
    if not shell_execute(ctypes.byref(execute)):
        error = ctypes.get_last_error()
        if error == 1223:
            raise DataCloneError("Windows permission was not granted. The target was not changed.", "blocked_elevation")
        raise DataCloneError("Windows could not start the protected clone worker.", "blocked_elevation")
    if not execute.hProcess:
        raise DataCloneError("Windows did not return the protected worker process handle.", "blocked_elevation")
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_pid = kernel32.GetProcessId
        get_pid.argtypes = [ctypes.c_void_p]
        get_pid.restype = ctypes.c_uint32
        process_id = int(get_pid(execute.hProcess))
        if process_id <= 0:
            raise DataCloneError("Windows did not identify the protected worker process.", "blocked_elevation")
        _wait_for_worker_ack(root, job_id, process_id, lambda: _process_handle_is_running(int(execute.hProcess)))
    finally:
        close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        close_handle(execute.hProcess)


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
        installer_launcher: Callable[[Path, str, str], None] | None = None,
        runtime_stage_preparer: Callable[[Path], None] | None = None,
        runtime_security_verifier: Callable[[], Any] | None = None,
    ):
        self.root = Path(root).resolve()
        self.inventory = inventory or WindowsDiskInventory()
        self.protected_path_resolver = protected_path_resolver or WindowsProtectedPathResolver()
        self.worker_launcher = worker_launcher or _launch_elevated_worker
        self.recovery_launcher = recovery_launcher or (lambda root, job_id: _launch_elevated_worker(root, job_id, recover_vss=True))
        self.installer_launcher = installer_launcher or _launch_elevated_runtime_installer
        self.runtime_stage_preparer = runtime_stage_preparer or _prepare_runtime_stage
        self.runtime_security_verifier = runtime_security_verifier or verify_clone_runtime_security
        self.store = CloneJobStore(self.root, protected=True)
        self._pending_state: dict[str, Any] | None = None
        self._cancel_pending = False
        self._launch_guard = threading.Lock()
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
        if os.name != "nt":
            blockers.append("Windows é necessário.")
        if not powershell.is_file() or not robocopy.is_file():
            blockers.append("Uma ferramenta nativa necessária do Windows não está disponível.")
        runtime_install_required = False
        runtime_security = None
        if os.name == "nt":
            runtime_security = self.runtime_security_verifier()
            if not runtime_security.ready:
                if runtime_security.installable:
                    installer, _, _, _, _ = _clone_runtime_paths(self.root)
                    if installer.is_file() and not _is_reparse_path(installer):
                        runtime_install_required = True
                    else:
                        blockers.append("L-vault could not prepare its protected clone runtime.")
                else:
                    blockers.append("The protected L-vault clone runtime failed its Windows safety checks.")
        return {
            "available": not blockers,
            "backend": MODE_LABEL,
            "version": "Windows inbox VSS / Storage / Robocopy",
            "bootable": False,
            "blocker": " ".join(blockers),
            "elevation_required": not _is_admin(),
            "runtime_install_required": runtime_install_required,
            "runtime_trust": (runtime_security.evidence.get("runtime_trust") if runtime_security else "unavailable"),
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
            "runtime_install_required": capabilities.get("runtime_install_required", False),
            "backend": capabilities.get("backend", MODE_LABEL),
        }

    def launch(self, *, confirmation: str) -> dict[str, Any]:
        if not self._launch_guard.acquire(blocking=False):
            raise DiskCloneBlocked("A clone is already being prepared in this L-vault session.", "blocked_active_job")
        try:
            return self._launch_once(confirmation=confirmation)
        finally:
            self._launch_guard.release()

    def _launch_once(self, *, confirmation: str) -> dict[str, Any]:
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
        initial_roles = tuple(_identity_digest(disk) for disk in (source, target, protected))
        initial_layouts = (_layout_digest(source), _layout_digest(protected))
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
        self._cancel_pending = False
        self._pending_state = state
        try:
            runtime_security = self.runtime_security_verifier()
            if not runtime_security.ready:
                if not runtime_security.installable:
                    raise DiskCloneBlocked("The protected L-vault clone runtime failed its Windows safety checks.", "blocked_backend")
                # Build-only tools run unelevated. The installer validates the
                # exact staged bytes, pins them under ProgramData, and then
                # launches only the protected copy under the same UAC consent.
                self.runtime_stage_preparer(self.root)
                if self._cancel_pending:
                    state.update(state="cancelled", error="Cancelled before the target was changed.")
                    self._pending_state = state
                    return self.monitor()
                fresh = self._roles()
                if tuple(_identity_digest(disk) for disk in fresh[:3]) != initial_roles:
                    raise DiskCloneBlocked("The source, target, or protected disk identity changed while L-vault prepared the clone.", "blocked_identity")
                if (_layout_digest(fresh[0]), _layout_digest(fresh[2])) != initial_layouts:
                    raise DiskCloneBlocked("The Kingston or protected HGST layout changed while L-vault prepared the clone.", "blocked_identity")
                source, target, protected = fresh[:3]
                state.update(
                    source=_public_disk(source),
                    target=_public_disk(target),
                    protected=_public_disk(protected),
                    source_layout_sha256=_layout_digest(source),
                    protected_layout_sha256=_layout_digest(protected),
                )
                self._pending_state = state
                runtime_security = self.runtime_security_verifier()
                if not runtime_security.installable:
                    raise DiskCloneBlocked("The protected L-vault clone runtime failed its Windows safety checks.", "blocked_backend")

            caller_sid = str(runtime_security.evidence.get("caller_sid", ""))
            if not re.fullmatch(r"S-1-\d+(?:-\d+)+", caller_sid):
                raise DiskCloneBlocked("L-vault could not identify the current Windows owner.", "blocked_backend")
            # Keep the named cancellation objects alive in this app process.
            # On first installation the SID comes from Windows' read-only ACL
            # inventory; the elevated installer writes the protected binding.
            self._cancel_gate = self.store.cancel_gate(job_id, create=True, owner_sid_override=caller_sid)
            self._cancel_gate_job_id = job_id
            if self._cancel_pending:
                self._cancel_gate.signal_cancel()
                state.update(state="cancelled", error="Cancelled before the target was changed.")
                self._pending_state = state
                self._cancel_gate.close()
                self._cancel_gate = None
                self._cancel_gate_job_id = None
                return self.monitor()
            if runtime_security.ready:
                self.worker_launcher(self.root, job_id)
            else:
                self.installer_launcher(self.root, job_id, caller_sid)
        except Exception as exc:
            if self._cancel_gate is not None:
                if not state.get("target_destroyed"):
                    try:
                        with self._cancel_gate.locked():
                            self._cancel_gate.signal_cancel()
                    except Exception:
                        pass
                self._cancel_gate.close()
                self._cancel_gate = None
                self._cancel_gate_job_id = None
            failure_state = str(getattr(exc, "state", "blocked_elevation"))
            failure_reason = str(getattr(exc, "reason", "Não foi possível iniciar o trabalhador elevado."))
            state.update(state="cancelled" if self._cancel_pending else "blocked", phase="PRECHECK", error=failure_reason)
            if self._cancel_pending:
                self._pending_state = state
                return self.monitor()
            if isinstance(exc, DiskCloneBlocked):
                raise
            raise DiskCloneBlocked(failure_reason, failure_state) from exc
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
        if state is None and self._pending_state and self._pending_state.get("state") in ACTIVE_STATES:
            if self._pending_state.get("target_destroyed") or self._pending_state.get("phase") in {"TARGET_PREPARE", "CLEANUP"}:
                raise DiskCloneBlocked("Target preparation has started, so cancellation is no longer available safely.", "blocked_cancel_too_late")
            self._cancel_pending = True
            if self._cancel_gate is not None and self._cancel_gate_job_id == self._pending_state.get("job_id"):
                with self._cancel_gate.locked():
                    self._cancel_gate.signal_cancel()
            return self.monitor()
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
        "source_encryption": _public_source_encryption(state.get("source_encryption")),
        "target_encryption": str(value.get("target_encryption", "unknown")),
        "metadata_limits": [str(item) for item in value.get("metadata_limits", []) if isinstance(item, str)],
        "verification_scope": str(value.get("verification_scope", "")),
    }


def _public_source_encryption(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return "unknown"
    states = []
    for item in value.values():
        if item == "unknown_not_reported" or not isinstance(item, str):
            return "unknown"
        parts = [part.casefold().replace(" ", "") for part in item.split(":")]
        if len(parts) != 3 or parts[2] not in {"unlocked", "0"}:
            return "unknown"
        if parts[0] not in {"fullyencrypted", "fullydecrypted", "decrypted"}:
            return "unknown"
        states.append(parts[0])
    if states and all(item in {"fullydecrypted", "decrypted"} for item in states):
        return "unencrypted"
    if states and all(item == "fullyencrypted" for item in states):
        return "encrypted_unlocked"
    return "unknown"


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
