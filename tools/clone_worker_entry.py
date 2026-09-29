"""Protected, one-file entry point for L-vault's elevated clone worker.

The only operational caller-supplied value is a random job ID. All clone plans,
identity checks, snapshots, status, and audit data are derived by the bundled
worker and stored under the protected ProgramData state directory.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(r"E:\LocalVault")
APP_ROOT = Path(r"C:\ProgramData\L-vault")
RUNTIME_DIR = APP_ROOT / "clone-runtime"
STATE_ROOT = APP_ROOT / "clone-state"
RUNTIME_TEMP_ROOT = RUNTIME_DIR / "Temp"
WORKER_EXE = RUNTIME_DIR / "LocalVaultCloneWorker.exe"
VSS_HELPER_EXE = RUNTIME_DIR / "LVaultVssSnapshot.exe"
OWNER_SID_FILE = STATE_ROOT / "owner.sid"
JOB_ID_RE = re.compile(r"[a-f0-9]{32}\Z")

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
USERS_SID = "S-1-5-32-545"
OWNER_RIGHTS_SID = "S-1-3-4"
FULL_CONTROL_MASK = 0x001F01FF
READ_EXECUTE_MASK = 0x001200A9
OWNER_CONTROL_MASK = 0x000C0000
UNSAFE_USER_WRITE_MASK = (
    0x00000002  # FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x00000004  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x00000010  # FILE_WRITE_EA
    | 0x00000040  # FILE_DELETE_CHILD
    | 0x00000100  # FILE_WRITE_ATTRIBUTES
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
)


class BootstrapError(RuntimeError):
    """A fixed-path, trust-boundary, or launch check failed closed."""


def _normal(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _system_directory() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel.GetSystemDirectoryW
    get_system_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    get_system_directory.restype = ctypes.c_uint32
    length = int(get_system_directory(buffer, len(buffer)))
    if not length or length >= len(buffer):
        raise BootstrapError("Windows system directory is unavailable")
    return Path(buffer.value)


def _assert_no_reparse_chain(path: Path, *, must_exist: bool = True) -> None:
    if os.name != "nt":
        raise BootstrapError("the protected worker requires Windows")
    full = Path(os.path.abspath(path))
    current = Path(full.anchor)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_attributes = kernel.GetFileAttributesW
    get_attributes.argtypes = [ctypes.c_wchar_p]
    get_attributes.restype = ctypes.c_uint32
    invalid = 0xFFFFFFFF
    reparse = 0x400
    parts = full.parts[1:]
    for index, part in enumerate(parts):
        current = current / part
        attributes = int(get_attributes(str(current)))
        if attributes == invalid:
            if must_exist or index < len(parts) - 1:
                raise BootstrapError(f"protected path is missing or inaccessible: {current}")
            return
        if attributes & reparse:
            raise BootstrapError(f"protected path contains a reparse point: {current}")


def _read_acl_facts(paths: list[Path]) -> list[dict[str, Any]]:
    """Use inbox Windows PowerShell to read ACL facts without localized names."""
    executable = _system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not executable.is_file():
        raise BootstrapError("inbox Windows PowerShell is unavailable for ACL verification")
    literal_paths = [str(path) for path in paths]
    encoded_paths = base64.b64encode(json.dumps(literal_paths).encode("utf-8")).decode("ascii")
    script = r"""
$ErrorActionPreference = 'Stop'
$paths = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('""" + encoded_paths + r"""')) | ConvertFrom-Json
$rows = foreach ($path in $paths) {
    $item = Get-Item -LiteralPath $path -Force
    $acl = Get-Acl -LiteralPath $path
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $access = foreach ($rule in $rules) {
        [pscustomobject]@{
            sid = $rule.IdentityReference.Value
            allow = ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)
            rights = [int64]$rule.FileSystemRights
            inherited = [bool]$rule.IsInherited
        }
    }
    [pscustomobject]@{
        path = $item.FullName
        is_directory = [bool]$item.PSIsContainer
        protected = [bool]$acl.AreAccessRulesProtected
        rules = @($access)
    }
}
ConvertTo-Json -InputObject @($rows) -Depth 5 -Compress
"""
    command = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    system_directory = executable.parents[2]
    windows_directory = system_directory.parent
    environment = {
        "SystemRoot": str(windows_directory),
        "windir": str(windows_directory),
        "SystemDrive": windows_directory.anchor.rstrip("\\/"),
        "PATH": str(system_directory),
        "PSModulePath": str(executable.parent / "Modules"),
        "TEMP": str(RUNTIME_TEMP_ROOT),
        "TMP": str(RUNTIME_TEMP_ROOT),
    }
    result = subprocess.run(
        [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
        cwd=str(executable.parent),
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise BootstrapError("the protected runtime ACL could not be verified")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise BootstrapError("Windows returned malformed ACL verification data") from exc
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list) or len(payload) != len(paths):
        raise BootstrapError("Windows returned incomplete ACL verification data")
    return payload


def _assert_safe_acl_facts(row: dict[str, Any], *, require_protected: bool) -> None:
    if require_protected and (not row.get("is_directory") or row.get("protected") is not True):
        raise BootstrapError(f"directory DACL is not explicitly protected: {row.get('path')}")
    rules = row.get("rules")
    if not isinstance(rules, list) or not rules:
        raise BootstrapError(f"directory/file has no readable DACL: {row.get('path')}")
    masks: dict[str, int] = {}
    owner_rights_deny = 0
    for rule in rules:
        if not isinstance(rule, dict):
            raise BootstrapError(f"unexpected deny or malformed ACE: {row.get('path')}")
        sid = str(rule.get("sid", ""))
        if sid == OWNER_RIGHTS_SID:
            mask = int(rule.get("rights", 0))
            if rule.get("allow") is not False or (mask & OWNER_CONTROL_MASK) != OWNER_CONTROL_MASK:
                raise BootstrapError(f"owner can modify the protected DACL: {row.get('path')}")
            owner_rights_deny |= mask
            continue
        if rule.get("allow") is not True:
            raise BootstrapError(f"unexpected deny or malformed ACE: {row.get('path')}")
        if sid not in {SYSTEM_SID, ADMINISTRATORS_SID, USERS_SID}:
            raise BootstrapError(f"unexpected DACL principal {sid!r}: {row.get('path')}")
        masks[sid] = masks.get(sid, 0) | int(rule.get("rights", 0))
    if (masks.get(SYSTEM_SID, 0) & FULL_CONTROL_MASK) != FULL_CONTROL_MASK:
        raise BootstrapError(f"SYSTEM lacks full control: {row.get('path')}")
    if (masks.get(ADMINISTRATORS_SID, 0) & FULL_CONTROL_MASK) != FULL_CONTROL_MASK:
        raise BootstrapError(f"Administrators lack full control: {row.get('path')}")
    user_mask = masks.get(USERS_SID, 0)
    if user_mask & READ_EXECUTE_MASK != READ_EXECUTE_MASK or user_mask & UNSAFE_USER_WRITE_MASK:
        raise BootstrapError(f"interactive users lack read/execute or have write access: {row.get('path')}")
    if not owner_rights_deny and row.get("owner_sid") not in {SYSTEM_SID, ADMINISTRATORS_SID}:
        raise BootstrapError(f"an unelevated owner can change protected ACLs: {row.get('path')}")


def _assert_secure_layout() -> None:
    expected_exe = _normal(WORKER_EXE)
    if not getattr(sys, "frozen", False) or _normal(sys.executable) != expected_exe:
        raise BootstrapError("worker was not started from its fixed ProgramData path")

    for path in (APP_ROOT, RUNTIME_DIR, RUNTIME_TEMP_ROOT, STATE_ROOT, OWNER_SID_FILE, WORKER_EXE, VSS_HELPER_EXE):
        _assert_no_reparse_chain(path)
    if not WORKER_EXE.is_file() or not VSS_HELPER_EXE.is_file():
        raise BootstrapError("the worker or native VSS requester is missing")

    extraction = getattr(sys, "_MEIPASS", None)
    if not extraction or not _normal(extraction).startswith(_normal(RUNTIME_TEMP_ROOT) + os.sep):
        raise BootstrapError("one-file extraction is outside the protected runtime Temp directory")
    _assert_no_reparse_chain(Path(extraction))

    directory_rows = _read_acl_facts([APP_ROOT, RUNTIME_DIR, RUNTIME_TEMP_ROOT, STATE_ROOT, Path(extraction)])
    for row in directory_rows:
        _assert_safe_acl_facts(
            row,
            require_protected=row["path"].casefold()
            in {str(APP_ROOT).casefold(), str(RUNTIME_DIR).casefold(), str(RUNTIME_TEMP_ROOT).casefold(), str(STATE_ROOT).casefold()},
        )
    file_rows = _read_acl_facts([WORKER_EXE, VSS_HELPER_EXE, OWNER_SID_FILE])
    for row in file_rows:
        _assert_safe_acl_facts(row, require_protected=False)

    # Reuse the app's read-only ancestor verifier so a weak C:\ or
    # C:\ProgramData parent cannot bypass the protected child DACL.
    if not getattr(sys, "frozen", False):
        sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
    from localvault.clone_runtime_security import require_clone_runtime_security

    require_clone_runtime_security()

    expected_sid = OWNER_SID_FILE.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"S-1-\d+(?:-\d+)+", expected_sid) or _current_user_sid().casefold() != expected_sid.casefold():
        raise BootstrapError("the elevated worker caller is not the installed L-vault owner")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise BootstrapError("worker did not receive Windows administrator elevation")


def _current_user_sid() -> str:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    token = ctypes.c_void_p()
    open_token = advapi.OpenProcessToken
    open_token.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    open_token.restype = ctypes.c_int
    get_process = kernel.GetCurrentProcess
    get_process.argtypes = []
    get_process.restype = ctypes.c_void_p
    if not open_token(get_process(), 0x0008, ctypes.byref(token)):
        raise BootstrapError("could not inspect the elevated caller token")
    try:
        needed = ctypes.c_uint32()
        get_info = advapi.GetTokenInformation
        get_info.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        get_info.restype = ctypes.c_int
        get_info(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not get_info(token, 1, buffer, needed, ctypes.byref(needed)):
            raise BootstrapError("could not read the elevated caller token")
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        sid_text = ctypes.c_wchar_p()
        convert = advapi.ConvertSidToStringSidW
        convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
        convert.restype = ctypes.c_int
        if not convert(sid_pointer, ctypes.byref(sid_text)):
            raise BootstrapError("could not identify the elevated caller")
        try:
            return str(sid_text.value)
        finally:
            kernel.LocalFree.argtypes = [ctypes.c_void_p]
            kernel.LocalFree.restype = ctypes.c_void_p
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
    finally:
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        kernel.CloseHandle(token)


def _validated_job_id(value: object) -> str:
    job_id = str(value or "")
    if not JOB_ID_RE.fullmatch(job_id):
        raise BootstrapError("job ID must be 32 lowercase hexadecimal characters")
    return job_id


def _load_bundled_worker():
    """Import packaged code only after the fixed runtime has passed ACL checks."""
    if not getattr(sys, "frozen", False):
        sys.path.insert(0, str(REPOSITORY_ROOT / "src"))
    from localvault import first_party_clone_worker as worker
    from localvault import first_party_data_clone as clone_data

    original_store = clone_data.CloneJobStore

    class ProgramDataCloneJobStore(original_store):
        def __init__(self, root: Path, *, protected: bool = False):
            super().__init__(root, protected=True)
            if _normal(self.job_root) != _normal(STATE_ROOT):
                raise BootstrapError("worker state resolved outside the fixed ProgramData directory")

    # The protected worker keeps both job state and clone audits under the
    # fixed ProgramData root. Cancellation uses an owner-restricted named event.
    clone_data.CloneJobStore = ProgramDataCloneJobStore
    worker.CloneJobStore = ProgramDataCloneJobStore
    return worker, ProgramDataCloneJobStore


def _run_job(job_id: str, *, recover_vss: bool = False) -> int:
    _assert_secure_layout()
    _assert_no_reparse_chain(REPOSITORY_ROOT)
    worker, store_type = _load_bundled_worker()
    if recover_vss:
        worker._recover_vss_job(REPOSITORY_ROOT, job_id)
    else:
        worker._run_clone_job(REPOSITORY_ROOT, job_id)
    state = store_type(REPOSITORY_ROOT, protected=True).load()
    if not state or state.get("job_id") != job_id:
        return 20
    if recover_vss:
        return 0 if state.get("vss_recovery_required") is not True and state.get("snapshot_cleanup_confirmed") is True else 21
    return 0 if state.get("state") == "complete" else 21


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="LocalVaultCloneWorker", allow_abbrev=False)
    parser.add_argument("--job-id")
    parser.add_argument("--recover-vss", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--self-check", action="store_true", help=argparse.SUPPRESS)
    return parser


def _self_check() -> list[str]:
    if _normal(WORKER_EXE) != r"c:\programdata\l-vault\clone-runtime\localvaultcloneworker.exe":
        raise AssertionError("The fixed protected worker path changed.")
    if _normal(STATE_ROOT) != r"c:\programdata\l-vault\clone-state":
        raise AssertionError("The fixed protected state path changed.")
    if _normal(VSS_HELPER_EXE) != r"c:\programdata\l-vault\clone-runtime\lvaultvsssnapshot.exe":
        raise AssertionError("The fixed native VSS helper path changed.")
    if _normal(STATE_ROOT).startswith(_normal(REPOSITORY_ROOT) + os.sep):
        raise AssertionError("Worker state must not be under the repository.")
    if JOB_ID_RE.fullmatch("0123456789abcdef0123456789abcdef") is None:
        raise AssertionError("A valid job ID was rejected.")
    for bad in ("../0123456789abcdef0123456789abcdef", "0123456789ABCDEF0123456789ABCDEF", "g" * 32, ""):
        if JOB_ID_RE.fullmatch(bad):
            raise AssertionError("An unsafe job ID was accepted.")
    args = _build_parser().parse_args(["--job-id", "0123456789abcdef0123456789abcdef"])
    if args.job_id != "0123456789abcdef0123456789abcdef" or args.self_check or args.recover_vss:
        raise AssertionError("The job-ID-only runtime contract changed.")
    recovery_args = _build_parser().parse_args(["--job-id", "0123456789abcdef0123456789abcdef", "--recover-vss"])
    if recovery_args.job_id != "0123456789abcdef0123456789abcdef" or not recovery_args.recover_vss:
        raise AssertionError("The protected recovery operation contract changed.")
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            _build_parser().parse_args(["--root", str(REPOSITORY_ROOT), "--job-id", "0" * 32])
        except SystemExit:
            pass
        else:
            raise AssertionError("An arbitrary repository root was accepted.")
    checks = [
        "fixed ProgramData worker path",
        "fixed protected ProgramData state path",
        "strict job-ID validation",
        "no caller-supplied root, disk, or plan arguments",
        "bundled application imports only after runtime ACL validation",
    ]
    return checks


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.self_check:
        for check in _self_check():
            print(f"PASS {check}")
        return 0
    job_id = _validated_job_id(args.job_id)
    try:
        return _run_job(job_id, recover_vss=args.recover_vss)
    except BootstrapError:
        return 2
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
