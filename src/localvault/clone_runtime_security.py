"""Read-only verification of the privileged clone runtime's Windows trust boundary.

The capability gate and the elevated worker can both call
``verify_clone_runtime_security``. It verifies that an unelevated principal cannot
delete or replace the runtime through ProgramData, and that the L-vault child
trees have protected DACLs. It never creates directories, changes ACLs, or opens
any physical disk.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SYSTEM_DRIVE_ROOT = Path("C:\\")
PROGRAM_DATA = Path(r"C:\ProgramData")
APP_ROOT = PROGRAM_DATA / "L-vault"
RUNTIME_ROOT = APP_ROOT / "clone-runtime"
RUNTIME_TEMP = RUNTIME_ROOT / "Temp"
STATE_ROOT = APP_ROOT / "clone-state"
WORKER = RUNTIME_ROOT / "LocalVaultCloneWorker.exe"
VSS_HELPER = RUNTIME_ROOT / "LVaultVssSnapshot.exe"
OWNER_SID = STATE_ROOT / "owner.sid"
RUNTIME_MANIFEST = STATE_ROOT / "runtime-install.json"
RUNTIME_TRANSACTION = STATE_ROOT / "runtime-install-transaction.json"
# Optional release hardening. Local installs use protected SHA-256 pins; a
# publisher signature is enforced only when an L-vault publisher is configured.
CLONE_RUNTIME_SIGNER_THUMBPRINT: str | None = None
RUNTIME_MANIFEST_SCHEMA = 1
RUNTIME_VERSION = "1"
SHA256_RE = re.compile(r"[A-Fa-f0-9]{64}\Z")
SID_RE = re.compile(r"S-1-\d+(?:-\d+)+\Z")

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
TRUSTED_PARENT_OWNERS = {SYSTEM_SID, ADMINISTRATORS_SID, TRUSTED_INSTALLER_SID}
USERS_SID = "S-1-5-32-545"
CREATOR_OWNER_SID = "S-1-3-0"
OWNER_RIGHTS_SID = "S-1-3-4"
FULL_CONTROL_MASK = 0x001F01FF
READ_EXECUTE_MASK = 0x001200A9
OWNER_CONTROL_MASK = 0x000C0000  # WRITE_DAC | WRITE_OWNER
REPLACE_CHILD_MASK = (
    0x00000040  # FILE_DELETE_CHILD
    | 0x00010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | 0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
)
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
STANDARD_PRINCIPALS = {
    "S-1-1-0",  # Everyone
    "S-1-2-0",  # LOCAL
    "S-1-5-4",  # INTERACTIVE
    "S-1-5-7",  # ANONYMOUS LOGON
    "S-1-5-11",  # Authenticated Users
    "S-1-5-12",  # Restricted
    USERS_SID,
    "S-1-5-32-547",  # BUILTIN\Power Users
}
ALLOWED_CHILD_PRINCIPALS = {SYSTEM_SID, ADMINISTRATORS_SID, USERS_SID, OWNER_RIGHTS_SID}


@dataclass(frozen=True)
class CloneRuntimeSecurityReport:
    ready: bool
    issues: tuple[str, ...]
    evidence: dict[str, Any]
    installable: bool = False


def _system_powershell() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel.GetSystemDirectoryW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    function.restype = ctypes.c_uint32
    length = int(function(buffer, len(buffer)))
    if not length or length >= len(buffer):
        raise OSError("Windows system directory is unavailable")
    executable = Path(buffer.value) / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not executable.is_file():
        raise OSError("inbox Windows PowerShell is unavailable")
    return executable


def _query_acl_facts(paths: list[Path]) -> list[dict[str, Any]]:
    encoded_paths = base64.b64encode(json.dumps([str(path) for path in paths]).encode("utf-8")).decode("ascii")
    script = r"""
$ErrorActionPreference = 'Stop'
$callerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$paths = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('""" + encoded_paths + r"""')) | ConvertFrom-Json
function Test-AnyReparse([string]$path) {
    $full = [IO.Path]::GetFullPath($path)
    $root = [IO.Path]::GetPathRoot($full)
    $current = $root
    $relative = $full.Substring($root.Length)
    foreach ($part in @($relative -split '[\\/]+' | Where-Object { $_ })) {
        $current = Join-Path $current $part
        if (-not [IO.File]::Exists($current) -and -not [IO.Directory]::Exists($current)) { return $false }
        $component = Get-Item -LiteralPath $current -Force
        if (($component.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
    }
    return $false
}
$rows = foreach ($path in $paths) {
    if (Test-AnyReparse $path) {
        [pscustomobject]@{ path = $path; exists = $true; reparse = $true }
        continue
    }
    if (-not (Test-Path -LiteralPath $path)) {
        [pscustomobject]@{ path = $path; exists = $false }
        continue
    }
    $item = Get-Item -LiteralPath $path -Force
    $acl = Get-Acl -LiteralPath $path
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $access = foreach ($rule in $rules) {
        [pscustomobject]@{
            sid = $rule.IdentityReference.Value
            allow = ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)
            rights = [int64]$rule.FileSystemRights
            inherited = [bool]$rule.IsInherited
            inheritance = [string]$rule.InheritanceFlags
            propagation = [string]$rule.PropagationFlags
        }
    }
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    [pscustomobject]@{
        path = $item.FullName
        exists = $true
        caller_sid = $callerSid
        is_directory = [bool]$item.PSIsContainer
        reparse = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        protected = [bool]$acl.AreAccessRulesProtected
        owner_sid = $ownerSid
        rules = @($access)
    }
}
ConvertTo-Json -InputObject @($rows) -Depth 6 -Compress
"""
    command = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    executable = _system_powershell()
    system_directory = executable.parents[2]
    windows_directory = system_directory.parent
    environment = {
        "SystemRoot": str(windows_directory),
        "windir": str(windows_directory),
        "SystemDrive": windows_directory.anchor.rstrip("\\/"),
        "PATH": str(system_directory),
        "PSModulePath": str(executable.parent / "Modules"),
        "TEMP": str(windows_directory / "Temp"),
        "TMP": str(windows_directory / "Temp"),
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
        raise OSError("Windows ACL query failed")
    payload = json.loads(result.stdout)
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list) or len(payload) != len(paths):
        raise OSError("Windows returned incomplete ACL facts")
    return payload


def _is_inherit_only(rule: dict[str, Any]) -> bool:
    return "inheritonly" in str(rule.get("propagation", "")).replace("_", "").replace(" ", "").casefold()


def _applicable_rules(row: dict[str, Any]) -> list[dict[str, Any]]:
    return [rule for rule in row.get("rules", []) if not _is_inherit_only(rule)]


def _check_parent_acl(row: dict[str, Any], issues: list[str]) -> None:
    path = str(row.get("path", "Windows system ancestor"))
    if row.get("reparse"):
        issues.append(f"{path} is a reparse point")
    if row.get("is_directory") is not True:
        issues.append(f"{path} is not a directory")
    if str(row.get("owner_sid", "")) not in TRUSTED_PARENT_OWNERS:
        issues.append(f"{path} is not owned by a trusted Windows principal")
    rules = _applicable_rules(row)
    masks: dict[str, int] = {}
    for rule in rules:
        sid = str(rule.get("sid", ""))
        if sid == CREATOR_OWNER_SID and _is_inherit_only(rule):
            continue
        if sid == CREATOR_OWNER_SID:
            # Creator Owner is safe only when it applies to future children,
            # never to the ProgramData directory itself.
            issues.append(f"{path} has an effective Creator Owner ACE")
            continue
        if not rule.get("allow") and sid in STANDARD_PRINCIPALS:
            issues.append(f"{path} has a deny ACE for standard principal {sid}")
            continue
        if not rule.get("allow"):
            continue
        masks[sid] = masks.get(sid, 0) | int(rule.get("rights", 0))
    for sid in (SYSTEM_SID, ADMINISTRATORS_SID):
        if (masks.get(sid, 0) & FULL_CONTROL_MASK) != FULL_CONTROL_MASK:
            issues.append(f"{path} does not grant full control to {sid}")
    standard_mask = 0
    for sid in STANDARD_PRINCIPALS:
        standard_mask |= masks.get(sid, 0)
    dangerous_mask = REPLACE_CHILD_MASK
    for rule in rules:
        sid = str(rule.get("sid", ""))
        if (
            sid not in STANDARD_PRINCIPALS | {SYSTEM_SID, ADMINISTRATORS_SID, CREATOR_OWNER_SID}
            and rule.get("allow")
            and not _is_inherit_only(rule)
            and int(rule.get("rights", 0)) & dangerous_mask
        ):
            issues.append(f"{path} grants child-replacement rights to an unclassified principal")
    if standard_mask & dangerous_mask:
        issues.append(f"standard users can delete or replace children beneath {path}")
    if path.casefold() == str(PROGRAM_DATA).casefold() and (masks.get(USERS_SID, 0) & READ_EXECUTE_MASK) != READ_EXECUTE_MASK:
        issues.append("BUILTIN\\Users lack read/execute on C:\\ProgramData")


def _check_child_acl(row: dict[str, Any], issues: list[str]) -> None:
    path = str(row.get("path", "L-vault runtime path"))
    if row.get("reparse"):
        issues.append(f"{path} is a reparse point")
    if row.get("exists") is not True:
        issues.append(f"{path} is missing")
        return
    if row.get("protected") is not True:
        issues.append(f"{path} inherits an unverified DACL")
    rules = row.get("rules")
    if not isinstance(rules, list) or not rules:
        issues.append(f"{path} has no readable DACL")
        return
    masks: dict[str, int] = {}
    owner_deny = 0
    for rule in rules:
        sid = str(rule.get("sid", ""))
        if sid not in ALLOWED_CHILD_PRINCIPALS:
            issues.append(f"{path} has an unexpected ACE principal {sid}")
            continue
        mask = int(rule.get("rights", 0))
        if sid == OWNER_RIGHTS_SID:
            if rule.get("allow") or (mask & OWNER_CONTROL_MASK) != OWNER_CONTROL_MASK:
                issues.append(f"{path} does not deny owner DACL/owner changes")
            else:
                owner_deny |= mask
            continue
        if not rule.get("allow"):
            issues.append(f"{path} has an unexpected deny ACE for {sid}")
            continue
        masks[sid] = masks.get(sid, 0) | mask
    for sid in (SYSTEM_SID, ADMINISTRATORS_SID):
        if masks.get(sid, 0) & FULL_CONTROL_MASK != FULL_CONTROL_MASK:
            issues.append(f"{path} does not grant full control to {sid}")
    user_mask = masks.get(USERS_SID, 0)
    if user_mask & READ_EXECUTE_MASK != READ_EXECUTE_MASK or user_mask & UNSAFE_USER_WRITE_MASK:
        issues.append(f"{path} does not limit BUILTIN\\Users to read/execute")
    if (owner_deny & OWNER_CONTROL_MASK) != OWNER_CONTROL_MASK:
        owner_sid = str(row.get("owner_sid", ""))
        if owner_sid not in {SYSTEM_SID, ADMINISTRATORS_SID}:
            issues.append(f"{path} is owned by an unelevated principal without owner-rights protection")


def _signature_issues(rows: list[dict[str, Any]], expected_thumbprint: str | None = CLONE_RUNTIME_SIGNER_THUMBPRINT) -> list[str]:
    if expected_thumbprint is None or expected_thumbprint == "":
        return []
    if not re.fullmatch(r"[A-Fa-f0-9]{40}", expected_thumbprint):
        return ["the configured L-vault Authenticode thumbprint is invalid"]
    wanted = {str(WORKER).casefold(), str(VSS_HELPER).casefold()}
    observed = {
        str(row.get("path", "")).casefold(): row
        for row in rows
        if isinstance(row, dict)
    }
    issues: list[str] = []
    for path in sorted(wanted):
        row = observed.get(path)
        if row is None:
            issues.append(f"runtime signature evidence is missing: {path}")
            continue
        if str(row.get("status", "")).casefold() != "valid":
            issues.append(f"runtime Authenticode signature is not valid: {path}")
        actual = re.sub(r"\s+", "", str(row.get("thumbprint", ""))).upper()
        if actual != expected_thumbprint.upper():
            issues.append(f"runtime signer does not match the pinned L-vault publisher: {path}")
    if set(observed) != wanted:
        issues.append("Authenticode query returned an unexpected runtime file set")
    return issues


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_issues(
    value: Any,
    *,
    caller_sid: str,
    owner_sid: str,
    worker_sha256: str,
    vss_helper_sha256: str,
    expected_signer: str | None = CLONE_RUNTIME_SIGNER_THUMBPRINT,
) -> list[str]:
    if not isinstance(value, dict):
        return ["the protected clone runtime manifest is malformed"]
    issues: list[str] = []
    if type(value.get("schema")) is not int or value.get("schema") != RUNTIME_MANIFEST_SCHEMA:
        issues.append("the protected clone runtime manifest schema is unsupported")
    manifest_sid = str(value.get("owner_sid", ""))
    if not SID_RE.fullmatch(manifest_sid) or manifest_sid.casefold() != caller_sid.casefold() or manifest_sid.casefold() != owner_sid.casefold():
        issues.append("the protected clone runtime is bound to a different Windows owner")
    if str(value.get("worker_path", "")).casefold() != str(WORKER).casefold():
        issues.append("the protected clone runtime manifest names an unexpected worker path")
    if str(value.get("vss_helper_path", "")).casefold() != str(VSS_HELPER).casefold():
        issues.append("the protected clone runtime manifest names an unexpected VSS helper path")
    for key, actual in (("worker_sha256", worker_sha256), ("vss_helper_sha256", vss_helper_sha256)):
        expected = value.get(key)
        if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected) or expected.casefold() != actual.casefold():
            issues.append(f"the installed clone runtime {key.removesuffix('_sha256')} bytes do not match the protected manifest")
    if str(value.get("runtime_version", "")) != RUNTIME_VERSION:
        issues.append("the protected clone runtime version is unsupported")
    if not isinstance(value.get("source_commit"), str) or len(value["source_commit"]) > 80:
        issues.append("the protected clone runtime build identifier is malformed")
    if not isinstance(value.get("installed_at_utc"), str) or not value["installed_at_utc"].strip():
        issues.append("the protected clone runtime installation time is missing")
    authenticode = value.get("authenticode")
    if not isinstance(authenticode, dict):
        issues.append("the protected clone runtime trust metadata is malformed")
    elif expected_signer:
        if authenticode.get("policy") != "pinned_publisher" or str(authenticode.get("thumbprint", "")).replace(" ", "").upper() != expected_signer.upper():
            issues.append("the protected clone runtime publisher metadata does not match the configured pin")
    elif authenticode.get("policy") != "local_integrity_pinned" or authenticode.get("thumbprint") is not None:
        issues.append("the protected clone runtime does not declare the expected local integrity trust mode")
    return issues


def _read_protected_manifest() -> dict[str, Any]:
    size = RUNTIME_MANIFEST.stat().st_size
    if size < 2 or size > 16 * 1024:
        raise OSError("protected clone runtime manifest has an invalid size")
    value = json.loads(RUNTIME_MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise OSError("protected clone runtime manifest is not an object")
    return value


def _query_signature_facts() -> list[dict[str, Any]]:
    files = [WORKER, VSS_HELPER]
    encoded_paths = base64.b64encode(json.dumps([str(path) for path in files]).encode("utf-8")).decode("ascii")
    script = r"""
$ErrorActionPreference = 'Stop'
$paths = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('""" + encoded_paths + r"""')) | ConvertFrom-Json
$rows = foreach ($path in $paths) {
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    [pscustomobject]@{
        path = [IO.Path]::GetFullPath($path)
        status = [string]$signature.Status
        thumbprint = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Thumbprint } else { '' }
    }
}
ConvertTo-Json -InputObject @($rows) -Depth 4 -Compress
"""
    command = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    executable = _system_powershell()
    system_directory = executable.parents[2]
    windows_directory = system_directory.parent
    environment = {
        "SystemRoot": str(windows_directory),
        "windir": str(windows_directory),
        "SystemDrive": windows_directory.anchor.rstrip("\\/"),
        "PATH": str(system_directory),
        "PSModulePath": str(executable.parent / "Modules"),
        "TEMP": str(windows_directory / "Temp"),
        "TMP": str(windows_directory / "Temp"),
    }
    result = subprocess.run(
        [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        cwd=str(executable.parent),
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise OSError("Authenticode runtime validation failed")
    payload = json.loads(result.stdout)
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list) or len(payload) != len(files):
        raise OSError("Windows returned incomplete Authenticode evidence")
    return payload


def verify_clone_runtime_security() -> CloneRuntimeSecurityReport:
    """Freshly audit fixed ProgramData ancestry and runtime ACLs, read-only."""
    if os.name != "nt":
        return CloneRuntimeSecurityReport(False, ("Windows clone runtime requires Windows",), {})
    paths = [SYSTEM_DRIVE_ROOT, PROGRAM_DATA, APP_ROOT, RUNTIME_ROOT, RUNTIME_TEMP, STATE_ROOT, WORKER, VSS_HELPER, OWNER_SID, RUNTIME_MANIFEST, RUNTIME_TRANSACTION]
    try:
        rows = _query_acl_facts(paths)
    except Exception as exc:
        return CloneRuntimeSecurityReport(False, (f"Windows ACL query failed ({type(exc).__name__})",), {})
    hard_issues: list[str] = []
    runtime_issues: list[str] = []
    evidence: dict[str, Any] = {}
    for row in rows[:2]:
        if row.get("exists") is not True:
            hard_issues.append(f"{row.get('path')} is missing")
        else:
            _check_parent_acl(row, hard_issues)
            evidence[f"{row.get('path')}_owner_sid"] = row.get("owner_sid")
            evidence[f"{row.get('path')}_standard_users_can_replace_child"] = any(
                rule.get("allow")
                and not _is_inherit_only(rule)
                and str(rule.get("sid", "")) in STANDARD_PRINCIPALS
                and (int(rule.get("rights", 0)) & REPLACE_CHILD_MASK) != 0
                for rule in row.get("rules", [])
            )
    for row in rows[2:]:
        if row.get("exists") is not True:
            if str(row.get("path", "")).casefold() == str(RUNTIME_TRANSACTION).casefold():
                continue
            runtime_issues.append(f"{row.get('path')} is missing")
            continue
        _check_child_acl(row, hard_issues)
        if str(row.get("path", "")).casefold() == str(RUNTIME_TRANSACTION).casefold():
            runtime_issues.append("a prior runtime installation needs recovery")
        evidence[str(row.get("path", "unknown"))] = {
            "exists": row.get("exists"),
            "owner_sid": row.get("owner_sid"),
            "dacl_protected": row.get("protected"),
            "reparse": row.get("reparse"),
        }
    caller_sid = str(rows[0].get("caller_sid", "")) if rows else ""
    evidence["caller_sid"] = caller_sid
    if not SID_RE.fullmatch(caller_sid):
        hard_issues.append("Windows did not return the current owner SID")
    owner_sid = ""
    try:
        if OWNER_SID.is_file():
            owner_sid = OWNER_SID.read_text(encoding="ascii").strip()
            if not SID_RE.fullmatch(owner_sid) or owner_sid.casefold() != caller_sid.casefold():
                hard_issues.append("the protected clone runtime belongs to a different Windows owner")
        else:
            runtime_issues.append("the protected clone runtime owner binding is missing")
    except (OSError, UnicodeError):
        hard_issues.append("the protected clone runtime owner binding is unreadable")
    if not hard_issues and WORKER.is_file() and VSS_HELPER.is_file() and RUNTIME_MANIFEST.is_file():
        try:
            manifest = _read_protected_manifest()
            worker_hash = _sha256_file(WORKER)
            helper_hash = _sha256_file(VSS_HELPER)
            manifest_issues = _manifest_issues(
                manifest,
                caller_sid=caller_sid,
                owner_sid=owner_sid,
                worker_sha256=worker_hash,
                vss_helper_sha256=helper_hash,
            )
            runtime_issues.extend(manifest_issues)
            if CLONE_RUNTIME_SIGNER_THUMBPRINT:
                runtime_issues.extend(_signature_issues(_query_signature_facts()))
            if not manifest_issues:
                evidence["runtime_trust"] = "pinned_publisher" if CLONE_RUNTIME_SIGNER_THUMBPRINT else "local_integrity_pinned"
                evidence["worker_sha256"] = worker_hash
                evidence["vss_helper_sha256"] = helper_hash
        except Exception as exc:
            runtime_issues.append(f"protected clone runtime verification failed ({type(exc).__name__})")
    else:
        runtime_issues.append("the protected clone worker, VSS requester, or installation manifest is missing")
    unique_issues = tuple(dict.fromkeys((*hard_issues, *runtime_issues)))
    evidence["runtime_trust"] = evidence.get("runtime_trust", "installation_required")
    return CloneRuntimeSecurityReport(not unique_issues, unique_issues, evidence, installable=not hard_issues)


def require_clone_runtime_security() -> CloneRuntimeSecurityReport:
    """Raise a stable error if the protected worker runtime cannot be trusted."""
    report = verify_clone_runtime_security()
    if not report.ready:
        raise RuntimeError("; ".join(report.issues))
    return report
