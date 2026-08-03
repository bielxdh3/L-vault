"""Non-destructive Clonezilla runtime contracts and disposable-channel fixtures.

This module owns the phase boundary between Windows preparation and a future
Clonezilla Live session.  It can inspect files and synthetic inventory only;
there is deliberately no production runner capable of invoking a clone
engine, mounting media, or opening a block device.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from posixpath import normpath
from typing import Any, Callable, Iterable

from .locks import BackupLock
from .offline_clone import (
    OFFLINE_ENGINE,
    OFFLINE_ENGINE_VERSION,
    OFFLINE_JOB_SCHEMA,
    OFFLINE_RESULT_SCHEMA,
    FakeDetachedSigner,
    FakeDetachedVerifier,
    FakeOfflineInventory,
    OfflineBlockDevice,
    OfflineCloneBlocked,
    OfflineJob,
    OfflineResult,
    OfflineResultStore,
    SignatureVerificationEvidence,
    ClonezillaCommandRenderer,
    build_fake_result,
    build_offline_job,
    canonical_json,
    resolve_offline_devices,
)
from .utils import atomic_write_bytes, sha256_file


RUNTIME_MANIFEST_SCHEMA = 2
RUNTIME_MANIFEST_FILE = "runtime-manifest.json"
RUNTIME_MANIFEST_SIGNATURE = "runtime-manifest.sig"
EXTRACTION_MANIFEST_SCHEMA = 1
EXTRACTION_MANIFEST_FILE = "extraction-manifest.json"
EXTRACTION_MANIFEST_SIGNATURE = "extraction-manifest.sig"
RETURN_CHANNEL_SCHEMA = 1
RETURN_CHANNEL_META = "channel.json"
RETURN_CHANNEL_SIGNATURE = "channel.sig"
RETURN_STATES = frozenset({"pending", "running", "result", "failed", "consumed"})
RETURN_TRANSITIONS = {
    "pending": frozenset({"running", "failed"}),
    "running": frozenset({"result", "failed"}),
    "result": frozenset({"consumed", "failed"}),
    "failed": frozenset(),
    "consumed": frozenset(),
}
REQUIRED_RUNTIME_TOOLS = (
    "gpg",
    "gpgv",
    "sha256sum",
    "lsblk",
    "blkid",
    "udevadm",
    "findmnt",
    "ocs-onthefly",
)
CLONEZILLA_SIGNER_FINGERPRINT = "54C0821A48715DAFD61BFCAF667857D045599AFD"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX_FINGERPRINT = re.compile(r"^[0-9A-F]{40,64}$")
_JOB_ID = re.compile(r"^[0-9a-f]{32}$")
_SAFE_FILENAME = re.compile(r"^[^\\/:\x00-\x1f\x7f]+$")
_EXTRACTION_METHODS = frozenset({"clonezilla-iso-extract-v1", "synthetic-test-fixture-v1"})
_OVERLAY_NAMES = frozenset({"upper", "upperdir", "work", "overlay", "cow"})
_MAX_TOOL_BYTES = 64 * 1024 * 1024
_MAX_INVENTORY_FILE_BYTES = 4 * 1024 * 1024 * 1024
_TOOL_PATH_ALLOWLIST = {
    name: frozenset(f"{directory}/{name}" for directory in ("bin", "sbin", "usr/bin", "usr/sbin"))
    for name in REQUIRED_RUNTIME_TOOLS
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_text(value: Any, *, field: str, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length or any(ord(char) < 32 for char in value):
        raise OfflineCloneBlocked(f"offline runtime {field} is not safely bounded", "offline_verification_failed")
    return value


def _safe_provenance(value: Any) -> str:
    text = _safe_text(value, field="ISO provenance")
    if text.startswith(("https://", "http://")):
        return text
    if re.search(r"(?:^[A-Za-z]:[\\/]|^\\\\|[A-Za-z]:[\\/])", text):
        raise OfflineCloneBlocked("offline ISO provenance contains a private path", "offline_verification_failed")
    return text


def _safe_filename(value: Any, *, field: str) -> str:
    text = _safe_text(value, field=field, max_length=255)
    if text in {".", ".."} or not _SAFE_FILENAME.fullmatch(text):
        raise OfflineCloneBlocked(f"offline runtime {field} is not a safe filename", "offline_verification_failed")
    return text


def _safe_relative_path(value: Any) -> str:
    text = _safe_text(value, field="extraction manifest path", max_length=512)
    if "\\" in text or text.startswith("/") or text.endswith("/") or normpath(text) != text:
        raise OfflineCloneBlocked("offline extraction manifest path is not normalized", "offline_verification_failed")
    parts = text.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise OfflineCloneBlocked("offline extraction manifest path escapes the extracted root", "offline_verification_failed")
    return text


def _read_json(path: Path, *, max_bytes: int = 256 * 1024) -> tuple[bytes, dict[str, Any]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise OfflineCloneBlocked("offline runtime package is unsafe or oversized", "offline_verification_failed")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OfflineCloneBlocked("offline runtime package is not valid UTF-8 JSON", "offline_verification_failed") from exc
    if not isinstance(value, dict):
        raise OfflineCloneBlocked("offline runtime package manifest is not an object", "offline_verification_failed")
    return raw, value


def _fsync_file(path: Path, data: bytes) -> None:
    with path.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


@dataclass(frozen=True)
class OfflineRuntimeManifest:
    artifact: "RuntimeArtifactEvidence" = field(default_factory=lambda: RuntimeArtifactEvidence())
    iso_provenance: str = "not-present"
    job_schema: int = OFFLINE_JOB_SCHEMA
    result_schema: int = OFFLINE_RESULT_SCHEMA
    engine: str = OFFLINE_ENGINE
    renderer_policy: str = "ocs-onthefly allowlist; argv only; batch disabled; never executed"
    return_channel_type: str = "temporary_directory_fixture"
    secure_boot_status: str = "documented_only_physically_unvalidated"
    vm_boot_completed: bool = False
    physical_boot_completed: bool = False
    schema: int = RUNTIME_MANIFEST_SCHEMA

    def payload(self) -> dict[str, Any]:
        value = asdict(self)
        value["artifact"]["required_tools"] = {key: dict(value["artifact"]["required_tools"][key]) for key in sorted(value["artifact"]["required_tools"])}
        return value

    def validate(self) -> None:
        if self.schema != RUNTIME_MANIFEST_SCHEMA:
            raise OfflineCloneBlocked("offline runtime manifest schema is not allowlisted", "offline_verification_failed")
        if not isinstance(self.artifact, RuntimeArtifactEvidence):
            raise OfflineCloneBlocked("offline runtime artifact evidence is invalid", "offline_verification_failed")
        self.artifact.validate()
        _safe_provenance(self.iso_provenance)
        if self.engine != OFFLINE_ENGINE or self.job_schema != OFFLINE_JOB_SCHEMA or self.result_schema != OFFLINE_RESULT_SCHEMA:
            raise OfflineCloneBlocked("offline runtime contract versions do not match", "offline_verification_failed")
        if self.return_channel_type not in {"temporary_directory_fixture", "disposable_image_fixture", "dedicated_fat_exchange_future"}:
            raise OfflineCloneBlocked("offline return-channel type is invalid", "offline_verification_failed")
        if self.secure_boot_status not in {"documented_only_physically_unvalidated", "virtually_tested_physically_unvalidated"}:
            raise OfflineCloneBlocked("offline Secure Boot status is invalid", "offline_verification_failed")
        if self.physical_boot_completed:
            raise OfflineCloneBlocked("physical boot cannot be marked complete in this phase", "offline_execution_disabled")
        if type(self.vm_boot_completed) is not bool or type(self.physical_boot_completed) is not bool:
            raise OfflineCloneBlocked("offline runtime boot flags are invalid", "offline_verification_failed")
        if self.vm_boot_completed:
            raise OfflineCloneBlocked("VM boot cannot be marked complete without an isolated boot record", "offline_verification_failed")

    def canonical_bytes(self) -> bytes:
        self.validate()
        return canonical_json(self.payload())

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "OfflineRuntimeManifest":
        required = set(asdict(cls()).keys())
        if set(value) != required:
            raise OfflineCloneBlocked("offline runtime manifest fields are invalid", "offline_verification_failed")
        artifact_value = value.get("artifact")
        if not isinstance(artifact_value, dict):
            raise OfflineCloneBlocked("offline runtime artifact evidence is invalid", "offline_verification_failed")
        manifest = cls(artifact=RuntimeArtifactEvidence.from_dict(artifact_value), iso_provenance=value["iso_provenance"], job_schema=value["job_schema"], result_schema=value["result_schema"], engine=value["engine"], renderer_policy=value["renderer_policy"], return_channel_type=value["return_channel_type"], secure_boot_status=value["secure_boot_status"], vm_boot_completed=value["vm_boot_completed"], physical_boot_completed=value["physical_boot_completed"], schema=value["schema"])
        manifest.validate()
        return manifest


@dataclass(frozen=True)
class RuntimeExtractionManifest:
    source_iso_filename: str
    source_iso_sha256: str
    extraction_method: str
    inventory_sha256: str
    files: tuple[dict[str, Any], ...]
    schema: int = EXTRACTION_MANIFEST_SCHEMA

    def payload(self) -> dict[str, Any]:
        return {"schema": self.schema, "source_iso_filename": self.source_iso_filename, "source_iso_sha256": self.source_iso_sha256, "extraction_method": self.extraction_method, "inventory_sha256": self.inventory_sha256, "files": [dict(entry) for entry in self.files]}

    def validate(self) -> None:
        if self.schema != EXTRACTION_MANIFEST_SCHEMA:
            raise OfflineCloneBlocked("offline extraction manifest schema is invalid", "offline_verification_failed")
        _safe_filename(self.source_iso_filename, field="extraction source ISO filename")
        if not _HEX64.fullmatch(self.source_iso_sha256):
            raise OfflineCloneBlocked("offline extraction source ISO digest is invalid", "offline_verification_failed")
        if self.extraction_method not in _EXTRACTION_METHODS:
            raise OfflineCloneBlocked("offline extraction method is not allowlisted", "offline_verification_failed")
        if not _HEX64.fullmatch(self.inventory_sha256):
            raise OfflineCloneBlocked("offline extraction inventory digest is invalid", "offline_verification_failed")
        previous = ""
        for entry in self.files:
            if not isinstance(entry, dict) or set(entry) != {"path", "file_type", "size", "sha256", "executable"}:
                raise OfflineCloneBlocked("offline extraction file evidence is incomplete", "offline_verification_failed")
            path = _safe_relative_path(entry["path"])
            if path <= previous:
                raise OfflineCloneBlocked("offline extraction file inventory is not canonically ordered", "offline_verification_failed")
            previous = path
            if entry["file_type"] != "regular" or type(entry["size"]) is not int or not 0 <= entry["size"] <= _MAX_INVENTORY_FILE_BYTES:
                raise OfflineCloneBlocked("offline extraction file evidence is unsafe", "offline_verification_failed")
            if not _HEX64.fullmatch(entry["sha256"]) or type(entry["executable"]) is not bool:
                raise OfflineCloneBlocked("offline extraction file evidence is invalid", "offline_verification_failed")
        if hashlib.sha256(canonical_json([dict(entry) for entry in self.files])).hexdigest() != self.inventory_sha256:
            raise OfflineCloneBlocked("offline extraction inventory digest does not match its files", "offline_verification_failed")

    def canonical_bytes(self) -> bytes:
        self.validate()
        return canonical_json(self.payload())

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RuntimeExtractionManifest":
        required = {"schema", "source_iso_filename", "source_iso_sha256", "extraction_method", "inventory_sha256", "files"}
        if set(value) != required or not isinstance(value.get("files"), list):
            raise OfflineCloneBlocked("offline extraction manifest fields are invalid", "offline_verification_failed")
        manifest = cls(source_iso_filename=value["source_iso_filename"], source_iso_sha256=value["source_iso_sha256"], extraction_method=value["extraction_method"], inventory_sha256=value["inventory_sha256"], files=tuple(value["files"]), schema=value["schema"])
        manifest.validate()
        return manifest


def _missing_tool() -> dict[str, Any]:
    return {"present": False, "status": "missing", "path": "", "file_type": "missing", "size": 0, "sha256": "", "executable": False}


@dataclass(frozen=True)
class RuntimeArtifactEvidence:
    clonezilla_release: str = OFFLINE_ENGINE_VERSION
    architecture: str = "amd64"
    iso_filename: str = ""
    iso_sha256: str = ""
    official_checksum_manifest_sha256: str = ""
    official_checksum_signature_state: str = "missing"
    official_checksum_signature_verified: bool = False
    signer_fingerprint: str = ""
    keyring_sha256: str = ""
    extraction_manifest_schema: int = 0
    extraction_method: str = ""
    extraction_manifest_sha256: str = ""
    extraction_inventory_sha256: str = ""
    extraction_signature_verified: bool = False
    required_tools: dict[str, dict[str, Any]] = field(default_factory=dict)

    def validate(self) -> None:
        if self.clonezilla_release != OFFLINE_ENGINE_VERSION or self.architecture not in {"amd64", "x86_64"}:
            raise OfflineCloneBlocked("offline runtime artifact release or architecture is not allowlisted", "offline_verification_failed")
        if self.iso_filename:
            _safe_filename(self.iso_filename, field="runtime ISO filename")
        for field_name in ("iso_sha256", "official_checksum_manifest_sha256", "keyring_sha256", "extraction_manifest_sha256", "extraction_inventory_sha256"):
            value = getattr(self, field_name)
            if value and not _HEX64.fullmatch(value):
                raise OfflineCloneBlocked(f"offline runtime {field_name} is invalid", "offline_verification_failed")
        if self.signer_fingerprint and not _HEX_FINGERPRINT.fullmatch(self.signer_fingerprint):
            raise OfflineCloneBlocked("offline runtime signer fingerprint is invalid", "offline_verification_failed")
        if self.official_checksum_signature_state not in {"missing", "verified", "invalid"}:
            raise OfflineCloneBlocked("offline runtime checksum signature state is invalid", "offline_verification_failed")
        if type(self.official_checksum_signature_verified) is not bool or type(self.extraction_signature_verified) is not bool:
            raise OfflineCloneBlocked("offline runtime signature evidence is invalid", "offline_verification_failed")
        if self.official_checksum_signature_verified != (self.official_checksum_signature_state == "verified" and bool(self.official_checksum_manifest_sha256)):
            raise OfflineCloneBlocked("offline runtime checksum signature evidence is inconsistent", "offline_verification_failed")
        if self.extraction_manifest_schema not in {0, EXTRACTION_MANIFEST_SCHEMA}:
            raise OfflineCloneBlocked("offline runtime extraction manifest schema is invalid", "offline_verification_failed")
        if self.extraction_method and self.extraction_method not in _EXTRACTION_METHODS:
            raise OfflineCloneBlocked("offline runtime extraction method is invalid", "offline_verification_failed")
        if set(self.required_tools) != set(REQUIRED_RUNTIME_TOOLS):
            raise OfflineCloneBlocked("offline runtime tool evidence has unexpected entries", "offline_verification_failed")
        for name in REQUIRED_RUNTIME_TOOLS:
            entry = self.required_tools.get(name)
            if not isinstance(entry, dict) or set(entry) != {"present", "status", "path", "file_type", "size", "sha256", "executable"}:
                raise OfflineCloneBlocked("offline runtime tool evidence is incomplete", "offline_verification_failed")
            if type(entry["present"]) is not bool or entry["status"] not in {"missing", "blocked", "present_unexecuted"} or type(entry["executable"]) is not bool:
                raise OfflineCloneBlocked("offline runtime tool evidence is invalid", "offline_verification_failed")
            if type(entry["size"]) is not int or not 0 <= entry["size"] <= _MAX_TOOL_BYTES:
                raise OfflineCloneBlocked("offline runtime tool size is invalid", "offline_verification_failed")
            if entry["path"]:
                if not entry["path"].startswith("/") or "\\" in entry["path"] or ":" in entry["path"]:
                    raise OfflineCloneBlocked("offline runtime tool path is not a sanitized image path", "offline_verification_failed")
            if entry["sha256"] and not _HEX64.fullmatch(entry["sha256"]):
                raise OfflineCloneBlocked("offline runtime tool digest is invalid", "offline_verification_failed")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RuntimeArtifactEvidence":
        if set(value) != set(asdict(cls()).keys()):
            raise OfflineCloneBlocked("offline runtime artifact evidence fields are invalid", "offline_verification_failed")
        evidence = cls(**value)
        evidence.validate()
        return evidence


class RuntimeManifestStore:
    def __init__(self, root: Path):
        self.root = Path(root)

    def create(self, manifest: OfflineRuntimeManifest, signer: Any) -> Path:
        manifest.validate()
        destination = self.root / "runtime-manifest"
        if destination.exists():
            raise OfflineCloneBlocked("offline runtime manifest already exists", "offline_verification_failed")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=".runtime-manifest-", dir=destination.parent))
        try:
            raw = manifest.canonical_bytes()
            _fsync_file(temporary / RUNTIME_MANIFEST_FILE, raw)
            _fsync_file(temporary / RUNTIME_MANIFEST_SIGNATURE, signer.sign(raw))
            os.replace(temporary, destination)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return destination

    def load(self, path: Path, verifier: Any) -> OfflineRuntimeManifest:
        path = Path(path)
        if path.is_symlink() or not path.is_dir() or set(item.name for item in path.iterdir()) != {RUNTIME_MANIFEST_FILE, RUNTIME_MANIFEST_SIGNATURE}:
            raise OfflineCloneBlocked("offline runtime manifest package is unsafe or incomplete", "offline_verification_failed")
        if any((path / name).is_symlink() for name in (RUNTIME_MANIFEST_FILE, RUNTIME_MANIFEST_SIGNATURE)):
            raise OfflineCloneBlocked("offline runtime manifest package contains a symlink", "offline_verification_failed")
        raw, value = _read_json(path / RUNTIME_MANIFEST_FILE)
        manifest = OfflineRuntimeManifest.from_dict(value)
        signature = (path / RUNTIME_MANIFEST_SIGNATURE).read_bytes()
        if raw != manifest.canonical_bytes() or not verifier.verify(raw, signature):
            raise OfflineCloneBlocked("offline runtime manifest signature is invalid", "offline_verification_failed")
        return manifest


@dataclass(frozen=True)
class RuntimeReadinessReport:
    state: str
    blockers: tuple[str, ...]
    evidence: dict[str, Any]
    manifest: OfflineRuntimeManifest

    def payload(self) -> dict[str, Any]:
        return {"state": self.state, "blockers": list(self.blockers), "evidence": self.evidence, "manifest": self.manifest.payload()}


class OfflineRuntimeValidator:
    """Inspect only a supplied, cryptographically bound ISO/tree; never boots it."""

    def __init__(self, *, expected_release: str = OFFLINE_ENGINE_VERSION, expected_iso_sha256: str = "482518ea32af3b82ed15d09e2e7714806775deb62aeed81491e534f6cc6bbc47"):
        self.expected_release = expected_release
        self.expected_iso_sha256 = expected_iso_sha256.lower()

    @staticmethod
    def _scan_tree(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
        inventory: list[dict[str, Any]] = []
        blockers: list[str] = []

        def visit(directory: Path, prefix: str = "") -> None:
            try:
                entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
            except OSError:
                blockers.append("extracted_tree_unreadable")
                return
            for entry in entries:
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                if entry.name.casefold() in _OVERLAY_NAMES or any(part.casefold() in _OVERLAY_NAMES for part in relative.split("/")):
                    blockers.append("unexpected_writable_overlay")
                if entry.is_symlink():
                    blockers.append("symlink_present")
                    if entry.name.casefold() in {name.casefold() for name in REQUIRED_RUNTIME_TOOLS}:
                        blockers.append(f"symlinked_tool:{entry.name.casefold()}")
                    continue
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    blockers.append("extracted_tree_entry_unreadable")
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if entry.name.casefold() in {name.casefold() for name in REQUIRED_RUNTIME_TOOLS}:
                        blockers.append(f"non_regular_tool:{entry.name.casefold()}")
                    visit(Path(entry.path), relative)
                elif stat.S_ISREG(info.st_mode):
                    try:
                        digest = sha256_file(Path(entry.path))
                    except OSError:
                        blockers.append("extracted_tree_entry_unreadable")
                        continue
                    inventory.append({"path": relative, "file_type": "regular", "size": info.st_size, "sha256": digest, "executable": bool(info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))})
                else:
                    blockers.append("non_regular_tree_entry")
                    if entry.name.casefold() in {name.casefold() for name in REQUIRED_RUNTIME_TOOLS}:
                        blockers.append(f"non_regular_tool:{entry.name.casefold()}")

        visit(root)
        inventory.sort(key=lambda entry: entry["path"])
        return inventory, sorted(set(blockers))

    @staticmethod
    def _check_tree(root: Path, extraction: RuntimeExtractionManifest | None) -> tuple[dict[str, dict[str, Any]], list[str]]:
        tools = {name: _missing_tool() for name in REQUIRED_RUNTIME_TOOLS}
        if root.is_symlink() or not root.is_dir():
            return tools, ["extracted_tree_missing"]
        actual, blockers = OfflineRuntimeValidator._scan_tree(root)
        actual_payload = [dict(entry) for entry in actual]
        if extraction is None:
            return tools, sorted(set((*blockers, "extracted_tree_binding_missing")))
        expected_payload = [dict(entry) for entry in extraction.files]
        if extraction.extraction_method == "synthetic-test-fixture-v1":
            actual_by_path = {entry["path"]: entry for entry in actual_payload}
            for expected in expected_payload:
                actual_entry = actual_by_path.get(expected["path"])
                if actual_entry and not actual_entry["executable"] and expected["executable"]:
                    actual_entry["executable"] = True
        if actual_payload != expected_payload:
            actual_by_path = {entry["path"]: entry for entry in actual_payload}
            expected_by_path = {entry["path"]: entry for entry in expected_payload}
            if set(actual_by_path) != set(expected_by_path):
                blockers.append("extracted_tree_inventory_mismatch")
            if any(actual_by_path.get(path) != expected_by_path.get(path) for path in set(actual_by_path) & set(expected_by_path)):
                blockers.append("extracted_tree_file_digest_mismatch")
        actual_digest = hashlib.sha256(canonical_json(actual_payload)).hexdigest()
        if actual_digest != extraction.inventory_sha256:
            blockers.append("extracted_tree_inventory_digest_mismatch")
        for name in REQUIRED_RUNTIME_TOOLS:
            candidates = [entry for entry in actual_payload if Path(entry["path"]).name.casefold() == name.casefold()]
            acceptable = [entry for entry in candidates if entry["path"] in _TOOL_PATH_ALLOWLIST[name]]
            if any(entry not in acceptable for entry in candidates):
                blockers.append(f"tool_path_not_allowlisted:{name}")
            if len(acceptable) == 0:
                blockers.append(f"missing_tool:{name}")
                continue
            if len(acceptable) != 1:
                blockers.append(f"ambiguous_tool:{name}")
                continue
            entry = acceptable[0]
            tool = {"present": True, "status": "present_unexecuted", "path": "/" + entry["path"], "file_type": entry["file_type"], "size": entry["size"], "sha256": entry["sha256"], "executable": entry["executable"]}
            if entry["size"] == 0:
                blockers.append(f"empty_tool:{name}")
                tool["status"] = "blocked"
            if entry["size"] > _MAX_TOOL_BYTES:
                blockers.append(f"oversized_tool:{name}")
                tool["status"] = "blocked"
            if not entry["executable"]:
                blockers.append(f"non_executable_tool:{name}")
                tool["status"] = "blocked"
            tools[name] = tool
        return tools, sorted(set(blockers))

    @staticmethod
    def _verifier_evidence(verifier: Any) -> SignatureVerificationEvidence:
        try:
            evidence = verifier.verification_evidence
        except (AttributeError, OfflineCloneBlocked) as exc:
            raise OfflineCloneBlocked("detached verifier did not expose derived key evidence", "offline_verification_failed") from exc
        if not isinstance(evidence, SignatureVerificationEvidence):
            raise OfflineCloneBlocked("detached verifier evidence has an invalid type", "offline_verification_failed")
        if not _HEX_FINGERPRINT.fullmatch(evidence.pinned_fingerprint) or not _HEX64.fullmatch(evidence.keyring_sha256):
            raise OfflineCloneBlocked("detached verifier evidence is invalid", "offline_verification_failed")
        return evidence

    def validate(
        self,
        *,
        iso_path: Path | None = None,
        extracted_tree: Path | None = None,
        checksums_path: Path | None = None,
        checksums_signature: bytes | None = None,
        verifier: Any | None = None,
        extraction_manifest_path: Path | None = None,
        extraction_manifest_signature: bytes | None = None,
        provenance: str = "official-artifact-not-present",
        architecture: str = "amd64",
        vm_boot_completed: bool = False,
    ) -> RuntimeReadinessReport:
        blockers: list[str] = []
        evidence: dict[str, Any] = {"iso_present": False, "iso_signature_verified": False, "checksum_signature_verified": False, "verifier_fingerprint_derived": False, "keyring_sha256_derived": False, "extracted_tree_binding_verified": False, "required_tools_static_only": True, "vm_boot_completed": False, "physical_boot_completed": False}
        iso_digest = ""
        iso_name = Path(iso_path).name if iso_path else ""
        checksum_digest = ""
        checksum_signature_state = "missing"
        verifier_evidence: SignatureVerificationEvidence | None = None
        extraction: RuntimeExtractionManifest | None = None
        if self.expected_release != OFFLINE_ENGINE_VERSION:
            blockers.append("pinned_release_changed_without_compatibility_decision")
        if iso_path is None:
            blockers.append("official_iso_missing")
        else:
            iso = Path(iso_path)
            if iso.is_symlink() or not iso.is_file():
                blockers.append("official_iso_unsafe_or_missing")
            else:
                evidence["iso_present"] = True
                iso_digest = sha256_file(iso)
                try:
                    iso_name = _safe_filename(iso.name, field="ISO filename")
                except OfflineCloneBlocked as exc:
                    blockers.append(exc.reason)
                evidence["iso_sha256"] = iso_digest
                if iso_digest != self.expected_iso_sha256:
                    blockers.append("iso_checksum_mismatch")
                if checksums_path is None:
                    blockers.append("official_checksum_manifest_missing")
                elif checksums_signature is None or verifier is None:
                    blockers.append("official_checksum_signature_missing")
                else:
                    try:
                        checksum_file = Path(checksums_path)
                        if checksum_file.is_symlink() or not checksum_file.is_file() or checksum_file.stat().st_size > 1024 * 1024:
                            blockers.append("official_checksum_manifest_unsafe")
                            checksum_signature_state = "invalid"
                            checksum_raw = b""
                        else:
                            checksum_raw = checksum_file.read_bytes()
                            checksum_digest = hashlib.sha256(checksum_raw).hexdigest()
                            evidence["official_checksum_manifest_sha256"] = checksum_digest
                        if checksum_raw and not verifier.verify(checksum_raw, checksums_signature):
                            checksum_signature_state = "invalid"
                            blockers.append("official_checksum_signature_invalid")
                        elif checksum_raw:
                            checksum_signature_state = "verified"
                            evidence["checksum_signature_verified"] = True
                            expected_line = re.compile(rf"^{re.escape(self.expected_iso_sha256)}\s+\*?{re.escape(iso_name)}\s*$", re.IGNORECASE | re.MULTILINE)
                            if not expected_line.search(checksum_raw.decode("utf-8")):
                                blockers.append("official_checksum_entry_missing")
                            else:
                                evidence["iso_signature_verified"] = True
                                try:
                                    verifier_evidence = self._verifier_evidence(verifier)
                                    evidence["verifier_fingerprint_derived"] = True
                                    evidence["keyring_sha256_derived"] = True
                                except OfflineCloneBlocked as exc:
                                    blockers.append(exc.reason)
                    except (OSError, UnicodeDecodeError, OfflineCloneBlocked):
                        blockers.append("official_checksum_manifest_invalid")
        if extracted_tree is not None:
            if extraction_manifest_path is None or extraction_manifest_signature is None:
                blockers.append("extracted_tree_binding_missing")
            else:
                try:
                    raw, value = _read_json(Path(extraction_manifest_path), max_bytes=8 * 1024 * 1024)
                    if raw != canonical_json(value):
                        raise OfflineCloneBlocked("offline extraction manifest is not canonical", "offline_verification_failed")
                    extraction = RuntimeExtractionManifest.from_dict(value)
                    if extraction.source_iso_filename != iso_name or extraction.source_iso_sha256 != iso_digest:
                        blockers.append("extracted_tree_source_iso_mismatch")
                    if verifier is None or not verifier.verify(raw, extraction_manifest_signature):
                        blockers.append("extraction_manifest_signature_invalid")
                    else:
                        verifier_evidence = self._verifier_evidence(verifier)
                        evidence["extracted_tree_binding_verified"] = True
                        evidence["extraction_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
                        evidence["extraction_inventory_sha256"] = extraction.inventory_sha256
                except (OSError, UnicodeDecodeError, OfflineCloneBlocked, TypeError, ValueError) as exc:
                    blockers.append(getattr(exc, "reason", "extraction_manifest_invalid"))
        tools, tree_blockers = self._check_tree(Path(extracted_tree), extraction) if extracted_tree is not None else ({name: _missing_tool() for name in REQUIRED_RUNTIME_TOOLS}, ["extracted_tree_missing"])
        blockers.extend(tree_blockers)
        evidence["tool_presence"] = {name: bool(entry["present"]) for name, entry in tools.items()}
        try:
            evidence["iso_provenance"] = _safe_provenance(provenance)[:512]
        except OfflineCloneBlocked as exc:
            evidence["iso_provenance"] = "unsafe-provenance-omitted"
            blockers.append(exc.reason)
        if vm_boot_completed:
            blockers.append("vm_boot_claim_requires_recorded_isolated_run")
        evidence["vm_boot_completed"] = False
        artifact = RuntimeArtifactEvidence(
            architecture=architecture,
            iso_filename=iso_name,
            iso_sha256=iso_digest,
            official_checksum_manifest_sha256=checksum_digest,
            official_checksum_signature_state=checksum_signature_state,
            official_checksum_signature_verified=bool(evidence["iso_signature_verified"]),
            signer_fingerprint=verifier_evidence.pinned_fingerprint if verifier_evidence else "",
            keyring_sha256=verifier_evidence.keyring_sha256 if verifier_evidence else "",
            extraction_manifest_schema=extraction.schema if extraction else 0,
            extraction_method=extraction.extraction_method if extraction else "",
            extraction_manifest_sha256=evidence.get("extraction_manifest_sha256", ""),
            extraction_inventory_sha256=extraction.inventory_sha256 if extraction else "",
            extraction_signature_verified=bool(evidence["extracted_tree_binding_verified"]),
            required_tools=tools,
        )
        manifest = OfflineRuntimeManifest(artifact=artifact, iso_provenance=evidence["iso_provenance"])
        try:
            manifest.validate()
        except OfflineCloneBlocked as exc:
            blockers.append(exc.reason)
        if blockers:
            state = "offline_runtime_blocked"
        else:
            state = "offline_runtime_static_validation_passed"
        return RuntimeReadinessReport(state, tuple(sorted(set(blockers))), evidence, manifest)


@dataclass(frozen=True)
class ReturnChannelStatus:
    state: str
    reason: str
    result_digest: str = ""
    partial: bool = False


@dataclass(frozen=True)
class ReturnChannelConsumption:
    state: str
    reason: str
    result: OfflineResult | None = None


class VirtualReturnChannel:
    """Crash-safe directory fixture for a future dedicated exchange volume."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.meta_path = self.root / RETURN_CHANNEL_META
        self.lock_path = self.root / ".channel.lock"

    @staticmethod
    def _meta(job_id: str, nonce: str, expires_at: str, state: str = "pending", result_digest: str = "") -> dict[str, Any]:
        return {"schema": RETURN_CHANNEL_SCHEMA, "job_id": job_id, "nonce_hash": hashlib.sha256(nonce.encode()).hexdigest(), "expires_at": expires_at, "state": state, "result_digest": result_digest, "updated_at": _now()}

    def _load_meta(self) -> dict[str, Any]:
        if not self.meta_path.exists():
            raise OfflineCloneBlocked("offline return channel is not initialized", "offline_return_channel_pending")
        _, value = _read_json(self.meta_path, max_bytes=64 * 1024)
        if set(value) != {"schema", "job_id", "nonce_hash", "expires_at", "state", "result_digest", "updated_at"} or value.get("schema") != RETURN_CHANNEL_SCHEMA or value.get("state") not in RETURN_STATES or not _JOB_ID.fullmatch(str(value.get("job_id") or "")) or not _HEX64.fullmatch(str(value.get("nonce_hash") or "")) or (value.get("result_digest") and not _HEX64.fullmatch(str(value.get("result_digest")))):
            raise OfflineCloneBlocked("offline return-channel state is invalid", "offline_return_channel_failed")
        try:
            expires = datetime.fromisoformat(str(value["expires_at"]).replace("Z", "+00:00"))
            updated = datetime.fromisoformat(str(value["updated_at"]).replace("Z", "+00:00"))
            if expires.tzinfo is None or updated.tzinfo is None:
                raise ValueError
        except ValueError as exc:
            raise OfflineCloneBlocked("offline return-channel timestamp is invalid", "offline_return_channel_failed") from exc
        return value

    def _write_meta(self, value: dict[str, Any]) -> None:
        atomic_write_bytes(self.meta_path, canonical_json(value))

    def _check_binding(self, job: OfflineJob, meta: dict[str, Any]) -> None:
        if meta["job_id"] != job.job_id or meta["nonce_hash"] != hashlib.sha256(job.nonce.encode()).hexdigest():
            raise OfflineCloneBlocked("offline return-channel job or nonce does not match", "offline_return_channel_failed")
        if meta["state"] != "consumed" and datetime.fromisoformat(meta["expires_at"].replace("Z", "+00:00")) < datetime.now(timezone.utc):
            raise OfflineCloneBlocked("offline return-channel package is stale", "offline_return_channel_failed")

    def initialize(self, job: OfflineJob) -> ReturnChannelStatus:
        job.validate()
        self.root.mkdir(parents=True, exist_ok=True)
        with BackupLock(self.lock_path):
            if self.meta_path.exists():
                meta = self._load_meta()
                self._check_binding(job, meta)
                return ReturnChannelStatus(meta["state"], "existing channel state", meta.get("result_digest", ""), self._has_partial())
            self._write_meta(self._meta(job.job_id, job.nonce, job.expires_at))
        return ReturnChannelStatus("pending", "return channel initialized", partial=False)

    def _has_partial(self) -> bool:
        if not self.root.exists():
            return False
        return any(path.name.startswith(".result-") or path.name.endswith(".part") for path in self.root.iterdir())

    def status(self) -> ReturnChannelStatus:
        try:
            meta = self._load_meta()
        except OfflineCloneBlocked as exc:
            return ReturnChannelStatus("pending", exc.reason, partial=self._has_partial())
        return ReturnChannelStatus(meta["state"], "durable channel state", meta.get("result_digest", ""), self._has_partial())

    def transition(self, job: OfflineJob, state: str, reason: str) -> ReturnChannelStatus:
        if state not in RETURN_STATES:
            raise OfflineCloneBlocked("offline return-channel state is invalid", "offline_return_channel_failed")
        with BackupLock(self.lock_path):
            meta = self._load_meta()
            self._check_binding(job, meta)
            if state != meta["state"] and state not in RETURN_TRANSITIONS[meta["state"]]:
                raise OfflineCloneBlocked("offline return-channel transition is not monotonic", "offline_return_channel_failed")
            meta["state"] = state
            meta["updated_at"] = _now()
            self._write_meta(meta)
        return ReturnChannelStatus(state, reason, meta.get("result_digest", ""), self._has_partial())

    def mark_running(self, job: OfflineJob) -> ReturnChannelStatus:
        return self.transition(job, "running", "virtual runner started")

    def publish_result(
        self,
        job: OfflineJob,
        result: OfflineResult,
        signer: Any,
        *,
        fault_injector: Callable[[str], None] | None = None,
    ) -> ReturnChannelStatus:
        job.validate()
        result_raw = result.canonical_bytes()
        if result.job_id != job.job_id:
            raise OfflineCloneBlocked("offline result job ID does not match the channel", "offline_return_channel_failed")
        with BackupLock(self.lock_path):
            meta = self._load_meta()
            self._check_binding(job, meta)
            if meta["state"] != "running":
                raise OfflineCloneBlocked("offline result can only be published from running", "offline_return_channel_failed")
            final = self.root / f"result-{job.job_id}"
            if final.exists() or any(path.is_dir() and path.name.startswith("result-") for path in self.root.iterdir()):
                raise OfflineCloneBlocked("duplicate or conflicting offline result package", "offline_return_channel_failed")
            temporary = Path(tempfile.mkdtemp(prefix=f".result-{job.job_id}-", dir=self.root))
            try:
                result_sig = signer.sign(result_raw)
                channel_raw = canonical_json({"schema": RETURN_CHANNEL_SCHEMA, "job_id": job.job_id, "nonce_hash": meta["nonce_hash"], "state": "result", "result_sha256": hashlib.sha256(result_raw).hexdigest(), "result_signature_sha256": hashlib.sha256(result_sig).hexdigest()})
                _fsync_file(temporary / "result.json", result_raw)
                if fault_injector:
                    fault_injector("result_manifest")
                _fsync_file(temporary / "result.sig", result_sig)
                if fault_injector:
                    fault_injector("result_signature")
                _fsync_file(temporary / RETURN_CHANNEL_META, channel_raw)
                _fsync_file(temporary / RETURN_CHANNEL_SIGNATURE, signer.sign(channel_raw))
                if fault_injector:
                    fault_injector("channel_manifest")
                os.replace(temporary, final)
                if fault_injector:
                    fault_injector("final_rename")
            except BaseException:
                raise
            meta["state"] = "result"
            meta["result_digest"] = hashlib.sha256(result_raw).hexdigest()
            meta["updated_at"] = _now()
            self._write_meta(meta)
        return ReturnChannelStatus("result", "signed result atomically published", meta["result_digest"], self._has_partial())

    def recover(self, job: OfflineJob) -> ReturnChannelStatus:
        with BackupLock(self.lock_path):
            meta = self._load_meta()
            self._check_binding(job, meta)
            final = self.root / f"result-{job.job_id}"
            if meta["state"] in {"pending", "running"} and (final.exists() or self._has_partial()):
                meta["state"] = "failed"
                meta["updated_at"] = _now()
                self._write_meta(meta)
                return ReturnChannelStatus("failed", "incomplete or orphaned result publication recovered as failed", partial=self._has_partial())
            if meta["state"] == "result" and not final.is_dir():
                meta["state"] = "failed"
                meta["updated_at"] = _now()
                self._write_meta(meta)
                return ReturnChannelStatus("failed", "result state had no durable package", partial=self._has_partial())
        return self.status()

    def consume(self, job: OfflineJob, verifier: Any, *, expected_command_hash: str, command_plan: Any, now: datetime | None = None, profile: str = "simulation") -> ReturnChannelConsumption:
        with BackupLock(self.lock_path):
            meta = self._load_meta()
            try:
                self._check_binding(job, meta)
            except OfflineCloneBlocked as exc:
                if meta["state"] != "consumed":
                    meta["state"] = "failed"
                    meta["updated_at"] = _now()
                    self._write_meta(meta)
                    return ReturnChannelConsumption("failed", exc.reason, None)
                raise
            final = self.root / f"result-{job.job_id}"
            if meta["state"] not in {"result", "consumed"}:
                return ReturnChannelConsumption(meta["state"], "no complete result is available", None)
            duplicates = [path for path in self.root.iterdir() if path.name.startswith("result-") and path != final]
            if duplicates:
                meta["state"] = "failed"
                meta["updated_at"] = _now()
                self._write_meta(meta)
                return ReturnChannelConsumption("failed", "duplicate or conflicting result packages are present", None)
            if not final.is_dir() or any((final / name).is_symlink() for name in ("result.json", "result.sig", RETURN_CHANNEL_META, RETURN_CHANNEL_SIGNATURE)):
                meta["state"] = "failed"
                meta["updated_at"] = _now()
                self._write_meta(meta)
                return ReturnChannelConsumption("failed", "result package is incomplete or unsafe", None)
            try:
                channel_raw, channel = _read_json(final / RETURN_CHANNEL_META, max_bytes=64 * 1024)
                channel_signature = (final / RETURN_CHANNEL_SIGNATURE).read_bytes()
            except (OSError, OfflineCloneBlocked) as exc:
                meta["state"] = "failed"
                meta["updated_at"] = _now()
                self._write_meta(meta)
                return ReturnChannelConsumption("failed", getattr(exc, "reason", "return-channel binding is incomplete"), None)
            expected_channel = {"schema": RETURN_CHANNEL_SCHEMA, "job_id": job.job_id, "nonce_hash": meta["nonce_hash"], "state": "result", "result_sha256": channel.get("result_sha256"), "result_signature_sha256": channel.get("result_signature_sha256")}
            try:
                valid_channel = verifier.verify(channel_raw, channel_signature)
            except OfflineCloneBlocked:
                valid_channel = False
            if channel != expected_channel or not valid_channel:
                meta["state"] = "failed"
                meta["updated_at"] = _now()
                self._write_meta(meta)
                return ReturnChannelConsumption("failed", "return-channel binding or signature is invalid", None)
            try:
                result = OfflineResultStore(self.root).consume(final, job, verifier, expected_command_hash=expected_command_hash, command_plan=command_plan, now=now, profile=profile)
            except OfflineCloneBlocked as exc:
                meta["state"] = "failed"
                meta["updated_at"] = _now()
                self._write_meta(meta)
                return ReturnChannelConsumption("failed", exc.reason, None)
            if hashlib.sha256((final / "result.json").read_bytes()).hexdigest() != meta["result_digest"]:
                meta["state"] = "failed"
                meta["updated_at"] = _now()
                self._write_meta(meta)
                return ReturnChannelConsumption("failed", "result digest does not match durable channel state", None)
            if meta["state"] == "result":
                meta["state"] = "consumed"
                meta["updated_at"] = _now()
                self._write_meta(meta)
        return ReturnChannelConsumption("consumed", "result consumed idempotently; replay remains consumed", result)


@dataclass(frozen=True)
class VirtualSimulationPolicy:
    name: str = "virtual_simulation_only"
    real_engine_available: bool = False


class VirtualOfflineRunner:
    """The only runner type in this phase; it can publish simulation results only."""

    def __init__(self, channel: VirtualReturnChannel, signer: Any, verifier: Any, *, policy: VirtualSimulationPolicy):
        if type(policy) is not VirtualSimulationPolicy or policy.real_engine_available:
            raise OfflineCloneBlocked("offline runner policy is not a virtual simulation policy", "offline_execution_disabled")
        self.channel = channel
        self.signer = signer
        self.verifier = verifier
        self.policy = policy

    def run(self, job: OfflineJob, inventory: Iterable[OfflineBlockDevice], *, now: datetime, boot_medium_nodes: Iterable[str] = ()) -> dict[str, Any]:
        job.validate()
        self.channel.initialize(job)
        self.channel.mark_running(job)
        resolution = resolve_offline_devices(job, FakeOfflineInventory(tuple(inventory)), boot_medium_nodes=boot_medium_nodes)
        if not resolution.ok:
            self.channel.transition(job, "failed", resolution.reason)
            return {"state": "offline_runtime_blocked", "reason": resolution.reason, "command_executed": False}
        plan = ClonezillaCommandRenderer().render(job, resolution)
        result = build_fake_result(job, plan, resolution.source, resolution.target, now=now)
        channel_status = self.channel.publish_result(job, result, self.signer)
        return {"state": "offline_return_channel_ready", "channel_state": channel_status.state, "command_executed": False, "displayed_argv": list(plan.displayed_argv), "argv_hash": plan.argv_hash, "boot_tested": False}


def simulate_virtual_offline_round_trip(root: Path) -> dict[str, Any]:
    root = Path(root)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    source = OfflineBlockDevice("/dev/vda", "Synthetic Source", "SYNTH-SOURCE", wwn="synthetic-wwn-source", transport="sata", size_bytes=1000, partition_style="gpt", partition_roles=("efi", "windows", "recovery"))
    target = OfflineBlockDevice("/dev/vdb", "Synthetic Target", "SYNTH-TARGET", wwn="synthetic-wwn-target", transport="sata", size_bytes=1200, partition_style="gpt", partition_roles=("efi", "windows", "recovery"))
    job = build_offline_job(source, target, now=now, job_id="a" * 32, nonce="synthetic-nonce-000001")
    signer = FakeDetachedSigner()
    verifier = FakeDetachedVerifier()
    channel = VirtualReturnChannel(root / "return-channel")
    runner = VirtualOfflineRunner(channel, signer, verifier, policy=VirtualSimulationPolicy())
    published = runner.run(job, (source, target), now=now)
    plan = ClonezillaCommandRenderer().render(job, resolve_offline_devices(job, (source, target)))
    consumed = channel.consume(job, verifier, expected_command_hash=plan.argv_hash, command_plan=plan, now=now, profile="simulation")
    return {**published, "state": consumed.state, "reason": consumed.reason, "durable_return_round_trip": consumed.state == "consumed", "replay_after_restart": channel.status().state == "consumed", "physical_disk_touched": False, "physical_boot_tested": False}


def default_runtime_status() -> RuntimeReadinessReport:
    return OfflineRuntimeValidator().validate()
