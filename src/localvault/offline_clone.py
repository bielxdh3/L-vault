"""Offline Clonezilla preparation and fail-closed verification boundaries.

This module deliberately has no host block-device commands or clone-engine
execution.  The Windows phase creates signed packages and dry-renders argv;
the only subprocess seam is the explicitly configured detached verifier.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

from .locks import BackupLock
from .utils import atomic_write_text


OFFLINE_JOB_SCHEMA = 1
OFFLINE_RESULT_SCHEMA = 1
OFFLINE_ENGINE = "clonezilla"
OFFLINE_ENGINE_VERSION = "3.3.3-15"
OFFLINE_ENGINE_COMPATIBILITY = "3.3.3-15 only until the offline runtime is validated"
OFFLINE_RESULT_PROFILE_SIMULATION = "simulation"
OFFLINE_RESULT_PROFILE_PRODUCTION = "production"
OFFLINE_RESULT_FAKE_PHASE = "fake_engine_rendered_only"
OFFLINE_RESULT_PRODUCTION_SUCCESS_PHASE = "clone_completed_structurally_verified"
OFFLINE_RESULT_PRODUCTION_FAILURE_PHASE = "clone_failed"
OFFLINE_RESULT_PHASES = frozenset({OFFLINE_RESULT_FAKE_PHASE, OFFLINE_RESULT_PRODUCTION_SUCCESS_PHASE, OFFLINE_RESULT_PRODUCTION_FAILURE_PHASE})
OFFLINE_RESULT_TARGET_OFFLINE_VALUES = frozenset({"not_changed_in_simulation", "confirmed_offline", "unknown"})
OFFLINE_RESULT_MAX_FUTURE_SKEW = timedelta(minutes=5)
OFFLINE_RESULT_MAX_JOB_SKEW = timedelta(minutes=5)
JOB_MANIFEST = "manifest.json"
JOB_SIGNATURE = "manifest.sig"
RESULT_MANIFEST = "result.json"
RESULT_SIGNATURE = "result.sig"
_JOB_ID = re.compile(r"^[0-9a-f]{32}$")
_NODE = re.compile(r"^/dev/[A-Za-z0-9._+:-]+$")
_NODE_SEARCH = re.compile(r"/dev/[A-Za-z0-9._+:-]+", re.IGNORECASE)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MASKED_LABEL = re.compile(r"^.+ \*{4}\S{4} \(\d+ bytes\)$")
_PRIVATE_KEY = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----", re.IGNORECASE)
_SENSITIVE_IDENTIFIER = re.compile(r"\b(?:wwn|id[_ -]?serial|serial(?:[_ -]?(?:number|no|id))?)(?:\s*[:=]|\s+|-)[^\s,;]+", re.IGNORECASE)


class OfflineCloneBlocked(RuntimeError):
    def __init__(self, reason: str, state: str = "offline_execution_disabled"):
        super().__init__(reason)
        self.reason = reason
        self.state = state


class DetachedSigner(Protocol):
    def sign(self, payload: bytes) -> bytes: ...


class DetachedVerifier(Protocol):
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


@dataclass(frozen=True)
class SignatureVerificationEvidence:
    """Evidence from the exact verifier/keyring used for a verification."""

    pinned_fingerprint: str
    keyring_sha256: str


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _normal(value: Any) -> str:
    return str(value or "").strip().casefold()


def _hash(value: Any) -> str:
    return hashlib.sha256(_normal(value).encode("utf-8")).hexdigest()


def _utc(value: datetime | str) -> datetime:
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _strict_utc(value: datetime | str, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise OfflineCloneBlocked(f"offline result {field} timestamp is invalid", "offline_verification_failed") from exc
    else:
        raise OfflineCloneBlocked(f"offline result {field} timestamp is invalid", "offline_verification_failed")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OfflineCloneBlocked(f"offline result {field} timestamp must include a timezone", "offline_verification_failed")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _utc(value).isoformat(timespec="seconds")


def _masked_serial(serial: str) -> str:
    serial = str(serial or "").strip()
    return "(serial oculto)" if not serial else f"****{serial[-4:]}"


def _validate_user_visible_text(field: str, value: str, *, label: bool = False, max_length: int = 512) -> None:
    if not isinstance(value, str) or not value or len(value) > max_length or any(ord(char) < 32 for char in value):
        raise OfflineCloneBlocked(f"offline result {field} is not safely bounded", "offline_verification_failed")
    if _NODE_SEARCH.search(value) or _PRIVATE_KEY.search(value) or _SENSITIVE_IDENTIFIER.search(value):
        raise OfflineCloneBlocked(f"offline result {field} contains sensitive material", "offline_verification_failed")
    if label and (not _MASKED_LABEL.fullmatch(value) or "wwn" in value.casefold() or "serial" in value.casefold().replace("serial oculto", "")):
        raise OfflineCloneBlocked(f"offline result {field} is not a safe masked label", "offline_verification_failed")


def _sanitize_error(value: str) -> str:
    value = re.sub(_NODE_SEARCH, "/dev/(oculto)", str(value or ""))
    value = re.sub(_PRIVATE_KEY, "(chave privada omitida)", value)
    value = re.sub(_SENSITIVE_IDENTIFIER, "(identificador omitido)", value)
    return re.sub(r"\s+", " ", value).strip()[:512]


@dataclass(frozen=True)
class OfflineBlockDevice:
    """Normalized evidence equivalent to lsblk, udev, sysfs, and blkid."""

    node: str
    model: str
    serial: str
    wwn: str = ""
    id_serial: str = ""
    id_serial_short: str = ""
    nvme_namespace: str = ""
    usb_bridge_id: str = ""
    transport: str = ""
    size_bytes: int = 0
    logical_sector_size: int = 512
    physical_sector_size: int = 4096
    partition_style: str = ""
    partition_roles: tuple[str, ...] = ()
    mounted: bool = False
    live_root: bool = False
    boot_medium: bool = False
    removable: bool = False
    usb_bridge_stable: bool = True
    read_only: bool = False
    protected: bool = False
    protected_ambiguous: bool = False

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "OfflineBlockDevice":
        roles = value.get("partition_roles") or value.get("roles") or ()
        if isinstance(roles, str):
            roles = (roles,)
        return cls(
            node=str(value.get("node") or value.get("path") or ""),
            model=str(value.get("model") or ""),
            serial=str(value.get("serial") or value.get("ID_SERIAL_SHORT") or ""),
            wwn=str(value.get("wwn") or value.get("ID_WWN") or ""),
            id_serial=str(value.get("id_serial") or value.get("ID_SERIAL") or ""),
            id_serial_short=str(value.get("id_serial_short") or value.get("ID_SERIAL_SHORT") or ""),
            nvme_namespace=str(value.get("nvme_namespace") or value.get("namespace") or ""),
            usb_bridge_id=str(value.get("usb_bridge_id") or value.get("bridge_id") or ""),
            transport=str(value.get("transport") or value.get("bus") or ""),
            size_bytes=int(value.get("size_bytes") or value.get("size") or 0),
            logical_sector_size=int(value.get("logical_sector_size") or value.get("logical_sector") or 512),
            physical_sector_size=int(value.get("physical_sector_size") or value.get("physical_sector") or 4096),
            partition_style=str(value.get("partition_style") or ""),
            partition_roles=tuple(str(item) for item in roles if str(item)),
            mounted=bool(value.get("mounted")),
            live_root=bool(value.get("live_root") or value.get("backing_live_root")),
            boot_medium=bool(value.get("boot_medium")),
            removable=bool(value.get("removable")),
            usb_bridge_stable=bool(value.get("usb_bridge_stable", True)),
            read_only=bool(value.get("read_only")),
            protected=bool(value.get("protected")),
            protected_ambiguous=bool(value.get("protected_ambiguous")),
        )

    @property
    def stable_values(self) -> dict[str, str]:
        return {
            key: value
            for key, value in {
                "serial": self.serial,
                "wwn": self.wwn,
                "id_serial": self.id_serial,
                "id_serial_short": self.id_serial_short,
                "nvme_namespace": self.nvme_namespace,
                "usb_bridge_id": self.usb_bridge_id,
            }.items()
            if str(value).strip()
        }

    @property
    def identity_policy(self) -> str:
        if _normal(self.transport) == "usb":
            return "usb_requires_serial_wwn_and_stable_bridge"
        return "native_requires_two_independent_ids"

    @property
    def identity_strength(self) -> str:
        values = {_normal(value) for value in self.stable_values.values() if _normal(value)}
        if _normal(self.transport) == "usb":
            if not self.usb_bridge_stable or not self.serial or not self.wwn or not self.usb_bridge_id:
                return "weak"
            return "strong" if len(values) >= 3 else "weak"
        return "strong" if len(values) >= 2 else "weak"

    @property
    def fingerprint(self) -> dict[str, Any]:
        return {
            "policy": self.identity_policy,
            "ids": {key: _hash(value) for key, value in self.stable_values.items()},
            "model": _hash(self.model),
            "size_bytes": self.size_bytes,
            "logical_sector_size": self.logical_sector_size,
            "physical_sector_size": self.physical_sector_size,
            "transport": _normal(self.transport),
            "partition_style": _normal(self.partition_style),
        }

    @property
    def masked_label(self) -> str:
        return f"{self.model or 'disco'} {_masked_serial(self.serial)} ({self.size_bytes} bytes)"


@dataclass(frozen=True)
class OfflineJob:
    job_id: str
    created_at: str
    expires_at: str
    source_identity_policy: str
    source_fingerprint: dict[str, Any]
    target_identity_policy: str
    target_fingerprint: dict[str, Any]
    source_capacity_bytes: int
    target_capacity_bytes: int
    source_partition_style: str
    target_partition_style: str
    required_partition_roles: tuple[str, ...]
    clone_mode: str = "whole_disk"
    approved_engine: str = OFFLINE_ENGINE
    expected_engine_release: str = OFFLINE_ENGINE_VERSION
    post_action: str = "true"
    protected_device_exclusions: tuple[str, ...] = (
        "mounted",
        "live_root",
        "boot_medium",
        "removable_ambiguity",
        "protected_device",
        "read_only_target",
    )
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    source_label: str = ""
    target_label: str = ""
    schema: int = OFFLINE_JOB_SCHEMA
    real_execution_authorized: bool = False

    def validate(self) -> None:
        if self.schema != OFFLINE_JOB_SCHEMA or not _JOB_ID.fullmatch(self.job_id):
            raise OfflineCloneBlocked("offline job schema or identifier is invalid", "offline_verification_failed")
        created, expires = _utc(self.created_at), _utc(self.expires_at)
        if expires <= created or not self.nonce or len(self.nonce) < 16:
            raise OfflineCloneBlocked("offline job lifetime or nonce is invalid", "offline_verification_failed")
        if self.approved_engine != OFFLINE_ENGINE or self.clone_mode != "whole_disk":
            raise OfflineCloneBlocked("offline engine or clone mode is not allowlisted", "offline_execution_disabled")
        if self.expected_engine_release != OFFLINE_ENGINE_VERSION:
            raise OfflineCloneBlocked("offline engine release is not allowlisted", "offline_execution_disabled")
        if self.real_execution_authorized:
            raise OfflineCloneBlocked("real offline execution is disabled in this phase", "offline_execution_disabled")
        _validate_user_visible_text("source label", self.source_label, label=True, max_length=160)
        _validate_user_visible_text("target label", self.target_label, label=True, max_length=160)
        if min(self.source_capacity_bytes, self.target_capacity_bytes, len(self.required_partition_roles)) <= 0:
            raise OfflineCloneBlocked("offline job geometry is incomplete", "offline_verification_failed")
        if self.target_capacity_bytes < self.source_capacity_bytes:
            raise OfflineCloneBlocked("offline target is smaller than source", "offline_identity_blocked")
        if self.source_identity_policy != self.source_fingerprint.get("policy") or self.target_identity_policy != self.target_fingerprint.get("policy"):
            raise OfflineCloneBlocked("offline identity policy does not match its fingerprint", "offline_verification_failed")
        if self.source_partition_style.casefold() != str(self.source_fingerprint.get("partition_style") or "").casefold() or self.target_partition_style.casefold() != str(self.target_fingerprint.get("partition_style") or "").casefold():
            raise OfflineCloneBlocked("offline partition policy does not match its fingerprint", "offline_verification_failed")
        required_exclusions = {"mounted", "live_root", "boot_medium", "removable_ambiguity", "protected_device", "read_only_target"}
        if not required_exclusions.issubset(set(self.protected_device_exclusions)):
            raise OfflineCloneBlocked("offline protected-device exclusions are incomplete", "offline_verification_failed")
        if self.source_fingerprint == self.target_fingerprint:
            raise OfflineCloneBlocked("offline source and target identity are equal", "offline_identity_blocked")

    def payload(self) -> dict[str, Any]:
        value = asdict(self)
        value["required_partition_roles"] = list(self.required_partition_roles)
        value["protected_device_exclusions"] = list(self.protected_device_exclusions)
        return value

    def canonical_bytes(self) -> bytes:
        self.validate()
        return canonical_json(self.payload())

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "OfflineJob":
        job = cls(
            job_id=str(value.get("job_id") or ""),
            created_at=str(value.get("created_at") or ""),
            expires_at=str(value.get("expires_at") or ""),
            source_identity_policy=str(value.get("source_identity_policy") or ""),
            source_fingerprint=dict(value.get("source_fingerprint") or {}),
            target_identity_policy=str(value.get("target_identity_policy") or ""),
            target_fingerprint=dict(value.get("target_fingerprint") or {}),
            source_capacity_bytes=int(value.get("source_capacity_bytes") or 0),
            target_capacity_bytes=int(value.get("target_capacity_bytes") or 0),
            source_partition_style=str(value.get("source_partition_style") or ""),
            target_partition_style=str(value.get("target_partition_style") or ""),
            required_partition_roles=tuple(str(item) for item in value.get("required_partition_roles") or ()),
            clone_mode=str(value.get("clone_mode") or ""),
            approved_engine=str(value.get("approved_engine") or ""),
            expected_engine_release=str(value.get("expected_engine_release") or ""),
            post_action=str(value.get("post_action") or ""),
            protected_device_exclusions=tuple(str(item) for item in value.get("protected_device_exclusions") or ()),
            nonce=str(value.get("nonce") or ""),
            source_label=str(value.get("source_label") or ""),
            target_label=str(value.get("target_label") or ""),
            schema=int(value.get("schema") or 0),
            real_execution_authorized=bool(value.get("real_execution_authorized")),
        )
        job.validate()
        return job


def build_offline_job(source: OfflineBlockDevice, target: OfflineBlockDevice, *, now: datetime | None = None, ttl: timedelta = timedelta(minutes=15), job_id: str | None = None, nonce: str | None = None) -> OfflineJob:
    if source.identity_strength != "strong" or target.identity_strength != "strong":
        raise OfflineCloneBlocked("source and target require strong persistent identity", "offline_identity_blocked")
    if source.size_bytes <= 0 or target.size_bytes < source.size_bytes:
        raise OfflineCloneBlocked("offline target is smaller than source", "offline_identity_blocked")
    if source.node == target.node or source.fingerprint == target.fingerprint:
        raise OfflineCloneBlocked("offline source and target identity are equal", "offline_identity_blocked")
    if not source.partition_style or source.partition_style.casefold() != target.partition_style.casefold():
        raise OfflineCloneBlocked("source and target partition styles do not match", "offline_identity_blocked")
    created = now or datetime.now(timezone.utc)
    job = OfflineJob(
        job_id=job_id or uuid.uuid4().hex,
        created_at=_iso(created),
        expires_at=_iso(created + ttl),
        source_identity_policy=source.identity_policy,
        source_fingerprint=source.fingerprint,
        target_identity_policy=target.identity_policy,
        target_fingerprint=target.fingerprint,
        source_capacity_bytes=source.size_bytes,
        target_capacity_bytes=target.size_bytes,
        source_partition_style=source.partition_style.casefold(),
        target_partition_style=target.partition_style.casefold(),
        required_partition_roles=tuple(sorted(set(source.partition_roles))),
        source_label=source.masked_label,
        target_label=target.masked_label,
        nonce=nonce or secrets.token_hex(16),
    )
    job.validate()
    return job


class FakeDetachedSigner:
    """Test-only token; it must never be used as a production signature."""

    def __init__(self, secret: bytes = b"fake-offline-signer-only"):
        self._secret = secret

    def sign(self, payload: bytes) -> bytes:
        return hashlib.sha256(self._secret + payload).hexdigest().encode("ascii")


class FakeDetachedVerifier(FakeDetachedSigner):
    @property
    def verification_evidence(self) -> SignatureVerificationEvidence:
        key_material = hashlib.sha256(self._secret).digest()
        return SignatureVerificationEvidence(
            pinned_fingerprint=hashlib.sha256(key_material).hexdigest()[:40].upper(),
            keyring_sha256=hashlib.sha256(key_material).hexdigest(),
        )

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return secrets.compare_digest(self.sign(payload), signature)


class ProductionOfflineSignatureVerifier:
    """Bounded, explicit ``gpgv`` adapter; never discovers or trusts a key."""

    def __init__(
        self,
        verifier_binary: Path | str,
        public_keyring: Path | str,
        expected_fingerprint: str,
        *,
        timeout_seconds: float = 10.0,
        max_payload_bytes: int = 8 * 1024 * 1024,
        max_signature_bytes: int = 256 * 1024,
        max_output_bytes: int = 64 * 1024,
        command_prefix: tuple[str, ...] = (),
        command_suffix: tuple[str, ...] = (),
    ):
        self.verifier_binary = Path(verifier_binary)
        self.public_keyring = Path(public_keyring)
        self._pinned_fingerprint = re.sub(r"\s+", "", str(expected_fingerprint)).upper()
        self._bound_keyring_sha256: str | None = None
        self._last_verification_evidence: SignatureVerificationEvidence | None = None
        self.timeout_seconds = float(timeout_seconds)
        self.max_payload_bytes = int(max_payload_bytes)
        self.max_signature_bytes = int(max_signature_bytes)
        self.max_output_bytes = int(max_output_bytes)
        self.command_prefix = tuple(str(item) for item in command_prefix)
        self.command_suffix = tuple(str(item) for item in command_suffix)
        if not re.fullmatch(r"[0-9A-F]{40,64}", self._pinned_fingerprint):
            raise OfflineCloneBlocked("pinned public-key fingerprint is invalid", "offline_verification_failed")
        if not (0 < self.timeout_seconds <= 60 and 0 < self.max_output_bytes <= 1024 * 1024):
            raise OfflineCloneBlocked("detached verifier limits are invalid", "offline_verification_failed")
        self._check_paths()

    @staticmethod
    def _bounded_reader(pipe, limit: int, output: list[bytes]) -> None:
        total = 0
        try:
            while True:
                chunk = pipe.read(8192)
                if not chunk:
                    return
                total += len(chunk)
                if total <= limit:
                    output.append(chunk)
                else:
                    output.append(b"\x00LOCALVAULT_OUTPUT_OVERFLOW")
                    return
        finally:
            pipe.close()

    @property
    def expected_fingerprint(self) -> str:
        return self._pinned_fingerprint

    @property
    def pinned_fingerprint(self) -> str:
        return self._pinned_fingerprint

    @property
    def keyring_sha256(self) -> str:
        if self._last_verification_evidence is None:
            self._check_paths()
        return self.verification_evidence.keyring_sha256

    @property
    def verification_evidence(self) -> SignatureVerificationEvidence:
        if self._last_verification_evidence is None:
            raise OfflineCloneBlocked("detached verifier evidence is unavailable", "offline_verification_failed")
        return self._last_verification_evidence

    def _check_paths(self) -> None:
        for label, path in (("verifier", self.verifier_binary), ("public keyring", self.public_keyring)):
            if path.is_symlink() or not path.is_file():
                raise OfflineCloneBlocked(f"offline {label} path is unsafe", "offline_verification_failed")
        try:
            key_stat = self.public_keyring.stat()
            if key_stat.st_size <= 0 or key_stat.st_size > 4 * 1024 * 1024 or key_stat.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                raise OfflineCloneBlocked("offline public keyring is missing, oversized, or writable", "offline_verification_failed")
            keyring_bytes = self.public_keyring.read_bytes()
            if _PRIVATE_KEY.search(keyring_bytes.decode("utf-8", errors="ignore")):
                raise OfflineCloneBlocked("offline public keyring contains private key material", "offline_verification_failed")
            keyring_sha256 = hashlib.sha256(keyring_bytes).hexdigest()
            if self._bound_keyring_sha256 is not None and self._bound_keyring_sha256 != keyring_sha256:
                raise OfflineCloneBlocked("offline public keyring changed during verification", "offline_verification_failed")
            self._bound_keyring_sha256 = keyring_sha256
            self._last_verification_evidence = SignatureVerificationEvidence(
                pinned_fingerprint=self._pinned_fingerprint,
                keyring_sha256=keyring_sha256,
            )
        except OSError as exc:
            raise OfflineCloneBlocked("offline public keyring cannot be inspected", "offline_verification_failed") from exc

    def verify(self, payload: bytes, signature: bytes) -> bool:
        if not isinstance(payload, bytes) or not isinstance(signature, bytes):
            raise OfflineCloneBlocked("detached signature inputs are invalid", "offline_verification_failed")
        if len(payload) > self.max_payload_bytes or len(signature) > self.max_signature_bytes:
            raise OfflineCloneBlocked("detached signature inputs are oversized", "offline_verification_failed")
        self._check_paths()
        with tempfile.TemporaryDirectory(prefix="localvault-gpgv-") as temp_root:
            temp = Path(temp_root)
            payload_path, signature_path = temp / "payload", temp / "signature"
            payload_path.write_bytes(payload)
            signature_path.write_bytes(signature)
            argv = (*self.command_prefix, str(self.verifier_binary), *self.command_suffix, "--status-fd", "1", "--keyring", str(self.public_keyring), str(signature_path), str(payload_path))
            env = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "PATH": ""}
            try:
                process = subprocess.Popen(argv, cwd=temp_root, env=env, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except (OSError, ValueError) as exc:
                raise OfflineCloneBlocked("detached verifier could not be started", "offline_verification_failed") from exc
            stdout: list[bytes] = []
            stderr: list[bytes] = []
            readers = [threading.Thread(target=self._bounded_reader, args=(process.stdout, self.max_output_bytes, stdout), daemon=True), threading.Thread(target=self._bounded_reader, args=(process.stderr, self.max_output_bytes, stderr), daemon=True)]
            for reader in readers:
                reader.start()
            try:
                exit_code = process.wait(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait(timeout=2)
                raise OfflineCloneBlocked("detached verifier timed out", "offline_verification_failed") from exc
            for reader in readers:
                reader.join(timeout=2)
            out = b"".join(stdout)
            err = b"".join(stderr)
            if b"\x00LOCALVAULT_OUTPUT_OVERFLOW" in out or b"\x00LOCALVAULT_OUTPUT_OVERFLOW" in err or len(out) > self.max_output_bytes or len(err) > self.max_output_bytes:
                raise OfflineCloneBlocked("detached verifier output exceeded the bound", "offline_verification_failed")
            if exit_code != 0:
                return False
            fingerprints = []
            for line in out.decode("utf-8", errors="replace").splitlines():
                fields = line.split()
                if fields and fields[0] == "[GNUPG:]" and len(fields) > 1 and fields[1] == "VALIDSIG" and len(fields) > 2:
                    fingerprints.append(re.sub(r"\s+", "", fields[2]).upper())
            return len(fingerprints) == 1 and fingerprints[0] == self.expected_fingerprint


class ReplayStore:
    def __init__(self, state_path: Path):
        self.state_path = Path(state_path)

    def claim(self, nonce: str) -> None:
        lock = BackupLock(self.state_path.with_name(self.state_path.name + ".lock"), stale_after=timedelta(minutes=10))
        with lock:
            try:
                state = json.loads(self.state_path.read_text(encoding="utf-8")) if self.state_path.exists() else {"schema": 1, "used_nonce_hashes": []}
            except (OSError, json.JSONDecodeError) as exc:
                raise OfflineCloneBlocked("replay state is unreadable", "offline_verification_failed") from exc
            if state.get("schema") != 1 or not isinstance(state.get("used_nonce_hashes"), list):
                raise OfflineCloneBlocked("replay state schema is invalid", "offline_verification_failed")
            nonce_hash = _hash(nonce)
            if nonce_hash in state["used_nonce_hashes"]:
                raise OfflineCloneBlocked("offline job nonce was already consumed", "offline_job_expired")
            state["used_nonce_hashes"].append(nonce_hash)
            atomic_write_text(self.state_path, json.dumps(state, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def _write_signed_directory(destination: Path, payload_name: str, signature_name: str, payload: bytes, signer: DetachedSigner) -> None:
    destination = Path(destination)
    if destination.exists():
        raise OfflineCloneBlocked("package already exists", "offline_verification_failed")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}-", dir=destination.parent))
    try:
        (temporary / payload_name).write_bytes(payload)
        (temporary / signature_name).write_bytes(signer.sign(payload))
        for child in (temporary / payload_name, temporary / signature_name):
            with child.open("rb") as handle:
                handle.read(0)
            with child.open("ab") as handle:
                handle.flush()
                os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


class OfflineJobStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.replay = ReplayStore(self.root / "replay.json")

    def _path(self, job_id: str) -> Path:
        if not _JOB_ID.fullmatch(job_id):
            raise OfflineCloneBlocked("offline job path is invalid", "offline_verification_failed")
        return self.root / job_id

    def create(self, job: OfflineJob, signer: DetachedSigner) -> Path:
        path = self._path(job.job_id)
        _write_signed_directory(path, JOB_MANIFEST, JOB_SIGNATURE, job.canonical_bytes(), signer)
        return path

    def load(self, job_id: str, verifier: DetachedVerifier, *, now: datetime | None = None, consume: bool = True) -> OfflineJob:
        path = self._path(job_id)
        if path.is_symlink() or not path.is_dir() or any((path / name).is_symlink() for name in (JOB_MANIFEST, JOB_SIGNATURE)):
            raise OfflineCloneBlocked("offline job package path is unsafe", "offline_verification_failed")
        try:
            raw = (path / JOB_MANIFEST).read_bytes()
            signature = (path / JOB_SIGNATURE).read_bytes()
        except OSError as exc:
            raise OfflineCloneBlocked("offline job package is incomplete", "offline_verification_failed") from exc
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OfflineCloneBlocked("offline job manifest is invalid", "offline_verification_failed") from exc
        job = OfflineJob.from_dict(value)
        if raw != job.canonical_bytes() or not verifier.verify(raw, signature):
            raise OfflineCloneBlocked("offline job signature or canonical encoding is invalid", "offline_verification_failed")
        if _utc(now or datetime.now(timezone.utc)) > _utc(job.expires_at):
            raise OfflineCloneBlocked("offline job is expired", "offline_job_expired")
        if consume:
            self.replay.claim(job.nonce)
        return job


@dataclass(frozen=True)
class FakeOfflineInventory:
    devices: tuple[OfflineBlockDevice, ...]

    def list_devices(self) -> list[OfflineBlockDevice]:
        return list(self.devices)


class LinuxBlockInventory:
    """Future collector seam. Host Linux commands are intentionally absent."""

    def list_devices(self) -> list[OfflineBlockDevice]:
        raise OfflineCloneBlocked("Linux inventory collection is reserved for the future offline runner")


@dataclass(frozen=True)
class OfflineResolution:
    ok: bool
    source: OfflineBlockDevice | None = None
    target: OfflineBlockDevice | None = None
    source_node: str = ""
    target_node: str = ""
    reason: str = ""
    rejections: tuple[str, ...] = ()
    identity_strength: str = "weak"


def _fingerprint_match(device: OfflineBlockDevice, expected: dict[str, Any], policy: str, *, role: str, source_capacity: int) -> tuple[bool, str]:
    if device.identity_strength != "strong":
        return False, f"{role} identity is weak"
    if device.identity_policy != policy:
        return False, f"{role} identity policy changed"
    if role == "target" and device.size_bytes < source_capacity:
        return False, "target is smaller than source"
    actual = device.fingerprint
    for key in ("model", "size_bytes", "logical_sector_size", "physical_sector_size", "transport", "partition_style"):
        if actual.get(key) != expected.get(key):
            return False, f"{role} {key} mismatch"
    expected_ids = expected.get("ids") or {}
    actual_ids = actual.get("ids") or {}
    if any(actual_ids.get(key) != value for key, value in expected_ids.items()):
        return False, f"{role} persistent identity changed"
    return True, ""


def _unsafe_reasons(device: OfflineBlockDevice, *, role: str, job: OfflineJob, live_root_nodes: set[str], boot_medium_nodes: set[str], protected_nodes: set[str]) -> list[str]:
    reasons: list[str] = []
    if device.mounted:
        reasons.append(f"{role} is mounted")
    if device.live_root or device.node in live_root_nodes:
        reasons.append(f"{role} backs the live root filesystem")
    if device.boot_medium or device.node in boot_medium_nodes:
        reasons.append(f"{role} is the Clonezilla boot medium")
    if device.removable and (not device.usb_bridge_stable or not device.usb_bridge_id):
        reasons.append(f"{role} removable identity is ambiguous")
    if device.protected or device.protected_ambiguous or device.node in protected_nodes:
        reasons.append(f"{role} is protected or protection is ambiguous")
    if role == "target" and device.read_only:
        reasons.append("target is read-only")
    if role == "target" and device.partition_style.casefold() != job.target_partition_style.casefold():
        reasons.append("target partition style mismatch")
    return reasons


def resolve_offline_devices(job: OfflineJob, inventory: Iterable[OfflineBlockDevice] | FakeOfflineInventory, *, live_root_nodes: Iterable[str] = (), boot_medium_nodes: Iterable[str] = (), protected_nodes: Iterable[str] = ()) -> OfflineResolution:
    job.validate()
    devices = inventory.list_devices() if hasattr(inventory, "list_devices") else list(inventory)
    live_root = set(live_root_nodes)
    boot_medium = set(boot_medium_nodes)
    protected = set(protected_nodes)

    def find(role: str, expected: dict[str, Any], policy: str) -> tuple[list[OfflineBlockDevice], list[str]]:
        matches: list[OfflineBlockDevice] = []
        reasons: list[str] = []
        for device in devices:
            matched, reason = _fingerprint_match(device, expected, policy, role=role, source_capacity=job.source_capacity_bytes)
            if matched:
                matches.append(device)
            elif reason.endswith("persistent identity changed") or "mismatch" in reason or "weak" in reason or "policy" in reason or "smaller" in reason:
                reasons.append(reason)
        return matches, reasons

    source_matches, source_rejections = find("source", job.source_fingerprint, job.source_identity_policy)
    if len(source_matches) == 0:
        return OfflineResolution(False, reason=source_rejections[0] if source_rejections else "no source match", rejections=tuple(source_rejections))
    if len(source_matches) > 1:
        return OfflineResolution(False, reason="duplicate source identity", rejections=("more than one source matched",))
    target_matches, target_rejections = find("target", job.target_fingerprint, job.target_identity_policy)
    if len(target_matches) == 0:
        return OfflineResolution(False, source=source_matches[0], reason=target_rejections[0] if target_rejections else "no target match", rejections=tuple(target_rejections))
    if len(target_matches) > 1:
        return OfflineResolution(False, source=source_matches[0], reason="duplicate target identity", rejections=("more than one target matched",))

    source, target = source_matches[0], target_matches[0]
    rejections = _unsafe_reasons(source, role="source", job=job, live_root_nodes=live_root, boot_medium_nodes=boot_medium, protected_nodes=protected)
    rejections.extend(_unsafe_reasons(target, role="target", job=job, live_root_nodes=live_root, boot_medium_nodes=boot_medium, protected_nodes=protected))
    if source.node == target.node or source.fingerprint == target.fingerprint:
        rejections.append("source and target identity are equal")
    if target.size_bytes < source.size_bytes:
        rejections.append("target is smaller than source")
    if rejections:
        return OfflineResolution(False, source=source, target=target, source_node=source.node, target_node=target.node, reason=rejections[0], rejections=tuple(rejections), identity_strength="strong")
    if not _NODE.fullmatch(source.node) or not _NODE.fullmatch(target.node):
        return OfflineResolution(False, source=source, target=target, reason="runtime device node is invalid", rejections=("device node injection rejected",))
    return OfflineResolution(True, source, target, source.node, target.node, "resolved exactly one source and target", (), "strong")


@dataclass(frozen=True)
class ClonezillaCommandPlan:
    argv: tuple[str, ...]
    displayed_argv: tuple[str, ...]
    argv_hash: str
    executable: bool = False
    batch: bool = False


class ClonezillaCommandRenderer:
    """Render documented argv only; never builds a shell command or runs it."""

    def render(self, job: OfflineJob, resolution: OfflineResolution, *, batch: bool = False) -> ClonezillaCommandPlan:
        job.validate()
        if not resolution.ok or not resolution.source_node or not resolution.target_node:
            raise OfflineCloneBlocked("command rendering requires an exact fresh resolution", "offline_identity_blocked")
        if batch:
            raise OfflineCloneBlocked("Clonezilla batch mode is disabled in this phase", "offline_execution_disabled")
        argv = (
            "ocs-onthefly",
            "-f",
            resolution.source_node,
            "-d",
            resolution.target_node,
            "-k0",
            "-j2",
            "-r",
            "-iefi",
            "-p",
            "true",
            "-nogui",
        )
        return ClonezillaCommandPlan(
            argv=argv,
            displayed_argv=("ocs-onthefly", "-f", "/dev/(source-resolved)", "-d", "/dev/(target-resolved)", *argv[5:]),
            argv_hash=hashlib.sha256(canonical_json(list(argv))).hexdigest(),
            executable=False,
            batch=False,
        )


@dataclass(frozen=True)
class OfflineResult:
    job_id: str
    engine: str
    engine_version: str
    started_at: str
    ended_at: str
    source_label: str
    target_label: str
    command_hash: str
    exit_status: int
    phase: str
    structurally_verified: bool
    target_offline: str
    log_hash: str
    sanitized_error: str = ""
    boot_tested: bool = False
    schema: int = OFFLINE_RESULT_SCHEMA

    def _validate_intrinsic(self) -> None:
        if self.schema != OFFLINE_RESULT_SCHEMA:
            raise OfflineCloneBlocked("offline result schema is invalid", "offline_verification_failed")
        if not _JOB_ID.fullmatch(self.job_id):
            raise OfflineCloneBlocked("offline result job identifier is invalid", "offline_verification_failed")
        if self.engine != OFFLINE_ENGINE or self.engine_version != OFFLINE_ENGINE_VERSION:
            raise OfflineCloneBlocked("offline result engine is not allowlisted", "offline_verification_failed")
        _strict_utc(self.started_at, "started_at")
        _strict_utc(self.ended_at, "ended_at")
        _validate_user_visible_text("source label", self.source_label, label=True, max_length=160)
        _validate_user_visible_text("target label", self.target_label, label=True, max_length=160)
        if not _SHA256.fullmatch(self.command_hash):
            raise OfflineCloneBlocked("offline result command hash is not a lowercase SHA-256 digest", "offline_verification_failed")
        if not _SHA256.fullmatch(self.log_hash):
            raise OfflineCloneBlocked("offline result log hash is not a lowercase SHA-256 digest", "offline_verification_failed")
        if type(self.exit_status) is not int or not 0 <= self.exit_status <= 255:
            raise OfflineCloneBlocked("offline result exit status is out of range", "offline_verification_failed")
        if type(self.structurally_verified) is not bool or type(self.boot_tested) is not bool:
            raise OfflineCloneBlocked("offline result verification flags are invalid", "offline_verification_failed")
        if self.phase not in OFFLINE_RESULT_PHASES:
            raise OfflineCloneBlocked("offline result phase is not allowlisted", "offline_verification_failed")
        if self.target_offline not in OFFLINE_RESULT_TARGET_OFFLINE_VALUES:
            raise OfflineCloneBlocked("offline result target-offline outcome is not allowlisted", "offline_verification_failed")
        if self.boot_tested:
            raise OfflineCloneBlocked("offline result claims an unsupported boot-test state", "offline_verification_failed")
        if not isinstance(self.sanitized_error, str) or len(self.sanitized_error) > 512 or self.sanitized_error != _sanitize_error(self.sanitized_error):
            raise OfflineCloneBlocked("offline result error text is not sanitized", "offline_verification_failed")

    def validate_semantics(
        self,
        job: OfflineJob,
        *,
        expected_command_hash: str | None = None,
        command_plan: ClonezillaCommandPlan | None = None,
        now: datetime | None = None,
        profile: str = OFFLINE_RESULT_PROFILE_PRODUCTION,
    ) -> None:
        job.validate()
        self._validate_intrinsic()
        if profile not in {OFFLINE_RESULT_PROFILE_SIMULATION, OFFLINE_RESULT_PROFILE_PRODUCTION}:
            raise OfflineCloneBlocked("offline result validation profile is invalid", "offline_verification_failed")
        if self.job_id != job.job_id:
            raise OfflineCloneBlocked("offline result job ID does not match the verified job", "offline_verification_failed")
        if self.engine != job.approved_engine or self.engine_version != job.expected_engine_release:
            raise OfflineCloneBlocked("offline result engine does not match the verified job", "offline_verification_failed")
        if self.source_label != job.source_label or self.target_label != job.target_label:
            raise OfflineCloneBlocked("offline result labels do not match the verified job", "offline_verification_failed")
        if command_plan is not None:
            if command_plan.executable or command_plan.batch:
                raise OfflineCloneBlocked("offline result command plan is not a safe non-executable plan", "offline_execution_disabled")
            if expected_command_hash is not None and expected_command_hash != command_plan.argv_hash:
                raise OfflineCloneBlocked("trusted command hash and command plan differ", "offline_verification_failed")
            expected_command_hash = command_plan.argv_hash
        if not isinstance(expected_command_hash, str) or not _SHA256.fullmatch(expected_command_hash):
            raise OfflineCloneBlocked("trusted command hash is required and must be a lowercase SHA-256 digest", "offline_verification_failed")
        if self.command_hash != expected_command_hash:
            raise OfflineCloneBlocked("offline result command hash does not match the trusted command plan", "offline_verification_failed")

        started = _strict_utc(self.started_at, "started_at")
        ended = _strict_utc(self.ended_at, "ended_at")
        if ended < started:
            raise OfflineCloneBlocked("offline result end time precedes start time", "offline_verification_failed")
        created = _utc(job.created_at)
        expires = _utc(job.expires_at)
        if started < created - OFFLINE_RESULT_MAX_JOB_SKEW or ended > expires + OFFLINE_RESULT_MAX_JOB_SKEW:
            raise OfflineCloneBlocked("offline result timestamps fall outside the verified job lifetime", "offline_verification_failed")
        current = _strict_utc(now or datetime.now(timezone.utc), "consumption")
        if started > current + OFFLINE_RESULT_MAX_FUTURE_SKEW or ended > current + OFFLINE_RESULT_MAX_FUTURE_SKEW:
            raise OfflineCloneBlocked("offline result timestamp is unreasonably far in the future", "offline_verification_failed")

        if profile == OFFLINE_RESULT_PROFILE_SIMULATION:
            if self.phase != OFFLINE_RESULT_FAKE_PHASE:
                raise OfflineCloneBlocked("simulation consumer accepts only the fake render-only phase", "offline_verification_failed")
            if self.target_offline != "not_changed_in_simulation":
                raise OfflineCloneBlocked("simulation result has an invalid target-offline outcome", "offline_verification_failed")
            if self.structurally_verified:
                raise OfflineCloneBlocked("fake render-only results cannot claim structural verification", "offline_verification_failed")
            return

        if self.phase == OFFLINE_RESULT_FAKE_PHASE:
            raise OfflineCloneBlocked("fake render-only result cannot be consumed as a production result", "offline_verification_failed")
        if self.target_offline not in {"confirmed_offline", "unknown"}:
            raise OfflineCloneBlocked("production result has an invalid target-offline outcome", "offline_verification_failed")
        if self.phase == OFFLINE_RESULT_PRODUCTION_SUCCESS_PHASE:
            if self.exit_status != 0 or not self.structurally_verified or self.target_offline != "confirmed_offline" or self.sanitized_error:
                raise OfflineCloneBlocked("production success requires terminal verification semantics", "offline_verification_failed")
            return
        if self.phase == OFFLINE_RESULT_PRODUCTION_FAILURE_PHASE:
            if self.exit_status == 0 or self.structurally_verified:
                raise OfflineCloneBlocked("production failure phase has inconsistent success fields", "offline_verification_failed")
            return
        raise OfflineCloneBlocked("offline result phase is not valid for the production consumer", "offline_verification_failed")

    def payload(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        self._validate_intrinsic()
        return canonical_json(self.payload())

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "OfflineResult":
        if not isinstance(value, dict):
            raise OfflineCloneBlocked("offline result manifest is not an object", "offline_verification_failed")
        required = {
            "job_id", "engine", "engine_version", "started_at", "ended_at", "source_label", "target_label",
            "command_hash", "exit_status", "phase", "structurally_verified", "target_offline", "log_hash",
            "sanitized_error", "boot_tested", "schema",
        }
        if set(value) != required:
            raise OfflineCloneBlocked("offline result manifest fields are invalid", "offline_verification_failed")
        string_fields = ("job_id", "engine", "engine_version", "started_at", "ended_at", "source_label", "target_label", "command_hash", "phase", "target_offline", "log_hash", "sanitized_error")
        if any(type(value[field]) is not str for field in string_fields):
            raise OfflineCloneBlocked("offline result manifest field types are invalid", "offline_verification_failed")
        if type(value["exit_status"]) is not int or type(value["structurally_verified"]) is not bool or type(value["boot_tested"]) is not bool or type(value["schema"]) is not int:
            raise OfflineCloneBlocked("offline result manifest field types are invalid", "offline_verification_failed")
        result = cls(
            job_id=value["job_id"],
            engine=value["engine"],
            engine_version=value["engine_version"],
            started_at=value["started_at"],
            ended_at=value["ended_at"],
            source_label=value["source_label"],
            target_label=value["target_label"],
            command_hash=value["command_hash"],
            exit_status=value["exit_status"],
            phase=value["phase"],
            structurally_verified=value["structurally_verified"],
            target_offline=value["target_offline"],
            log_hash=value["log_hash"],
            sanitized_error=value["sanitized_error"],
            boot_tested=value["boot_tested"],
            schema=value["schema"],
        )
        result._validate_intrinsic()
        return result


def fake_structural_verify(source: OfflineBlockDevice, target: OfflineBlockDevice) -> bool:
    return (
        source.partition_style.casefold() == target.partition_style.casefold()
        and set(source.partition_roles).issubset(set(target.partition_roles))
        and target.size_bytes >= source.size_bytes
    )


def build_fake_result(job: OfflineJob, plan: ClonezillaCommandPlan, source: OfflineBlockDevice, target: OfflineBlockDevice, *, now: datetime) -> OfflineResult:
    verified = fake_structural_verify(source, target)
    log = "fake engine: command rendered; no subprocess executed; no storage mutated"
    return OfflineResult(
        job_id=job.job_id,
        engine=OFFLINE_ENGINE,
        engine_version=job.expected_engine_release,
        started_at=_iso(now),
        ended_at=_iso(now),
        source_label=job.source_label,
        target_label=job.target_label,
        command_hash=plan.argv_hash,
        exit_status=0,
        phase=OFFLINE_RESULT_FAKE_PHASE,
        structurally_verified=False,
        target_offline="not_changed_in_simulation",
        log_hash=hashlib.sha256(log.encode("utf-8")).hexdigest(),
        sanitized_error="" if verified else _sanitize_error("fake structural verification failed"),
    )


class OfflineResultStore:
    def __init__(self, root: Path):
        self.root = Path(root)

    def create(self, result: OfflineResult, signer: DetachedSigner) -> Path:
        if not _JOB_ID.fullmatch(result.job_id):
            raise OfflineCloneBlocked("offline result job identifier is invalid", "offline_verification_failed")
        destination = self.root / f"result-{result.job_id}"
        _write_signed_directory(destination, RESULT_MANIFEST, RESULT_SIGNATURE, result.canonical_bytes(), signer)
        return destination

    def consume(
        self,
        path: Path,
        job: OfflineJob,
        verifier: DetachedVerifier,
        *,
        expected_command_hash: str | None = None,
        command_plan: ClonezillaCommandPlan | None = None,
        now: datetime | None = None,
        profile: str = OFFLINE_RESULT_PROFILE_PRODUCTION,
    ) -> OfflineResult:
        path = Path(path)
        if path.is_symlink() or not path.is_dir() or any((path / name).is_symlink() for name in (RESULT_MANIFEST, RESULT_SIGNATURE)):
            raise OfflineCloneBlocked("offline result package path is unsafe", "offline_verification_failed")
        try:
            raw = (path / RESULT_MANIFEST).read_bytes()
            signature = (path / RESULT_SIGNATURE).read_bytes()
        except OSError as exc:
            raise OfflineCloneBlocked("offline result package is incomplete", "offline_verification_failed") from exc
        try:
            result = OfflineResult.from_dict(json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, AttributeError) as exc:
            raise OfflineCloneBlocked("offline result manifest is invalid", "offline_verification_failed") from exc
        if raw != result.canonical_bytes() or not verifier.verify(raw, signature):
            raise OfflineCloneBlocked("offline result signature or canonical encoding is invalid", "offline_verification_failed")
        result.validate_semantics(
            job,
            expected_command_hash=expected_command_hash,
            command_plan=command_plan,
            now=now,
            profile=profile,
        )
        return result


@dataclass(frozen=True)
class OfflineResultOutcome:
    state: str
    reason: str
    result: OfflineResult | None


def consume_offline_result(
    path: Path,
    job: OfflineJob,
    verifier: DetachedVerifier,
    *,
    expected_command_hash: str | None = None,
    command_plan: ClonezillaCommandPlan | None = None,
    now: datetime | None = None,
    profile: str = OFFLINE_RESULT_PROFILE_PRODUCTION,
) -> OfflineResultOutcome:
    if not Path(path).is_dir():
        return OfflineResultOutcome("offline_result_pending", "no offline result package received", None)
    result = OfflineResultStore(Path(path).parent).consume(
        path,
        job,
        verifier,
        expected_command_hash=expected_command_hash,
        command_plan=command_plan,
        now=now,
        profile=profile,
    )
    if profile == OFFLINE_RESULT_PROFILE_SIMULATION:
        if result.exit_status != 0 or result.sanitized_error:
            return OfflineResultOutcome("offline_verification_failed", result.sanitized_error or "fake offline simulation failed", result)
        return OfflineResultOutcome("offline_simulation_completed", "fake render completed; no clone or structural verification was performed", result)
    if result.phase != OFFLINE_RESULT_PRODUCTION_SUCCESS_PHASE:
        return OfflineResultOutcome("offline_verification_failed", result.sanitized_error or "offline engine or structural verification failed", result)
    return OfflineResultOutcome("offline_clone_structurally_verified", "structure verified; boot test not manually performed", result)


@dataclass(frozen=True)
class OfflineBootHandoffPlan:
    mechanism: str = "dedicated_clonezilla_usb_manual"
    configured: bool = False
    manual_action_required: bool = True
    mutates_boot_configuration: bool = False
    reboot_requested: bool = False
    target_must_not_be_boot_medium: bool = True
    blockers: tuple[str, ...] = (
        "Secure Boot compatibility remains a manual validation gate.",
        "Detached GPG verifier availability in Clonezilla Live is not proven.",
        "Return-channel and crash-recovery setup are not configured.",
    )


def build_offline_boot_handoff_plan() -> OfflineBootHandoffPlan:
    return OfflineBootHandoffPlan()


def simulate_offline_round_trip(root: Path) -> dict[str, Any]:
    """Complete fake round trip; it never calls subprocess or host storage APIs."""
    root = Path(root)
    now = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)
    source_before = OfflineBlockDevice("/dev/sda", "Fake Source", "FAKE-SOURCE", wwn="wwn-source", transport="sata", size_bytes=1000, partition_style="gpt", partition_roles=("efi", "windows", "recovery"))
    target_before = OfflineBlockDevice("/dev/sdb", "Fake Target", "FAKE-TARGET", wwn="wwn-target", transport="sata", size_bytes=1200, partition_style="gpt", partition_roles=("efi", "windows", "recovery"))
    signer = FakeDetachedSigner()
    verifier = FakeDetachedVerifier()
    job = build_offline_job(source_before, target_before, now=now, nonce="fake-nonce-00000001")
    jobs = OfflineJobStore(root / "jobs")
    job_path = jobs.create(job, signer)
    loaded = jobs.load(job.job_id, verifier, now=now)
    source_after = OfflineBlockDevice("/dev/nvme1n1", source_before.model, source_before.serial, wwn=source_before.wwn, transport=source_before.transport, size_bytes=source_before.size_bytes, partition_style="gpt", partition_roles=source_before.partition_roles)
    target_after = OfflineBlockDevice("/dev/sdc", target_before.model, target_before.serial, wwn=target_before.wwn, transport=target_before.transport, size_bytes=target_before.size_bytes, partition_style="gpt", partition_roles=target_before.partition_roles)
    resolution = resolve_offline_devices(loaded, FakeOfflineInventory((source_after, target_after)), boot_medium_nodes=("/dev/sr0",))
    plan = ClonezillaCommandRenderer().render(loaded, resolution)
    result = build_fake_result(loaded, plan, source_after, target_after, now=now)
    result_path = OfflineResultStore(root / "results").create(result, signer)
    outcome = consume_offline_result(result_path, loaded, verifier, command_plan=plan, now=now, profile=OFFLINE_RESULT_PROFILE_SIMULATION)
    return {
        "state": outcome.state,
        "reason": outcome.reason,
        "job_id": loaded.job_id,
        "job_path": str(job_path),
        "result_path": str(result_path),
        "displayed_argv": list(plan.displayed_argv),
        "argv_hash": plan.argv_hash,
        "command_executed": False,
        "subprocess_called": False,
        "host_disk_touched": False,
        "reboot_boundary": {"recorded": True, "reboot_requested": False},
        "handoff": asdict(build_offline_boot_handoff_plan()),
        "boot_tested": outcome.result.boot_tested,
    }
