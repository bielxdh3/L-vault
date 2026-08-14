"""Bounded, non-booted Clonezilla artifact provisioning and extraction helpers.

Only regular files and ordinary directories are handled here.  The module has
no disk, mount, VM, boot, or Clonezilla-runtime execution path.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .offline_clone import (
    OfflineCloneBlocked,
    ProductionOfflineSignatureVerifier,
    SignatureVerificationEvidence,
    canonical_json,
)
from .offline_runtime import (
    CLONEZILLA_SIGNER_FINGERPRINT,
    CLONEZILLA_STABLE_AMD64_ISO_FILENAME,
    CLONEZILLA_STABLE_AMD64_ISO_SHA256,
    LOCAL_EXTRACTION_ATTESTATION_DOMAIN,
    LOCAL_EXTRACTION_ATTESTATION_SCHEME,
    PRODUCTION_EXTRACTION_MANIFEST_SCHEMA,
    PRODUCTION_EXTRACTION_METHOD,
    PRODUCTION_EXTRACTION_POLICY,
    REQUIRED_RUNTIME_TOOLS,
    RuntimeExtractionManifest,
    OfflineRuntimeValidator,
    OfficialChecksumVerifier,
)
from .utils import sha256_file


OFFICIAL_MIRROR_BASE = "https://free.nchc.org.tw/clonezilla-live/stable"
OFFICIAL_MIRROR_HOST = "free.nchc.org.tw"
OFFICIAL_KEY_HOST = "keys.openpgp.org"
OFFICIAL_KEY_URL = f"https://{OFFICIAL_KEY_HOST}/vks/v1/by-fingerprint/{CLONEZILLA_SIGNER_FINGERPRINT}"
OFFICIAL_CHECKSUM_FILENAME = "CHECKSUMS.TXT"
OFFICIAL_SIGNATURE_FILENAME = "CHECKSUMS.TXT.gpg"
OFFICIAL_KEY_FILENAME = "drbl-clonezilla-public.asc"
ARTIFACT_RECORD_FILENAME = "official-artifact-record.json"
MAX_ISO_BYTES = 800 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SIGNATURE_BYTES = 256 * 1024
MAX_KEY_BYTES = 4 * 1024 * 1024
MAX_EXTRACTOR_OUTPUT_BYTES = 256 * 1024
MAX_EXTRACTOR_SECONDS = 30 * 60
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT = re.compile(r"^[0-9A-F]{40,64}$")
_SAFE_NAME = re.compile(r"^[^\\/:\x00-\x1f\x7f]+$")
_REPARSE_POINT = 0x400


def _gpg_fs_path(value: str) -> str:
    if re.fullmatch(r"[A-Za-z]:[\\/].*", value):
        return f"/{value[0].lower()}/{value[2:].replace('\\\\', '/').replace('\\', '/')}"
    return value.replace("\\", "/") if value.startswith("\\\\") else value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_reparse(path: Path) -> bool:
    try:
        value = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(value & _REPARSE_POINT)


def _regular_file(path: Path, *, label: str) -> None:
    if path.is_symlink() or _is_reparse(path) or not path.is_file():
        raise OfflineCloneBlocked(f"{label} path is unsafe", "artifact_provisioning_blocked")


def _safe_name(value: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."} or not _SAFE_NAME.fullmatch(value):
        raise OfflineCloneBlocked("artifact filename is unsafe", "artifact_provisioning_blocked")
    return value


def _assert_outside(path: Path, forbidden: Iterable[Path]) -> None:
    target = path.resolve(strict=False)
    for item in forbidden:
        base = item.resolve(strict=False)
        if target == base or target.is_relative_to(base):
            raise OfflineCloneBlocked("artifact cache must be outside the repository", "artifact_provisioning_blocked")


def ensure_private_cache(cache: Path, *, repository: Path) -> Path:
    cache = Path(cache)
    _assert_outside(cache, (repository, repository / ".git"))
    if cache.exists() and (cache.is_symlink() or _is_reparse(cache) or not cache.is_dir()):
        raise OfflineCloneBlocked("artifact cache directory is unsafe", "artifact_provisioning_blocked")
    cache.mkdir(parents=True, exist_ok=True)
    try:
        cache.chmod(0o700)
    except OSError:
        pass
    return cache


@dataclass(frozen=True)
class ArtifactRecord:
    filename: str
    source_host: str
    retrieval_date: str
    content_length: int
    sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "source_host": self.source_host,
            "retrieval_date": self.retrieval_date,
            "content_length": self.content_length,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class OfficialArtifactBundle:
    iso: Path
    checksums: Path
    signature: Path
    public_key: Path
    records: tuple[ArtifactRecord, ...]


class _BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str]):
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        parsed = urllib.parse.urlparse(newurl)
        host = (parsed.hostname or "").casefold()
        if parsed.scheme != "https" or (host not in self.allowed_hosts and not host.endswith(".dl.sourceforge.net")):
            raise OfflineCloneBlocked("official artifact redirect leaves the allowlisted HTTPS hosts", "artifact_provisioning_blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class BoundedArtifactDownloader:
    """Fetch only bounded public files, atomically, with no ambient credentials."""

    def __init__(self, *, allowed_hosts: frozenset[str] | None = None, timeout_seconds: float = 60.0):
        self.allowed_hosts = allowed_hosts or frozenset({OFFICIAL_MIRROR_HOST, OFFICIAL_KEY_HOST, "clonezilla.org", "sourceforge.net", "downloads.sourceforge.net"})
        self.timeout_seconds = float(timeout_seconds)

    def fetch(self, url: str, destination: Path, *, max_bytes: int, expected_sha256: str | None = None, offline: bool = False) -> ArtifactRecord:
        destination = Path(destination)
        _safe_name(destination.name)
        _assert_outside(destination, (destination.parent / ".git",))
        if destination.exists():
            _regular_file(destination, label="artifact destination")
            if destination.stat().st_size > max_bytes:
                raise OfflineCloneBlocked("cached artifact exceeds its size bound", "artifact_provisioning_blocked")
            digest = sha256_file(destination)
            if expected_sha256 and digest != expected_sha256:
                raise OfflineCloneBlocked("cached artifact digest does not match the pinned digest", "artifact_provisioning_blocked")
            if offline:
                return ArtifactRecord(destination.name, (urllib.parse.urlparse(url).hostname or "").casefold(), _now(), destination.stat().st_size, digest)
        if offline:
            raise OfflineCloneBlocked("required artifact is missing in offline mode", "artifact_provisioning_blocked")
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").casefold()
        if parsed.scheme != "https" or (host not in self.allowed_hosts and not host.endswith(".dl.sourceforge.net")):
            raise OfflineCloneBlocked("artifact source host is not allowlisted", "artifact_provisioning_blocked")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.parent.is_symlink() or _is_reparse(destination.parent):
            raise OfflineCloneBlocked("artifact destination directory is unsafe", "artifact_provisioning_blocked")
        opener = urllib.request.build_opener(_BoundedRedirectHandler(self.allowed_hosts))
        request = urllib.request.Request(url, headers={"User-Agent": "LocalVault-static-artifact-validator/1"}, method="GET")
        descriptor, partial_name = tempfile.mkstemp(prefix=f".{destination.name}.partial-", dir=destination.parent)
        os.close(descriptor)
        partial = Path(partial_name)
        try:
            partial.chmod(0o600)
            with opener.open(request, timeout=self.timeout_seconds) as response:
                final = urllib.parse.urlparse(response.geturl())
                final_host = (final.hostname or "").casefold()
                if final.scheme != "https" or (final_host not in self.allowed_hosts and not final_host.endswith(".dl.sourceforge.net")):
                    raise OfflineCloneBlocked("artifact final host is not allowlisted", "artifact_provisioning_blocked")
                header_length = response.headers.get("Content-Length")
                if header_length and int(header_length) > max_bytes:
                    raise OfflineCloneBlocked("artifact response exceeds its size bound", "artifact_provisioning_blocked")
                digest = hashlib.sha256()
                written = 0
                with partial.open("wb") as handle:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > max_bytes:
                            raise OfflineCloneBlocked("artifact response exceeded its size bound", "artifact_provisioning_blocked")
                        digest.update(chunk)
                        handle.write(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
                actual = digest.hexdigest()
                if expected_sha256 and actual != expected_sha256:
                    raise OfflineCloneBlocked("downloaded artifact digest does not match the pinned digest", "artifact_provisioning_blocked")
                os.replace(partial, destination)
                return ArtifactRecord(destination.name, final_host, _now(), written, actual)
        except OfflineCloneBlocked:
            raise
        except (OSError, urllib.error.URLError, ValueError) as exc:
            raise OfflineCloneBlocked("official artifact download failed", "artifact_provisioning_blocked") from exc


def official_artifact_urls() -> dict[str, str]:
    return {
        "iso": f"{OFFICIAL_MIRROR_BASE}/{CLONEZILLA_STABLE_AMD64_ISO_FILENAME}",
        "checksums": f"{OFFICIAL_MIRROR_BASE}/{OFFICIAL_CHECKSUM_FILENAME}",
        "signature": f"{OFFICIAL_MIRROR_BASE}/{OFFICIAL_SIGNATURE_FILENAME}",
        "public_key": OFFICIAL_KEY_URL,
    }


def acquire_official_bundle(cache: Path, *, repository: Path, offline: bool = False, downloader: BoundedArtifactDownloader | None = None) -> OfficialArtifactBundle:
    cache = ensure_private_cache(cache, repository=repository)
    fetcher = downloader or BoundedArtifactDownloader()
    urls = official_artifact_urls()
    records = (
        fetcher.fetch(urls["checksums"], cache / OFFICIAL_CHECKSUM_FILENAME, max_bytes=MAX_MANIFEST_BYTES, offline=offline),
        fetcher.fetch(urls["signature"], cache / OFFICIAL_SIGNATURE_FILENAME, max_bytes=MAX_SIGNATURE_BYTES, offline=offline),
        fetcher.fetch(urls["public_key"], cache / OFFICIAL_KEY_FILENAME, max_bytes=MAX_KEY_BYTES, offline=offline),
        fetcher.fetch(urls["iso"], cache / CLONEZILLA_STABLE_AMD64_ISO_FILENAME, max_bytes=MAX_ISO_BYTES, expected_sha256=CLONEZILLA_STABLE_AMD64_ISO_SHA256, offline=offline),
    )
    return OfficialArtifactBundle(cache / CLONEZILLA_STABLE_AMD64_ISO_FILENAME, cache / OFFICIAL_CHECKSUM_FILENAME, cache / OFFICIAL_SIGNATURE_FILENAME, cache / OFFICIAL_KEY_FILENAME, records)


def _run_gpg(argv: list[str], *, cwd: Path, timeout_seconds: float = 30.0) -> subprocess.CompletedProcess[bytes]:
    if not argv or not Path(argv[0]).is_absolute():
        raise OfflineCloneBlocked("GPG executable path must be absolute", "artifact_provisioning_blocked")
    try:
        translated = [argv[0], *(_gpg_fs_path(value) for value in argv[1:])]
        return subprocess.run(translated, cwd=cwd, env={"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "PATH": ""}, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OfflineCloneBlocked("isolated GPG operation could not complete", "artifact_provisioning_blocked") from exc


def provision_official_public_keyring(*, armored_key: Path, destination: Path, gpg_binary: Path, repository: Path) -> tuple[str, str]:
    """Import one fingerprint-directed public key into an isolated public keyring."""
    _regular_file(armored_key, label="official public key")
    if armored_key.stat().st_size > MAX_KEY_BYTES:
        raise OfflineCloneBlocked("official public key is oversized", "artifact_provisioning_blocked")
    _assert_outside(destination, (repository, repository / ".git"))
    if destination.exists():
        _regular_file(destination, label="official public keyring")
        if destination.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
            raise OfflineCloneBlocked("official public keyring is writable", "artifact_provisioning_blocked")
        if b"PRIVATE KEY" in destination.read_bytes():
            raise OfflineCloneBlocked("official public keyring contains private key material", "artifact_provisioning_blocked")
        with tempfile.TemporaryDirectory(prefix="localvault-drbl-inspect-") as isolated:
            inspected = _run_gpg([str(gpg_binary), "--batch", "--no-options", "--no-autostart", "--homedir", isolated, "--with-colons", "--show-keys", str(destination)], cwd=destination.parent)
        fingerprints = [line.split(":")[9].upper() for line in inspected.stdout.decode("utf-8", "replace").splitlines() if line.startswith("fpr:") and len(line.split(":")) > 9 and _FINGERPRINT.fullmatch(line.split(":")[9].upper())]
        primary_count = sum(1 for line in inspected.stdout.decode("utf-8", "replace").splitlines() if line.startswith("pub:"))
        if inspected.returncode != 0 or primary_count != 1 or not fingerprints or fingerprints[0] != CLONEZILLA_SIGNER_FINGERPRINT:
            raise OfflineCloneBlocked("official public keyring does not contain exactly the pinned DRBL key", "artifact_provisioning_blocked")
        return CLONEZILLA_SIGNER_FINGERPRINT, sha256_file(destination)
    _regular_file(gpg_binary, label="GPG executable")
    with tempfile.TemporaryDirectory(prefix="localvault-drbl-key-") as isolated:
        home = Path(isolated)
        imported = home / "key.asc"
        imported.write_bytes(armored_key.read_bytes())
        _run_gpg([str(gpg_binary), "--batch", "--no-options", "--no-autostart", "--homedir", str(home), "--import", str(imported)], cwd=home)
        listed = _run_gpg([str(gpg_binary), "--batch", "--no-options", "--no-autostart", "--homedir", str(home), "--with-colons", "--fingerprint", "--list-keys"], cwd=home)
        if listed.returncode != 0:
            raise OfflineCloneBlocked("official public key fingerprint inspection failed", "artifact_provisioning_blocked")
        fingerprints = []
        primary_count = 0
        for line in listed.stdout.decode("utf-8", "replace").splitlines():
            fields = line.split(":")
            if fields and fields[0] == "pub":
                primary_count += 1
            if len(fields) > 9 and fields[0] == "fpr" and _FINGERPRINT.fullmatch(fields[9].upper()):
                fingerprints.append(fields[9].upper())
        primary = fingerprints[0] if fingerprints else ""
        if primary_count != 1 or primary != CLONEZILLA_SIGNER_FINGERPRINT or not fingerprints:
            raise OfflineCloneBlocked("official public key fingerprint is not the pinned DRBL key", "artifact_provisioning_blocked")
        exported = _run_gpg([str(gpg_binary), "--batch", "--no-options", "--no-autostart", "--homedir", str(home), "--export-options", "export-minimal", "--export", CLONEZILLA_SIGNER_FINGERPRINT], cwd=home)
        if exported.returncode != 0 or not exported.stdout:
            raise OfflineCloneBlocked("official public key export failed", "artifact_provisioning_blocked")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.partial-", dir=destination.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.chmod(0o600)
        with temporary.open("wb") as handle:
            handle.write(exported.stdout)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o444)
        os.replace(temporary, destination)
    except OSError as exc:
        raise OfflineCloneBlocked("official public keyring could not be promoted safely", "artifact_provisioning_blocked") from exc
    return provision_official_public_keyring(armored_key=armored_key, destination=destination, gpg_binary=gpg_binary, repository=repository)


def parse_sha256_manifest(raw: bytes, *, expected_filename: str, expected_sha256: str) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OfflineCloneBlocked("official checksum manifest is not UTF-8", "artifact_provisioning_blocked") from exc
    matches: list[str] = []
    in_sha256_section = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("### "):
            in_sha256_section = line.casefold() == "### sha256sums:"
            continue
        if not in_sha256_section:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?([^\s]+)", line)
        if match and match.group(2) == expected_filename:
            matches.append(match.group(1).lower())
    if matches != [expected_sha256.lower()]:
        raise OfflineCloneBlocked("official checksum manifest does not bind exactly one pinned ISO filename and digest", "artifact_provisioning_blocked")


@dataclass(frozen=True)
class OfficialVerification:
    verifier: OfficialChecksumVerifier
    evidence: SignatureVerificationEvidence
    checksum_manifest_sha256: str
    iso_sha256: str


def verify_official_bundle(bundle: OfficialArtifactBundle, *, gpgv_binary: Path, public_keyring: Path) -> OfficialVerification:
    _regular_file(bundle.iso, label="official ISO")
    _regular_file(bundle.checksums, label="official checksum manifest")
    _regular_file(bundle.signature, label="official checksum signature")
    _regular_file(public_keyring, label="official public keyring")
    if bundle.iso.name != CLONEZILLA_STABLE_AMD64_ISO_FILENAME:
        raise OfflineCloneBlocked("official ISO filename is not pinned", "artifact_provisioning_blocked")
    iso_digest = sha256_file(bundle.iso)
    if iso_digest != CLONEZILLA_STABLE_AMD64_ISO_SHA256:
        raise OfflineCloneBlocked("official ISO digest is not pinned", "artifact_provisioning_blocked")
    official = OfficialChecksumVerifier(ProductionOfflineSignatureVerifier(gpgv_binary, public_keyring, CLONEZILLA_SIGNER_FINGERPRINT))
    checksum_raw = bundle.checksums.read_bytes()
    signature = bundle.signature.read_bytes()
    if not official.verify(checksum_raw, signature):
        raise OfflineCloneBlocked("official checksum signature is invalid", "artifact_provisioning_blocked")
    parse_sha256_manifest(checksum_raw, expected_filename=bundle.iso.name, expected_sha256=CLONEZILLA_STABLE_AMD64_ISO_SHA256)
    return OfficialVerification(official, official.verification_evidence, hashlib.sha256(checksum_raw).hexdigest(), iso_digest)


class GpgDetachedSigner:
    """Use an existing protected local identity through normal pinentry."""

    def __init__(self, *, gpg_binary: Path, gnupg_home: Path, key_fingerprint: str):
        _regular_file(gpg_binary, label="GPG executable")
        if not Path(gnupg_home).is_absolute() or Path(gnupg_home).is_symlink() or _is_reparse(Path(gnupg_home)) or not Path(gnupg_home).is_dir():
            raise OfflineCloneBlocked("local attestor key home is unsafe", "local_attestation_provisioning_blocked")
        fingerprint = re.sub(r"\s+", "", str(key_fingerprint)).upper()
        if not _FINGERPRINT.fullmatch(fingerprint):
            raise OfflineCloneBlocked("local attestor fingerprint is invalid", "local_attestation_provisioning_blocked")
        self.gpg_binary = Path(gpg_binary)
        self.gnupg_home = Path(gnupg_home)
        self.key_fingerprint = fingerprint

    def sign(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes) or len(payload) > 8 * 1024 * 1024:
            raise OfflineCloneBlocked("local attestation payload is invalid or oversized", "local_attestation_provisioning_blocked")
        with tempfile.TemporaryDirectory(prefix="localvault-attestation-sign-") as temporary:
            root = Path(temporary)
            payload_path = root / "payload"
            payload_path.write_bytes(payload)
            result = _run_gpg([str(self.gpg_binary), "--homedir", str(self.gnupg_home), "--local-user", self.key_fingerprint, "--detach-sign", "--output", "-", str(payload_path)], cwd=root, timeout_seconds=60)
            if result.returncode != 0 or not result.stdout:
                raise OfflineCloneBlocked("local attestation signing failed", "local_attestation_provisioning_blocked")
            return result.stdout


def inspect_local_attestor(*, gpg_binary: Path, gnupg_home: Path, public_keyring: Path | None = None) -> dict[str, Any]:
    """Return sanitized local-attestor state without exposing private paths or key bytes."""
    private_present = False
    fingerprints: list[str] = []
    if Path(gnupg_home).is_dir() and not Path(gnupg_home).is_symlink() and not _is_reparse(Path(gnupg_home)):
        result = _run_gpg([str(gpg_binary), "--batch", "--homedir", str(gnupg_home), "--with-colons", "--list-secret-keys"], cwd=Path(gnupg_home))
        if result.returncode == 0:
            private_present = any(line.startswith("sec:") for line in result.stdout.decode("utf-8", "replace").splitlines())
            fingerprints = [line.split(":")[9].upper() for line in result.stdout.decode("utf-8", "replace").splitlines() if line.startswith("fpr:") and len(line.split(":")) > 9 and _FINGERPRINT.fullmatch(line.split(":")[9].upper())]
    public_present = bool(public_keyring and public_keyring.is_file() and not public_keyring.is_symlink() and not _is_reparse(public_keyring))
    return {"private_key_present": private_present, "public_keyring_present": public_present, "public_keyring_sha256": sha256_file(public_keyring) if public_present and public_keyring else "", "fingerprint_count": len(fingerprints), "fingerprints": fingerprints}


def _bounded_run(argv: list[str], *, cwd: Path, timeout_seconds: float, max_output_bytes: int) -> tuple[int, bytes, bytes]:
    if not argv or not Path(argv[0]).is_absolute():
        raise OfflineCloneBlocked("extractor executable path must be absolute", "official_artifacts_verified_extraction_blocked")
    process = subprocess.Popen(argv, cwd=cwd, env={"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "PATH": ""}, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out: list[bytes] = []
    err: list[bytes] = []

    def reader(pipe, sink: list[bytes]) -> None:  # type: ignore[no-untyped-def]
        total = 0
        for chunk in iter(lambda: pipe.read(8192), b""):
            total += len(chunk)
            if total <= max_output_bytes:
                sink.append(chunk)
            else:
                sink.append(b"\x00LOCALVAULT_OUTPUT_OVERFLOW")
                break
        pipe.close()

    threads = [threading.Thread(target=reader, args=(process.stdout, out), daemon=True), threading.Thread(target=reader, args=(process.stderr, err), daemon=True)]
    for thread in threads:
        thread.start()
    try:
        code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait(timeout=2)
        raise OfflineCloneBlocked("trusted extraction timed out", "official_artifacts_verified_extraction_blocked") from exc
    for thread in threads:
        thread.join(timeout=2)
    stdout, stderr = b"".join(out), b"".join(err)
    if b"\x00LOCALVAULT_OUTPUT_OVERFLOW" in stdout or b"\x00LOCALVAULT_OUTPUT_OVERFLOW" in stderr:
        raise OfflineCloneBlocked("trusted extraction output exceeded its bound", "official_artifacts_verified_extraction_blocked")
    if code != 0:
        raise OfflineCloneBlocked("trusted extraction failed", "official_artifacts_verified_extraction_blocked")
    return code, stdout, stderr


@dataclass(frozen=True)
class ExtractorIdentity:
    product: str
    version: str
    executable_sha256: str
    origin: str = "already-installed-local-tool"

    def validate(self) -> None:
        if not self.product or not self.version or not _HEX64.fullmatch(self.executable_sha256) or self.origin != "already-installed-local-tool":
            raise OfflineCloneBlocked("extractor identity is incomplete", "official_artifacts_verified_extraction_blocked")


@dataclass(frozen=True)
class ExtractionProducts:
    rootfs_relative_path: str
    rootfs_sha256: str
    iso_extractor: ExtractorIdentity
    rootfs_extractor: ExtractorIdentity
    extraction_log_sha256: str


class TrustedClonezillaExtractor:
    """Narrow adapter for explicitly named host extractors; never runs output."""

    def __init__(self, *, iso_executable: Path, rootfs_executable: Path, iso_product: str, iso_version: str, rootfs_product: str, rootfs_version: str, timeout_seconds: float = MAX_EXTRACTOR_SECONDS):
        self.iso_executable = Path(iso_executable)
        self.rootfs_executable = Path(rootfs_executable)
        self.iso_identity = self._identity(self.iso_executable, iso_product, iso_version)
        self.rootfs_identity = self._identity(self.rootfs_executable, rootfs_product, rootfs_version)
        if not 0 < float(timeout_seconds) <= MAX_EXTRACTOR_SECONDS:
            raise OfflineCloneBlocked("trusted extraction timeout is invalid", "official_artifacts_verified_extraction_blocked")
        self.timeout_seconds = float(timeout_seconds)

    @staticmethod
    def _identity(executable: Path, product: str, version: str) -> ExtractorIdentity:
        _regular_file(executable, label="extractor executable")
        if not executable.is_absolute():
            raise OfflineCloneBlocked("extractor executable path must be absolute", "official_artifacts_verified_extraction_blocked")
        identity = ExtractorIdentity(product, version, sha256_file(executable))
        identity.validate()
        return identity

    def extract(self, iso: Path, stage_root: Path) -> ExtractionProducts:
        _regular_file(iso, label="verified ISO")
        if iso.name != CLONEZILLA_STABLE_AMD64_ISO_FILENAME or sha256_file(iso) != CLONEZILLA_STABLE_AMD64_ISO_SHA256:
            raise OfflineCloneBlocked("ISO digest changed before extraction", "official_artifacts_verified_extraction_blocked")
        stage_root = Path(stage_root)
        if stage_root.exists() and (stage_root.is_symlink() or _is_reparse(stage_root)):
            raise OfflineCloneBlocked("extraction staging root is unsafe", "official_artifacts_verified_extraction_blocked")
        stage_root.mkdir(parents=True, exist_ok=True)
        iso_tree = stage_root / "iso-tree"
        root_tree = stage_root / "root-tree"
        for destination in (iso_tree, root_tree):
            if destination.exists():
                if destination.is_symlink() or _is_reparse(destination) or any(destination.iterdir()):
                    raise OfflineCloneBlocked("extraction destination must be new and empty", "official_artifacts_verified_extraction_blocked")
            else:
                destination.mkdir()
        log = bytearray()
        # 7-Zip and bsdtar are intentionally the only supported ISO command shapes.
        if self.iso_identity.product.casefold() in {"7-zip", "7z"}:
            iso_argv = [str(self.iso_executable), "x", "-y", f"-o{iso_tree}", str(iso)]
        elif self.iso_identity.product.casefold() in {"bsdtar", "tar"}:
            iso_argv = [str(self.iso_executable), "-xf", str(iso), "-C", str(iso_tree)]
        else:
            raise OfflineCloneBlocked("trusted ISO extractor product is not allowlisted", "official_artifacts_verified_extraction_blocked")
        _, stdout, stderr = _bounded_run(iso_argv, cwd=stage_root, timeout_seconds=self.timeout_seconds, max_output_bytes=MAX_EXTRACTOR_OUTPUT_BYTES)
        log.extend(f"iso-extractor={self.iso_identity.product};version={self.iso_identity.version};exit=0\n".encode())
        log.extend(stdout[:MAX_EXTRACTOR_OUTPUT_BYTES])
        log.extend(stderr[:MAX_EXTRACTOR_OUTPUT_BYTES])
        candidates: list[Path] = []
        pending = [iso_tree]
        while pending:
            directory = pending.pop()
            try:
                entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
            except OSError as exc:
                raise OfflineCloneBlocked("trusted ISO tree cannot be inspected safely", "official_artifacts_verified_extraction_blocked") from exc
            for item in entries:
                path = Path(item.path)
                if item.is_symlink() or _is_reparse(path):
                    raise OfflineCloneBlocked("trusted ISO extraction produced a link or reparse point", "official_artifacts_verified_extraction_blocked")
                if item.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif item.is_file(follow_symlinks=False) and item.name.casefold() == "filesystem.squashfs":
                    candidates.append(path)
        if len(candidates) != 1:
            raise OfflineCloneBlocked("verified ISO did not yield exactly one compressed root filesystem", "official_artifacts_verified_extraction_blocked")
        rootfs = candidates[0]
        rootfs_digest = sha256_file(rootfs)
        _, stdout, stderr = _bounded_run([str(self.rootfs_executable), "-d", str(root_tree), str(rootfs)], cwd=stage_root, timeout_seconds=self.timeout_seconds, max_output_bytes=MAX_EXTRACTOR_OUTPUT_BYTES)
        log.extend(f"rootfs-extractor={self.rootfs_identity.product};version={self.rootfs_identity.version};exit=0\n".encode())
        log.extend(stdout[:MAX_EXTRACTOR_OUTPUT_BYTES])
        log.extend(stderr[:MAX_EXTRACTOR_OUTPUT_BYTES])
        relative = rootfs.relative_to(iso_tree).as_posix()
        return ExtractionProducts(relative, rootfs_digest, self.iso_identity, self.rootfs_identity, hashlib.sha256(bytes(log)).hexdigest())


def build_production_extraction_manifest(*, iso_filename: str, iso_sha256: str, checksum_manifest_sha256: str, official_evidence: SignatureVerificationEvidence, extracted_root: Path, products: ExtractionProducts, extraction_log: bytes = b"") -> RuntimeExtractionManifest:
    inventory, blockers = OfflineRuntimeValidator._scan_real_tree(Path(extracted_root))
    if blockers:
        raise OfflineCloneBlocked("real extracted tree failed safe inventory", "real_tree_validation_blocked")
    total_bytes = sum(item["size"] for item in inventory if item["file_type"] == "regular")
    inventory_digest = hashlib.sha256(canonical_json(inventory)).hexdigest()
    manifest = RuntimeExtractionManifest(
        source_iso_filename=iso_filename,
        source_iso_sha256=iso_sha256,
        attestation_domain=LOCAL_EXTRACTION_ATTESTATION_DOMAIN,
        attestation_scheme=LOCAL_EXTRACTION_ATTESTATION_SCHEME,
        extraction_method=PRODUCTION_EXTRACTION_METHOD,
        extractor_policy_version=PRODUCTION_EXTRACTION_POLICY,
        inventory_sha256=inventory_digest,
        files=tuple(inventory),
        created_at=_now(),
        production_extraction_completed=True,
        schema=PRODUCTION_EXTRACTION_MANIFEST_SCHEMA,
        rootfs_relative_path=products.rootfs_relative_path,
        rootfs_sha256=products.rootfs_sha256,
        iso_extractor_product=products.iso_extractor.product,
        iso_extractor_version=products.iso_extractor.version,
        iso_extractor_sha256=products.iso_extractor.executable_sha256,
        rootfs_extractor_product=products.rootfs_extractor.product,
        rootfs_extractor_version=products.rootfs_extractor.version,
        rootfs_extractor_sha256=products.rootfs_extractor.executable_sha256,
        extraction_log_sha256=hashlib.sha256(extraction_log).hexdigest() if extraction_log else products.extraction_log_sha256,
        entry_count=len(inventory),
        total_regular_file_bytes=total_bytes,
        required_tools_evidence_sha256="0" * 64,
        official_checksum_manifest_sha256=checksum_manifest_sha256,
        official_signer_fingerprint=official_evidence.pinned_fingerprint,
        official_keyring_sha256=official_evidence.keyring_sha256,
        vm_boot_completed=False,
        physical_boot_completed=False,
        clone_executed=False,
    )
    tools, blockers = OfflineRuntimeValidator._check_tree(Path(extracted_root), manifest)
    if blockers:
        raise OfflineCloneBlocked("real extracted tree required-tool policy failed", "real_tree_validation_blocked")
    evidence_digest = hashlib.sha256(canonical_json(tools)).hexdigest()
    return RuntimeExtractionManifest(**{**manifest.__dict__, "required_tools_evidence_sha256": evidence_digest})


def sanitize_artifact_records(records: Iterable[ArtifactRecord]) -> list[dict[str, Any]]:
    return [record.payload() for record in records]


def write_official_artifact_record(bundle: OfficialArtifactBundle, verification: OfficialVerification, *, keyring_sha256: str) -> Path:
    payload = {
        "schema": 1,
        "retrieval_date": max(record.retrieval_date for record in bundle.records),
        "source_hosts": sorted({record.source_host for record in bundle.records}),
        "artifacts": sanitize_artifact_records(bundle.records),
        "iso_filename": bundle.iso.name,
        "iso_sha256": verification.iso_sha256,
        "checksum_manifest_sha256": verification.checksum_manifest_sha256,
        "official_signer_fingerprint": verification.evidence.pinned_fingerprint,
        "official_keyring_sha256": keyring_sha256,
        "verification": "official_checksum_signature_and_exact_iso_digest",
    }
    destination = bundle.iso.parent / ARTIFACT_RECORD_FILENAME
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.partial-", dir=destination.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.chmod(0o600)
        with temporary.open("wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except OSError as exc:
        raise OfflineCloneBlocked("official artifact record could not be written safely", "artifact_provisioning_blocked") from exc
    return destination
