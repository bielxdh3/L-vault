from __future__ import annotations

import hashlib
import inspect
import os
import sys
from pathlib import Path

import pytest

import localvault.clonezilla_artifacts as artifacts
from localvault.clonezilla_artifacts import (
    BoundedArtifactDownloader,
    ExtractorIdentity,
    ExtractionProducts,
    TrustedClonezillaExtractor,
    build_production_extraction_manifest,
    ensure_private_cache,
    parse_sha256_manifest,
)
from localvault.offline_clone import OfflineCloneBlocked, SignatureVerificationEvidence
from localvault.offline_runtime import REQUIRED_RUNTIME_TOOLS, OfflineRuntimeValidator, PRODUCTION_EXTRACTION_MANIFEST_SCHEMA, RuntimeExtractionManifest


class _Response:
    def __init__(self, payload: bytes, url: str = "https://free.nchc.org.tw/file"):
        self.payload = payload
        self.offset = 0
        self.headers = {"Content-Length": str(len(payload))}
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def geturl(self):
        return self.url

    def read(self, size: int = -1):
        if self.offset >= len(self.payload):
            return b""
        end = len(self.payload) if size < 0 else min(self.offset + size, len(self.payload))
        value = self.payload[self.offset:end]
        self.offset = end
        return value


class _Opener:
    def __init__(self, payload: bytes):
        self.payload = payload

    def open(self, *_args, **_kwargs):
        return _Response(self.payload)


def _tools_tree(root: Path) -> None:
    for name in REQUIRED_RUNTIME_TOOLS:
        folder = root / "usr" / ("sbin" if name == "ocs-onthefly" else "bin")
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / name
        path.write_bytes(name.encode())
        path.chmod(0o755)


def test_manifest_requires_one_exact_pinned_filename():
    digest = "a" * 64
    parse_sha256_manifest(f"### SHA256SUMS:\n{digest} *clonezilla.iso\n".encode(), expected_filename="clonezilla.iso", expected_sha256=digest)
    with pytest.raises(OfflineCloneBlocked):
        parse_sha256_manifest(f"### SHA256SUMS:\n{digest} *clonezilla.iso\n{digest} *clonezilla.iso\n".encode(), expected_filename="clonezilla.iso", expected_sha256=digest)
    with pytest.raises(OfflineCloneBlocked):
        parse_sha256_manifest(f"### SHA256SUMS:\n{digest} *other.iso\n".encode(), expected_filename="clonezilla.iso", expected_sha256=digest)
    parse_sha256_manifest(f"### SHA256SUMS:\n{digest} *clonezilla.iso\n### B3SUMS:\n{'b' * 64} *clonezilla.iso\n".encode(), expected_filename="clonezilla.iso", expected_sha256=digest)


def test_cache_refuses_repository(tmp_path: Path):
    with pytest.raises(OfflineCloneBlocked):
        ensure_private_cache(tmp_path / "repo-cache", repository=tmp_path)
    cache = ensure_private_cache(tmp_path / "outside" / "cache", repository=tmp_path / "repo")
    assert cache.is_dir()


def test_bounded_downloader_promotes_atomically_and_revalidates_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    payload = b"artifact-bytes"
    monkeypatch.setattr(artifacts.urllib.request, "build_opener", lambda *_args: _Opener(payload))
    destination = tmp_path / "cache" / "artifact.bin"
    expected = hashlib.sha256(payload).hexdigest()
    record = BoundedArtifactDownloader().fetch("https://free.nchc.org.tw/artifact.bin", destination, max_bytes=1024, expected_sha256=expected)
    assert destination.read_bytes() == payload
    assert record.sha256 == expected
    cached = BoundedArtifactDownloader().fetch("https://free.nchc.org.tw/artifact.bin", destination, max_bytes=1024, expected_sha256=expected, offline=True)
    assert cached.sha256 == expected
    assert not list(destination.parent.glob("*.partial-*"))


def test_bounded_downloader_quarantines_oversized_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    payload = b"too-large"
    monkeypatch.setattr(artifacts.urllib.request, "build_opener", lambda *_args: _Opener(payload))
    with pytest.raises(OfflineCloneBlocked):
        BoundedArtifactDownloader().fetch("https://free.nchc.org.tw/artifact.bin", tmp_path / "artifact.bin", max_bytes=3)
    assert list(tmp_path.glob(".artifact.bin.partial-*"))


def test_extractor_requires_absolute_paths_and_does_not_use_shell(tmp_path: Path):
    with pytest.raises(OfflineCloneBlocked):
        TrustedClonezillaExtractor(iso_executable=Path("tar.exe"), rootfs_executable=Path(sys.executable), iso_product="tar", iso_version="x", rootfs_product="unsquashfs", rootfs_version="x")
    source = Path(sys.executable)
    extractor = TrustedClonezillaExtractor(iso_executable=source, rootfs_executable=source, iso_product="bsdtar", iso_version="fixture", rootfs_product="unsquashfs", rootfs_version="fixture")
    assert extractor.iso_identity.executable_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert "shell=False" in inspect.getsource(artifacts._bounded_run)


def test_real_inventory_preserves_safe_absolute_symlink_and_rejects_escape(tmp_path: Path):
    root = tmp_path / "tree"
    (root / "usr" / "bin").mkdir(parents=True)
    target = root / "usr" / "bin" / "gpg"
    target.write_bytes(b"gpg")
    try:
        (root / "usr" / "bin" / "gpgv").symlink_to("/usr/bin/gpg")
        (root / "usr" / "bin" / "escape").symlink_to("../../../outside")
    except OSError:
        pytest.skip("symlink fixtures are unavailable on this host")
    inventory, blockers = OfflineRuntimeValidator._scan_real_tree(root)
    assert any(item["file_type"] == "symlink" and item["target"] == "/usr/bin/gpg" for item in inventory)
    assert "symlink_escapes_image_root" in blockers


def test_production_attestation_binds_real_inventory_and_tool_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "root"
    _tools_tree(root)
    real_scan = OfflineRuntimeValidator._scan_real_tree

    def fixture_scan(path: Path):
        inventory, blockers = real_scan(path)
        for entry in inventory:
            if Path(entry["path"]).name in REQUIRED_RUNTIME_TOOLS and entry["file_type"] == "regular":
                entry["executable"] = True
        return inventory, blockers

    monkeypatch.setattr(OfflineRuntimeValidator, "_scan_real_tree", staticmethod(fixture_scan))
    executable = Path(sys.executable)
    identity = ExtractorIdentity("fixture-extractor", "1", hashlib.sha256(executable.read_bytes()).hexdigest())
    products = ExtractionProducts("live/filesystem.squashfs", "b" * 64, identity, identity, "c" * 64)
    manifest = build_production_extraction_manifest(iso_filename="clonezilla-live-3.3.3-15-amd64.iso", iso_sha256="d" * 64, checksum_manifest_sha256="e" * 64, official_evidence=SignatureVerificationEvidence("F" * 40, "f" * 64), extracted_root=root, products=products)
    assert manifest.schema == PRODUCTION_EXTRACTION_MANIFEST_SCHEMA
    assert manifest.entry_count == len(manifest.files)
    assert manifest.required_tools_evidence_sha256 != "0" * 64
    assert RuntimeExtractionManifest.from_dict(manifest.payload()) == manifest
