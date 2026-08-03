from __future__ import annotations

import hashlib
import json
import os
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from localvault.offline_clone import (
    ClonezillaCommandRenderer,
    FakeDetachedSigner,
    FakeDetachedVerifier,
    OfflineBlockDevice,
    OfflineCloneBlocked,
    ProductionOfflineSignatureVerifier,
    SignatureVerificationEvidence,
    build_offline_job,
    resolve_offline_devices,
)
from localvault.offline_runtime import (
    REQUIRED_RUNTIME_TOOLS,
    RuntimeArtifactEvidence,
    RuntimeExtractionManifest,
    OfflineRuntimeManifest,
    OfflineRuntimeValidator,
    RuntimeManifestStore,
    VirtualOfflineRunner,
    VirtualReturnChannel,
    VirtualSimulationPolicy,
    simulate_virtual_offline_round_trip,
)


def _devices() -> tuple[OfflineBlockDevice, OfflineBlockDevice]:
    return (
        OfflineBlockDevice("/dev/vda", "Synthetic Source", "SYNTH-SOURCE", wwn="wwn-source", transport="sata", size_bytes=1000, partition_style="gpt", partition_roles=("efi", "windows", "recovery")),
        OfflineBlockDevice("/dev/vdb", "Synthetic Target", "SYNTH-TARGET", wwn="wwn-target", transport="sata", size_bytes=1200, partition_style="gpt", partition_roles=("efi", "windows", "recovery")),
    )


def _job() -> tuple:
    source, target = _devices()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return build_offline_job(source, target, now=now, job_id="b" * 32, nonce="test-nonce-00000001"), source, target, now


def _tools_tree(root: Path) -> None:
    for name in REQUIRED_RUNTIME_TOOLS:
        folder = root / "usr" / ("sbin" if name == "ocs-onthefly" else "bin")
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / name
        path.write_text("synthetic-" + name, encoding="utf-8")
        path.chmod(0o755)


class _FixtureVerifier(FakeDetachedVerifier):
    @property
    def verification_evidence(self) -> SignatureVerificationEvidence:
        return SignatureVerificationEvidence("A" * 40, hashlib.sha256(b"fixture-public-keyring").hexdigest())


def _extraction_manifest(tmp_path: Path, tree: Path, iso: Path, signer: FakeDetachedSigner, *, source_iso_sha256: str | None = None, force_executable: bool = True) -> tuple[Path, bytes]:
    inventory, _ = OfflineRuntimeValidator._scan_tree(tree)
    if force_executable:
        for entry in inventory:
            if Path(entry["path"]).name in REQUIRED_RUNTIME_TOOLS:
                entry["executable"] = True
    manifest = RuntimeExtractionManifest(
        source_iso_filename=iso.name,
        source_iso_sha256=source_iso_sha256 or hashlib.sha256(iso.read_bytes()).hexdigest(),
        extraction_method="synthetic-test-fixture-v1",
        inventory_sha256=hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        files=tuple(inventory),
    )
    path = tmp_path / "extraction-manifest.json"
    raw = manifest.canonical_bytes()
    path.write_bytes(raw)
    return path, signer.sign(raw)


def test_manifest_is_canonical_signed_and_tampering_fails(tmp_path: Path):
    tools = {name: {"present": True, "status": "present_unexecuted", "path": f"/usr/{'sbin' if name == 'ocs-onthefly' else 'bin'}/{name}", "file_type": "regular", "size": 8, "sha256": "a" * 64, "executable": True} for name in REQUIRED_RUNTIME_TOOLS}
    artifact = RuntimeArtifactEvidence(iso_filename="clonezilla.iso", iso_sha256="a" * 64, official_checksum_manifest_sha256="b" * 64, official_checksum_signature_state="verified", official_checksum_signature_verified=True, signer_fingerprint="A" * 40, keyring_sha256="c" * 64, extraction_manifest_schema=1, extraction_method="synthetic-test-fixture-v1", extraction_manifest_sha256="d" * 64, extraction_inventory_sha256="e" * 64, required_tools=tools)
    manifest = OfflineRuntimeManifest(artifact=artifact, iso_provenance="synthetic fixture")
    store = RuntimeManifestStore(tmp_path)
    package = store.create(manifest, FakeDetachedSigner())
    assert store.load(package, FakeDetachedVerifier()) == manifest
    raw = json.loads((package / "runtime-manifest.json").read_text(encoding="utf-8"))
    raw["clonezilla_release"] = "3.3.3-18"
    (package / "runtime-manifest.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(OfflineCloneBlocked):
        store.load(package, FakeDetachedVerifier())


def test_runtime_validator_requires_official_artifacts_and_can_pass_static_fixture(tmp_path: Path):
    blocked = OfflineRuntimeValidator().validate()
    assert blocked.state == "offline_runtime_blocked"
    assert "official_iso_missing" in blocked.blockers

    iso = tmp_path / "clonezilla-live-3.3.3-15-amd64.iso"
    iso.write_bytes(b"synthetic official ISO fixture")
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    tree = tmp_path / "tree"
    _tools_tree(tree)
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    signer = FakeDetachedSigner()
    verifier = _FixtureVerifier()
    extraction_manifest, extraction_signature = _extraction_manifest(tmp_path, tree, iso, signer)
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(
        iso_path=iso,
        extracted_tree=tree,
        checksums_path=checksums,
        checksums_signature=signer.sign(checksums.read_bytes()),
        verifier=verifier,
        extraction_manifest_path=extraction_manifest,
        extraction_manifest_signature=extraction_signature,
        provenance="official stable artifact; filename only",
    )
    assert report.state == "offline_runtime_static_validation_passed"
    assert report.blockers == ()
    assert report.manifest.physical_boot_completed is False
    assert report.manifest.vm_boot_completed is False
    assert report.manifest.artifact.iso_filename == iso.name
    assert report.manifest.artifact.signer_fingerprint == verifier.verification_evidence.pinned_fingerprint
    assert report.manifest.artifact.keyring_sha256 == verifier.verification_evidence.keyring_sha256
    assert report.evidence["extracted_tree_binding_verified"] is True


def test_runtime_validator_rejects_missing_tool_and_checksum_mismatch(tmp_path: Path):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    (tree / "usr" / "bin" / "gpgv").unlink()
    report = OfflineRuntimeValidator(expected_iso_sha256="0" * 64).validate(iso_path=iso, extracted_tree=tree)
    assert "iso_checksum_mismatch" in report.blockers
    assert "extracted_tree_binding_missing" in report.blockers
    assert report.state == "offline_runtime_blocked"


def test_correct_iso_with_unrelated_fabricated_tree_is_blocked(tmp_path: Path):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "unrelated-tree"
    _tools_tree(tree)
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text(f"{hashlib.sha256(iso.read_bytes()).hexdigest()} *{iso.name}\n", encoding="utf-8")
    signer = FakeDetachedSigner()
    report = OfflineRuntimeValidator(expected_iso_sha256=hashlib.sha256(iso.read_bytes()).hexdigest()).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=signer.sign(checksums.read_bytes()), verifier=_FixtureVerifier())
    assert report.state == "offline_runtime_blocked"
    assert "extracted_tree_binding_missing" in report.blockers


@pytest.mark.parametrize("kind", ["empty", "directory", "symlink", "outside", "duplicate", "non_executable"])
def test_required_tool_policy_blocks_unsafe_candidates(tmp_path: Path, kind: str):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    candidate = tree / "usr" / "bin" / "gpg"
    if kind == "empty":
        candidate.write_bytes(b"")
    elif kind == "directory":
        candidate.unlink()
        candidate.mkdir()
    elif kind == "symlink":
        candidate.unlink()
        try:
            candidate.symlink_to(tree / "usr" / "bin" / "gpgv")
        except OSError:
            pytest.skip("symlink fixtures are unavailable on this host")
    elif kind == "outside":
        candidate.unlink()
        outside = tmp_path / "outside-gpg"
        outside.write_text("outside", encoding="utf-8")
        try:
            candidate.symlink_to(outside)
        except OSError:
            pytest.skip("symlink fixtures are unavailable on this host")
    elif kind == "duplicate":
        duplicate = tree / "usr" / "sbin" / "gpg"
        duplicate.parent.mkdir(parents=True, exist_ok=True)
        duplicate.write_text("duplicate", encoding="utf-8")
        duplicate.chmod(0o755)
    elif kind == "non_executable":
        candidate.chmod(0o644)
    signer = FakeDetachedSigner()
    manifest, signature = _extraction_manifest(tmp_path, tree, iso, signer, force_executable=kind != "non_executable")
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=signer.sign(checksums.read_bytes()), verifier=_FixtureVerifier(), extraction_manifest_path=manifest, extraction_manifest_signature=signature)
    assert report.state == "offline_runtime_blocked"
    assert any(name in " ".join(report.blockers) for name in ("gpg", "symlink", "non_executable", "ambiguous", "missing"))


def test_tree_manifest_binding_rejects_wrong_iso_digest_and_altered_file(tmp_path: Path):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    signer = FakeDetachedSigner()
    wrong_manifest, wrong_signature = _extraction_manifest(tmp_path, tree, iso, signer, source_iso_sha256="f" * 64)
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=signer.sign(checksums.read_bytes()), verifier=_FixtureVerifier(), extraction_manifest_path=wrong_manifest, extraction_manifest_signature=wrong_signature)
    assert report.state == "offline_runtime_blocked"
    assert "extracted_tree_source_iso_mismatch" in report.blockers

    altered = tree / "usr" / "bin" / "gpg"
    altered.write_text("altered", encoding="utf-8")
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=signer.sign(checksums.read_bytes()), verifier=_FixtureVerifier(), extraction_manifest_path=wrong_manifest, extraction_manifest_signature=wrong_signature)
    assert report.state == "offline_runtime_blocked"
    assert "extracted_tree_file_digest_mismatch" in report.blockers


def test_extraction_manifest_is_strict_canonical_and_signed(tmp_path: Path):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    signer = FakeDetachedSigner()
    manifest, signature = _extraction_manifest(tmp_path, tree, iso, signer)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["unexpected"] = True
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=signer.sign(checksums.read_bytes()), verifier=_FixtureVerifier(), extraction_manifest_path=manifest, extraction_manifest_signature=signature)
    assert report.state == "offline_runtime_blocked"
    assert "manifest" in " ".join(report.blockers)


@pytest.mark.parametrize("mutation", ["added", "removed", "wrong_signature"])
def test_extraction_manifest_changes_or_signature_replay_are_blocked(tmp_path: Path, mutation: str):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    signer = FakeDetachedSigner()
    manifest, signature = _extraction_manifest(tmp_path, tree, iso, signer)
    if mutation == "wrong_signature":
        signature = b"wrong-signature"
    else:
        raw = json.loads(manifest.read_text(encoding="utf-8"))
        if mutation == "removed":
            raw["files"] = raw["files"][1:]
        else:
            raw["files"].append({"path": "usr/bin/extra-tool", "file_type": "regular", "size": 1, "sha256": "a" * 64, "executable": True})
        raw["inventory_sha256"] = hashlib.sha256(json.dumps(raw["files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        raw_bytes = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        manifest.write_bytes(raw_bytes)
        signature = signer.sign(raw_bytes)
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=signer.sign(checksums.read_bytes()), verifier=_FixtureVerifier(), extraction_manifest_path=manifest, extraction_manifest_signature=signature)
    assert report.state == "offline_runtime_blocked"
    assert any("extraction" in blocker or "inventory" in blocker for blocker in report.blockers)


def test_runtime_public_payload_does_not_leak_fixture_paths_or_device_nodes(tmp_path: Path):
    report = OfflineRuntimeValidator().validate(provenance="synthetic fixture")
    payload = json.dumps(report.payload(), ensure_ascii=False)
    assert str(tmp_path) not in payload
    assert "/dev/" not in payload
    assert "private key" not in payload.casefold()


def test_verifier_evidence_is_derived_and_legacy_keyring_injection_is_not_accepted(tmp_path: Path):
    verifier, fingerprint = _fake_verifier(tmp_path)
    assert verifier.pinned_fingerprint == fingerprint
    assert verifier.keyring_sha256 == hashlib.sha256(b"public test keyring").hexdigest()
    with pytest.raises(TypeError):
        ProductionOfflineSignatureVerifier(sys.executable, verifier.public_keyring, fingerprint, keyring_sha256="a" * 64)


def test_production_keyring_writable_or_changed_during_verification_is_blocked(tmp_path: Path):
    verifier, _ = _fake_verifier(tmp_path)
    verifier.public_keyring.chmod(0o644)
    with pytest.raises(OfflineCloneBlocked, match="writable"):
        verifier.verify(b"payload", b"detached")

    stable_dir = tmp_path / "stable"
    stable_dir.mkdir()
    stable, _ = _fake_verifier(stable_dir)
    assert stable.verify(b"payload", b"detached") is True
    stable.public_keyring.chmod(0o644)
    stable.public_keyring.write_bytes(b"changed public keyring")
    stable.public_keyring.chmod(0o444)
    with pytest.raises(OfflineCloneBlocked, match="changed"):
        stable.verify(b"payload", b"detached")


def _fake_verifier(tmp_path: Path, mode: str = "valid") -> tuple[ProductionOfflineSignatureVerifier, str]:
    fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
    script = tmp_path / "fake_gpgv.py"
    script.write_text(
        textwrap.dedent(
            f"""
            import sys, time
            mode = {mode!r}
            if mode == 'timeout':
                time.sleep(2)
            if mode == 'oversized':
                print('x' * 100000)
            elif mode == 'valid':
                print('[GNUPG:] VALIDSIG {fingerprint} 20260802T000000Z 1 10 00 0123456789ABCDEF0123456789ABCDEF01234567')
            elif mode == 'wrong-key':
                print('[GNUPG:] VALIDSIG FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 20260802T000000Z 1 10 00 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
            sys.exit(0)
            """
        ),
        encoding="utf-8",
    )
    keyring = tmp_path / "trusted.gpg"
    keyring.write_bytes(b"public test keyring")
    keyring.chmod(0o444)
    verifier = ProductionOfflineSignatureVerifier(
        sys.executable,
        keyring,
        fingerprint,
        command_suffix=(str(script),),
        timeout_seconds=0.2 if mode == "timeout" else 5,
        max_output_bytes=4096,
    )
    return verifier, fingerprint


def test_production_gpgv_adapter_is_argv_only_pinned_and_bounded(tmp_path: Path):
    verifier, _ = _fake_verifier(tmp_path)
    assert verifier.verify(b"payload", b"detached") is True

    missing = ProductionOfflineSignatureVerifier(tmp_path / "missing-gpgv", verifier.public_keyring, verifier.expected_fingerprint)
    with pytest.raises(OfflineCloneBlocked, match="path is unsafe"):
        missing.verify(b"payload", b"detached")
    private_keyring = tmp_path / "private-key-material.gpg"
    private_keyring.write_bytes(b"-----BEGIN PRIVATE KEY-----")
    private_keyring.chmod(0o444)
    private_material = ProductionOfflineSignatureVerifier(sys.executable, private_keyring, verifier.expected_fingerprint, command_suffix=verifier.command_suffix)
    with pytest.raises(OfflineCloneBlocked, match="private key"):
        private_material.verify(b"payload", b"detached")

    wrong_dir = tmp_path / "wrong-key"
    wrong_dir.mkdir()
    wrong, _ = _fake_verifier(wrong_dir, "wrong-key")
    assert wrong.verify(b"payload", b"detached") is False

    timeout_dir = tmp_path / "timeout"
    timeout_dir.mkdir()
    timeout, _ = _fake_verifier(timeout_dir, "timeout")
    with pytest.raises(OfflineCloneBlocked, match="timed out"):
        timeout.verify(b"payload", b"detached")

    oversized_dir = tmp_path / "oversized"
    oversized_dir.mkdir()
    oversized, _ = _fake_verifier(oversized_dir, "oversized")
    with pytest.raises(OfflineCloneBlocked, match="output"):
        oversized.verify(b"payload", b"detached")


def test_virtual_return_channel_round_trip_is_durable_and_idempotent(tmp_path: Path):
    result = simulate_virtual_offline_round_trip(tmp_path)
    assert result["state"] == "consumed"
    assert result["durable_return_round_trip"] is True
    assert result["replay_after_restart"] is True
    assert result["physical_disk_touched"] is False
    assert "/dev/vda" not in json.dumps(result)
    assert "SYNTH-SOURCE" not in json.dumps(result)


@pytest.mark.parametrize("step", ["result_manifest", "result_signature", "channel_manifest", "final_rename"])
def test_return_channel_crash_never_becomes_success(tmp_path: Path, step: str):
    job, source, target, now = _job()
    channel = VirtualReturnChannel(tmp_path / "channel")
    signer = FakeDetachedSigner()
    channel.initialize(job)
    channel.mark_running(job)
    plan = ClonezillaCommandRenderer().render(job, resolve_offline_devices(job, (source, target)))
    from localvault.offline_clone import build_fake_result

    result = build_fake_result(job, plan, source, target, now=now)
    with pytest.raises(RuntimeError):
        channel.publish_result(job, result, signer, fault_injector=lambda actual: (_ for _ in ()).throw(RuntimeError("simulated crash")) if actual == step else None)
    assert channel.status().state == "running"
    recovered = channel.recover(job)
    assert recovered.state == "failed"
    assert channel.status().state != "consumed"


def test_virtual_runner_rejects_boot_medium_and_production_consumer_rejects_fake_result(tmp_path: Path):
    job, source, target, now = _job()
    channel = VirtualReturnChannel(tmp_path / "channel")
    runner = VirtualOfflineRunner(channel, FakeDetachedSigner(), FakeDetachedVerifier(), policy=VirtualSimulationPolicy())
    blocked = runner.run(job, (source, target), now=now, boot_medium_nodes=(source.node,))
    assert blocked["state"] == "offline_runtime_blocked"
    assert channel.status().state == "failed"

    job, source, target, now = _job()
    channel = VirtualReturnChannel(tmp_path / "channel2")
    runner = VirtualOfflineRunner(channel, FakeDetachedSigner(), FakeDetachedVerifier(), policy=VirtualSimulationPolicy())
    published = runner.run(job, (source, target), now=now)
    assert published["state"] == "offline_return_channel_ready"
    plan = ClonezillaCommandRenderer().render(job, resolve_offline_devices(job, (source, target)))
    consumed = channel.consume(job, FakeDetachedVerifier(), expected_command_hash=plan.argv_hash, command_plan=plan, now=now, profile="production")
    assert consumed.state == "failed"
    assert not hasattr(runner, "execute_real")


def test_return_channel_rejects_duplicate_and_stale_packages(tmp_path: Path):
    job, source, target, now = _job()
    channel = VirtualReturnChannel(tmp_path / "duplicate")
    runner = VirtualOfflineRunner(channel, FakeDetachedSigner(), FakeDetachedVerifier(), policy=VirtualSimulationPolicy())
    runner.run(job, (source, target), now=now)
    (channel.root / "result-conflict").mkdir()
    plan = ClonezillaCommandRenderer().render(job, resolve_offline_devices(job, (source, target)))
    duplicate = channel.consume(job, FakeDetachedVerifier(), expected_command_hash=plan.argv_hash, command_plan=plan, now=now, profile="simulation")
    assert duplicate.state == "failed"

    job, source, target, now = _job()
    channel = VirtualReturnChannel(tmp_path / "stale")
    runner = VirtualOfflineRunner(channel, FakeDetachedSigner(), FakeDetachedVerifier(), policy=VirtualSimulationPolicy())
    runner.run(job, (source, target), now=now)
    metadata = json.loads(channel.meta_path.read_text(encoding="utf-8"))
    metadata["expires_at"] = (now - timedelta(minutes=1)).isoformat()
    channel.meta_path.write_text(json.dumps(metadata), encoding="utf-8")
    plan = ClonezillaCommandRenderer().render(job, resolve_offline_devices(job, (source, target)))
    stale = channel.consume(job, FakeDetachedVerifier(), expected_command_hash=plan.argv_hash, command_plan=plan, now=now, profile="simulation")
    assert stale.state == "failed"
    assert channel.status().state == "failed"
