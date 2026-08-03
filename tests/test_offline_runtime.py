from __future__ import annotations

import hashlib
import inspect
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
    LOCAL_EXTRACTION_ATTESTATION_DOMAIN,
    LOCAL_EXTRACTION_ATTESTATION_SCHEME,
    PRODUCTION_EXTRACTION_METHOD,
    PRODUCTION_EXTRACTION_POLICY,
    REQUIRED_RUNTIME_TOOLS,
    SYNTHETIC_EXTRACTION_METHOD,
    SYNTHETIC_EXTRACTION_POLICY,
    OfficialChecksumVerifier,
    LocalExtractionAttestationVerifier,
    RuntimeArtifactEvidence,
    RuntimeExtractionManifest,
    OfflineRuntimeManifest,
    OfflineRuntimeValidator,
    RuntimeManifestStore,
    VirtualOfflineRunner,
    VirtualReturnChannel,
    VirtualSimulationPolicy,
    RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST,
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


def _roles() -> tuple[FakeDetachedSigner, FakeDetachedSigner, OfficialChecksumVerifier, LocalExtractionAttestationVerifier]:
    official_secret = b"official-test-root"
    local_secret = b"local-attestation-test-root"
    return (
        FakeDetachedSigner(official_secret),
        FakeDetachedSigner(local_secret),
        OfficialChecksumVerifier(FakeDetachedVerifier(official_secret)),
        LocalExtractionAttestationVerifier(FakeDetachedVerifier(local_secret)),
    )


def _extraction_manifest(tmp_path: Path, tree: Path, iso: Path, signer: FakeDetachedSigner, *, source_iso_sha256: str | None = None, force_executable: bool = True, extraction_method: str = SYNTHETIC_EXTRACTION_METHOD, production_extraction_completed: bool = False) -> tuple[Path, bytes]:
    inventory, _ = OfflineRuntimeValidator._scan_tree(tree)
    if force_executable:
        for entry in inventory:
            if Path(entry["path"]).name in REQUIRED_RUNTIME_TOOLS:
                entry["executable"] = True
    manifest = RuntimeExtractionManifest(
        source_iso_filename=iso.name,
        source_iso_sha256=source_iso_sha256 or hashlib.sha256(iso.read_bytes()).hexdigest(),
        attestation_domain=LOCAL_EXTRACTION_ATTESTATION_DOMAIN,
        attestation_scheme=LOCAL_EXTRACTION_ATTESTATION_SCHEME,
        extraction_method=extraction_method,
        extractor_policy_version=PRODUCTION_EXTRACTION_POLICY if extraction_method == PRODUCTION_EXTRACTION_METHOD else SYNTHETIC_EXTRACTION_POLICY,
        inventory_sha256=hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        files=tuple(inventory),
        created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        production_extraction_completed=production_extraction_completed,
    )
    path = tmp_path / "extraction-manifest.json"
    raw = manifest.canonical_bytes()
    path.write_bytes(raw)
    return path, signer.sign(raw)


def test_manifest_is_canonical_signed_and_tampering_fails(tmp_path: Path):
    tools = {name: {"present": True, "status": "present_unexecuted", "path": f"/usr/{'sbin' if name == 'ocs-onthefly' else 'bin'}/{name}", "file_type": "regular", "size": 8, "sha256": "a" * 64, "executable": True} for name in REQUIRED_RUNTIME_TOOLS}
    _, local_signer, _, local_verifier = _roles()
    local_evidence = local_verifier.verification_evidence
    artifact = RuntimeArtifactEvidence(iso_filename="clonezilla.iso", iso_sha256="a" * 64, official_checksum_manifest_sha256="b" * 64, official_checksum_signature_state="verified", official_checksum_signature_verified=True, official_signer_fingerprint="A" * 40, official_keyring_sha256="c" * 64, local_attestation_scheme=LOCAL_EXTRACTION_ATTESTATION_SCHEME, local_attestation_domain=LOCAL_EXTRACTION_ATTESTATION_DOMAIN, local_attestor_fingerprint=local_evidence.pinned_fingerprint, local_attestor_keyring_sha256=local_evidence.keyring_sha256, extraction_manifest_schema=2, extraction_method=SYNTHETIC_EXTRACTION_METHOD, extraction_policy_version=SYNTHETIC_EXTRACTION_POLICY, extraction_manifest_sha256="e" * 64, extraction_inventory_sha256="f" * 64, local_extraction_signature_state="verified", extraction_signature_verified=True, required_tools=tools)
    manifest = OfflineRuntimeManifest(artifact=artifact, iso_provenance="synthetic fixture")
    store = RuntimeManifestStore(tmp_path)
    package = store.create(manifest, local_signer)
    assert store.load(package, local_verifier) == manifest
    raw = json.loads((package / "runtime-manifest.json").read_text(encoding="utf-8"))
    raw["clonezilla_release"] = "3.3.3-18"
    (package / "runtime-manifest.json").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(OfflineCloneBlocked):
        store.load(package, local_verifier)


def test_runtime_validator_requires_official_artifacts_and_can_pass_static_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
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
    official_signer, local_signer, official_verifier, local_verifier = _roles()
    extraction_manifest, extraction_signature = _extraction_manifest(tmp_path, tree, iso, local_signer)
    real_scan = OfflineRuntimeValidator._scan_tree

    def synthetic_scan(root: Path):
        inventory, blockers = real_scan(root)
        for entry in inventory:
            if Path(entry["path"]).name in REQUIRED_RUNTIME_TOOLS:
                entry["executable"] = True
        return inventory, blockers

    monkeypatch.setattr(OfflineRuntimeValidator, "_scan_tree", staticmethod(synthetic_scan))
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(
        iso_path=iso,
        extracted_tree=tree,
        checksums_path=checksums,
        checksums_signature=official_signer.sign(checksums.read_bytes()),
        official_verifier=official_verifier,
        local_attestation_verifier=local_verifier,
        extraction_manifest_path=extraction_manifest,
        extraction_manifest_signature=extraction_signature,
        provenance="official stable artifact; filename only",
        profile=RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST,
    )
    assert report.state == "offline_runtime_synthetic_validation_passed"
    assert report.blockers == ()
    assert report.manifest.physical_boot_completed is False
    assert report.manifest.vm_boot_completed is False
    assert report.manifest.artifact.iso_filename == iso.name
    assert report.manifest.artifact.official_signer_fingerprint == official_verifier.verification_evidence.pinned_fingerprint
    assert report.manifest.artifact.local_attestor_fingerprint == local_verifier.verification_evidence.pinned_fingerprint
    assert report.evidence["extracted_tree_binding_verified"] is True


def test_verifier_roles_are_non_interchangeable():
    official_signer, _, official_verifier, _ = _roles()
    report = OfflineRuntimeValidator().validate(official_verifier=official_verifier, local_attestation_verifier=official_verifier)
    assert report.state == "offline_runtime_blocked"
    assert "offline_verifier_role_missing_or_ambiguous" in report.blockers


def test_shared_fingerprint_and_keyring_digest_are_blocked():
    shared_secret = b"shared-test-root"
    official = OfficialChecksumVerifier(FakeDetachedVerifier(shared_secret))
    local = LocalExtractionAttestationVerifier(FakeDetachedVerifier(shared_secret))
    report = OfflineRuntimeValidator().validate(official_verifier=official, local_attestation_verifier=local)
    assert "official_local_fingerprints_shared" in report.blockers
    assert "official_local_keyrings_shared" in report.blockers


def test_official_and_local_signatures_cannot_cross_roles(tmp_path: Path):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    official_signer, local_signer, official_verifier, local_verifier = _roles()
    manifest, _ = _extraction_manifest(tmp_path, tree, iso, local_signer)
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(
        iso_path=iso,
        extracted_tree=tree,
        checksums_path=checksums,
        checksums_signature=local_signer.sign(checksums.read_bytes()),
        official_verifier=official_verifier,
        local_attestation_verifier=local_verifier,
        extraction_manifest_path=manifest,
        extraction_manifest_signature=official_signer.sign(manifest.read_bytes()),
        profile=RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST,
    )
    assert "official_checksum_signature_invalid" in report.blockers
    assert "extraction_manifest_signature_invalid" in report.blockers


def test_missing_roles_block_production_validation():
    report = OfflineRuntimeValidator().validate()
    assert "official_checksum_verifier_missing_or_ambiguous" in report.blockers
    assert "local_extraction_attestation_verifier_missing_or_ambiguous" in report.blockers


def test_validator_has_no_caller_supplied_trust_evidence_inputs():
    assert "official_fingerprint" not in inspect.signature(OfflineRuntimeValidator.validate).parameters
    with pytest.raises(TypeError):
        OfflineRuntimeValidator().validate(official_fingerprint="A" * 40)  # type: ignore[call-arg]


def test_local_keyring_substitution_after_construction_is_blocked(tmp_path: Path):
    verifier, _ = _fake_verifier(tmp_path)
    verifier.public_keyring.chmod(0o644)
    verifier.public_keyring.write_bytes(b"substituted local public keyring")
    verifier.public_keyring.chmod(0o444)
    with pytest.raises(OfflineCloneBlocked, match="changed"):
        verifier.verify(b"payload", b"detached")


@pytest.mark.parametrize("field,value", [("attestation_domain", "wrong.domain.v1"), ("attestation_scheme", "unknown-scheme-v9")])
def test_unknown_local_attestation_contract_values_are_rejected(tmp_path: Path, field: str, value: str):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    _, local_signer, _, _ = _roles()
    manifest, _ = _extraction_manifest(tmp_path, tree, iso, local_signer)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw[field] = value
    with pytest.raises(OfflineCloneBlocked):
        RuntimeExtractionManifest.from_dict(raw)


def test_synthetic_fixture_is_rejected_by_production_profile(tmp_path: Path):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    official_signer, local_signer, official_verifier, local_verifier = _roles()
    manifest, signature = _extraction_manifest(tmp_path, tree, iso, local_signer)
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=official_signer.sign(checksums.read_bytes()), official_verifier=official_verifier, local_attestation_verifier=local_verifier, extraction_manifest_path=manifest, extraction_manifest_signature=signature)
    assert report.state == "offline_runtime_blocked"
    assert "synthetic_fixture_not_allowed_in_production" in report.blockers
    assert "offline_runtime_static_validation_passed" != report.state


def test_production_manifest_still_rejects_fake_verifiers(tmp_path: Path):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    official_signer, local_signer, official_verifier, local_verifier = _roles()
    manifest, signature = _extraction_manifest(tmp_path, tree, iso, local_signer, extraction_method=PRODUCTION_EXTRACTION_METHOD, production_extraction_completed=True)
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=official_signer.sign(checksums.read_bytes()), official_verifier=official_verifier, local_attestation_verifier=local_verifier, extraction_manifest_path=manifest, extraction_manifest_signature=signature)
    assert "production_official_verifier_is_test_only" in report.blockers
    assert "production_local_attestation_verifier_is_test_only" in report.blockers


def test_legacy_collapsed_runtime_schema_is_rejected():
    raw = OfflineRuntimeManifest().payload()
    raw["artifact"]["signer_fingerprint"] = "A" * 40
    with pytest.raises(OfflineCloneBlocked):
        OfflineRuntimeManifest.from_dict(raw)


def test_fixture_executable_normalization_is_not_in_production_scan():
    source = inspect.getsource(OfflineRuntimeValidator._check_tree)
    assert '"executable"] = True' not in source


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
    official_signer, _, official_verifier, local_verifier = _roles()
    report = OfflineRuntimeValidator(expected_iso_sha256=hashlib.sha256(iso.read_bytes()).hexdigest()).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=official_signer.sign(checksums.read_bytes()), official_verifier=official_verifier, local_attestation_verifier=local_verifier, profile=RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST)
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
    official_signer, local_signer, official_verifier, local_verifier = _roles()
    manifest, signature = _extraction_manifest(tmp_path, tree, iso, local_signer, force_executable=kind != "non_executable")
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=official_signer.sign(checksums.read_bytes()), official_verifier=official_verifier, local_attestation_verifier=local_verifier, extraction_manifest_path=manifest, extraction_manifest_signature=signature, profile=RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST)
    assert report.state == "offline_runtime_blocked"
    assert any(name in " ".join(report.blockers) for name in ("gpg", "symlink", "non_executable", "ambiguous", "missing"))


def test_tree_manifest_binding_rejects_wrong_iso_digest_and_altered_file(tmp_path: Path):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    official_signer, local_signer, official_verifier, local_verifier = _roles()
    wrong_manifest, wrong_signature = _extraction_manifest(tmp_path, tree, iso, local_signer, source_iso_sha256="f" * 64)
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=official_signer.sign(checksums.read_bytes()), official_verifier=official_verifier, local_attestation_verifier=local_verifier, extraction_manifest_path=wrong_manifest, extraction_manifest_signature=wrong_signature, profile=RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST)
    assert report.state == "offline_runtime_blocked"
    assert "extracted_tree_source_iso_mismatch" in report.blockers

    altered = tree / "usr" / "bin" / "gpg"
    altered.write_text("altered", encoding="utf-8")
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=official_signer.sign(checksums.read_bytes()), official_verifier=official_verifier, local_attestation_verifier=local_verifier, extraction_manifest_path=wrong_manifest, extraction_manifest_signature=wrong_signature, profile=RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST)
    assert report.state == "offline_runtime_blocked"
    assert "extracted_tree_file_digest_mismatch" in report.blockers


def test_extraction_manifest_is_strict_canonical_and_signed(tmp_path: Path):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    official_signer, local_signer, official_verifier, local_verifier = _roles()
    manifest, signature = _extraction_manifest(tmp_path, tree, iso, local_signer)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["unexpected"] = True
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=official_signer.sign(checksums.read_bytes()), official_verifier=official_verifier, local_attestation_verifier=local_verifier, extraction_manifest_path=manifest, extraction_manifest_signature=signature, profile=RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST)
    assert report.state == "offline_runtime_blocked"
    assert "manifest" in " ".join(report.blockers)


@pytest.mark.parametrize("mutation", ["added", "removed", "wrong_signature"])
def test_extraction_manifest_changes_or_signature_replay_are_blocked(tmp_path: Path, mutation: str):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    official_signer, local_signer, official_verifier, local_verifier = _roles()
    manifest, signature = _extraction_manifest(tmp_path, tree, iso, local_signer)
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
        signature = local_signer.sign(raw_bytes)
    checksums = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    checksums.write_text(f"{digest} *{iso.name}\n", encoding="utf-8")
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(iso_path=iso, extracted_tree=tree, checksums_path=checksums, checksums_signature=official_signer.sign(checksums.read_bytes()), official_verifier=official_verifier, local_attestation_verifier=local_verifier, extraction_manifest_path=manifest, extraction_manifest_signature=signature, profile=RUNTIME_VALIDATION_PROFILE_SYNTHETIC_TEST)
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

    with pytest.raises(OfflineCloneBlocked, match="path is unsafe"):
        ProductionOfflineSignatureVerifier(tmp_path / "missing-gpgv", verifier.public_keyring, verifier.expected_fingerprint)
    private_keyring = tmp_path / "private-key-material.gpg"
    private_keyring.write_bytes(b"-----BEGIN PRIVATE KEY-----")
    private_keyring.chmod(0o444)
    with pytest.raises(OfflineCloneBlocked, match="private key"):
        ProductionOfflineSignatureVerifier(sys.executable, private_keyring, verifier.expected_fingerprint, command_suffix=verifier.command_suffix)

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
