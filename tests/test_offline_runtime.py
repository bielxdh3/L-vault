from __future__ import annotations

import hashlib
import json
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
    build_offline_job,
    resolve_offline_devices,
)
from localvault.offline_runtime import (
    REQUIRED_RUNTIME_TOOLS,
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
        (folder / name).write_text("synthetic", encoding="utf-8")


def test_manifest_is_canonical_signed_and_tampering_fails(tmp_path: Path):
    tools = {name: {"present": True, "version": "fixture", "path": f"/usr/{'sbin' if name == 'ocs-onthefly' else 'bin'}/{name}"} for name in REQUIRED_RUNTIME_TOOLS}
    manifest = OfflineRuntimeManifest(required_tools=tools, iso_sha256="a" * 64, iso_signature_state="verified", public_key_fingerprint="A" * 40)
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
    report = OfflineRuntimeValidator(expected_iso_sha256=digest).validate(
        iso_path=iso,
        extracted_tree=tree,
        checksums_path=checksums,
        checksums_signature=signer.sign(checksums.read_bytes()),
        verifier=FakeDetachedVerifier(),
        provenance="official stable artifact; filename only",
    )
    assert report.state == "offline_runtime_static_validation_passed"
    assert report.blockers == ()
    assert report.manifest.physical_boot_completed is False
    assert report.manifest.vm_boot_completed is False


def test_runtime_validator_rejects_missing_tool_and_checksum_mismatch(tmp_path: Path):
    iso = tmp_path / "clonezilla.iso"
    iso.write_bytes(b"fixture")
    tree = tmp_path / "tree"
    _tools_tree(tree)
    (tree / "usr" / "bin" / "gpgv").unlink()
    report = OfflineRuntimeValidator(expected_iso_sha256="0" * 64).validate(iso_path=iso, extracted_tree=tree)
    assert "iso_checksum_mismatch" in report.blockers
    assert "missing_tool:gpgv" in report.blockers
    assert report.state == "offline_runtime_blocked"


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
