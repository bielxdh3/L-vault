import json
import hashlib
import hmac
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from localvault.disk_clone import DiskIdentity, FakeDiskInventory, PartitionIdentity
from localvault.offline_clone import FakeDetachedSigner, FakeDetachedVerifier, OfflineCloneBlocked, OfflineJobStore
from localvault.offline_clone import canonical_json
from localvault.offline_preparation import PreparationConfig, ProductionPreparationAdapter


NOW = datetime(2026, 9, 17, 18, 0, tzinfo=timezone.utc)


def _disk(number: int, model: str, serial: str, unique: str, *, system=False, boot=False, size=1000):
    return DiskIdentity(
        number=number,
        model=model,
        serial=serial,
        pnp_device_id=f"pnp-{serial}",
        storage_unique_id=unique,
        runtime_selector=f"\\\\.\\PHYSICALDRIVE{number}",
        bus_type="SATA" if not system else "NVMe",
        size_bytes=size,
        logical_sector_size=512,
        physical_sector_size=4096,
        partition_style="GPT",
        is_system=system,
        is_boot=boot,
        partitions=(
            PartitionIdentity(number=1, kind="Basic", size_bytes=size - 1, gpt_type="EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", is_os_volume=system),
            PartitionIdentity(number=2, kind="System", size_bytes=100, gpt_type="C12A7328-F81F-11D2-BA4B-00A0C93EC93B"),
        ),
    )


def _config(tmp_path: Path, source: DiskIdentity, target: DiskIdentity, excluded: DiskIdentity) -> PreparationConfig:
    for name, value in (("source", source), ("target", target), ("excluded", excluded)):
        (tmp_path / f"{name}.json").write_text(json.dumps({"persistent_identity": value.persistent_identity_payload()}), encoding="utf-8")
    runtime = tmp_path / "runtime.json"
    runtime.write_text(json.dumps({"state": "offline_runtime_static_validation_passed", "blockers": []}), encoding="utf-8")
    signer_gpg = tmp_path / "gpg.exe"
    signer_gpg.write_bytes(b"gpg")
    verifier_gpgv = tmp_path / "gpgv.exe"
    verifier_gpgv.write_bytes(b"gpgv")
    keyring = tmp_path / "public.gpg"
    keyring.write_bytes(b"public")
    keyring.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    home = tmp_path / "signer-home"
    home.mkdir()
    return PreparationConfig(
        jobs_root=tmp_path / "jobs",
        exchange_root=tmp_path / "exchange",
        replay_state=tmp_path / "jobs" / "replay.json",
        audit_path=tmp_path / "audit.json",
        signer_gpg=signer_gpg,
        signer_gnupg_home=home,
        signer_fingerprint="A" * 40,
        verifier_gpgv=verifier_gpgv,
        verifier_keyring=keyring,
        verifier_fingerprint="A" * 40,
        runtime_report=runtime,
        source_enrollment=tmp_path / "source.json",
        target_enrollment=tmp_path / "target.json",
        excluded_enrollment=tmp_path / "excluded.json",
    )


def test_prepare_signs_one_shot_job_and_initializes_channel(tmp_path: Path):
    source = _disk(0, "KINGSTON SNV2S1000G", "source", "source-id", system=True, boot=True)
    target = _disk(1, "ST1000VM002-1CT162", "target", "target-id")
    excluded = _disk(2, "HGST HTS541010A9E680", "hgst", "hgst-id")
    config = _config(tmp_path, source, target, excluded)
    adapter = ProductionPreparationAdapter(config, inventory=FakeDiskInventory([source, target, excluded]), signer=FakeDetachedSigner(), verifier=FakeDetachedVerifier(), clock=lambda: NOW)
    result = adapter.prepare(now=NOW)
    assert result["state"] == "ready_for_offline_clone"
    assert result["signed_job"]["signature_verified"] is True
    assert (config.exchange_root / "return-channel" / "channel.json").is_file()
    job_dirs = [path for path in config.jobs_root.iterdir() if path.is_dir()]
    assert len(job_dirs) == 1
    assert (job_dirs[0] / "manifest.sig").is_file()
    assert json.loads(config.audit_path.read_text(encoding="utf-8"))["safety"]["physical_clone_performed"] is False


def test_prepare_rejects_ambiguous_or_changed_target(tmp_path: Path):
    source = _disk(0, "KINGSTON SNV2S1000G", "source", "source-id", system=True, boot=True)
    target = _disk(1, "ST1000VM002-1CT162", "target", "target-id")
    excluded = _disk(2, "HGST HTS541010A9E680", "hgst", "hgst-id")
    config = _config(tmp_path, source, target, excluded)
    changed = _disk(1, "ST1000VM002-1CT162", "different", "target-id")
    adapter = ProductionPreparationAdapter(config, inventory=FakeDiskInventory([source, changed, excluded]), signer=FakeDetachedSigner(), verifier=FakeDetachedVerifier(), clock=lambda: NOW)
    with pytest.raises(OfflineCloneBlocked, match="ambiguous"):
        adapter.prepare(now=NOW)


def test_prepare_rejects_private_material_in_public_keyring(tmp_path: Path):
    source = _disk(0, "KINGSTON SNV2S1000G", "source", "source-id", system=True, boot=True)
    target = _disk(1, "ST1000VM002-1CT162", "target", "target-id")
    excluded = _disk(2, "HGST HTS541010A9E680", "hgst", "hgst-id")
    config = _config(tmp_path, source, target, excluded)
    config.verifier_keyring.chmod(stat.S_IRUSR | stat.S_IWUSR)
    config.verifier_keyring.write_bytes(b"PRIVATE KEY")
    with pytest.raises(OfflineCloneBlocked, match="private key"):
        ProductionPreparationAdapter(config, inventory=FakeDiskInventory([source, target, excluded]), signer=FakeDetachedSigner(), verifier=FakeDetachedVerifier()).prepare(now=NOW)


def test_prepare_rejects_tampered_enrollment_when_integrity_secret_is_configured(tmp_path: Path):
    source = _disk(0, "KINGSTON SNV2S1000G", "source", "source-id", system=True, boot=True)
    target = _disk(1, "ST1000VM002-1CT162", "target", "target-id")
    excluded = _disk(2, "HGST HTS541010A9E680", "hgst", "hgst-id")
    config = _config(tmp_path, source, target, excluded)
    secret = tmp_path / "enrollment.secret"
    secret.write_bytes(b"s" * 32)
    for path in (config.source_enrollment, config.target_enrollment, config.excluded_enrollment):
        value = json.loads(path.read_text())
        payload = value["persistent_identity"]
        value["hmac"] = hmac.new(secret.read_bytes(), canonical_json(payload), hashlib.sha256).hexdigest()
        path.write_text(json.dumps(value), encoding="utf-8")
    config = PreparationConfig(**(config.__dict__ | {"enrollment_secret": secret}))
    value = json.loads(config.target_enrollment.read_text())
    value["persistent_identity"]["serial"] = "other"
    config.target_enrollment.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OfflineCloneBlocked, match="integrity"):
        ProductionPreparationAdapter(config, inventory=FakeDiskInventory([source, target, excluded]), signer=FakeDetachedSigner(), verifier=FakeDetachedVerifier()).prepare(now=NOW)
