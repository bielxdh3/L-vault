from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from localvault.offline_clone import (
    ClonezillaCommandRenderer,
    FakeDetachedSigner,
    FakeDetachedVerifier,
    FakeOfflineInventory,
    LinuxBlockInventory,
    OfflineBlockDevice,
    OfflineCloneBlocked,
    OfflineJobStore,
    OfflineResult,
    OfflineResultStore,
    build_fake_result,
    build_offline_job,
    consume_offline_result,
    resolve_offline_devices,
    simulate_offline_round_trip,
)


NOW = datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc)


def _disk(node: str, serial: str, *, model: str = "Fake Disk", size: int = 1000, transport: str = "sata", style: str = "gpt", **flags) -> OfflineBlockDevice:
    wwn = flags.pop("wwn", f"wwn-{serial}")
    logical_sector = flags.pop("logical_sector_size", 512)
    physical_sector = flags.pop("physical_sector_size", 4096)
    return OfflineBlockDevice(
        node,
        model,
        serial,
        wwn=wwn,
        transport=transport,
        size_bytes=size,
        logical_sector_size=logical_sector,
        physical_sector_size=physical_sector,
        partition_style=style,
        partition_roles=("efi", "windows", "recovery"),
        **flags,
    )


def _job(tmp_path: Path, *, source: OfflineBlockDevice | None = None, target: OfflineBlockDevice | None = None):
    source = source or _disk("/dev/sda", "source")
    target = target or _disk("/dev/sdb", "target", size=1200)
    job = build_offline_job(source, target, now=NOW, nonce="nonce-00000000000001")
    store = OfflineJobStore(tmp_path / "jobs")
    signer = FakeDetachedSigner()
    verifier = FakeDetachedVerifier()
    store.create(job, signer)
    return job, store, signer, verifier, source, target


def _resolved(job, source, target):
    return resolve_offline_devices(job, FakeOfflineInventory((source, target)))


def test_valid_signature_is_canonical_and_private_material_is_not_serialized(tmp_path):
    job, store, _, verifier, *_ = _job(tmp_path)
    manifest = (store.root / job.job_id / "manifest.json").read_text(encoding="utf-8")
    assert "wwn-source" not in manifest
    assert "fake-offline-signer-only" not in manifest
    assert store.load(job.job_id, verifier, now=NOW) == job
    with pytest.raises(OfflineCloneBlocked, match="already consumed"):
        store.load(job.job_id, verifier, now=NOW)


def test_tampered_manifest_wrong_schema_expired_and_engine_are_rejected(tmp_path):
    job, store, signer, verifier, *_ = _job(tmp_path)
    path = store.root / job.job_id / "manifest.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["source_label"] = "tampered"
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    with pytest.raises(OfflineCloneBlocked, match="signature"):
        store.load(job.job_id, verifier, now=NOW)

    expired, expired_store, expired_signer, expired_verifier, *_ = _job(tmp_path / "expired")
    expired = build_offline_job(_disk("/dev/sda", "source"), _disk("/dev/sdb", "target", size=1200), now=NOW - timedelta(hours=1), ttl=timedelta(minutes=1), nonce="nonce-expired-0001")
    expired_store.create(expired, expired_signer)
    with pytest.raises(OfflineCloneBlocked, match="expired"):
        expired_store.load(expired.job_id, expired_verifier, now=NOW)

    bad = json.loads((store.root / job.job_id / "manifest.json").read_text(encoding="utf-8"))
    bad["schema"] = 99
    bad_raw = json.dumps(bad, sort_keys=True, separators=(",", ":")).encode()
    (store.root / job.job_id / "manifest.json").write_bytes(bad_raw)
    (store.root / job.job_id / "manifest.sig").write_bytes(signer.sign(bad_raw))
    with pytest.raises(OfflineCloneBlocked, match="schema"):
        store.load(job.job_id, verifier, now=NOW)


def test_default_execution_is_false_and_non_allowlisted_engine_is_blocked(tmp_path):
    job, store, signer, verifier, *_ = _job(tmp_path)
    assert job.real_execution_authorized is False
    value = job.payload() | {"approved_engine": "dd", "nonce": "nonce-engine-0001"}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    path = store.root / job.job_id
    (path / "manifest.json").write_bytes(raw)
    (path / "manifest.sig").write_bytes(signer.sign(raw))
    with pytest.raises(OfflineCloneBlocked, match="allowlisted"):
        store.load(job.job_id, verifier, now=NOW)


def test_device_names_can_change_without_changing_resolution(tmp_path):
    job, *_ = _job(tmp_path)
    result = _resolved(job, _disk("/dev/nvme1n1", "source"), _disk("/dev/sdc", "target", size=1200))
    assert result.ok
    assert (result.source_node, result.target_node) == ("/dev/nvme1n1", "/dev/sdc")


@pytest.mark.parametrize(
    ("source_flags", "target_flags", "expected"),
    [
        ({"live_root": True}, {}, "live root"),
        ({"boot_medium": True}, {}, "boot medium"),
        ({"mounted": True}, {}, "mounted"),
        ({}, {"mounted": True}, "mounted"),
        ({}, {"read_only": True}, "read-only"),
        ({}, {"style": "mbr"}, "mismatch"),
    ],
)
def test_fail_closed_identity_and_device_guards(source_flags, target_flags, expected, tmp_path):
    source = _disk("/dev/sda", "source", **source_flags)
    target = _disk("/dev/sdb", "target", size=1200, **target_flags)
    job, *_ = _job(tmp_path, source=_disk("/dev/sda", "source"), target=_disk("/dev/sdb", "target", size=1200))
    result = _resolved(job, source, target)
    assert not result.ok
    assert expected in (result.reason + " " + " ".join(result.rejections)).lower()


def test_usb_serial_only_bridge_is_weak(tmp_path):
    source = _disk("/dev/sda", "source", transport="usb", usb_bridge_id="bridge", usb_bridge_stable=True)
    target = _disk("/dev/sdb", "target", size=1200, transport="usb", usb_bridge_id="bridge", usb_bridge_stable=True)
    job, *_ = _job(tmp_path, source=source, target=target)
    weak = _disk("/dev/sda", "source", transport="usb", wwn="", usb_bridge_id="", usb_bridge_stable=False)
    result = _resolved(job, weak, target)
    assert not result.ok
    assert "weak" in result.reason


def test_duplicate_source_and_target_identities_block(tmp_path):
    job, *_ = _job(tmp_path)
    source = _disk("/dev/sda", "source")
    target = _disk("/dev/sdb", "target", size=1200)
    duplicate_source = _disk("/dev/nvme0n1", "source")
    duplicate_target = _disk("/dev/nvme1n1", "target", size=1200)
    source_result = resolve_offline_devices(job, FakeOfflineInventory((source, duplicate_source, target)))
    target_result = resolve_offline_devices(job, FakeOfflineInventory((source, target, duplicate_target)))
    assert source_result.reason == "duplicate source identity"
    assert target_result.reason == "duplicate target identity"


def test_changed_identity_geometry_and_final_reinventory_block(tmp_path):
    job, *_ = _job(tmp_path)
    changed = _resolved(job, _disk("/dev/sda", "changed"), _disk("/dev/sdb", "target", size=1200))
    assert not changed.ok
    assert "identity" in changed.reason
    smaller = _resolved(job, _disk("/dev/sda", "source"), _disk("/dev/sdb", "target", size=900))
    assert not smaller.ok
    assert "smaller" in (smaller.reason + " " + " ".join(smaller.rejections))
    sector = _disk("/dev/sdb", "target", size=1200, physical_sector_size=512)
    sector_result = _resolved(job, _disk("/dev/sda", "source"), sector)
    assert not sector_result.ok
    assert "sector" in (sector_result.reason + " " + " ".join(sector_result.rejections))


def test_protected_ambiguity_and_source_target_same_node_block(tmp_path):
    job, *_ = _job(tmp_path)
    protected = _resolved(job, _disk("/dev/sda", "source"), _disk("/dev/sdb", "target", size=1200, protected_ambiguous=True))
    assert not protected.ok
    assert "protected" in protected.reason
    same_node = _disk("/dev/sda", "target", size=1200)
    same_node_result = _resolved(job, _disk("/dev/sda", "source"), same_node)
    assert not same_node_result.ok


def test_renderer_is_argv_only_masks_nodes_and_blocks_batch(tmp_path):
    job, *_ = _job(tmp_path)
    resolution = _resolved(job, _disk("/dev/nvme1n1", "source;$(bad)"), _disk("/dev/sdc", "target", size=1200))
    assert not resolution.ok
    resolution = _resolved(job, _disk("/dev/nvme1n1", "source"), _disk("/dev/sdc", "target", size=1200))
    plan = ClonezillaCommandRenderer().render(job, resolution)
    assert isinstance(plan.argv, tuple)
    assert "/dev/sda" not in " ".join(plan.displayed_argv)
    assert "/dev/sdb" not in " ".join(plan.displayed_argv)
    assert "$(" not in " ".join(plan.argv)
    assert plan.executable is False
    with pytest.raises(OfflineCloneBlocked, match="batch"):
        ClonezillaCommandRenderer().render(job, resolution, batch=True)


def test_command_hash_is_stable(tmp_path):
    job, *_ = _job(tmp_path)
    source = _disk("/dev/nvme1n1", "source")
    target = _disk("/dev/sdc", "target", size=1200)
    first = ClonezillaCommandRenderer().render(job, _resolved(job, source, target))
    second = ClonezillaCommandRenderer().render(job, _resolved(job, source, target))
    assert first.argv_hash == second.argv_hash


def test_result_round_trip_mismatch_tamper_failure_and_boot_test_guard(tmp_path):
    job, store, signer, verifier, source, target = _job(tmp_path)
    resolution = _resolved(job, _disk("/dev/nvme1n1", "source"), _disk("/dev/sdc", "target", size=1200))
    plan = ClonezillaCommandRenderer().render(job, resolution)
    result = build_fake_result(job, plan, source, target, now=NOW)
    results = OfflineResultStore(tmp_path / "results")
    path = results.create(result, signer)
    outcome = consume_offline_result(path, job.job_id, verifier)
    assert outcome.state == "offline_clone_structurally_verified"
    assert outcome.result.boot_tested is False
    with pytest.raises(OfflineCloneBlocked, match="does not match"):
        results.consume(path, "0" * 32, verifier)
    (path / "result.json").write_text((path / "result.json").read_text(encoding="utf-8").replace("fake_engine_rendered_only", "tampered"), encoding="utf-8")
    with pytest.raises(OfflineCloneBlocked, match="signature"):
        results.consume(path, job.job_id, verifier)
    with pytest.raises(OfflineCloneBlocked, match="boot-test"):
        OfflineResult.from_dict(result.payload() | {"boot_tested": True})


def test_missing_result_stays_pending(tmp_path):
    outcome = consume_offline_result(tmp_path / "missing-result", "0" * 32, FakeDetachedVerifier())
    assert outcome.state == "offline_result_pending"
    assert outcome.result is None


def test_structural_failure_does_not_report_success(tmp_path):
    job, *_ = _job(tmp_path)
    resolution = _resolved(job, _disk("/dev/nvme1n1", "source"), _disk("/dev/sdc", "target", size=1200))
    plan = ClonezillaCommandRenderer().render(job, resolution)
    bad_target = _disk("/dev/sdc", "target", size=1200, style="mbr")
    result = build_fake_result(job, plan, _disk("/dev/nvme1n1", "source"), bad_target, now=NOW)
    assert result.structurally_verified is False
    assert result.sanitized_error


def test_linux_collector_is_a_blocked_seam_and_fake_e2e_is_safe(tmp_path):
    with pytest.raises(OfflineCloneBlocked, match="reserved"):
        LinuxBlockInventory().list_devices()
    result = simulate_offline_round_trip(tmp_path)
    assert result["state"] == "offline_clone_structurally_verified"
    assert result["command_executed"] is False
    assert result["subprocess_called"] is False
    assert result["host_disk_touched"] is False
    assert result["reboot_boundary"]["reboot_requested"] is False
    assert result["boot_tested"] is False
