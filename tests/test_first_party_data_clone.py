from __future__ import annotations

import os
from pathlib import Path

import pytest

from localvault.clone_roles import PROTECTED_ROLE, SOURCE_ROLE, TARGET_ROLE
from localvault.disk_clone import DiskCloneBlocked, DiskIdentity, PartitionIdentity
from localvault.first_party_data_clone import (
    DataCloneError,
    REPARSE_TAG_MOUNT_POINT,
    REPARSE_TAG_SYMLINK,
    build_manifest,
    compare_manifests,
    parse_vss_shadowstorage,
    resolve_clone_roles,
    robocopy_arguments,
)
from localvault.first_party_clone_worker import (
    CloneVolume,
    MAX_SAMPLE_HASH_BYTES,
    _device_key,
    _cleanup_snapshots,
    _read_vss_journal,
    _robocopy_relative_path,
    _sample_ranges,
    _source_volumes,
    _verify_sample_hashes,
)


def _disk(role, number, *, serial=None, pnp=None, unique=None, is_system=False, is_boot=False, parts=()):
    return DiskIdentity(
        number=number,
        model=role.model,
        serial=serial or f"device-{role.serial_suffix}",
        pnp_device_id=pnp or role.pnp_device_id,
        storage_unique_id=unique or role.storage_unique_id,
        bus_type=role.bus_type,
        size_bytes=role.size_bytes,
        logical_sector_size=512,
        physical_sector_size=4096,
        partition_style="GPT",
        is_system=is_system,
        is_boot=is_boot,
        partitions=tuple(parts),
    )


def _known_disks():
    return [
        _disk(SOURCE_ROLE, 7, is_system=True, is_boot=True, parts=(PartitionIdentity(number=3, mount_point="C:"),)),
        _disk(TARGET_ROLE, 4, parts=(PartitionIdentity(number=1, mount_point="D:"),)),
        _disk(PROTECTED_ROLE, 9, parts=(PartitionIdentity(number=1, mount_point="E:"),)),
    ]


def test_resolves_authorized_roles_by_persistent_identity_not_mutable_selectors():
    source, target, protected = resolve_clone_roles(_known_disks())
    assert (source.number, target.number, protected.number) == (7, 4, 9)
    changed = _known_disks()
    changed[0] = DiskIdentity.from_dict(changed[0].to_dict() | {"number": 0, "mount_points": ["Z:"]})
    changed[1] = DiskIdentity.from_dict(changed[1].to_dict() | {"number": 1, "mount_points": ["Q:"]})
    assert resolve_clone_roles(changed)[0].number == 0
    assert resolve_clone_roles(changed)[1].number == 1


@pytest.mark.parametrize("field", ["serial", "pnp", "unique"])
def test_role_resolution_fails_closed_on_each_persistent_identifier_mismatch(field):
    disks = _known_disks()
    options = {"serial": {"serial": "different-XXXX"}, "pnp": {"pnp": "different-pnp"}, "unique": {"unique": "different-unique"}}
    disks[1] = _disk(TARGET_ROLE, 1, **options[field])
    with pytest.raises(DiskCloneBlocked):
        resolve_clone_roles(disks)


def test_role_resolution_rejects_missing_target_and_source_target_reversal():
    disks = _known_disks()
    with pytest.raises(DiskCloneBlocked):
        resolve_clone_roles(disks[:1] + disks[2:])
    reversed_disks = [_disk(TARGET_ROLE, 0, is_system=True, is_boot=True), _disk(SOURCE_ROLE, 1), _disk(PROTECTED_ROLE, 2)]
    with pytest.raises(DiskCloneBlocked):
        resolve_clone_roles(reversed_disks)


def test_data_clone_does_not_require_matching_sector_geometry():
    disks = _known_disks()
    disks[1] = DiskIdentity.from_dict(disks[1].to_dict() | {"logical_sector_size": 4096, "physical_sector_size": 4096})
    source, target, protected = resolve_clone_roles(disks)
    assert source.storage_unique_id != target.storage_unique_id
    assert protected.storage_unique_id == PROTECTED_ROLE.storage_unique_id


def test_role_resolution_rejects_hgst_as_authorized_target():
    disks = _known_disks()
    disks[1] = _disk(TARGET_ROLE, 1, unique=PROTECTED_ROLE.storage_unique_id, serial="device-4EM2")
    with pytest.raises(DiskCloneBlocked):
        resolve_clone_roles(disks)


def test_shadowstorage_parser_uses_volume_guids_not_drive_letters_or_locale():
    output = """Associação do armazenamento de cópias de sombra
For volume: (C:)\\\\?\\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\\
Shadow Copy Storage volume: (C:)\\\\?\\Volume{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}\\
Maximum Shadow Copy Storage space: 10 GB
"""
    assert parse_vss_shadowstorage(output) == {
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    }


def test_shadowstorage_parser_rejects_incomplete_or_ambiguous_associations():
    with pytest.raises(DataCloneError):
        parse_vss_shadowstorage("For volume: \\\\?\\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\\")
    duplicate = """For volume: \\\\?\\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\\
Shadow Copy Storage volume: \\\\?\\Volume{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}\\
For volume: \\\\?\\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\\
Shadow Copy Storage volume: \\\\?\\Volume{cccccccc-cccc-cccc-cccc-cccccccccccc}\\
"""
    with pytest.raises(DataCloneError):
        parse_vss_shadowstorage(duplicate)


def test_manifest_copies_runtime_named_files_and_excludes_only_root_vss_metadata(tmp_path: Path):
    (tmp_path / "pagefile.sys").write_bytes(b"volatile")
    (tmp_path / "hiberfil.sys").write_bytes(b"volatile")
    (tmp_path / "swapfile.sys").write_bytes(b"volatile")
    (tmp_path / "normal").mkdir()
    (tmp_path / "normal" / "pagefile.sys").write_bytes(b"user data")
    (tmp_path / "normal" / "System Volume Information").mkdir()
    (tmp_path / "normal" / "System Volume Information" / "user-data.bin").write_bytes(b"user data")
    (tmp_path / "System Volume Information").mkdir()
    (tmp_path / "System Volume Information" / "shadow.bin").write_bytes(b"internal")
    result = build_manifest(tmp_path)
    paths = {entry.path for entry in result.entries}
    assert "normal/pagefile.sys" in paths
    assert {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "normal/System Volume Information/user-data.bin"} <= paths
    assert "System Volume Information/shadow.bin" not in paths
    assert {row["reason"] for row in result.excluded} == {"windows_vss_metadata"}
    assert result.logical_bytes == len(b"volatile") * 3 + len(b"user data") * 2


def test_manifest_revalidates_snapshot_identity_during_traversal(tmp_path: Path):
    (tmp_path / "file.bin").write_bytes(b"data")
    checks = []
    result = build_manifest(tmp_path, snapshot_guard=lambda: checks.append("checked"))
    assert result.file_count == 1
    assert checks


def test_manifest_explicitly_excludes_root_runtime_artifacts_without_relying_on_attributes(tmp_path: Path, monkeypatch):
    class Entry:
        name = "pagefile.sys"
        path = str(tmp_path / name)

        @staticmethod
        def is_dir(*, follow_symlinks=True):
            return False

        @staticmethod
        def is_file(*, follow_symlinks=True):
            return True

        @staticmethod
        def is_symlink():
            return False

        @staticmethod
        def stat(*, follow_symlinks=True):
            return type("Stat", (), {"st_file_attributes": 0, "st_mtime_ns": 1, "st_size": 10})()

    monkeypatch.setattr(os, "scandir", lambda _path: [Entry()])
    windows = build_manifest(tmp_path, exclude_windows_runtime_artifacts=True)
    data_volume = build_manifest(tmp_path)
    assert not windows.entries
    assert windows.excluded == ({"path": "pagefile.sys", "reason": "windows_runtime_file"},)
    assert [entry.path for entry in data_volume.entries] == ["pagefile.sys"]


def test_manifest_rejects_casefold_collisions_in_source_paths(tmp_path: Path, monkeypatch):
    class Entry:
        def __init__(self, name):
            self.name = name
            self.path = str(tmp_path / name)

        def is_dir(self, *, follow_symlinks=True):
            return False

        def is_symlink(self):
            return False

        def is_file(self, *, follow_symlinks=True):
            return True

        def stat(self, *, follow_symlinks=True):
            return type("Stat", (), {"st_file_attributes": 0, "st_mtime_ns": 1, "st_size": 1})()

    monkeypatch.setattr(os, "scandir", lambda _path: [Entry("same.txt"), Entry("SAME.TXT")])
    with pytest.raises(DataCloneError, match="diferem apenas por maiúsculas/minúsculas"):
        build_manifest(tmp_path)


def test_manifest_never_descends_a_junction_that_points_outside_source(tmp_path: Path):
    source = tmp_path / "source"
    outside = tmp_path / "protected-hgst-fixture"
    source.mkdir()
    outside.mkdir()
    (outside / "secret.dat").write_bytes(b"must not be read")
    junction = source / "junction-to-protected"
    try:
        junction.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory link creation requires Windows developer mode or elevation")
    result = build_manifest(source, reparse_tag_reader=lambda _: REPARSE_TAG_MOUNT_POINT)
    assert all("secret.dat" not in entry.path for entry in result.entries)
    assert {row["path"] for row in result.excluded} == {"junction-to-protected"}


def test_manifest_preserves_symlink_as_link_without_following_target(tmp_path: Path):
    source = tmp_path / "source"
    outside = tmp_path / "protected-hgst-fixture"
    source.mkdir()
    outside.mkdir()
    (outside / "secret.dat").write_bytes(b"must not be read")
    link = source / "link-to-protected"
    try:
        link.symlink_to(outside / "secret.dat")
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires Windows developer mode or elevation")
    result = build_manifest(source, reparse_tag_reader=lambda _: REPARSE_TAG_SYMLINK)
    entry = next(row for row in result.entries if row.path == "link-to-protected")
    assert entry.kind == "symlink"
    assert "secret.dat" not in {row.path for row in result.entries}


def test_unsupported_reparse_tag_fails_before_target_preparation(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    link = source / "link"
    try:
        link.symlink_to(tmp_path / "elsewhere")
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation requires Windows developer mode or elevation")
    with pytest.raises(DataCloneError, match="reparse point"):
        build_manifest(source, reparse_tag_reader=lambda _: 0x9000001A)


def test_manifest_comparison_detects_missing_file_and_metadata_mismatch(tmp_path: Path):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "same.txt").write_text("source", encoding="utf-8")
    (target / "same.txt").write_text("source", encoding="utf-8")
    source_time = (source / "same.txt").stat().st_mtime_ns
    os.utime(target / "same.txt", ns=(source_time, source_time))
    (source / "missing.txt").write_text("missing", encoding="utf-8")
    source_manifest = build_manifest(source)
    target_manifest = build_manifest(target)
    result = compare_manifests(source_manifest, target_manifest)
    assert not result["verified"]
    assert result["missing_count"] == 1
    assert result["metadata_or_size_difference_count"] == 0


def test_robocopy_is_inbox_metadata_copy_without_mirroring_or_following_junctions(tmp_path: Path):
    args = robocopy_arguments(tmp_path / "source", tmp_path / "target")
    joined = " ".join(args).casefold()
    folded = [arg.casefold() for arg in args]
    assert "/e" in folded
    assert "/copyall" in folded
    assert "/dcopy:date" in joined
    assert "/sparse:y" in joined
    assert "/sl" in folded and "/xj" in folded and "/efsraw" in folded
    assert "/mir" not in folded
    assert "/fp" in folded
    assert "/xf" not in folded
    assert args[folded.index("/xd") + 1].casefold() == str(tmp_path / "source" / "system volume information").casefold()


def test_robocopy_runtime_exclusion_is_narrow_and_directory_eas_are_requested(tmp_path: Path):
    args = robocopy_arguments(tmp_path / "source", tmp_path / "target", runtime_exclusions=["pagefile.sys"])
    folded = [arg.casefold() for arg in args]
    assert "/dcopy:date" in folded
    assert folded[folded.index("/xf") + 1] == str(tmp_path / "source" / "pagefile.sys").casefold()


def test_data_volume_inventory_rejects_non_ntfs_and_malformed_volume_paths():
    source = _known_disks()[0]
    common = {
        "DiskUniqueId": SOURCE_ROLE.storage_unique_id,
        "DiskNumber": source.number,
        "PnpDeviceId": source.pnp_device_id,
        "PartitionNumber": 3,
        "PartitionType": "Basic",
        "GptType": "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
        "PartitionSizeBytes": 500_000_000_000,
        "FileSystem": "NTFS",
        "VolumeGuid": r"\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}" + "\\",
        "SizeBytes": 500_000_000_000,
        "FreeBytes": 100_000_000_000,
        "DriveLetter": "C",
        "IsSystemVolume": True,
    }
    volumes, excluded = _source_volumes(source, [common])
    assert len(volumes) == 1 and volumes[0].is_system_volume
    assert not excluded
    with pytest.raises(DataCloneError, match="fora do NTFS"):
        _source_volumes(source, [{**common, "FileSystem": "ReFS"}])
    with pytest.raises(DataCloneError, match="identidade/capacidade"):
        _source_volumes(source, [{**common, "VolumeGuid": "C:\\"}])
    with pytest.raises(DataCloneError, match="associada a um único volume"):
        _source_volumes(source, [{**common, "VolumeLookupError": "AccessDenied", "VolumeGuid": ""}])
    with pytest.raises(DataCloneError, match="não reconhecida"):
        _source_volumes(source, [{**common, "GptType": "11111111-1111-1111-1111-111111111111"}])


def test_data_volume_inventory_rejects_duplicate_storage_id_from_another_device():
    source = _known_disks()[0]
    row = {
        "DiskUniqueId": SOURCE_ROLE.storage_unique_id,
        "DiskNumber": source.number + 1,
        "PnpDeviceId": "different-physical-device",
        "PartitionNumber": 3,
    }
    with pytest.raises(DataCloneError, match="também apareceu ligado a outro dispositivo"):
        _source_volumes(source, [row])


def test_selected_content_hashing_is_deterministic_and_bounded(tmp_path: Path):
    from localvault.first_party_data_clone import build_manifest

    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    content = bytes(range(256)) * (128 * 1024)  # 32 MiB
    (source / "large.bin").write_bytes(content)
    (target / "large.bin").write_bytes(content)
    manifest = build_manifest(source)
    assert _sample_ranges(len(content)) == [(0, 1024 * 1024), (len(content) - 1024 * 1024, 1024 * 1024)]
    result = _verify_sample_hashes(source, target, manifest, None, max_sample_bytes=2 * 1024 * 1024)
    assert len(result) == 1
    assert result[0]["match"] is True
    assert result[0]["method"] == "head_tail"
    assert result[0]["bytes_hashed_per_copy"] == 2 * 1024 * 1024
    assert _verify_sample_hashes(source, target, manifest, None, max_sample_bytes=0) == []
    assert 2 * 1024 * 1024 < MAX_SAMPLE_HASH_BYTES


def test_small_content_hash_reads_complete_file_and_reports_exact_bytes(tmp_path: Path):
    from localvault.first_party_data_clone import build_manifest

    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "small.txt").write_bytes(b"first-party-data")
    (target / "small.txt").write_bytes(b"first-party-data")
    manifest = build_manifest(source)
    result = _verify_sample_hashes(source, target, manifest, None)
    assert result[0]["match"] is True
    assert result[0]["method"] == "full"
    assert result[0]["bytes_hashed_per_copy"] == len(b"first-party-data")


def test_sample_hashing_revalidates_source_snapshot(tmp_path: Path):
    from localvault.first_party_clone_worker import _sha256_file_ranges

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"first-party-data")
    checks = []
    _sha256_file_ranges(sample, [(0, sample.stat().st_size)], None, snapshot_guard=lambda: checks.append("checked"))
    assert checks


def test_runtime_signature_gate_requires_both_exactly_pinned_valid_signatures():
    from localvault.clone_runtime_security import VSS_HELPER, WORKER, _signature_issues

    thumbprint = "0123456789ABCDEF" * 2 + "01234567"
    rows = [
        {"path": str(WORKER), "status": "Valid", "thumbprint": thumbprint.lower()},
        {"path": str(VSS_HELPER), "status": "Valid", "thumbprint": thumbprint},
    ]
    assert _signature_issues(rows, thumbprint) == []
    assert _signature_issues(rows, "SET_IN_RELEASE_BUILD")
    assert _signature_issues(rows[:-1], thumbprint)
    assert _signature_issues([rows[0], rows[1] | {"status": "NotSigned"}], thumbprint)


def test_cancel_gate_uses_random_job_scoped_name_and_owner_only_acl():
    from localvault.clone_control import CloneCancelGate, CloneCancelGateError, _event_sddl, _mutex_name, _mutex_sddl

    job_id = "0123456789abcdef0123456789abcdef"
    owner_sid = "S-1-5-21-111111111-222222222-333333333-1001"
    assert _mutex_name(job_id) == f"Local\\L-vault-CloneCancel-{job_id}"
    sddl = _mutex_sddl(owner_sid)
    assert f";;;{owner_sid})" in sddl
    assert "0x00100001" in sddl
    event_sddl = _event_sddl(owner_sid)
    assert f";;;{owner_sid})" in event_sddl
    assert "0x00100002" in event_sddl
    with pytest.raises(CloneCancelGateError):
        _mutex_name("../unsafe")
    with pytest.raises(CloneCancelGateError):
        _mutex_sddl("S-1-5-32-545")

    # The non-Windows gate is a deterministic unit-test stand-in for the
    # cross-process Windows mutex; production worker paths are Windows-only.
    with CloneCancelGate(job_id, owner_sid, create=True) as gate:
        assert not gate.is_cancelled()
        with gate.locked():
            pass
        gate.signal_cancel()
        assert gate.is_cancelled()


def test_snapshot_reads_use_validated_stable_vss_device_path_only():
    from localvault.first_party_clone_worker import _snapshot_root

    device = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy42"
    assert str(_snapshot_root(device)) == device
    assert str(_snapshot_root(device + "\\")) == device
    for unsafe in (
        r"C:\\",
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy42\..\PhysicalDrive2",
        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX",
    ):
        with pytest.raises(DataCloneError, match="GlobalRoot"):
            _snapshot_root(unsafe)


def test_cancel_check_rejects_untrusted_path_or_marker_controls(tmp_path: Path):
    from localvault.first_party_clone_worker import _cancel_requested

    with pytest.raises(DataCloneError, match="trava protegida"):
        _cancel_requested(tmp_path / "cancel.request")


def test_windows_process_liveness_probe_never_uses_os_kill(monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows process handles are required for this regression test")
    import localvault.disk_clone as disk_clone

    def forbidden_kill(*_args, **_kwargs):
        raise AssertionError("Windows liveness checks must not signal a process")

    monkeypatch.setattr(disk_clone.os, "kill", forbidden_kill)
    assert disk_clone._process_is_live(os.getpid()) is True
    assert disk_clone._process_is_live(0) is False


def test_stale_lock_with_malformed_pid_fails_closed(tmp_path: Path):
    import localvault.disk_clone as disk_clone

    lock = tmp_path / "worker.lock"
    lock.write_text("{}", encoding="utf-8")
    assert disk_clone._pid_is_live(lock) is True


def test_vss_journal_accepts_exact_unique_guid_ids_and_rejects_reparse_or_duplicate(tmp_path: Path):
    journal = tmp_path / "vss_snapshot_journal.json"
    journal.write_text('{"snapshot_ids":["{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}"]}', encoding="utf-8")
    assert _read_vss_journal(journal) == ["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]
    journal.write_text('{"snapshot_ids":["{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}","bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]}', encoding="utf-8")
    with pytest.raises(DataCloneError, match="repetidos"):
        _read_vss_journal(journal)
    journal.write_text('{"snapshot_ids":[]}', encoding="utf-8")
    assert _read_vss_journal(journal) == []


def test_vss_cleanup_refuses_baseline_or_foreign_volume_snapshot(monkeypatch):
    from localvault import first_party_clone_worker as worker

    volume_guid = r"\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}" + "\\"
    snapshot = {"Id": "{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}", "VolumeName": volume_guid, "DeviceObject": r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy42", "State": "12"}
    monkeypatch.setattr(worker, "_query_shadow_copies", lambda: [snapshot])
    monkeypatch.setattr(worker, "_run_vss_helper", lambda *_args, **_kwargs: {"deleted_snapshot_id": snapshot["Id"]})
    assert not _cleanup_snapshots(["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"], [volume_guid], {"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"})
    foreign = snapshot | {"VolumeName": r"\\?\Volume{cccccccc-cccc-cccc-cccc-cccccccccccc}" + "\\"}
    monkeypatch.setattr(worker, "_query_shadow_copies", lambda: [foreign])
    assert not _cleanup_snapshots(["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"], [volume_guid], set())


def test_vss_crash_recovery_removes_only_journaled_source_snapshot_without_touching_target(tmp_path: Path, monkeypatch):
    from dataclasses import asdict
    import json

    from localvault import first_party_clone_worker as worker
    from localvault.first_party_data_clone import _layout_digest

    source, _target, protected = _known_disks()
    volume_guid = r"\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}" + "\\"
    snapshot_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    baseline_id = "cccccccc-cccc-cccc-cccc-cccccccccccc"
    clone_volume = CloneVolume(
        volume_guid=volume_guid,
        disk_unique_id=SOURCE_ROLE.storage_unique_id,
        disk_number=source.number,
        partition_number=3,
        filesystem="ntfs",
        label="Windows",
        size_bytes=900_000_000_000,
        free_bytes=500_000_000_000,
        drive_letter="C",
        is_system_volume=True,
        role="windows",
    )
    state = {
        "job_id": "0123456789abcdef0123456789abcdef",
        "state": "failed",
        "phase": "CLEANUP",
        "target_destroyed": False,
        "source": worker._public_disk(source),
        "protected": worker._public_disk(protected),
        "source_layout_sha256": _layout_digest(source),
        "protected_layout_sha256": _layout_digest(protected),
        "source_volumes": [asdict(clone_volume)],
        "snapshot_ids_before_set": [baseline_id],
        "vss_helper_started": True,
        "vss_recovery_required": True,
        "snapshot_cleanup_confirmed": False,
    }
    job_directory = tmp_path / state["job_id"]
    job_directory.mkdir()
    (job_directory / "vss_snapshot_journal.json").write_text(
        json.dumps({"snapshot_ids": [snapshot_id]}), encoding="utf-8"
    )

    class Store:
        job_root = tmp_path

        def __init__(self, *_args, **_kwargs):
            self.value = state

        def load(self):
            return self.value

        def update(self, job_id, **fields):
            assert self.value["job_id"] == job_id
            self.value.update(fields)
            return self.value

        def new_job(self, value):
            self.value = value

        def job_directory(self, _job_id):
            return job_directory

    class Lock:
        def __init__(self, *_args, **_kwargs):
            pass

        def acquire(self, _run_id):
            pass

        def release(self):
            pass

    class Inventory:
        def list_disks(self):
            return [source, _target, protected]

    source_row = {
        "VolumeGuid": volume_guid,
        "DiskUniqueId": SOURCE_ROLE.storage_unique_id,
        "DiskNumber": source.number,
        "PnpDeviceId": source.pnp_device_id,
        "PartitionNumber": 3,
        "GptType": "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
        "PartitionSizeBytes": 900_000_000_000,
        "FileSystem": "NTFS",
        "Label": "Windows",
        "SizeBytes": 900_000_000_000,
        "FreeBytes": 500_000_000_000,
        "VolumeLookupError": "",
        "IsSystemVolume": True,
        "DriveLetter": "C",
    }
    current = [{"Id": "{" + snapshot_id + "}", "VolumeName": volume_guid, "DeviceObject": r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy42", "State": "12"}]

    monkeypatch.setattr(worker, "CloneJobStore", Store)
    monkeypatch.setattr(worker, "CloneLock", Lock)
    monkeypatch.setattr(worker, "WindowsDiskInventory", Inventory)
    monkeypatch.setattr(worker, "_all_volumes", lambda: [source_row])
    monkeypatch.setattr(worker, "verify_protected_repository", lambda *_args: None)
    monkeypatch.setattr(worker, "_query_shadow_copies", lambda: list(current))
    monkeypatch.setattr(worker, "_run_vss_helper", lambda *_args, **_kwargs: (current.clear() or {"deleted_snapshot_id": snapshot_id}))
    monkeypatch.setattr(worker, "_prepare_target", lambda *_args: (_ for _ in ()).throw(AssertionError("target mutation during VSS recovery")))

    assert worker._recover_vss_job(tmp_path, state["job_id"])
    assert state["vss_recovery_required"] is False
    assert state["snapshot_cleanup_confirmed"] is True
    assert state["target_destroyed"] is False
    assert state["vss_snapshot_ids"] == []


def test_robocopy_progress_matches_full_source_path_without_localizing_status_text(tmp_path: Path):
    source = tmp_path / "snapshot source"
    assert _robocopy_relative_path(f"New File          17  {source}\\Users\\Biel\\résumé.txt", source) == "users\\biel\\résumé.txt"
