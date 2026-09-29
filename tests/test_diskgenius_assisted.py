from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from localvault.config import ensure_directories
from localvault.disk_clone import (
    DiskCloneBlocked,
    DiskIdentity,
    FakeDiskInventory,
    PartitionIdentity,
    ProtectedPathResolution,
)
from localvault.diskgenius_assisted import (
    BASIC_GPT_TYPE,
    DISKGENIUS_PUBLISHER,
    DISKGENIUS_VERSION,
    EFI_GPT_TYPE,
    EXPECTED_SIZE_BYTES,
    PROTECTED_ROLE,
    SOURCE_ROLE,
    TARGET_ROLE,
    DiskGeniusNormalProvider,
    verify_system_migration_layout,
)


def _source_disk(number: int = 0, *, system: bool = True, letter: str = "C:", bitlocker_state: str = "unknown") -> DiskIdentity:
    partitions = [
        PartitionIdentity(
            1,
            "Basic Data",
            size_bytes=999_782_612_992,
            gpt_type=BASIC_GPT_TYPE,
            filesystem="NTFS",
            is_os_volume=True,
            offset_bytes=1_048_576,
            gpt_partition_id="part-os",
        )
    ]
    partitions.extend(
        PartitionIdentity(
            n,
            "System",
            size_bytes=104_857_600,
            gpt_type=EFI_GPT_TYPE,
            filesystem="FAT32",
            offset_bytes=n * 104_857_600,
            gpt_partition_id=f"part-esp-{n}",
        )
        for n in range(2, 6)
    )
    return DiskIdentity(
        number=number,
        model=SOURCE_ROLE.model,
        serial=f"KINGSTON-{SOURCE_ROLE.serial_suffix}",
        pnp_device_id=SOURCE_ROLE.pnp_device_id,
        storage_unique_id=SOURCE_ROLE.storage_unique_id,
        runtime_selector=rf"\\.\PHYSICALDRIVE{number}",
        bus_type=SOURCE_ROLE.bus_type,
        size_bytes=EXPECTED_SIZE_BYTES,
        logical_sector_size=512,
        physical_sector_size=4096,
        partition_style="GPT",
        is_system=system,
        is_boot=system,
        bitlocker_state=bitlocker_state,
        mount_points=(letter,),
        partitions=tuple(partitions),
        disk_guid="source-disk-guid",
    )


def _target_disk(number: int = 1, *, letter: str = "D:") -> DiskIdentity:
    return DiskIdentity(
        number=number,
        model=TARGET_ROLE.model,
        serial=f"SEAGATE-{TARGET_ROLE.serial_suffix}",
        pnp_device_id=TARGET_ROLE.pnp_device_id,
        storage_unique_id=TARGET_ROLE.storage_unique_id,
        runtime_selector=rf"\\.\PHYSICALDRIVE{number}",
        bus_type=TARGET_ROLE.bus_type,
        size_bytes=EXPECTED_SIZE_BYTES,
        logical_sector_size=512,
        physical_sector_size=4096,
        partition_style="GPT",
        mount_points=(letter,) if letter else (),
        partitions=(PartitionIdentity(1, "Basic Data", size_bytes=EXPECTED_SIZE_BYTES - 1_048_576, gpt_type=BASIC_GPT_TYPE, filesystem="NTFS"),),
        disk_guid="target-disk-guid",
    )


def _protected_disk(number: int = 2) -> DiskIdentity:
    return DiskIdentity(
        number=number,
        model=PROTECTED_ROLE.model,
        serial=f"HGST-{PROTECTED_ROLE.serial_suffix}",
        pnp_device_id=PROTECTED_ROLE.pnp_device_id,
        storage_unique_id=PROTECTED_ROLE.storage_unique_id,
        runtime_selector=rf"\\.\PHYSICALDRIVE{number}",
        bus_type=PROTECTED_ROLE.bus_type,
        size_bytes=EXPECTED_SIZE_BYTES,
        partition_style="GPT",
        mount_points=("E:",),
        partitions=(PartitionIdentity(1, "Basic Data", size_bytes=EXPECTED_SIZE_BYTES - 1_048_576, gpt_type=BASIC_GPT_TYPE, filesystem="NTFS"),),
        disk_guid="protected-disk-guid",
    )


class _Resolver:
    def __init__(self, protected: DiskIdentity):
        self.protected = protected

    def resolve(self, paths):
        return [
            ProtectedPathResolution(
                str(path), True, self.protected.runtime_selector,
                self.protected.number, self.protected.stable_identifiers(),
            )
            for path in paths
        ]


def _provider(
    tmp_path: Path,
    disks: list[DiskIdentity] | None = None,
    *,
    metadata: dict | None = None,
    launcher=None,
    process_checker=None,
    file_verifier=None,
    now: datetime | None = None,
) -> DiskGeniusNormalProvider:
    root = tmp_path / "vault"
    ensure_directories(root)
    protected = _protected_disk()
    executable = tmp_path / "DiskGenius.exe"
    executable.write_bytes(b"test executable placeholder")
    provider = DiskGeniusNormalProvider(
        root,
        inventory=FakeDiskInventory(disks or [_source_disk(), _target_disk(), protected]),
        protected_path_resolver=_Resolver(protected),
        executable=executable,
        metadata_reader=lambda _path: metadata or {
            "version": DISKGENIUS_VERSION,
            "signature_status": "Valid",
            "publisher": f"CN={DISKGENIUS_PUBLISHER}",
            "sha256": "a" * 64,
        },
        launcher=launcher or (lambda _path: None),
        process_checker=process_checker or (lambda _path: False),
        file_verifier=file_verifier or (lambda _target: {"verified": True}),
        clock=lambda: now or datetime(2026, 9, 28, tzinfo=timezone.utc),
    )
    provider._protected_paths = lambda: [root]
    return provider


def test_role_resolution_uses_authorized_persistent_ids_and_accepts_runtime_number_changes(tmp_path: Path):
    source = _source_disk(8, letter="Q:")
    target = _target_disk(11, letter="R:")
    protected = _protected_disk(14)
    provider = _provider(tmp_path, [source, target, protected])

    result = provider.preflight()

    assert result.source.number == 8
    assert result.target.number == 11
    assert result.protected.number == 14
    assert result.source.mount_points == ("Q:",)
    assert result.target.mount_points == ("R:",)


@pytest.mark.parametrize("field", ["serial", "pnp_device_id", "storage_unique_id"])
def test_source_identity_mismatch_fails_closed(tmp_path: Path, field: str):
    source = replace(_source_disk(), **{field: f"wrong-{field}"})
    provider = _provider(tmp_path, [source, _target_disk(), _protected_disk()])
    with pytest.raises(DiskCloneBlocked):
        provider.resolve_source([source, _target_disk(), _protected_disk()])


@pytest.mark.parametrize("field", ["serial", "pnp_device_id", "storage_unique_id"])
def test_target_identity_mismatch_fails_closed(tmp_path: Path, field: str):
    source, target, protected = _source_disk(), _target_disk(), _protected_disk()
    target = replace(target, **{field: f"wrong-{field}"})
    provider = _provider(tmp_path, [source, target, protected])
    with pytest.raises(DiskCloneBlocked):
        provider.resolve_target([source, target, protected], source)


def test_same_exact_capacity_is_supported_and_one_byte_smaller_is_rejected(tmp_path: Path):
    provider = _provider(tmp_path)
    assert provider.preflight().target.size_bytes == EXPECTED_SIZE_BYTES

    source, target, protected = _source_disk(), _target_disk(), _protected_disk()
    target = replace(target, size_bytes=EXPECTED_SIZE_BYTES - 1)
    provider = _provider(tmp_path / "smaller", [source, target, protected])
    with pytest.raises(DiskCloneBlocked):
        provider.resolve_target([source, target, protected], source)


def test_target_disappearing_or_offline_is_rejected(tmp_path: Path):
    source, target, protected = _source_disk(), _target_disk(), _protected_disk()
    provider = _provider(tmp_path, [source, protected])
    with pytest.raises(DiskCloneBlocked):
        provider.resolve_target([source, protected], source)

    offline = replace(target, online=False)
    with pytest.raises(DiskCloneBlocked):
        provider.resolve_target([source, offline, protected], source)


def test_source_target_reversal_and_protected_hgst_as_target_are_rejected(tmp_path: Path):
    source = replace(_source_disk(), is_system=False, is_boot=False)
    target = replace(_target_disk(), is_system=True, is_boot=True)
    provider = _provider(tmp_path, [source, target, _protected_disk()])
    with pytest.raises(DiskCloneBlocked):
        provider.resolve_source([source, target, _protected_disk()])

    provider = _provider(tmp_path / "hgst", [_source_disk(), _protected_disk()])
    with pytest.raises(DiskCloneBlocked):
        provider.resolve_target([_source_disk(), _protected_disk()], _source_disk())


def test_launch_creates_identity_bound_assisted_session_and_requires_owner_selection_attestation(tmp_path: Path):
    launched = []
    provider = _provider(tmp_path, launcher=lambda path: launched.append(path))

    session = provider.launch()

    assert launched == [provider.executable]
    assert session["state"] == "launched"
    assert session["source"]["disk_number"] == 0
    assert session["target"]["disk_number"] == 1
    assert session["protected"]["disk_number"] == 2
    with pytest.raises(DiskCloneBlocked):
        provider.revalidate_before_overwrite(session["session_id"], selected_devices_verified=False)


def test_revalidation_rejects_stale_disk_number_or_volume_mapping(tmp_path: Path):
    provider = _provider(tmp_path)
    session = provider.launch()
    inventory = provider.inventory
    inventory.replace([_source_disk(), _target_disk(9), _protected_disk()])

    with pytest.raises(DiskCloneBlocked):
        provider.revalidate_before_overwrite(session["session_id"], selected_devices_verified=True)


def test_revalidation_rejects_changed_drive_letter_even_when_persistent_identity_is_same(tmp_path: Path):
    provider = _provider(tmp_path)
    session = provider.launch()
    inventory = provider.inventory
    inventory.replace([_source_disk(), _target_disk(letter="X:"), _protected_disk()])

    with pytest.raises(DiskCloneBlocked):
        provider.revalidate_before_overwrite(session["session_id"], selected_devices_verified=True)


def test_revalidation_rejects_changed_source_bitlocker_state(tmp_path: Path):
    provider = _provider(tmp_path)
    session = provider.launch()
    provider.inventory.replace([_source_disk(bitlocker_state="FullyEncrypted:On"), _target_disk(), _protected_disk()])
    with pytest.raises(DiskCloneBlocked, match="BitLocker"):
        provider.revalidate_before_overwrite(session["session_id"], selected_devices_verified=True)


def test_revalidation_expiry_returns_owner_to_the_identity_check(tmp_path: Path):
    current = [datetime(2026, 9, 28, tzinfo=timezone.utc)]
    provider = _provider(tmp_path, now=current[0])
    provider.clock = lambda: current[0]
    session = provider.launch()

    ready = provider.revalidate_before_overwrite(session["session_id"], selected_devices_verified=True)
    assert ready["state"] == "ready_to_confirm"
    current[0] = current[0].replace(minute=3)
    expired = provider.monitor()
    assert expired["state"] == "ready_to_confirm"
    assert expired["revalidation_expired"] is True


@pytest.mark.parametrize(
    "metadata",
    [
        {"version": "6.1.0", "signature_status": "Valid", "publisher": DISKGENIUS_PUBLISHER},
        {"version": DISKGENIUS_VERSION, "signature_status": "NotSigned", "publisher": DISKGENIUS_PUBLISHER},
        {"version": DISKGENIUS_VERSION, "signature_status": "Valid", "publisher": "Unknown"},
    ],
)
def test_untrusted_or_wrong_diskgenius_build_never_launches(tmp_path: Path, metadata: dict):
    launches = []
    provider = _provider(tmp_path, metadata=metadata, launcher=lambda path: launches.append(path))
    with pytest.raises(DiskCloneBlocked):
        provider.launch()
    assert launches == []


def test_missing_diskgenius_fails_closed(tmp_path: Path):
    provider = _provider(tmp_path)
    provider.executable = tmp_path / "missing.exe"
    assert provider.inspect_capabilities().available is False
    with pytest.raises(DiskCloneBlocked):
        provider.launch()


def test_system_migration_postverify_requires_gpt_efi_and_windows_partition():
    source = _source_disk()
    target = replace(
        _target_disk(),
        partitions=(
            PartitionIdentity(1, "System", size_bytes=104_857_600, gpt_type=EFI_GPT_TYPE, filesystem="FAT32"),
            PartitionIdentity(2, "Basic Data", size_bytes=EXPECTED_SIZE_BYTES - 110_000_000, gpt_type=BASIC_GPT_TYPE, filesystem="NTFS"),
        ),
    )
    result = verify_system_migration_layout(source, target)
    assert result.structurally_verified is True

    duplicate_esp = replace(target, partitions=target.partitions + (target.partitions[0],))
    assert verify_system_migration_layout(source, duplicate_esp).structurally_verified is False

    missing_windows = replace(target, partitions=(target.partitions[0],))
    assert verify_system_migration_layout(source, missing_windows).structurally_verified is False


def test_postverify_marks_source_or_hgst_changes_and_file_verification_failure(tmp_path: Path):
    provider = _provider(tmp_path, file_verifier=lambda _target: {"verified": False, "reason": "BCD mismatch"})
    session = provider.launch()
    provider.revalidate_before_overwrite(session["session_id"], selected_devices_verified=True)
    inventory = provider.inventory
    inventory.replace([
        _source_disk(),
        replace(
            _target_disk(),
            partitions=(
                PartitionIdentity(1, "System", size_bytes=104_857_600, gpt_type=EFI_GPT_TYPE, filesystem="FAT32"),
                PartitionIdentity(2, "Basic Data", size_bytes=EXPECTED_SIZE_BYTES - 110_000_000, gpt_type=BASIC_GPT_TYPE, filesystem="NTFS"),
            ),
        ),
        _protected_disk(),
    ])
    with pytest.raises(DiskCloneBlocked):
        provider.verify(session["session_id"], owner_confirmed_complete=False)
    result = provider.verify(session["session_id"], owner_confirmed_complete=True)
    assert result["state"] == "failed_partial"
    assert result["verification"]["source_layout_unchanged"] is True
    assert result["verification"]["protected_disk_unchanged"] is True
    assert result["verification"]["files_and_bcd_verified"] is False
    assert session["session_id"] == result["session_id"]


def test_postverify_detects_source_layout_and_hgst_volume_changes(tmp_path: Path):
    provider = _provider(tmp_path, file_verifier=lambda _target: {"verified": True})
    session = provider.launch()
    provider.revalidate_before_overwrite(session["session_id"], selected_devices_verified=True)
    inventory = provider.inventory
    source = _source_disk()
    changed_source = replace(source, partitions=(replace(source.partitions[0], offset_bytes=2_097_152),) + source.partitions[1:])
    changed_protected = replace(_protected_disk(), mount_points=("F:",))
    migrated_target = replace(
        _target_disk(),
        partitions=(
            PartitionIdentity(1, "System", size_bytes=104_857_600, gpt_type=EFI_GPT_TYPE, filesystem="FAT32"),
            PartitionIdentity(2, "Basic Data", size_bytes=EXPECTED_SIZE_BYTES - 110_000_000, gpt_type=BASIC_GPT_TYPE, filesystem="NTFS"),
        ),
    )
    inventory.replace([changed_source, migrated_target, changed_protected])
    provider.protected_path_resolver = _Resolver(changed_protected)

    result = provider.verify(session["session_id"], owner_confirmed_complete=True)

    assert result["state"] == "failed_partial"
    assert result["verification"]["source_layout_unchanged"] is False
    assert result["verification"]["protected_disk_unchanged"] is False


def test_cancelled_before_warning_requires_explicit_attestation_and_is_audited(tmp_path: Path):
    provider = _provider(tmp_path)
    session = provider.launch()
    with pytest.raises(DiskCloneBlocked):
        provider.cancel_before_overwrite(session["session_id"], confirmed_not_started=False)
    cancelled = provider.cancel_before_overwrite(session["session_id"], confirmed_not_started=True)
    assert cancelled["state"] == "cancelled_before_overwrite"


def test_cancel_is_blocked_while_diskgenius_process_is_open(tmp_path: Path):
    provider = _provider(tmp_path, process_checker=lambda _path: True)
    session = provider.launch()
    with pytest.raises(DiskCloneBlocked, match="Feche o DiskGenius"):
        provider.cancel_before_overwrite(session["session_id"], confirmed_not_started=True)
    assert provider.monitor()["state"] == "launched"


def test_verification_requires_matching_session_completion_attestation_and_closed_gui(tmp_path: Path):
    provider = _provider(tmp_path, process_checker=lambda _path: True)
    session = provider.launch()
    provider.revalidate_before_overwrite(session["session_id"], selected_devices_verified=True)
    with pytest.raises(DiskCloneBlocked):
        provider.verify(session["session_id"], owner_confirmed_complete=True)
    assert provider.monitor()["state"] == "ready_to_confirm"
    with pytest.raises(DiskCloneBlocked):
        provider.verify("stale-session", owner_confirmed_complete=True)


def test_verification_is_unavailable_until_overwrite_revalidation(tmp_path: Path):
    provider = _provider(tmp_path)
    session = provider.launch()
    with pytest.raises(DiskCloneBlocked):
        provider.verify(session["session_id"], owner_confirmed_complete=True)


def test_revalidation_can_happen_only_once_per_gui_session(tmp_path: Path):
    provider = _provider(tmp_path)
    session = provider.launch()
    provider.revalidate_before_overwrite(session["session_id"], selected_devices_verified=True)
    with pytest.raises(DiskCloneBlocked):
        provider.revalidate_before_overwrite(session["session_id"], selected_devices_verified=True)
