"""Pinned physical-disk roles shared by normal and legacy clone flows."""

from __future__ import annotations

from dataclasses import dataclass

from .disk_clone import DiskIdentity, _normal


EXPECTED_SIZE_BYTES = 1_000_204_886_016


@dataclass(frozen=True)
class DiskRole:
    name: str
    model: str
    serial_suffix: str
    pnp_device_id: str
    storage_unique_id: str
    size_bytes: int
    bus_type: str


SOURCE_ROLE = DiskRole(
    "source", "KINGSTON SNV2S1000G", "775.",
    r"SCSI\DISK&VEN_NVME&PROD_KINGSTON_SNV2S10\5&1664D250&0&000000",
    "eui.00000000000000000026B76866541775", EXPECTED_SIZE_BYTES, "NVMe",
)
TARGET_ROLE = DiskRole(
    "target", "ST1000VM002-1CT162", "4EM2",
    r"SCSI\DISK&VEN_&PROD_ST1000VM002-1CT1\5&BC4E48B&0&000000",
    "5000C50074F087A4", EXPECTED_SIZE_BYTES, "SATA",
)
PROTECTED_ROLE = DiskRole(
    "protected", "HGST HTS541010A9E680", "91NS",
    r"SCSI\DISK&VEN_HGST&PROD_HTS541010A9E680\5&BC4E48B&0&030000",
    "5000CC8AD6DC50FE", EXPECTED_SIZE_BYTES, "SATA",
)


def matches_role(disk: DiskIdentity, role: DiskRole) -> bool:
    return (
        disk.identity_strength() == "strong"
        and _normal(disk.model) == _normal(role.model)
        and _normal(disk.serial).endswith(_normal(role.serial_suffix))
        and _normal(disk.pnp_device_id) == _normal(role.pnp_device_id)
        and _normal(disk.storage_unique_id) == _normal(role.storage_unique_id)
        and disk.size_bytes == role.size_bytes
        and _normal(disk.bus_type) == _normal(role.bus_type)
    )
