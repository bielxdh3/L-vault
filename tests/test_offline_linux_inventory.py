from __future__ import annotations

import json

import pytest

from localvault.offline_clone import OfflineCloneBlocked
from localvault.offline_linux_inventory import parse_lsblk_json


def _payload():
    return json.dumps(
        {
            "blockdevices": [
                {
                    "name": "nvme0n1",
                    "path": "/dev/nvme0n1",
                    "type": "disk",
                    "model": "Synthetic NVMe",
                    "serial": "SRC-0001",
                    "wwn": "WWN-SRC-0001",
                    "tran": "nvme",
                    "size": 1000000,
                    "log-sec": 512,
                    "phy-sec": 4096,
                    "pttype": "gpt",
                    "rm": 0,
                    "ro": 0,
                    "mountpoints": [None],
                    "children": [
                        {
                            "type": "part",
                            "parttype": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
                            "fstype": "vfat",
                            "label": "EFI",
                            "mountpoints": [None],
                        },
                        {
                            "type": "part",
                            "parttype": "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
                            "fstype": "ntfs",
                            "label": "Windows",
                            "mountpoints": [None],
                        },
                        {
                            "type": "part",
                            "parttype": "de94bba4-06d1-4d40-a16a-bfd50179d6ac",
                            "fstype": "ntfs",
                            "label": "Recovery",
                            "mountpoints": [None],
                        },
                    ],
                },
                {
                    "name": "nvme0n1p1",
                    "path": "/dev/nvme0n1p1",
                    "type": "part",
                    "size": 1000,
                },
            ]
        }
    )


def test_parser_normalizes_only_top_level_disks():
    devices = parse_lsblk_json(_payload())
    assert len(devices) == 1
    disk = devices[0]
    assert disk.node == "/dev/nvme0n1"
    assert disk.model == "Synthetic NVMe"
    assert disk.size_bytes == 1000000
    assert disk.logical_sector_size == 512
    assert disk.physical_sector_size == 4096
    assert disk.partition_style == "gpt"
    assert disk.partition_roles == ("efi", "recovery", "windows")
    assert disk.mounted is False
    assert disk.read_only is False
    assert disk.removable is False
    assert disk.identity_strength == "strong"


def test_child_mount_marks_parent_disk_mounted():
    value = json.loads(_payload())
    value["blockdevices"][0]["children"][1]["mountpoints"] = ["/mnt/windows"]
    disk = parse_lsblk_json(json.dumps(value))[0]
    assert disk.mounted is True


def test_read_only_and_removable_flags_are_preserved():
    value = json.loads(_payload())
    value["blockdevices"][0]["ro"] = 1
    value["blockdevices"][0]["rm"] = 1
    disk = parse_lsblk_json(json.dumps(value))[0]
    assert disk.read_only is True
    assert disk.removable is True


def test_invalid_json_and_invalid_device_node_fail_closed():
    with pytest.raises(OfflineCloneBlocked, match="JSON is invalid"):
        parse_lsblk_json("{")

    value = json.loads(_payload())
    value["blockdevices"][0]["path"] = "../../dev/sda"
    with pytest.raises(OfflineCloneBlocked, match="invalid device node"):
        parse_lsblk_json(json.dumps(value))
