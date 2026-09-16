"""Read-only Linux inventory parsing for the future trusted offline runner.

The parser is intentionally pure: it consumes JSON captured from ``lsblk`` and
returns normalized ``OfflineBlockDevice`` objects. It never mounts, writes, or
opens block devices. A later integration step may pair it with a bounded,
allowlisted subprocess collector inside the pinned Clonezilla Live runtime.
"""

from __future__ import annotations

import json
from typing import Any

from .offline_clone import OfflineBlockDevice, OfflineCloneBlocked


EFI_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
WINDOWS_BASIC_GUID = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
WINDOWS_RECOVERY_GUID = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"


def _text(value: Any) -> str:
    return str(value or "").strip()


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _mounted(value: Any) -> bool:
    if isinstance(value, list):
        return any(_text(item) for item in value)
    return bool(_text(value))


def _partition_roles(children: list[dict[str, Any]]) -> tuple[str, ...]:
    roles: set[str] = set()
    for child in children:
        parttype = _text(child.get("parttype")).casefold()
        fstype = _text(child.get("fstype")).casefold()
        label = _text(child.get("label")).casefold()
        if parttype == EFI_GUID or fstype in {"vfat", "fat32"} and "efi" in label:
            roles.add("efi")
        if parttype == WINDOWS_RECOVERY_GUID or "recovery" in label or "winre" in label:
            roles.add("recovery")
        if parttype == WINDOWS_BASIC_GUID or fstype in {"ntfs", "refs"}:
            roles.add("windows")
    return tuple(sorted(roles))


def parse_lsblk_json(payload: str) -> list[OfflineBlockDevice]:
    """Parse deterministic ``lsblk --json --bytes`` style output.

    Only top-level ``type=disk`` entries are returned. The caller must add
    trusted live-root, boot-medium, and protected-device classification from
    independently collected runtime evidence before a destructive operation.
    """

    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise OfflineCloneBlocked(
            "offline lsblk inventory JSON is invalid",
            "offline_identity_blocked",
        ) from exc

    rows = value.get("blockdevices") if isinstance(value, dict) else None
    if not isinstance(rows, list):
        raise OfflineCloneBlocked(
            "offline lsblk inventory has no blockdevices array",
            "offline_identity_blocked",
        )

    devices: list[OfflineBlockDevice] = []
    for row in rows:
        if not isinstance(row, dict) or _text(row.get("type")).casefold() != "disk":
            continue
        children = [item for item in row.get("children") or [] if isinstance(item, dict)]
        node = _text(row.get("path")) or (f"/dev/{_text(row.get('name'))}" if _text(row.get("name")) else "")
        if not node.startswith("/dev/"):
            raise OfflineCloneBlocked(
                "offline inventory contains an invalid device node",
                "offline_identity_blocked",
            )
        devices.append(
            OfflineBlockDevice(
                node=node,
                model=_text(row.get("model")),
                serial=_text(row.get("serial")),
                wwn=_text(row.get("wwn")),
                transport=_text(row.get("tran")),
                size_bytes=_integer(row.get("size")),
                logical_sector_size=_integer(row.get("log-sec"), 512),
                physical_sector_size=_integer(row.get("phy-sec"), 4096),
                partition_style=_text(row.get("pttype")),
                partition_roles=_partition_roles(children),
                mounted=_mounted(row.get("mountpoints")) or any(_mounted(child.get("mountpoints")) for child in children),
                removable=bool(_integer(row.get("rm"))),
                read_only=bool(_integer(row.get("ro"))),
            )
        )
    return devices
