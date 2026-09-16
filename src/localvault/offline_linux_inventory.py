"""Read-only Linux inventory parsing and collection for the trusted offline runner.

The parser is intentionally pure: it consumes JSON captured from ``lsblk`` and
returns normalized ``OfflineBlockDevice`` objects. It never mounts, writes, or
opens block devices. ``LinuxOfflineInventoryCollector`` pairs it with a
bounded, allowlisted ``lsblk`` subprocess inside the pinned Clonezilla Live
runtime.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Protocol

from .offline_clone import OfflineBlockDevice, OfflineCloneBlocked


TRUSTED_LSBLK_PATH = "/usr/bin/lsblk"


EFI_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
WINDOWS_BASIC_GUID = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
WINDOWS_RECOVERY_GUID = "de94bba4-06d1-4d40-a16a-bfd50179d6ac"
MSR_GUID = "e3c9e316-0b5c-4db8-817d-f92df00215ae"


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
        if parttype == MSR_GUID or "reserved" in label:
            roles.add("msr")
    return tuple(sorted(roles))


def parse_lsblk_json(
    payload: str,
    *,
    live_root_nodes: tuple[str, ...] = (),
    boot_medium_nodes: tuple[str, ...] = (),
    protected_nodes: tuple[str, ...] = (),
) -> list[OfflineBlockDevice]:
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

    live_root = set(live_root_nodes)
    boot_medium = set(boot_medium_nodes)
    protected = set(protected_nodes)
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
                serial=_text(row.get("serial") or row.get("id-serial-short")),
                wwn=_text(row.get("wwn") or row.get("id-wwn")),
                id_serial=_text(row.get("id-serial")),
                id_serial_short=_text(row.get("id-serial-short")),
                usb_bridge_id=_text(row.get("usb_bridge_id") or row.get("id-path")) if _text(row.get("tran")).casefold() == "usb" else "",
                transport=_text(row.get("tran")),
                size_bytes=_integer(row.get("size")),
                logical_sector_size=_integer(row.get("log-sec"), 512),
                physical_sector_size=_integer(row.get("phy-sec"), 4096),
                partition_style=_text(row.get("pttype")),
                partition_roles=_partition_roles(children),
                mounted=_mounted(row.get("mountpoints")) or any(_mounted(child.get("mountpoints")) for child in children),
                live_root=node in live_root,
                boot_medium=node in boot_medium,
                protected=node in protected,
                removable=bool(_integer(row.get("rm"))),
                read_only=bool(_integer(row.get("ro"))),
            )
        )
    return devices


class ReadOnlyInventoryRunner(Protocol):
    def __call__(self, argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[bytes]: ...


def _run_lsblk(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
        timeout=timeout,
    )


class LinuxOfflineInventoryCollector:
    """Bounded, read-only collector for the pinned Clonezilla Live runtime."""

    def __init__(
        self,
        *,
        lsblk_path: str = "/usr/bin/lsblk",
        runner: ReadOnlyInventoryRunner | None = None,
        classifier: Callable[[], dict[str, Any]] | None = None,
        timeout_seconds: float = 10.0,
        max_output_bytes: int = 4 * 1024 * 1024,
    ):
        self.lsblk_path = str(lsblk_path)
        self.runner = runner or _run_lsblk
        self.classifier = classifier
        self.timeout_seconds = float(timeout_seconds)
        self.max_output_bytes = int(max_output_bytes)
        candidate = PurePosixPath(self.lsblk_path)
        if not self.lsblk_path.startswith("/") or candidate.name != "lsblk" or ".." in candidate.parts or str(candidate) != TRUSTED_LSBLK_PATH:
            raise OfflineCloneBlocked("offline lsblk binary is not allowlisted", "offline_identity_blocked")
        if not 0 < self.timeout_seconds <= 60 or not 1024 <= self.max_output_bytes <= 16 * 1024 * 1024:
            raise OfflineCloneBlocked("offline inventory limits are invalid", "offline_identity_blocked")

    def _validate_binary(self) -> None:
        if self.runner is not _run_lsblk:
            return
        path = Path(self.lsblk_path)
        try:
            info = path.lstat()
        except OSError as exc:
            raise OfflineCloneBlocked("offline lsblk binary is missing", "offline_identity_blocked") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
            raise OfflineCloneBlocked("offline lsblk binary is not a regular executable", "offline_identity_blocked")

    def collect(
        self,
        *,
        live_root_nodes: tuple[str, ...] = (),
        boot_medium_nodes: tuple[str, ...] = (),
        protected_nodes: tuple[str, ...] = (),
    ) -> list[OfflineBlockDevice]:
        self._validate_binary()
        if self.classifier is not None:
            try:
                evidence = self.classifier()
                if not isinstance(evidence, dict):
                    raise ValueError
                live_root_nodes = tuple(str(item) for item in evidence.get("live_root_nodes") or live_root_nodes)
                boot_medium_nodes = tuple(str(item) for item in evidence.get("boot_medium_nodes") or boot_medium_nodes)
                protected_nodes = tuple(str(item) for item in evidence.get("protected_nodes") or protected_nodes)
            except Exception as exc:
                raise OfflineCloneBlocked("offline device classification evidence is unavailable", "offline_identity_blocked") from exc
        argv = [
            self.lsblk_path,
            "--json",
            "--bytes",
            "--output",
            "PATH,NAME,TYPE,MODEL,SERIAL,WWN,TRAN,SIZE,LOG-SEC,PHY-SEC,PTTYPE,RM,RO,MOUNTPOINTS,FSTYPE,LABEL,PARTTYPE,ID-SERIAL,ID-SERIAL-SHORT,ID-WWN,ID-PATH",
        ]
        try:
            result = self.runner(argv, timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            raise OfflineCloneBlocked("offline lsblk inventory timed out", "offline_identity_blocked") from exc
        except OSError as exc:
            raise OfflineCloneBlocked("offline lsblk inventory failed", "offline_identity_blocked") from exc
        stdout = result.stdout or b""
        if len(stdout) > self.max_output_bytes:
            raise OfflineCloneBlocked("offline lsblk inventory output is oversized", "offline_identity_blocked")
        if int(result.returncode) != 0:
            raise OfflineCloneBlocked("offline lsblk inventory returned an error", "offline_identity_blocked")
        try:
            text = stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OfflineCloneBlocked("offline lsblk inventory is not UTF-8", "offline_identity_blocked") from exc
        return parse_lsblk_json(
            text,
            live_root_nodes=live_root_nodes,
            boot_medium_nodes=boot_medium_nodes,
            protected_nodes=protected_nodes,
        )


# Short alias used by the offline runtime integration.
LinuxBlockInventoryCollector = LinuxOfflineInventoryCollector
