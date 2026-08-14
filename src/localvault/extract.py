from __future__ import annotations

import zipfile
import stat
from pathlib import Path
from pathlib import PurePosixPath
import re

from .utils import atomic_write_from_fileobj, sha256_file


MAX_ZIP_ENTRIES = 10_000
MAX_ZIP_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


def is_within_directory(base: Path, candidate: Path) -> bool:
    base_resolved = base.resolve()
    candidate_resolved = candidate.resolve()
    return base_resolved == candidate_resolved or base_resolved in candidate_resolved.parents


def safe_extract_zip(zip_path: Path, dest_root: Path, dry_run: bool = False) -> Path:
    dest = dest_root / f"{zip_path.stem}_{sha256_file(zip_path)[:16]}"
    with zipfile.ZipFile(zip_path) as archive:
        infos = archive.infolist()
        _validate_zip_infos(infos)
        if dry_run:
            return dest
        dest.mkdir(parents=True, exist_ok=True)
        for info in infos:
            name = safe_zip_member_name(info.filename)
            target = dest / name
            if not is_within_directory(dest, target):
                raise ValueError(f"Unsafe ZIP path blocked: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src:
                    atomic_write_from_fileobj(target, src, expected_size=info.file_size, dry_run=False)
    return dest


def safe_zip_member_name(filename: str) -> str:
    name = filename.replace("\\", "/")
    parts = PurePosixPath(name).parts
    if (
        "\x00" in name
        or not name
        or name.startswith(("/", "//"))
        or any(part in {"", ".", ".."} for part in parts)
        or ":" in parts[0]
        or any(_reserved_windows_component(part) for part in parts)
    ):
        raise ValueError(f"Unsafe ZIP path blocked: {filename}")
    return name


def safe_zip_infos(zip_path: Path) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(zip_path) as archive:
        infos = archive.infolist()
        _validate_zip_infos(infos)
    return infos


def _validate_zip_infos(infos: list[zipfile.ZipInfo]) -> None:
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ValueError("ZIP contains too many entries.")
    total_size = 0
    names: set[str] = set()
    for info in infos:
        _validate_zip_info(info)
        total_size += int(info.file_size or 0)
        if info.file_size > MAX_ZIP_MEMBER_BYTES:
            raise ValueError(f"ZIP entry exceeds the safe size limit: {info.filename}")
        if total_size > MAX_ZIP_TOTAL_BYTES:
            raise ValueError("ZIP exceeds the safe uncompressed size limit.")
        normalized = info.filename.replace("\\", "/").casefold().rstrip("/")
        prefixes = {"/".join(normalized.split("/")[:index]) for index in range(1, len(normalized.split("/")) + 1)}
        if names.intersection(prefixes):
            raise ValueError(f"ZIP contains colliding entries: {info.filename}")
        names.add(normalized)


def _validate_zip_info(info: zipfile.ZipInfo) -> None:
    safe_zip_member_name(info.filename)
    mode = (info.external_attr >> 16) & 0o170000
    if stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode):
        raise ValueError(f"Unsafe ZIP entry blocked: {info.filename}")


def _reserved_windows_component(value: str) -> bool:
    stem = re.split(r"[.]", value, maxsplit=1)[0].casefold()
    return stem in WINDOWS_RESERVED_NAMES
