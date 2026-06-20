from __future__ import annotations

import zipfile
from pathlib import Path

from .utils import sha256_file


def is_within_directory(base: Path, candidate: Path) -> bool:
    base_resolved = base.resolve()
    candidate_resolved = candidate.resolve()
    return base_resolved == candidate_resolved or base_resolved in candidate_resolved.parents


def safe_extract_zip(zip_path: Path, dest_root: Path, dry_run: bool = False) -> Path:
    dest = dest_root / f"{zip_path.stem}_{sha256_file(zip_path)[:16]}"
    if dry_run:
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            name = safe_zip_member_name(info.filename)
            target = dest / name
            if not is_within_directory(dest, target):
                raise ValueError(f"Unsafe ZIP path blocked: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, target.open("wb") as out:
                    out.write(src.read())
    return dest


def safe_zip_member_name(filename: str) -> str:
    name = filename.replace("\\", "/")
    if name.startswith("/") or name.startswith("../") or "/../" in name:
        raise ValueError(f"Unsafe ZIP path blocked: {filename}")
    return name


def safe_zip_infos(zip_path: Path) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(zip_path) as archive:
        infos = archive.infolist()
        for info in infos:
            safe_zip_member_name(info.filename)
    return infos
