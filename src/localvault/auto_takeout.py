from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from .config import VaultPaths, load_config
from .extract import safe_zip_infos, safe_zip_member_name
from .gmail_takeout import ingest_gmail_takeout
from .photos import PHOTO_EXTS, VIDEO_EXTS, ingest_photos_takeout
from .reports import RunReport
from .utils import sha256_file, unique_path

INCOMPLETE_SUFFIXES = {".crdownload", ".tmp", ".part"}


def auto_takeout(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    moved = 0
    for source in _source_dirs(p):
        if not source.exists() or not source.is_dir():
            continue
        for zip_path in sorted(source.iterdir()):
            if not _candidate_zip(zip_path):
                continue
            try:
                if not _is_takeout_zip(zip_path):
                    continue
                digest = sha256_file(zip_path)
                if _inbox_has_hash(p, digest):
                    report.skipped_duplicates += 1
                    continue
                dest = unique_path(p.google_takeout_inbox / zip_path.name)
                if dry_run:
                    report.warn(f"Would move Takeout ZIP: {zip_path} -> {dest}")
                    report.imported_count += 1
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(zip_path), str(dest))
                moved += 1
                report.imported_count += 1
                report.storage_added += dest.stat().st_size
            except zipfile.BadZipFile as exc:
                report.warn(f"Ignored invalid ZIP: {zip_path} ({exc})")
            except (OSError, ValueError) as exc:
                report.error(zip_path, str(exc))
    if moved:
        ingest_photos_takeout(p, report, dry_run=False)
        ingest_gmail_takeout(p, report, dry_run=False)
    return report


def _source_dirs(p: VaultPaths) -> list[Path]:
    cfg = load_config(p.root).get("source_sync", {})
    return [Path(value) for value in cfg.get("google_takeout_sources", [])]


def _candidate_zip(path: Path) -> bool:
    if not path.is_file():
        return False
    suffixes = {suffix.lower() for suffix in path.suffixes}
    if suffixes & INCOMPLETE_SUFFIXES:
        return False
    return path.suffix.lower() == ".zip"


def _is_takeout_zip(zip_path: Path) -> bool:
    infos = safe_zip_infos(zip_path)
    for info in infos:
        name = safe_zip_member_name(info.filename).lower()
        parts = [part for part in name.split("/") if part]
        if any(part in {"takeout", "google photos", "google fotos", "mail", "gmail"} for part in parts):
            return True
        if info.is_dir():
            continue
        if Path(name).suffix.lower() == ".mbox":
            return True
        if "takeout" in parts and Path(name).suffix.lower() in PHOTO_EXTS | VIDEO_EXTS:
            return True
    return False


def _inbox_has_hash(p: VaultPaths, digest: str) -> bool:
    for existing in p.google_takeout_inbox.glob("*.zip"):
        try:
            if sha256_file(existing) == digest:
                return True
        except OSError:
            continue
    return False
