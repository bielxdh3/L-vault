from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

from .config import VaultPaths, load_config
from .extract import safe_zip_infos, safe_zip_member_name
from .gmail_takeout import ingest_gmail_takeout
from .photos import PHOTO_EXTS, VIDEO_EXTS, ingest_photos_takeout
from .reports import RunReport
from .utils import atomic_copy, atomic_move_or_copy, sha256_file, unique_path

INCOMPLETE_SUFFIXES = {".crdownload", ".tmp", ".part"}


@dataclass(frozen=True)
class TakeoutMove:
    source: Path
    dest: Path
    size: int


def auto_takeout(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    moves = _planned_moves(p, report, dry_run=dry_run)
    never_delete_sources = bool(load_config(p.root).get("safety", {}).get("never_delete_sources", True))
    if dry_run:
        operation = "copy" if never_delete_sources else "move"
        for move in moves:
            report.warn(f"Would {operation} Takeout ZIP: {move.source} -> {move.dest}")
            report.imported_count += 1
            report.storage_added += move.size
        return report

    moved = []
    move_failed = False
    for move in moves:
        try:
            digest = sha256_file(move.source)
            if never_delete_sources:
                atomic_copy(move.source, move.dest)
            else:
                atomic_move_or_copy(move.source, move.dest, expected_sha256=digest)
            moved.append(move)
            report.imported_count += 1
            report.storage_added += move.dest.stat().st_size
        except (OSError, ValueError) as exc:
            move_failed = True
            report.error(move.source, str(exc))
    if moved and not move_failed:
        moved_zips = [move.dest for move in moved]
        ingest_photos_takeout(p, report, dry_run=False, zip_paths=moved_zips)
        ingest_gmail_takeout(p, report, dry_run=False, zip_paths=moved_zips)
    return report


def _planned_moves(p: VaultPaths, report: RunReport, dry_run: bool = False) -> list[TakeoutMove]:
    moves = []
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
                moves.append(TakeoutMove(source=zip_path, dest=dest, size=zip_path.stat().st_size))
            except zipfile.BadZipFile as exc:
                report.warn(f"Ignored invalid ZIP: {zip_path} ({exc})")
            except (OSError, ValueError) as exc:
                report.error(zip_path, str(exc))
    return moves


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
        if parts and parts[0] == "takeout":
            return True
        if any(part in {"google photos", "google fotos"} for part in parts):
            return True
        if info.is_dir():
            continue
        if Path(name).suffix.lower() == ".mbox":
            return True
        if parts and parts[0] == "takeout" and Path(name).suffix.lower() in PHOTO_EXTS | VIDEO_EXTS:
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
