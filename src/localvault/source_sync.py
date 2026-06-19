from __future__ import annotations

from pathlib import Path
from typing import Iterable

from . import db
from .config import VaultPaths, load_config
from .reports import RunReport
from .utils import copy_preserve, guess_mime, media_kind, sha256_file, unique_path

WHATSAPP_MEDIA_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".mov", ".3gp", ".opus", ".ogg", ".mp3", ".m4a", ".pdf", ".doc", ".docx", ".xls", ".xlsx"}


def sync_sources(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    cfg = load_config(p.root).get("source_sync", {})
    if not cfg.get("enabled", True):
        report.warn("Source sync is disabled.")
        return report
    with db.connect(p.db) as conn:
        for source in _paths(cfg.get("google_takeout_sources", [])):
            _copy_filtered(conn, source, p.google_takeout_inbox, report, dry_run, "source_sync_google_takeout", _is_takeout)
        for source in _paths(cfg.get("whatsapp_export_sources", [])):
            _copy_filtered(conn, source, p.whatsapp_exports_inbox, report, dry_run, "source_sync_whatsapp_export", _is_whatsapp_export)
        for source in _paths(cfg.get("whatsapp_media_sources", [])):
            _copy_filtered(conn, source, p.whatsapp_media / "synced", report, dry_run, "source_sync_whatsapp_media", lambda x: x.suffix.lower() in WHATSAPP_MEDIA_EXTS)
    return report


def _paths(values: Iterable[str]) -> list[Path]:
    return [Path(v).expanduser() for v in values if str(v).strip()]


def _copy_filtered(conn, source: Path, dest_dir: Path, report: RunReport, dry_run: bool, source_name: str, predicate) -> None:
    if not source.exists():
        report.warn(f"Source folder not found: {source}")
        return
    for file_path in source.rglob("*"):
        if not file_path.is_file() or not predicate(file_path):
            continue
        try:
            digest = sha256_file(file_path)
            if conn.execute("SELECT id FROM files WHERE sha256=? AND source=?", (digest, source_name)).fetchone():
                report.skipped_duplicates += 1
                continue
            dest = unique_path(dest_dir / file_path.name)
            size = copy_preserve(file_path, dest, dry_run=dry_run)
            if not dry_run:
                db.upsert_file(conn, sha256=digest, path=dest, original_path=file_path, media_type=media_kind(dest), mime_type=guess_mime(dest), size=size, source=source_name)
            report.imported_count += 1
            report.storage_added += size
        except Exception as exc:
            report.error(file_path, str(exc))


def _is_takeout(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() == ".zip" and ("takeout" in name or "google photos" in name or "google fotos" in name or "gmail" in name)


def _is_whatsapp_export(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in {".zip", ".txt"} and ("whatsapp" in name or "whats app" in name or "_chat" in name or "conversa" in name)
