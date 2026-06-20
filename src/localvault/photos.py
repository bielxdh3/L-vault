from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image, ExifTags

from . import db
from .config import VaultPaths, load_config
from .email_names import sanitize_filename_component
from .extract import safe_extract_zip
from .reports import RunReport
from .utils import copy_preserve, guess_mime, sha256_file, unique_path

PHOTO_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".tif", ".tiff", ".bmp"}
VIDEO_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".webm", ".3gp", ".m4v"}


def ingest_google_photos_takeout(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    extracted_root = p.manual_imports_inbox / "extracted_google_takeout"
    roots = []
    for zip_path in sorted(p.google_takeout_inbox.glob("*.zip")):
        try:
            roots.append(safe_extract_zip(zip_path, extracted_root, dry_run=dry_run))
        except Exception as exc:
            report.error(zip_path, str(exc))
    roots.extend([x for x in p.google_takeout_inbox.iterdir() if x.is_dir()])
    with db.connect(p.db) as conn:
        for root in roots:
            for media in root.rglob("*"):
                if media.is_file() and media.suffix.lower() in PHOTO_EXTS | VIDEO_EXTS:
                    try:
                        _import_media(conn, p, media, root, report, dry_run, source="google_photos_takeout")
                    except Exception as exc:
                        report.error(media, str(exc))
    return report


def ingest_google_photos_local_sources(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    cfg = load_config(p.root).get("google_photos", {})
    sources = [Path(x).expanduser() for x in cfg.get("local_media_sources", []) if str(x).strip()]
    preserve_folders = bool(cfg.get("preserve_folder_structure", True))
    with db.connect(p.db) as conn:
        for source in sources:
            if not source.exists():
                report.warn(f"Google Photos local source not found: {source}")
                continue
            for media in source.rglob("*"):
                if media.is_file() and media.suffix.lower() in PHOTO_EXTS | VIDEO_EXTS:
                    try:
                        _import_media(conn, p, media, source, report, dry_run, source="google_photos_local", preserve_folders=preserve_folders)
                    except Exception as exc:
                        report.error(media, str(exc))
    return report


def scan_existing_media(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    with db.connect(p.db) as conn:
        for root in (p.photos, p.videos, p.whatsapp_media):
            for path in root.rglob("*"):
                if path.is_file():
                    digest = sha256_file(path)
                    db.upsert_file(conn, sha256=digest, path=path, media_type="media", mime_type=guess_mime(path), size=path.stat().st_size, source="scan-media")
                    report.imported_count += 1
    return report


def _import_media(conn, p: VaultPaths, media: Path, root: Path, report: RunReport, dry_run: bool, source: str, preserve_folders: bool = False) -> None:
    digest = sha256_file(media)
    if conn.execute("SELECT id FROM google_photos_items WHERE sha256=?", (digest,)).fetchone():
        report.skipped_duplicates += 1
        return
    sidecar = _sidecar(media)
    meta = _read_json(sidecar)
    gdate = _google_date(meta)
    exif_date, width, height = _image_meta(media)
    created = gdate or exif_date or datetime.fromtimestamp(media.stat().st_mtime, timezone.utc).isoformat()
    year, month = _year_month(created)
    kind = "video" if media.suffix.lower() in VIDEO_EXTS else "photo"
    base = p.videos if kind == "video" else p.photos
    if preserve_folders:
        for part in _folder_parts(media, root):
            base = base / part
    dest = unique_path(base / year / month / media.name)
    size = copy_preserve(media, dest, dry_run=dry_run)
    sidecar_dest = None
    if sidecar:
        sidecar_dest = unique_path(dest.with_name(dest.name + ".json"))
        copy_preserve(sidecar, sidecar_dest, dry_run=dry_run)
    if not dry_run:
        db.upsert_file(conn, sha256=digest, path=dest, original_path=media, media_type=kind, mime_type=guess_mime(dest), size=size, source=source)
        conn.execute("""INSERT OR IGNORE INTO google_photos_items
        (filename,path,sidecar_path,original_path,creation_date,exif_date,google_metadata_date,file_size,mime_type,sha256,width,height,album,media_type)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (dest.name, str(dest), str(sidecar_dest) if sidecar_dest else None, str(media), created, exif_date, gdate, size, guess_mime(dest), digest, width, height, _album(media, root), kind))
    report.imported_count += 1
    report.storage_added += size


def _sidecar(path: Path) -> Path | None:
    for c in [path.with_name(path.name + ".json"), path.with_suffix(path.suffix + ".json"), path.with_suffix(".json")]:
        if c.exists():
            return c
    return None


def _read_json(path: Path | None) -> dict:
    if not path:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _google_date(meta: dict) -> str | None:
    for key in ("photoTakenTime", "creationTime"):
        val = meta.get(key)
        if isinstance(val, dict) and val.get("timestamp"):
            return datetime.fromtimestamp(int(val["timestamp"]), timezone.utc).isoformat()
    return None


def _image_meta(path: Path) -> tuple[str | None, int | None, int | None]:
    if path.suffix.lower() not in PHOTO_EXTS:
        return None, None, None
    try:
        with Image.open(path) as img:
            tags = {ExifTags.TAGS.get(k, k): v for k, v in img.getexif().items()}
            return str(tags.get("DateTimeOriginal") or tags.get("DateTime")) if tags else None, img.size[0], img.size[1]
    except Exception:
        return None, None, None


def _year_month(text: str | None) -> tuple[str, str]:
    try:
        d = datetime.fromisoformat((text or "").replace("Z", "+00:00"))
        return f"{d.year:04d}", f"{d.month:02d}"
    except Exception:
        return "unknown", "unknown"


def _album(path: Path, root: Path) -> str | None:
    try:
        rel = path.relative_to(root)
        return rel.parts[-2] if len(rel.parts) >= 2 else None
    except Exception:
        return None


def _folder_parts(path: Path, root: Path) -> list[str]:
    try:
        rel_parent = path.relative_to(root).parent
        raw_parts = list(rel_parent.parts)
    except Exception:
        raw_parts = []
    if not raw_parts or raw_parts == ["."]:
        raw_parts = [root.name]
    return [sanitize_filename_component(part, "pasta", max_length=48) for part in raw_parts[-3:]]
