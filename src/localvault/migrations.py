from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from . import db
from .config import VaultPaths, load_config


OLD_MEDIA_ROOT = "vault\\google_photos"
OLD_PHOTOS = "vault\\google_photos\\photos"
OLD_VIDEOS = "vault\\google_photos\\videos"
NEW_MEDIA_ROOT = "vault\\fotos"
NEW_PHOTOS = "vault\\fotos\\imagens"
NEW_VIDEOS = "vault\\fotos\\videos"


def migrate_to_takeout_photos(p: VaultPaths) -> None:
    _move_existing_media(p)
    with db.connect(p.db) as conn:
        _migrate_photo_table(conn)
        _rewrite_paths(conn, str(p.root))
        _archive_local_sources(conn)
    _rewrite_config(p)


def _move_existing_media(p: VaultPaths) -> None:
    old_root = p.root / "vault" / "google_photos"
    if not old_root.exists():
        return
    old_photos = old_root / "photos"
    old_videos = old_root / "videos"
    _merge_tree(old_photos, p.photos)
    _merge_tree(old_videos, p.videos)
    _remove_empty_parents(old_root)


def _merge_tree(source: Path, target: Path) -> None:
    if not source.exists():
        return
    target.mkdir(parents=True, exist_ok=True)
    for item in sorted(source.rglob("*")):
        rel = item.relative_to(source)
        dest = target / rel
        if item.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            if item.stat().st_size == dest.stat().st_size:
                item.unlink()
                continue
            dest = _unique_path(dest)
        shutil.move(str(item), str(dest))


def _remove_empty_parents(root: Path) -> None:
    for item in sorted(root.rglob("*"), reverse=True):
        if item.is_dir():
            try:
                item.rmdir()
            except OSError:
                pass
    try:
        root.rmdir()
    except OSError:
        pass


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for idx in range(1, 10000):
        candidate = path.with_name(f"{stem}_{idx}{suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError(path)


def _migrate_photo_table(conn) -> None:
    old_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='google_photos_items'").fetchone()
    if not old_exists:
        return
    conn.execute("""
        INSERT OR IGNORE INTO photo_items
        (id,filename,path,sidecar_path,original_path,creation_date,exif_date,google_metadata_date,file_size,mime_type,sha256,width,height,album,media_type,imported_at)
        SELECT id,filename,path,sidecar_path,original_path,creation_date,exif_date,google_metadata_date,file_size,mime_type,sha256,width,height,album,media_type,imported_at
        FROM google_photos_items
    """)
    conn.execute("DROP TABLE google_photos_items")


def _rewrite_paths(conn, root: str) -> None:
    replacements = [
        (f"{root}\\{OLD_PHOTOS}", f"{root}\\{NEW_PHOTOS}"),
        (f"{root}\\{OLD_VIDEOS}", f"{root}\\{NEW_VIDEOS}"),
        (f"{root}\\{OLD_MEDIA_ROOT}", f"{root}\\{NEW_MEDIA_ROOT}"),
    ]
    for table, columns in {
        "files": ["path", "original_path", "source"],
        "photo_items": ["path", "sidecar_path", "original_path"],
        "backup_runs": ["source", "mode"],
        "import_errors": ["source", "item_path"],
        "duplicate_groups": [],
    }.items():
        exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        if not exists:
            continue
        for column in columns:
            for old, new in replacements:
                conn.execute(f"UPDATE {table} SET {column}=REPLACE({column}, ?, ?) WHERE {column} LIKE ?", (old, new, f"%{old}%"))
    conn.execute("UPDATE files SET source='photos_takeout' WHERE source='google_photos_takeout'")
    conn.execute("UPDATE files SET source='photos_local_archived' WHERE source='google_photos_local'")
    conn.execute("UPDATE backup_runs SET source='photos_takeout' WHERE source='google_photos'")


def _archive_local_sources(conn) -> None:
    exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='local_source_cleanup_queue'").fetchone()
    if exists:
        conn.execute("UPDATE local_source_cleanup_queue SET status='archived' WHERE status='pending'")


def _rewrite_config(p: VaultPaths) -> None:
    cfg_path = p.config / "config.yaml"
    if not cfg_path.exists():
        return
    cfg = load_config(p.root)
    cfg.pop("google_photos", None)
    cfg["photos"] = {"takeout_enabled": True}
    cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
