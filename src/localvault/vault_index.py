from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from . import db
from .config import VaultPaths


def source_label(row: Any) -> str:
    source = str(row["source"] or "").lower()
    media_type = str(row["media_type"] or "").lower()
    path = str(row["path"] or "").lower()
    if "gmail" in source or media_type == "email" or "gmail" in path:
        return "E-mail"
    if "whatsapp" in source or "whatsapp" in media_type or "whatsapp" in path:
        return "WhatsApp"
    if "photo" in source or "google_photos" in source or media_type in {"photo", "video"}:
        return "Drive/Fotos"
    return "Arquivo"


def safe_vault_path(root: Path, value: str) -> Path:
    requested = Path(value).resolve()
    root_resolved = root.resolve()
    if root_resolved != requested and root_resolved not in requested.parents:
        raise ValueError("Path is outside LocalVault.")
    return requested


def open_in_explorer(path: Path) -> None:
    if os.name != "nt":
        return
    target = path if path.exists() else path.parent
    if path.exists() and path.is_file():
        subprocess.Popen(["explorer.exe", f"/select,{path}"])
    elif target.exists():
        os.startfile(target)  # type: ignore[attr-defined]


def dashboard_data(p: VaultPaths) -> dict[str, Any]:
    with db.connect(p.db) as conn:
        gmail_rows = conn.execute("SELECT eml_path FROM gmail_messages").fetchall()
        attachment_rows = conn.execute("SELECT path FROM gmail_attachments").fetchall()
        photo_rows = conn.execute("SELECT path,media_type FROM google_photos_items").fetchall()
        file_rows = conn.execute("SELECT * FROM files ORDER BY first_seen_at DESC, id DESC LIMIT 25").fetchall()
        existing_files = conn.execute("SELECT path,size FROM files").fetchall()
        stats = {
            "emails": _existing_count(row["eml_path"] for row in gmail_rows),
            "email_indexed": len(gmail_rows),
            "attachments": _existing_count(row["path"] for row in attachment_rows),
            "photos": _existing_count(row["path"] for row in photo_rows if row["media_type"] == "photo"),
            "videos": _existing_count(row["path"] for row in photo_rows if row["media_type"] == "video"),
            "chats": int(conn.execute("SELECT COUNT(*) FROM whatsapp_chats").fetchone()[0]),
            "storage": sum(int(row["size"] or 0) for row in existing_files if Path(row["path"]).exists()),
            "missing_files": sum(1 for row in existing_files if not Path(row["path"]).exists()),
            "last_run": conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 1").fetchone(),
        }
    recent = []
    for row in file_rows:
        path = Path(row["path"])
        recent.append({
            "path": str(path),
            "name": path.name,
            "size": int(row["size"] or 0),
            "source": source_label(row),
            "media_type": row["media_type"] or "file",
            "exists": path.exists(),
            "first_seen_at": row["first_seen_at"],
        })
    return {"stats": stats, "recent_files": recent}


def cleanup_missing_index_entries(p: VaultPaths) -> int:
    removed = 0
    with db.connect(p.db) as conn:
        for row in conn.execute("SELECT id,path FROM files ORDER BY id").fetchall():
            path = Path(row["path"])
            if path.exists():
                continue
            removed += _delete_index_for_path(conn, str(path))
        for row in conn.execute("SELECT id,eml_path FROM gmail_messages WHERE eml_path IS NOT NULL AND eml_path != ''").fetchall():
            path = Path(row["eml_path"])
            if not path.exists():
                conn.execute("DELETE FROM gmail_messages WHERE id=?", (row["id"],))
                removed += 1
        for row in conn.execute("SELECT id,path FROM gmail_attachments WHERE path IS NOT NULL AND path != ''").fetchall():
            if not Path(row["path"]).exists():
                conn.execute("DELETE FROM gmail_attachments WHERE id=?", (row["id"],))
                removed += 1
        for row in conn.execute("SELECT id,path FROM google_photos_items WHERE path IS NOT NULL AND path != ''").fetchall():
            if not Path(row["path"]).exists():
                conn.execute("DELETE FROM google_photos_items WHERE id=?", (row["id"],))
                removed += 1
    return removed


def delete_local_file_and_index(p: VaultPaths, path: Path) -> int:
    removed = 0
    if path.exists() and path.is_file():
        path.unlink()
        removed += 1
    with db.connect(p.db) as conn:
        removed += _delete_index_for_path(conn, str(path))
    return removed


def _delete_index_for_path(conn, path: str) -> int:
    removed = 0
    removed += conn.execute("DELETE FROM files WHERE path=?", (path,)).rowcount
    removed += conn.execute("DELETE FROM gmail_attachments WHERE path=?", (path,)).rowcount
    removed += conn.execute("DELETE FROM google_photos_items WHERE path=?", (path,)).rowcount
    removed += conn.execute("DELETE FROM gmail_messages WHERE eml_path=?", (path,)).rowcount
    return removed


def _existing_count(paths) -> int:
    return sum(1 for value in paths if value and Path(value).exists())
