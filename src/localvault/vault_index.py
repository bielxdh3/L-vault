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
    if "photo" in source or "photos" in source or media_type in {"photo", "video"}:
        return "Fotos"
    return "Arquivo"


def safe_vault_path(root: Path, value: str, *, require_vault: bool = False) -> Path:
    requested = Path(value).resolve()
    root_resolved = root.resolve()
    if root_resolved != requested and root_resolved not in requested.parents:
        raise ValueError("Path is outside LocalVault.")
    if require_vault:
        vault_resolved = (root / "vault").resolve()
        if vault_resolved != requested and vault_resolved not in requested.parents:
            raise ValueError("Path is outside the Vault storage folder.")
    return requested


def open_in_explorer(path: Path) -> None:
    if os.name != "nt":
        return
    target = path if path.exists() else path.parent
    if path.exists() and path.is_file():
        try:
            subprocess.Popen(f'explorer.exe /select,"{path}"')
        except OSError:
            if path.parent.exists():
                os.startfile(path.parent)  # type: ignore[attr-defined]
    elif target.exists():
        os.startfile(target)  # type: ignore[attr-defined]


def dashboard_data(p: VaultPaths) -> dict[str, Any]:
    vault_root = p.root / "vault"
    with db.connect(p.db) as conn:
        gmail_rows = conn.execute("SELECT eml_path FROM gmail_messages").fetchall()
        attachment_rows = conn.execute("SELECT path FROM gmail_attachments").fetchall()
        photo_rows = conn.execute("SELECT path,media_type FROM photo_items").fetchall()
        file_rows = conn.execute("SELECT * FROM files ORDER BY first_seen_at DESC, id DESC LIMIT 25").fetchall()
        existing_files = conn.execute("SELECT path,size FROM files").fetchall()
        stats = {
            "emails": _existing_count(row["eml_path"] for row in gmail_rows),
            "email_indexed": len(gmail_rows),
            "attachments": _existing_count(row["path"] for row in attachment_rows),
            "photos": _existing_count(row["path"] for row in photo_rows if row["media_type"] == "photo"),
            "videos": _existing_count(row["path"] for row in photo_rows if row["media_type"] == "video"),
            "storage": sum(int(row["size"] or 0) for row in existing_files if Path(row["path"]).exists()),
            "missing_files": sum(1 for row in existing_files if not Path(row["path"]).exists()),
            "last_run": conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 1").fetchone(),
        }
    recent = []
    for row in file_rows:
        path = Path(row["path"])
        if not _is_under(path, vault_root):
            continue
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
        for row in conn.execute("SELECT id,path FROM photo_items WHERE path IS NOT NULL AND path != ''").fetchall():
            if not Path(row["path"]).exists():
                conn.execute("DELETE FROM photo_items WHERE id=?", (row["id"],))
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
    removed += conn.execute("DELETE FROM photo_items WHERE path=?", (path,)).rowcount
    removed += conn.execute("DELETE FROM gmail_messages WHERE eml_path=?", (path,)).rowcount
    return removed


def _existing_count(paths) -> int:
    return sum(1 for value in paths if value and Path(value).exists())


def _is_under(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
        return resolved == root_resolved or root_resolved in resolved.parents
    except Exception:
        return False
