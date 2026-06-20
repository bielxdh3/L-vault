from __future__ import annotations

from pathlib import Path
from typing import Any

from . import db
from .config import VaultPaths, load_config
from .reports import RunReport
from .utils import sha256_file, utc_now


def cleanup_config(p: VaultPaths) -> dict[str, Any]:
    cfg = load_config(p.root).get("google_photos", {}).get("cleanup_originals", {})
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "only_if_path_contains": list(cfg.get("only_if_path_contains", ["OneDrive"])),
        "delete_after_next_backup": bool(cfg.get("delete_after_next_backup", True)),
    }


def maybe_queue_cleanup(conn, p: VaultPaths, *, original: Path, vault_path: Path, sha256: str, source: str, run_id: int | None) -> None:
    cfg = cleanup_config(p)
    if not cfg["enabled"]:
        return
    if source != "google_photos_local":
        return
    if not _allowed_original(original, cfg):
        return
    conn.execute("""
        INSERT INTO local_source_cleanup_queue (original_path,vault_path,sha256,source,queued_run_id,status,last_error)
        VALUES (?,?,?,?,?,'pending',NULL)
        ON CONFLICT(original_path) DO UPDATE SET
          vault_path=excluded.vault_path,
          sha256=excluded.sha256,
          source=excluded.source,
          queued_run_id=COALESCE(local_source_cleanup_queue.queued_run_id, excluded.queued_run_id),
          status=CASE WHEN local_source_cleanup_queue.status='deleted' THEN 'deleted' ELSE 'pending' END,
          last_error=NULL
    """, (str(original), str(vault_path), sha256, source, run_id))


def queue_existing_local_source_cleanup(p: VaultPaths, report: RunReport | None = None) -> int:
    cfg = cleanup_config(p)
    if not cfg["enabled"]:
        return 0
    queued = 0
    with db.connect(p.db) as conn:
        rows = conn.execute("""
            SELECT path,original_path,sha256 FROM files
            WHERE source='google_photos_local' AND original_path IS NOT NULL AND original_path != ''
        """).fetchall()
        for row in rows:
            original = Path(row["original_path"])
            vault_path = Path(row["path"])
            if not _allowed_original(original, cfg):
                continue
            maybe_queue_cleanup(conn, p, original=original, vault_path=vault_path, sha256=row["sha256"], source="google_photos_local", run_id=report.run_id if report else None)
            queued += 1
    return queued


def process_cleanup_queue(p: VaultPaths, report: RunReport, dry_run: bool = False) -> int:
    cfg = cleanup_config(p)
    if not cfg["enabled"]:
        return 0
    deleted = 0
    with db.connect(p.db) as conn:
        rows = conn.execute("""
            SELECT * FROM local_source_cleanup_queue
            WHERE status='pending' AND (queued_run_id IS NULL OR queued_run_id != ?)
            ORDER BY id
        """, (report.run_id,)).fetchall()
        for row in rows:
            original = Path(row["original_path"])
            vault_path = Path(row["vault_path"])
            try:
                if not _allowed_original(original, cfg):
                    raise ValueError("Original path is not allowed for automatic cleanup.")
                if not original.exists():
                    conn.execute("UPDATE local_source_cleanup_queue SET status='deleted',deleted_at=?,last_error=NULL WHERE id=?", (utc_now(), row["id"]))
                    continue
                if not vault_path.exists():
                    raise ValueError("Vault copy is missing.")
                if sha256_file(vault_path) != row["sha256"]:
                    raise ValueError("Vault copy hash mismatch.")
                if sha256_file(original) != row["sha256"]:
                    raise ValueError("Original hash changed after backup.")
                if not dry_run:
                    original.unlink()
                    conn.execute("UPDATE local_source_cleanup_queue SET status='deleted',deleted_at=?,last_error=NULL WHERE id=?", (utc_now(), row["id"]))
                deleted += 1
            except Exception as exc:
                conn.execute("UPDATE local_source_cleanup_queue SET last_error=? WHERE id=?", (str(exc), row["id"]))
                report.warn(f"OneDrive cleanup skipped: {original} - {exc}")
    if deleted:
        report.warn(f"Deleted {deleted} verified OneDrive source file(s) after backup.")
    return deleted


def _allowed_original(path: Path, cfg: dict[str, Any]) -> bool:
    text = str(path).lower()
    needles = [str(x).lower() for x in cfg.get("only_if_path_contains", []) if str(x).strip()]
    return bool(needles) and any(needle in text for needle in needles)
