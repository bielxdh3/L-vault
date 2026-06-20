from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import db
from .config import VaultPaths
from .reports import RunReport
from .utils import utc_now, write_json


def audit_gmail_duplicates(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    payload: dict[str, Any] = {}
    with db.connect(p.db) as conn:
        payload["duplicate_gmail_id"] = _duplicates(conn, "gmail_messages", "gmail_id")
        payload["duplicate_raw_sha256"] = _duplicates(conn, "gmail_messages", "raw_sha256")
        payload["duplicate_eml_path"] = _duplicates(conn, "gmail_messages", "eml_path")
        payload["duplicate_email_file_sha256"] = conn.execute("""
            SELECT sha256,COUNT(*) count,GROUP_CONCAT(path, char(10)) paths
            FROM files
            WHERE media_type='email' OR source LIKE 'gmail%'
            GROUP BY sha256 HAVING COUNT(*) > 1
            ORDER BY count DESC
        """).fetchall()
        payload["orphan_email_files"] = conn.execute("""
            SELECT f.path FROM files f
            LEFT JOIN gmail_messages g ON g.eml_path=f.path
            WHERE (f.media_type='email' OR f.source LIKE 'gmail%') AND g.id IS NULL
            ORDER BY f.path
        """).fetchall()
    serializable = {key: [dict(row) for row in rows] for key, rows in payload.items()}
    report.imported_count = sum(len(rows) for rows in serializable.values())
    if not dry_run:
        out = p.reports / "gmail_duplicates_latest.json"
        write_json(out, serializable)
        report.report_path = str(out)
    return report


def repair_stale_gmail_runs(p: VaultPaths, report: RunReport, dry_run: bool = False, older_than_hours: int = 6) -> RunReport:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=older_than_hours)
    repaired = 0
    with db.connect(p.db) as conn:
        rows = conn.execute("""
            SELECT id,started_at FROM backup_runs
            WHERE source='gmail' AND status='running' AND finished_at IS NULL
        """).fetchall()
        for row in rows:
            if not _older_than(row["started_at"], cutoff):
                continue
            repaired += 1
            if not dry_run:
                conn.execute("""
                    UPDATE backup_runs
                    SET status='warning', finished_at=?, warnings=?
                    WHERE id=?
                """, (utc_now(), '["Marked stale by gmail-repair-runs"]', row["id"]))
    report.imported_count = repaired
    if repaired:
        report.warn(f"Marked {repaired} stale Gmail run(s) as warning.")
    return report


def _duplicates(conn, table: str, column: str):
    return conn.execute(f"""
        SELECT {column} value,COUNT(*) count
        FROM {table}
        WHERE {column} IS NOT NULL AND {column} != ''
        GROUP BY {column} HAVING COUNT(*) > 1
        ORDER BY count DESC
    """).fetchall()


def _older_than(value: str, cutoff: datetime) -> bool:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc) < cutoff
    except Exception:
        return False
