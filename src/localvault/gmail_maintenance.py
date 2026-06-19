from __future__ import annotations

from pathlib import Path

from . import db
from .config import VaultPaths
from .email_names import unique_friendly_email_path
from .reports import RunReport


def rename_existing_gmail_files(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    missing = 0
    with db.connect(p.db) as conn:
        rows = conn.execute("""
            SELECT id,gmail_id,message_id_header,subject,sender,message_date,eml_path,raw_sha256
            FROM gmail_messages
            WHERE eml_path IS NOT NULL AND eml_path != ''
            ORDER BY id
        """).fetchall()
        for row in rows:
            current = Path(row["eml_path"])
            if not current.exists():
                missing += 1
                continue
            unique_id = row["gmail_id"] or row["message_id_header"] or (row["raw_sha256"] or "")[:16] or str(row["id"])
            target = unique_friendly_email_path(
                p.gmail_messages,
                message_date=row["message_date"],
                sender=row["sender"],
                subject=row["subject"],
                unique_id=unique_id,
            )
            if current.resolve() == target.resolve():
                report.skipped_duplicates += 1
                continue
            if not dry_run:
                target.parent.mkdir(parents=True, exist_ok=True)
                current.rename(target)
                conn.execute("UPDATE gmail_messages SET eml_path=? WHERE id=?", (str(target), row["id"]))
                conn.execute("UPDATE files SET path=? WHERE path=?", (str(target), str(current)))
            report.imported_count += 1
    if missing:
        report.warn(f"Skipped {missing} indexed Gmail messages because the .eml files were not found on disk.")
    return report
