from __future__ import annotations

import json

from . import db
from .config import VaultPaths
from .reports import RunReport


def build_duplicate_report(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    with db.connect(p.db) as conn:
        rows = conn.execute("""SELECT sha256,COUNT(*) file_count,SUM(size) total_size FROM files
        WHERE sha256 IS NOT NULL AND sha256 != '' GROUP BY sha256 HAVING COUNT(*) > 1 ORDER BY total_size DESC""").fetchall()
        if not dry_run:
            conn.execute("DELETE FROM duplicate_files")
            conn.execute("DELETE FROM duplicate_groups")
        out = []
        for row in rows:
            files = conn.execute("SELECT id,path,size,source FROM files WHERE sha256=?", (row["sha256"],)).fetchall()
            out.append({"sha256": row["sha256"], "file_count": row["file_count"], "total_size": row["total_size"], "files": [dict(f) for f in files]})
            if not dry_run:
                cur = conn.execute("INSERT INTO duplicate_groups (sha256,file_count,total_size) VALUES (?,?,?)", (row["sha256"], row["file_count"], row["total_size"] or 0))
                gid = int(cur.lastrowid)
                for f in files:
                    conn.execute("INSERT OR IGNORE INTO duplicate_files (group_id,file_id) VALUES (?,?)", (gid, f["id"]))
        report.imported_count = len(out)
        if not dry_run:
            path = p.reports / "duplicates_latest.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    return report
