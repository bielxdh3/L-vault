from __future__ import annotations

from pathlib import Path

from . import db
from .config import VaultPaths
from .reports import RunReport
from .utils import sha256_file


def verify_vault(p: VaultPaths, report: RunReport, dry_run: bool = False, sample_limit: int | None = None) -> RunReport:
    checked = 0
    with db.connect(p.db) as conn:
        for row in conn.execute("SELECT path,sha256 FROM files ORDER BY id").fetchall():
            if sample_limit and checked >= sample_limit:
                break
            path = Path(row["path"])
            if not path.exists():
                report.error(path, "Indexed file is missing")
                continue
            if sha256_file(path) != row["sha256"]:
                report.error(path, "SHA-256 mismatch")
                continue
            checked += 1
    report.imported_count = checked
    return report
