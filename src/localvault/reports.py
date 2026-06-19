from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import db
from .utils import utc_now, write_json


@dataclass
class RunReport:
    source: str
    mode: str
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    status: str = "running"
    imported_count: int = 0
    skipped_duplicates: int = 0
    failed_count: int = 0
    storage_added: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    report_path: str | None = None
    run_id: int | None = None

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        logging.warning(message)

    def error(self, item_path: Path | str, message: str) -> None:
        self.failed_count += 1
        self.errors.append({"item_path": str(item_path), "error": message})
        logging.error("%s: %s", item_path, message)


def start_run(database: Path, report: RunReport) -> RunReport:
    with db.connect(database) as conn:
        cur = conn.execute("INSERT INTO backup_runs (source,mode,started_at,status) VALUES (?,?,?,?)",
                           (report.source, report.mode, report.started_at, report.status))
        report.run_id = int(cur.lastrowid)
    return report


def finish_run(database: Path, reports_dir: Path, report: RunReport, status: str = "ok") -> RunReport:
    report.finished_at = utc_now()
    report.status = "warning" if status == "ok" and report.warnings else status
    name = f"{report.started_at.replace(':','').replace('+','Z')}_{report.source}_{report.mode}.json"
    path = reports_dir / name
    report.report_path = str(path)
    write_json(path, asdict(report))
    with db.connect(database) as conn:
        conn.execute(
            """UPDATE backup_runs SET finished_at=?,status=?,imported_count=?,skipped_duplicates=?,
            failed_count=?,storage_added=?,warnings=?,report_path=? WHERE id=?""",
            (report.finished_at, report.status, report.imported_count, report.skipped_duplicates,
             report.failed_count, report.storage_added, json.dumps(report.warnings, ensure_ascii=False),
             report.report_path, report.run_id),
        )
        for err in report.errors:
            conn.execute("INSERT INTO import_errors (run_id,source,item_path,error) VALUES (?,?,?,?)",
                         (report.run_id, report.source, err["item_path"], err["error"]))
    return report
