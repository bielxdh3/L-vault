from pathlib import Path

from localvault import db
from localvault.config import ensure_directories
from localvault.reports import RunReport, finish_run, start_run


def test_finish_run_persists_item_failures_as_warning(tmp_path: Path):
    p = ensure_directories(tmp_path)
    db.init_db(p.db)
    report = start_run(p.db, RunReport(source="test", mode="finalize"))
    report.error("item", "failed")

    finish_run(p.db, p.reports, report)

    assert report.status == "warning"
    with db.connect(p.db) as conn:
        row = conn.execute("SELECT status, failed_count FROM backup_runs WHERE id=?", (report.run_id,)).fetchone()
    assert dict(row) == {"status": "warning", "failed_count": 1}
    assert '"status": "warning"' in Path(report.report_path).read_text(encoding="utf-8")
