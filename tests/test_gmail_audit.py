from pathlib import Path

from localvault import db
from localvault.config import ensure_directories
from localvault.gmail_audit import audit_gmail_duplicates, repair_stale_gmail_runs
from localvault.reports import RunReport


def test_gmail_audit_reports_duplicate_file_hash_and_orphan(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    one = p.gmail_messages / "one.eml"
    two = p.gmail_messages / "two.eml"
    orphan = p.gmail_messages / "orphan.eml"
    one.parent.mkdir(parents=True, exist_ok=True)
    for path in (one, two, orphan):
        path.write_bytes(b"same")
    with db.connect(p.db) as conn:
        conn.execute("INSERT INTO gmail_messages (gmail_id,eml_path,raw_sha256,source) VALUES (?,?,?,?)", ("1", str(one), "raw1", "gmail_api"))
        db.upsert_file(conn, sha256="samehash", path=one, media_type="email", size=4, source="gmail_api")
        db.upsert_file(conn, sha256="samehash", path=two, media_type="email", size=4, source="gmail_api")
        db.upsert_file(conn, sha256="orphanhash", path=orphan, media_type="email", size=4, source="gmail_api")

    report = audit_gmail_duplicates(p, RunReport(source="gmail", mode="audit"))

    assert report.imported_count == 3
    assert Path(report.report_path).exists()


def test_repair_stale_gmail_runs_marks_old_running_rows(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    with db.connect(p.db) as conn:
        conn.execute("INSERT INTO backup_runs (source,mode,started_at,status) VALUES (?,?,?,?)", ("gmail", "api", "2020-01-01T00:00:00+00:00", "running"))

    report = repair_stale_gmail_runs(p, RunReport(source="gmail", mode="repair"), older_than_hours=1)

    assert report.imported_count == 1
    with db.connect(p.db) as conn:
        row = conn.execute("SELECT status,finished_at FROM backup_runs").fetchone()
    assert row["status"] == "warning"
    assert row["finished_at"]
