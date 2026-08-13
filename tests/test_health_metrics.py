from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

from localvault import db
from localvault.cli import app
from localvault.config import ensure_directories
from localvault.health import health_snapshot
from typer.testing import CliRunner


runner = CliRunner()


def _prepared(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    return p


def test_health_metrics_healthy_and_never_verified(tmp_path: Path, monkeypatch):
    p = _prepared(tmp_path)
    monkeypatch.setattr("localvault.health.disk_usage", lambda _: type("Usage", (), {"total": 100 * 1024 ** 3, "used": 20 * 1024 ** 3, "free": 80 * 1024 ** 3})())

    health = health_snapshot(p)

    assert health["metrics"]["filesystem"]["low_space"] is False
    assert health["metrics"]["last_successful_full_verification"] is None
    assert health["metrics"]["future_surfaces"] == {
        "replica": {"status": "available"},
        "restore": {"status": "available"},
        "clone": {"status": "gated"},
    }


def test_health_check_json_is_bounded_and_machine_readable(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("localvault.health._has_ready_daily_task", lambda _cfg: False)
    result = runner.invoke(app, ["health-check", "--root", str(tmp_path / "vault"), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["metrics"]["future_surfaces"]["clone"]["status"] == "gated"
    assert "auth.json" not in result.output
    assert "localvault.sqlite" not in result.output


def test_health_metrics_low_space_simulation(tmp_path: Path, monkeypatch):
    p = _prepared(tmp_path)
    monkeypatch.setattr("localvault.health.disk_usage", lambda _: type("Usage", (), {"total": 100, "used": 95, "free": 5})())

    health = health_snapshot(p)

    assert health["status"] == "attention"
    assert health["metrics"]["filesystem"]["low_space"] is True


def test_health_metrics_missing_files_duplicates_and_runs(tmp_path: Path, monkeypatch):
    p = _prepared(tmp_path)
    monkeypatch.setattr("localvault.health.disk_usage", lambda _: type("Usage", (), {"total": 100 * 1024 ** 3, "used": 10, "free": 90 * 1024 ** 3})())
    old = (datetime.now(timezone.utc) - timedelta(hours=13)).isoformat()
    with db.connect(p.db) as conn:
        first = p.photos / "one.jpg"
        missing = p.gmail_messages / "gone.eml"
        first.parent.mkdir(parents=True, exist_ok=True)
        first.write_bytes(b"photo")
        db.upsert_file(conn, sha256="same", path=first, media_type="photo", size=10, source="photos_takeout")
        db.upsert_file(conn, sha256="same", path=missing, media_type="email", size=20, source="gmail_takeout")
        conn.execute("INSERT INTO photo_items (filename,path,media_type,file_size) VALUES (?,?,?,?)", ("one.jpg", str(first), "photo", 10))
        conn.execute("INSERT INTO duplicate_groups (sha256,file_count,total_size) VALUES (?,?,?)", ("same", 2, 30))
        group_id = conn.execute("SELECT id FROM duplicate_groups").fetchone()[0]
        for file_id in conn.execute("SELECT id FROM files").fetchall():
            conn.execute("INSERT INTO duplicate_files (group_id,file_id) VALUES (?,?)", (group_id, file_id[0]))
        conn.execute("INSERT INTO backup_runs (source,mode,started_at,finished_at,status,storage_added) VALUES (?,?,?,?,?,?)", ("vault", "verify_full", old, old, "warning", 7))
        conn.execute("INSERT INTO backup_runs (source,mode,started_at,finished_at,status,storage_added) VALUES (?,?,?,?,?,?)", ("vault", "verify_full", old, old, "failed", 3))
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("INSERT INTO backup_runs (source,mode,started_at,finished_at,status,storage_added) VALUES (?,?,?,?,?,?)", ("vault", "verify_full", now, now, "ok", 5))
        conn.execute("INSERT INTO import_errors (source,item_path,error) VALUES (?,?,?)", ("test", "private-path", "error"))

    health = health_snapshot(p)

    metrics = health["metrics"]
    assert metrics["indexed"]["file_count"] == 2
    assert metrics["indexed"]["missing_count"] == 1
    assert metrics["duplicates"] == {"group_count": 1, "storage_estimate_bytes": 10}
    assert metrics["stale_interrupted_run_count"] == 0
    assert metrics["recent_import_error_count"] >= 1
    assert metrics["recent_storage_growth"]["available"] is True
    assert metrics["recent_storage_growth"]["bytes"] == 15
    assert metrics["source_breakdown"]["photos_takeout"]["count"] == 1
    assert metrics["last_runs"]["successful"]["status"] == "ok"
    assert metrics["last_successful_full_verification"]["status"] == "ok"


def test_health_metrics_stale_and_interrupted_runs(tmp_path: Path, monkeypatch):
    p = _prepared(tmp_path)
    monkeypatch.setattr("localvault.health.disk_usage", lambda _: type("Usage", (), {"total": 100 * 1024 ** 3, "used": 1, "free": 99 * 1024 ** 3})())
    old = (datetime.now(timezone.utc) - timedelta(hours=13)).isoformat()
    with db.connect(p.db) as conn:
        conn.execute("INSERT INTO backup_runs (source,mode,started_at,status) VALUES (?,?,?,?)", ("test", "old", old, "running"))
        conn.execute("INSERT INTO backup_runs (source,mode,started_at,status) VALUES (?,?,?,?)", ("test", "interrupted", old, "interrupted"))

    health = health_snapshot(p)

    assert health["metrics"]["stale_interrupted_run_count"] == 2
