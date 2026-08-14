import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest
import yaml
from typer.testing import CliRunner

from localvault import db
from localvault.cli import app
from localvault.config import ensure_directories
from localvault.auto_takeout import auto_takeout
from localvault.extract import safe_extract_zip
from localvault.gmail_takeout import ingest_gmail_takeout
from localvault.locks import BackupLock
from localvault.photos import ingest_photos_takeout
from localvault.recovery import _write_fixture_zip, run_recovery_test
from localvault.reports import RunReport, mark_stale_running_runs, start_run
from localvault.restore import execute_restore, plan_restore
from localvault.utils import atomic_copy, sha256_file, temp_path_for
from localvault.verify import verify_vault


runner = CliRunner()


def test_recovery_command_distinguishes_integrity_and_restore_status():
    result = runner.invoke(app, ["recovery-test"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["integrity"]["status"] == "integrity_verified"
    assert payload["restore"]["status"] == "restore_drill_passed"
    assert payload["fixture"] == {"synthetic": True, "temporary": True, "bounded": True}


def test_recovery_drill_is_repeatable_and_sources_are_synthetic():
    first = run_recovery_test()
    second = run_recovery_test()

    assert first["status"] == second["status"] == "passed"
    assert first["restore"]["copied"] == second["restore"]["copied"]


def test_duplicate_synthetic_source_is_skipped_without_new_index_rows(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    first = _write_fixture_zip(p.google_takeout_inbox / "first.zip", marker="duplicate")
    second = first
    first_report = RunReport(source="synthetic", mode="ingest")
    ingest_photos_takeout(p, first_report, zip_paths=[first])
    ingest_gmail_takeout(p, first_report, zip_paths=[first])
    with db.connect(p.db) as conn:
        before = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    second_report = RunReport(source="synthetic", mode="ingest")
    ingest_photos_takeout(p, second_report, zip_paths=[second])
    ingest_gmail_takeout(p, second_report, zip_paths=[second])
    with db.connect(p.db) as conn:
        after = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    assert second_report.skipped_duplicates >= 2
    assert after == before


def test_multi_zip_failure_gates_ingest_and_retry_processes_remaining_zip(monkeypatch, tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    (p.config / "config.yaml").write_text(yaml.safe_dump({"source_sync": {"google_takeout_sources": [str(downloads)]}}), encoding="utf-8")
    first = _write_fixture_zip(downloads / "first.zip", marker="first")
    second = _write_fixture_zip(downloads / "second.zip", marker="second")
    original_copy = __import__("localvault.auto_takeout", fromlist=["atomic_copy"]).atomic_copy

    def fail_second(source, destination, **kwargs):
        if source == second:
            raise OSError("synthetic copy interruption")
        return original_copy(source, destination, **kwargs)

    monkeypatch.setattr("localvault.auto_takeout.atomic_copy", fail_second)
    first_report = auto_takeout(p, RunReport(source="synthetic", mode="auto"))
    assert first_report.failed_count == 1
    assert not list(p.root.glob("vault/gmail/messages/*.eml"))

    monkeypatch.undo()
    retry_report = auto_takeout(p, RunReport(source="synthetic", mode="auto"))
    assert retry_report.failed_count == 0
    assert retry_report.imported_count >= 1
    assert (p.google_takeout_inbox / first.name).exists()
    assert (p.google_takeout_inbox / second.name).exists()


def test_corrupted_indexed_file_verify_and_restore_report_failure(tmp_path: Path):
    p, source = _indexed_fixture(tmp_path)
    source.write_bytes(b"corrupt")
    verify_report = RunReport(source="vault", mode="verify_full")
    verify_vault(p, verify_report)
    assert verify_report.failed_count == 1

    result = execute_restore(p, plan_restore(p, tmp_path / "restore"))
    assert result.status == "partial"
    assert result.public()["counts"]["errors"] == 1


def test_missing_indexed_file_has_clean_error_and_orphan_is_not_restored(tmp_path: Path):
    p, source = _indexed_fixture(tmp_path)
    source.unlink()
    orphan = p.root / "vault" / "orphan.bin"
    orphan.write_bytes(b"orphan")
    result = execute_restore(p, plan_restore(p, tmp_path / "restore"))

    assert result.status == "partial"
    assert result.public()["counts"]["errors"] == 1
    assert not (tmp_path / "restore" / "orphan.bin").exists()


def test_low_space_is_checked_before_restore(monkeypatch, tmp_path: Path):
    from localvault import health

    monkeypatch.setattr(health, "disk_usage", lambda _: os.statvfs(tmp_path) if False else type("Usage", (), {"total": 100, "used": 90, "free": 10})())
    p, _ = _indexed_fixture(tmp_path)
    snapshot = health.health_snapshot(p)

    assert snapshot["metrics"]["filesystem"]["low_space"] is True
    assert not (tmp_path / "restore").exists()


def test_stale_run_and_lock_are_recoverable(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    report = RunReport(source="synthetic", mode="recovery", started_at=(datetime.now(timezone.utc) - timedelta(hours=13)).isoformat())
    start_run(p.db, report)
    assert mark_stale_running_runs(p.db) == 1

    lock_path = p.logs / "localvault_backup.lock"
    lock_path.write_text('{"started_at":"2020-01-01T00:00:00+00:00"}', encoding="utf-8")
    lock = BackupLock(lock_path)
    lock.acquire()
    lock.release()
    assert not lock_path.exists()


def test_zip_traversal_and_symlink_hazards_are_rejected(tmp_path: Path):
    traversal = tmp_path / "traversal.zip"
    with ZipFile(traversal, "w") as archive:
        archive.writestr("../escape.txt", b"escape")
    with pytest.raises(ValueError):
        safe_extract_zip(traversal, tmp_path / "out")

    symlink = tmp_path / "symlink.zip"
    info = ZipInfo("link")
    info.create_system = 3
    info.external_attr = (0o120777 << 16) | 0xA000
    with ZipFile(symlink, "w") as archive:
        archive.writestr(info, b"target")
    with pytest.raises(ValueError):
        safe_extract_zip(symlink, tmp_path / "out")


def test_atomic_copy_interruption_leaves_no_partial_and_retry_succeeds(monkeypatch, tmp_path: Path):
    source = tmp_path / "source.bin"
    destination = tmp_path / "destination.bin"
    source.write_bytes(b"synthetic-bytes")

    def interrupted(*args, **kwargs):
        raise OSError("synthetic interruption")

    monkeypatch.setattr("localvault.utils.shutil.copyfileobj", interrupted)
    with pytest.raises(OSError):
        atomic_copy(source, destination)
    assert not destination.exists()
    assert not temp_path_for(destination).exists()

    monkeypatch.undo()
    atomic_copy(source, destination)
    assert sha256_file(source) == sha256_file(destination)


def test_restore_manifest_is_truthful_after_rerun(tmp_path: Path):
    p, _ = _indexed_fixture(tmp_path)
    destination = tmp_path / "restore"
    execute_restore(p, plan_restore(p, destination))
    second = execute_restore(p, plan_restore(p, destination))
    manifest = json.loads(second.manifest_path.read_text(encoding="utf-8"))

    assert manifest["counts"] == {"selected": 1, "copied": 0, "skipped": 1, "renamed": 0, "overwritten": 0, "errors": 0, "bytes": 0}


def _indexed_fixture(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    source = p.root / "vault" / "synthetic" / "item.bin"
    source.parent.mkdir(parents=True, exist_ok=True)
    data = b"indexed synthetic item"
    source.write_bytes(data)
    with db.connect(p.db) as conn:
        db.upsert_file(conn, sha256=hashlib.sha256(data).hexdigest(), path=source, media_type="photo", size=len(data), source="synthetic")
    return p, source
