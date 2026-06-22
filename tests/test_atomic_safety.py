from datetime import datetime, timedelta, timezone
from pathlib import Path
from zipfile import ZipFile

import pytest

from localvault import db
from localvault.config import ensure_directories
from localvault.extract import safe_extract_zip
from localvault.locks import BackupLock
from localvault.reports import RunReport, mark_stale_running_runs, start_run
from localvault.utils import atomic_copy, atomic_write_bytes, cleanup_stale_temp_files, copy_preserve, sha256_file, temp_path_for


def test_atomic_copy_does_not_leave_final_when_copy_fails(monkeypatch, tmp_path: Path):
    src = tmp_path / "source.bin"
    dest = tmp_path / "dest.bin"
    src.write_bytes(b"abcdef")

    def fail_copy(in_file, out_file, length=0):
        out_file.write(b"abc")
        raise OSError("power loss")

    monkeypatch.setattr("localvault.utils.shutil.copyfileobj", fail_copy)

    with pytest.raises(OSError):
        atomic_copy(src, dest)

    assert not dest.exists()
    assert not temp_path_for(dest).exists()


def test_atomic_write_bytes_does_not_leave_final_when_replace_fails(monkeypatch, tmp_path: Path):
    dest = tmp_path / "message.eml"

    def fail_replace(src, dst):
        raise OSError("disk error")

    monkeypatch.setattr("localvault.utils.os.replace", fail_replace)

    with pytest.raises(OSError):
        atomic_write_bytes(dest, b"partial")

    assert not dest.exists()
    assert not temp_path_for(dest).exists()


def test_safe_extract_zip_does_not_leave_final_when_write_fails(monkeypatch, tmp_path: Path):
    archive = tmp_path / "takeout.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("Takeout/photo.jpg", b"photo")

    def fail_write(dest, src, expected_size=None, dry_run=False):
        temp = temp_path_for(dest)
        temp.parent.mkdir(parents=True, exist_ok=True)
        temp.write_bytes(b"part")
        temp.unlink()
        raise OSError("extract failed")

    monkeypatch.setattr("localvault.extract.atomic_write_from_fileobj", fail_write)

    with pytest.raises(OSError):
        safe_extract_zip(archive, tmp_path / "out")

    assert not list((tmp_path / "out").rglob("photo.jpg"))


def test_copy_preserve_uses_atomic_copy_normal_case(tmp_path: Path):
    src = tmp_path / "source.txt"
    dest = tmp_path / "nested" / "dest.txt"
    src.write_text("hello", encoding="utf-8")

    size = copy_preserve(src, dest)

    assert size == 5
    assert dest.read_text(encoding="utf-8") == "hello"
    assert sha256_file(src) == sha256_file(dest)


def test_cleanup_stale_temp_files_removes_old_and_keeps_recent(tmp_path: Path):
    old = tmp_path / ".localvault_tmp_1_old.part"
    recent = tmp_path / ".localvault_tmp_1_recent.part"
    old.write_bytes(b"old")
    recent.write_bytes(b"recent")
    old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).timestamp()
    old.touch()
    recent.touch()
    import os

    os.utime(old, (old_time, old_time))

    removed = cleanup_stale_temp_files(tmp_path, older_than_hours=24)

    assert removed == 1
    assert not old.exists()
    assert recent.exists()


def test_backup_lock_blocks_concurrent_and_ignores_stale(tmp_path: Path):
    lock_path = tmp_path / "localvault.lock"
    first = BackupLock(lock_path)
    first.acquire()
    with pytest.raises(RuntimeError):
        BackupLock(lock_path).acquire()
    first.release()

    stale_time = (datetime.now(timezone.utc) - timedelta(hours=13)).timestamp()
    lock_path.write_text('{"started_at":"2020-01-01T00:00:00+00:00"}', encoding="utf-8")
    import os

    os.utime(lock_path, (stale_time, stale_time))
    stale = BackupLock(lock_path)
    stale.acquire()
    stale.release()
    assert not lock_path.exists()


def test_stale_running_run_is_marked_interrupted(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    report = RunReport(
        source="localvault",
        mode="daily_backup",
        started_at=(datetime.now(timezone.utc) - timedelta(hours=13)).isoformat(),
    )
    start_run(p.db, report)

    updated = mark_stale_running_runs(p.db, older_than_hours=12)

    assert updated == 1
    with db.connect(p.db) as conn:
        row = conn.execute("SELECT status FROM backup_runs WHERE id=?", (report.run_id,)).fetchone()
    assert row["status"] == "interrupted"
