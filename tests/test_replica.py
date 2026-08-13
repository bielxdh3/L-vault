import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from localvault import db
from localvault.cli import app
from localvault.config import ensure_directories, paths
from localvault.locks import BackupLock
from localvault.replica import ReplicaValidationError, execute_replica, plan_replica, replica_status
from localvault.restore import execute_restore, plan_restore


runner = CliRunner()


def test_replica_fresh_incremental_changed_and_db_snapshot(tmp_path: Path):
    p, source = _fixture(tmp_path)
    destination = tmp_path / "replica"

    first = execute_replica(p, plan_replica(p, destination))
    assert first.status == "completed"
    assert (destination / "vault" / "photos" / "one.bin").read_bytes() == b"one"
    assert (destination / "config" / "config.yaml").exists()
    with sqlite3.connect(destination / "db" / "localvault.sqlite") as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'").fetchone()
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 1

    second = execute_replica(p, plan_replica(p, destination))
    assert second.status == "completed"
    assert second.public()["counts"]["skipped"] >= 3
    source.write_bytes(b"changed")
    third = execute_replica(p, plan_replica(p, destination))
    assert third.public()["counts"]["copied"] >= 1
    assert (destination / "vault" / "photos" / "one.bin").read_bytes() == b"changed"


def test_replica_preserves_target_when_source_disappears_and_marks_stale(tmp_path: Path):
    p, source = _fixture(tmp_path)
    destination = tmp_path / "replica"
    execute_replica(p, plan_replica(p, destination))
    source.unlink()

    plan = plan_replica(p, destination)
    assert plan.stale is True
    assert any(item.status == "source_missing_preserved" for item in plan.items)
    result = execute_replica(p, plan)

    assert result.status == "stale"
    assert (destination / "vault" / "photos" / "one.bin").read_bytes() == b"one"


def test_replica_interruption_leaves_no_final_partial_and_rerun_succeeds(monkeypatch, tmp_path: Path):
    p, source = _fixture(tmp_path)
    destination = tmp_path / "replica"

    monkeypatch.setattr("localvault.replica.copy_preserve", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("interrupted")))
    result = execute_replica(p, plan_replica(p, destination))
    assert result.status == "incomplete"
    assert not (destination / "vault" / "photos" / "one.bin").exists()
    assert list(destination.parent.glob(".localvault_replica_staging_*"))

    monkeypatch.undo()
    retry_plan = plan_replica(p, destination)
    assert retry_plan.incomplete is True
    result = execute_replica(p, retry_plan)
    assert result.status == "completed"
    assert (destination / "vault" / "photos" / "one.bin").read_bytes() == b"one"


def test_replica_hash_mismatch_is_reported_without_promoting_item(monkeypatch, tmp_path: Path):
    p, source = _fixture(tmp_path)
    destination = tmp_path / "replica"

    def corrupt_copy(source_path, target_path, **kwargs):
        from localvault.utils import copy_preserve
        size = copy_preserve(source_path, target_path, **kwargs)
        target_path.write_bytes(b"tampered")
        return size

    monkeypatch.setattr("localvault.replica.copy_preserve", corrupt_copy)

    result = execute_replica(p, plan_replica(p, destination))

    assert result.status == "incomplete"
    assert not (destination / "vault" / "photos" / "one.bin").exists()


def test_replica_low_space_and_recursive_targets_are_rejected(monkeypatch, tmp_path: Path):
    p, _ = _fixture(tmp_path)
    monkeypatch.setattr("localvault.replica.shutil.disk_usage", lambda _: type("Usage", (), {"free": 0, "total": 1, "used": 1})())
    result = execute_replica(p, plan_replica(p, tmp_path / "replica"))
    assert result.status == "low_space"

    with pytest.raises(ReplicaValidationError):
        plan_replica(p, p.root / "vault" / "nested")
    with pytest.raises(ReplicaValidationError):
        plan_replica(p, p.root)


def test_replica_excludes_secret_config_and_logs(tmp_path: Path):
    p, _ = _fixture(tmp_path)
    (p.config / "auth.json").write_text("synthetic-secret", encoding="utf-8")
    (p.config / "gmail_token.json").write_text("synthetic-token", encoding="utf-8")
    (p.config / "google_oauth_client_secret.json").write_text("synthetic-client-secret", encoding="utf-8")
    (p.logs / "private.log").write_text("synthetic-log", encoding="utf-8")

    plan = plan_replica(p, tmp_path / "replica")
    paths_in_plan = {item.relative for item in plan.items}

    assert "config/config.yaml" in paths_in_plan
    assert not any(name in "/".join(paths_in_plan) for name in ("auth.json", "gmail_token.json", "google_oauth_client_secret.json", "private.log"))


def test_replica_stale_manifest_and_restore_fixture(tmp_path: Path):
    p, _ = _fixture(tmp_path)
    destination = tmp_path / "replica"
    first = execute_replica(p, plan_replica(p, destination))
    manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
    manifest["status"] = "incomplete"
    first.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert replica_status(p)["status"] == "not_configured"

    restore_destination = tmp_path / "restored"
    result = execute_restore(paths(destination), plan_restore(paths(destination), restore_destination))
    assert result.status == "completed"
    assert (restore_destination / "photos" / "one.bin").read_bytes() == b"one"


def test_health_reports_configured_replica_only_after_manifest(tmp_path: Path):
    from localvault.health import health_snapshot

    p, _ = _fixture(tmp_path)
    destination = tmp_path / "replica"
    p.config.joinpath("config.yaml").write_text(yaml.safe_dump({"safety": {"minimum_free_gb": 0}, "replica": {"destination": str(destination)}}), encoding="utf-8")
    assert health_snapshot(p)["metrics"]["replica"]["status"] == "unavailable"
    execute_replica(p, plan_replica(p, destination))
    assert health_snapshot(p)["metrics"]["replica"]["status"] == "completed"


def test_replica_cli_requires_explicit_destination_and_honors_lock(tmp_path: Path):
    p, _ = _fixture(tmp_path)
    missing = runner.invoke(app, ["replica-plan", "--root", str(p.root)])
    assert missing.exit_code == 2
    assert json.loads(missing.output)["status"] == "rejected"

    lock = BackupLock(p.logs / "localvault_backup.lock")
    lock.acquire()
    try:
        conflict = runner.invoke(app, ["replica", "--root", str(p.root), "--destination", str(tmp_path / "replica")])
    finally:
        lock.release()
    assert conflict.exit_code == 1
    assert json.loads(conflict.output)["status"] == "lock_conflict"


def _fixture(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    (p.config / "config.yaml").write_text(yaml.safe_dump({"safety": {"minimum_free_gb": 0}}), encoding="utf-8")
    source = p.root / "vault" / "photos" / "one.bin"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"one")
    with db.connect(p.db) as conn:
        db.upsert_file(conn, sha256=hashlib.sha256(b"one").hexdigest(), path=source, media_type="photo", size=3, source="synthetic")
    return p, source
