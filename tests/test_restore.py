import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from localvault import db
from localvault.cli import app
from localvault.config import ensure_directories
from localvault.restore import RestoreValidationError, execute_restore, plan_restore


runner = CliRunner()


def _prepared(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    files = [
        (p.gmail_messages / "2026" / "message.eml", "email", b"From: test@example.com\n\nhello\n"),
        (p.gmail_attachments / "hash" / "attachment.bin", "gmail_attachment", b"attachment"),
        (p.photos / "2026" / "01" / "photo.jpg", "photo", b"photo-bytes"),
        (p.videos / "2026" / "01" / "video.mp4", "video", b"video-bytes"),
    ]
    with db.connect(p.db) as conn:
        for path, media_type, data in files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            db.upsert_file(conn, sha256=digest, path=path, media_type=media_type, size=len(data), source=media_type)
    return p, files


def test_restore_all_copies_bytes_hashes_and_manifest(tmp_path: Path):
    p, files = _prepared(tmp_path)
    destination = tmp_path / "restored"
    plan = plan_restore(p, destination)
    result = execute_restore(p, plan)

    assert result.status == "completed"
    assert result.manifest_path == destination / ".localvault_restore_manifest.json"
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["counts"]["copied"] == 4
    for source, _, data in files:
        target = destination / source.relative_to(p.root / "vault")
        assert target.read_bytes() == data
        assert hashlib.sha256(target.read_bytes()).hexdigest() == hashlib.sha256(source.read_bytes()).hexdigest()
    assert all("source_path" not in item for item in manifest["items"])


def test_restore_media_selection_and_limit(tmp_path: Path):
    p, _ = _prepared(tmp_path)
    plan = plan_restore(p, tmp_path / "restored", media_type="email", limit=1)

    assert len(plan.items) == 1
    assert plan.items[0].source_path.suffix == ".eml"


def test_restore_dry_run_has_no_destination_side_effect(tmp_path: Path):
    p, _ = _prepared(tmp_path)
    destination = tmp_path / "restored"
    result = execute_restore(p, plan_restore(p, destination), dry_run=True)

    assert result.status == "dry_run"
    assert not destination.exists()

def test_restore_conflicts_skip_rename_and_overwrite(tmp_path: Path):
    p, files = _prepared(tmp_path)
    destination = tmp_path / "restored"
    target = destination / files[0][0].relative_to(p.root / "vault")
    target.parent.mkdir(parents=True)
    target.write_bytes(b"existing")

    skipped = execute_restore(p, plan_restore(p, destination, media_type="email"))
    assert skipped.public()["counts"]["skipped"] == 1
    assert target.read_bytes() == b"existing"

    renamed = execute_restore(p, plan_restore(p, destination, media_type="email", conflict="rename"))
    assert renamed.public()["counts"]["renamed"] == 1
    assert target.with_name("message_1.eml").exists()

    overwritten = execute_restore(p, plan_restore(p, destination, media_type="email", conflict="overwrite"))
    assert overwritten.public()["counts"]["overwritten"] == 1
    assert target.read_bytes() == files[0][2]


def test_restore_rerun_is_idempotent_by_default(tmp_path: Path):
    p, _ = _prepared(tmp_path)
    destination = tmp_path / "restored"
    execute_restore(p, plan_restore(p, destination))
    second = execute_restore(p, plan_restore(p, destination))

    assert second.status == "completed"
    assert second.public()["counts"]["skipped"] == 4


def test_restore_rejects_traversal_self_target_and_missing_source(tmp_path: Path):
    p, files = _prepared(tmp_path)
    try:
        plan_restore(p, p.root / "vault" / "restore")
    except RestoreValidationError:
        pass
    else:
        raise AssertionError("expected vault destination rejection")
    try:
        plan_restore(p, tmp_path / ".." / "outside")
    except RestoreValidationError:
        pass
    else:
        raise AssertionError("expected traversal rejection")
    files[0][0].unlink()
    plan = plan_restore(p, tmp_path / "restored", media_type="email")
    assert plan.items[0].status == "error"
    assert "missing" in (plan.items[0].error or "").lower()


def test_restore_plan_cli_is_json_and_does_not_write_destination(tmp_path: Path):
    p, _ = _prepared(tmp_path)
    destination = tmp_path / "restored"
    result = runner.invoke(app, ["restore-plan", "--root", str(p.root), "--destination", str(destination), "--media-type", "photo"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "planned"
    assert payload["counts"]["selected"] == 1
    assert not destination.exists()
