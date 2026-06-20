from pathlib import Path

import yaml

from localvault import db
from localvault.config import ensure_directories
from localvault.photos import ingest_google_photos_local_sources
from localvault.reports import RunReport
from localvault.source_cleanup import process_cleanup_queue, queue_existing_local_source_cleanup
from localvault.utils import sha256_file


def _config(p, source: Path):
    (p.config / "config.yaml").write_text(yaml.safe_dump({
        "google_photos": {
            "local_media_sources": [str(source)],
            "cleanup_originals": {
                "enabled": True,
                "only_if_path_contains": ["OneDrive"],
                "delete_after_next_backup": True,
            },
        }
    }), encoding="utf-8")


def test_onedrive_cleanup_waits_until_next_run(tmp_path: Path):
    root = tmp_path / "vault"
    source = tmp_path / "OneDrive" / "Imagens"
    source.mkdir(parents=True)
    original = source / "photo.jpg"
    original.write_bytes(b"photo")
    p = ensure_directories(root)
    _config(p, source)
    db.init_db(p.db)

    first = RunReport(source="test", mode="first", run_id=1)
    ingest_google_photos_local_sources(p, first)
    assert original.exists()
    assert process_cleanup_queue(p, first) == 0
    assert original.exists()

    second = RunReport(source="test", mode="second", run_id=2)
    assert process_cleanup_queue(p, second) == 1
    assert not original.exists()


def test_onedrive_cleanup_refuses_changed_original(tmp_path: Path):
    root = tmp_path / "vault"
    source = tmp_path / "OneDrive" / "Imagens"
    source.mkdir(parents=True)
    original = source / "photo.jpg"
    original.write_bytes(b"photo")
    p = ensure_directories(root)
    _config(p, source)
    db.init_db(p.db)

    report = RunReport(source="test", mode="first", run_id=1)
    ingest_google_photos_local_sources(p, report)
    original.write_bytes(b"changed")
    second = RunReport(source="test", mode="second", run_id=2)

    assert process_cleanup_queue(p, second) == 0
    assert original.exists()
    assert second.warnings


def test_queue_existing_local_source_cleanup(tmp_path: Path):
    root = tmp_path / "vault"
    source = tmp_path / "OneDrive" / "Imagens"
    source.mkdir(parents=True)
    original = source / "photo.jpg"
    original.write_bytes(b"photo")
    p = ensure_directories(root)
    _config(p, source)
    db.init_db(p.db)
    vault_copy = p.photos / "Camera_Roll" / "2026" / "06" / "photo.jpg"
    vault_copy.parent.mkdir(parents=True)
    vault_copy.write_bytes(b"photo")
    digest = sha256_file(vault_copy)
    with db.connect(p.db) as conn:
        db.upsert_file(conn, sha256=digest, path=vault_copy, original_path=original, media_type="photo", size=5, source="google_photos_local")

    assert queue_existing_local_source_cleanup(p) == 1
