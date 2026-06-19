from pathlib import Path

import yaml

from localvault import db
from localvault.config import ensure_directories
from localvault.photos import ingest_google_photos_local_sources
from localvault.reports import RunReport


def test_ingest_google_photos_local_sources_imports_media(tmp_path: Path):
    root = tmp_path / "vault"
    source = tmp_path / "GooglePhotosSync"
    source.mkdir()
    (source / "photo.jpg").write_bytes(b"fake jpg")
    p = ensure_directories(root)
    (p.config / "config.yaml").write_text(yaml.safe_dump({"google_photos": {"local_media_sources": [str(source)]}}), encoding="utf-8")
    db.init_db(p.db)

    report = ingest_google_photos_local_sources(p, RunReport(source="test", mode="photos_local"))

    assert report.imported_count == 1
    imported = list(p.photos.rglob("photo.jpg"))
    assert len(imported) == 1
    with db.connect(p.db) as conn:
        row = conn.execute("SELECT media_type,original_path FROM google_photos_items").fetchone()
        file_row = conn.execute("SELECT source FROM files").fetchone()
    assert row["media_type"] == "photo"
    assert row["original_path"] == str(source / "photo.jpg")
    assert file_row["source"] == "google_photos_local"


def test_ingest_google_photos_local_sources_skips_duplicates(tmp_path: Path):
    root = tmp_path / "vault"
    source = tmp_path / "GooglePhotosSync"
    source.mkdir()
    (source / "photo.jpg").write_bytes(b"same")
    p = ensure_directories(root)
    (p.config / "config.yaml").write_text(yaml.safe_dump({"google_photos": {"local_media_sources": [str(source)]}}), encoding="utf-8")
    db.init_db(p.db)

    first = ingest_google_photos_local_sources(p, RunReport(source="test", mode="photos_local"))
    second = ingest_google_photos_local_sources(p, RunReport(source="test", mode="photos_local"))

    assert first.imported_count == 1
    assert second.skipped_duplicates == 1
    assert len(list(p.photos.rglob("photo.jpg"))) == 1
