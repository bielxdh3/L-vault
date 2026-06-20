from pathlib import Path

from localvault import db
from localvault.config import ensure_directories
from localvault.photos import ingest_photos_takeout
from localvault.reports import RunReport


def test_ingest_photos_takeout_imports_media_to_fotos_vault(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    takeout_dir = p.google_takeout_inbox / "Takeout" / "Fotos"
    takeout_dir.mkdir(parents=True)
    (takeout_dir / "photo.jpg").write_bytes(b"fake jpg")

    report = ingest_photos_takeout(p, RunReport(source="test", mode="takeout"))

    assert report.imported_count == 1
    imported = list(p.photos.rglob("photo.jpg"))
    assert len(imported) == 1
    with db.connect(p.db) as conn:
        row = conn.execute("SELECT path,media_type FROM photo_items").fetchone()
        file_row = conn.execute("SELECT source FROM files").fetchone()
    assert row["media_type"] == "photo"
    assert "vault\\fotos\\imagens" in row["path"]
    assert file_row["source"] == "photos_takeout"


def test_ingest_photos_takeout_skips_duplicates(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    takeout_dir = p.google_takeout_inbox / "Takeout" / "Fotos"
    takeout_dir.mkdir(parents=True)
    (takeout_dir / "photo.jpg").write_bytes(b"same")

    first = ingest_photos_takeout(p, RunReport(source="test", mode="takeout"))
    second = ingest_photos_takeout(p, RunReport(source="test", mode="takeout"))

    assert first.imported_count == 1
    assert second.skipped_duplicates == 1
    assert len(list(p.photos.rglob("photo.jpg"))) == 1
