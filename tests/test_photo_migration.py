from pathlib import Path

import yaml

from localvault import db
from localvault.config import ensure_directories
from localvault.migrations import migrate_to_takeout_photos


def test_migration_moves_old_photo_vault_and_rewrites_database(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    old_photo = p.root / "vault" / "google_photos" / "photos" / "2026" / "06" / "photo.jpg"
    old_photo.parent.mkdir(parents=True)
    old_photo.write_bytes(b"photo")
    old_path = str(old_photo)
    old_original = str(p.root / "inbox" / "google_takeout" / "photo.jpg")
    old_config_key = "google" + "_photos"
    old_sources_key = "local_media" + "_sources"
    (p.config / "config.yaml").write_text(yaml.safe_dump({
        old_config_key: {old_sources_key: ["C:\\Temp\\Imagens"]},
        "source_sync": {"google_takeout_sources": ["C:\\Users\\User\\Downloads"]},
    }), encoding="utf-8")
    with db.connect(p.db) as conn:
        conn.execute("""CREATE TABLE google_photos_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, path TEXT NOT NULL UNIQUE,
            sidecar_path TEXT, original_path TEXT, creation_date TEXT, exif_date TEXT,
            google_metadata_date TEXT, file_size INTEGER, mime_type TEXT, sha256 TEXT,
            width INTEGER, height INTEGER, album TEXT, media_type TEXT, imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.execute("INSERT INTO google_photos_items (filename,path,original_path,media_type,sha256,file_size) VALUES (?,?,?,?,?,?)", ("photo.jpg", old_path, old_original, "photo", "hash", 5))
        db.upsert_file(conn, sha256="hash", path=old_photo, original_path=Path(old_original), media_type="photo", size=5, source="google_photos_takeout")

    migrate_to_takeout_photos(p)

    new_photo = p.root / "vault" / "fotos" / "imagens" / "2026" / "06" / "photo.jpg"
    assert new_photo.exists()
    assert not old_photo.exists()
    with db.connect(p.db) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='google_photos_items'").fetchone() is None
        row = conn.execute("SELECT path,source FROM files").fetchone()
        item = conn.execute("SELECT path FROM photo_items").fetchone()
    assert row["path"] == str(new_photo)
    assert row["source"] == "photos_takeout"
    assert item["path"] == str(new_photo)
    cfg = yaml.safe_load((p.config / "config.yaml").read_text(encoding="utf-8"))
    assert "google_photos" not in cfg
    assert cfg["photos"]["takeout_enabled"] is True


def test_migration_preserves_same_size_files_with_different_content(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    old_photo = p.root / "vault" / "google_photos" / "photos" / "2026" / "06" / "photo.jpg"
    new_photo = p.root / "vault" / "fotos" / "imagens" / "2026" / "06" / "photo.jpg"
    old_photo.parent.mkdir(parents=True)
    new_photo.parent.mkdir(parents=True)
    old_photo.write_bytes(b"old!")
    new_photo.write_bytes(b"new!")

    migrate_to_takeout_photos(p)

    preserved_old_photo = new_photo.with_name("photo_1.jpg")
    assert new_photo.read_bytes() == b"new!"
    assert preserved_old_photo.read_bytes() == b"old!"
    assert not old_photo.exists()
