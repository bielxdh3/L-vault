from pathlib import Path

from localvault import db
from localvault.config import ensure_directories
from localvault.vault_index import cleanup_missing_index_entries, dashboard_data, delete_local_file_and_index


def test_cleanup_missing_index_entries_updates_dashboard_counts(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    message = p.gmail_messages / "old.eml"
    message.parent.mkdir(parents=True, exist_ok=True)
    message.write_bytes(b"email")
    with db.connect(p.db) as conn:
        conn.execute("INSERT INTO gmail_messages (gmail_id,subject,eml_path,raw_sha256,source) VALUES (?,?,?,?,?)", ("1", "Oi", str(message), "hash1", "gmail_api"))
        db.upsert_file(conn, sha256="hash1", path=message, media_type="email", mime_type="message/rfc822", size=5, source="gmail_api")

    assert dashboard_data(p)["stats"]["emails"] == 1
    message.unlink()
    assert dashboard_data(p)["stats"]["emails"] == 0
    assert dashboard_data(p)["stats"]["missing_files"] == 1
    assert cleanup_missing_index_entries(p) >= 1

    with db.connect(p.db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM gmail_messages").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0


def test_delete_local_file_and_index_removes_file_and_rows(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    photo = p.photos / "2026" / "06" / "photo.jpg"
    photo.parent.mkdir(parents=True, exist_ok=True)
    photo.write_bytes(b"photo")
    with db.connect(p.db) as conn:
        conn.execute("INSERT INTO google_photos_items (filename,path,media_type,sha256,file_size) VALUES (?,?,?,?,?)", ("photo.jpg", str(photo), "photo", "hash2", 5))
        db.upsert_file(conn, sha256="hash2", path=photo, media_type="photo", mime_type="image/jpeg", size=5, source="google_photos")

    delete_local_file_and_index(p, photo)
    assert not photo.exists()
    with db.connect(p.db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM google_photos_items").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
