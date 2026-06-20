from pathlib import Path
import os

from localvault import db
from localvault.config import ensure_directories
from localvault.vault_index import cleanup_missing_index_entries, dashboard_data, delete_local_file_and_index, open_in_explorer, safe_vault_path


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
        conn.execute("INSERT INTO photo_items (filename,path,media_type,sha256,file_size) VALUES (?,?,?,?,?)", ("photo.jpg", str(photo), "photo", "hash2", 5))
        db.upsert_file(conn, sha256="hash2", path=photo, media_type="photo", mime_type="image/jpeg", size=5, source="photos_takeout")

    delete_local_file_and_index(p, photo)
    assert not photo.exists()
    with db.connect(p.db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM photo_items").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0


def test_dashboard_recent_files_only_shows_vault_paths(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    photo = p.photos / "2026" / "06" / "photo.jpg"
    photo.parent.mkdir(parents=True, exist_ok=True)
    photo.write_bytes(b"photo")
    outside = p.root / "inbox" / "manual_imports" / "outside.jpg"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_bytes(b"outside")
    with db.connect(p.db) as conn:
        db.upsert_file(conn, sha256="hash2", path=photo, media_type="photo", mime_type="image/jpeg", size=5, source="photos_takeout")
        db.upsert_file(conn, sha256="hash3", path=outside, media_type="photo", mime_type="image/jpeg", size=7, source="manual_import")

    recent = dashboard_data(p)["recent_files"]

    assert [Path(item["path"]).name for item in recent] == ["photo.jpg"]


def test_safe_vault_path_can_require_storage_folder(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    target = p.photos / "photo.jpg"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"photo")
    assert safe_vault_path(p.root, str(target), require_vault=True) == target.resolve()
    try:
        safe_vault_path(p.root, str(p.inbox / "photo.jpg"), require_vault=True)
    except ValueError:
        pass
    else:
        raise AssertionError("expected inbox path to be blocked")


def test_open_in_explorer_quotes_selected_file(monkeypatch, tmp_path: Path):
    if os.name != "nt":
        return
    target = tmp_path / "folder with spaces" / "file with spaces.mp4"
    target.parent.mkdir()
    target.write_bytes(b"video")
    calls = []

    monkeypatch.setattr("localvault.vault_index.subprocess.Popen", lambda command: calls.append(command))

    open_in_explorer(target)

    assert calls == [f'explorer.exe /select,"{target}"']
