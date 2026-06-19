from pathlib import Path

from localvault import db
from localvault.config import ensure_directories
from localvault.gmail_maintenance import rename_existing_gmail_files
from localvault.reports import RunReport


def test_rename_existing_gmail_files_updates_message_and_file_index(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    old = p.gmail_messages / "abc123.eml"
    old.parent.mkdir(parents=True, exist_ok=True)
    old.write_bytes(b"email")

    with db.connect(p.db) as conn:
        conn.execute("""
            INSERT INTO gmail_messages
            (gmail_id,subject,sender,message_date,eml_path,raw_sha256,source)
            VALUES (?,?,?,?,?,?,?)
        """, ("abc123", "Plano LocalVault", "Ana <ana@example.com>", "Fri, 19 Jun 2026 13:10:00 -0400", str(old), "hash1", "gmail_api"))
        db.upsert_file(conn, sha256="hash1", path=old, media_type="email", mime_type="message/rfc822", size=5, source="gmail_api")

    report = rename_existing_gmail_files(p, RunReport(source="gmail", mode="rename"))
    assert report.imported_count == 1
    assert not old.exists()

    with db.connect(p.db) as conn:
        new_path = Path(conn.execute("SELECT eml_path FROM gmail_messages").fetchone()[0])
        file_path = Path(conn.execute("SELECT path FROM files").fetchone()[0])
    assert new_path.exists()
    assert new_path == file_path
    assert "Ana" in new_path.name
    assert "Plano_LocalVault" in new_path.name
