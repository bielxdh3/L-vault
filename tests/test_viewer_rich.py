from email.message import EmailMessage
from pathlib import Path

from fastapi.testclient import TestClient

from localvault import db
from localvault.config import ensure_directories
from localvault.viewer import create_app


def _client(tmp_path: Path) -> tuple[TestClient, object]:
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    return TestClient(create_app(p.root)), p


def test_top_navigation_includes_main_sections(tmp_path: Path):
    client, _p = _client(tmp_path)

    response = client.get("/")

    assert response.status_code == 200
    for label in ["Dashboard", "Backups", "Gmail", "Fotos", "Relatorios"]:
        assert label in response.text


def test_photos_gallery_lists_existing_and_missing_media(tmp_path: Path):
    client, p = _client(tmp_path)
    existing = p.photos / "2026" / "06" / "foto.jpg"
    existing.parent.mkdir(parents=True, exist_ok=True)
    existing.write_bytes(b"fake image")
    missing = p.videos / "2026" / "06" / "video.mp4"
    with db.connect(p.db) as conn:
        conn.execute(
            "INSERT INTO photo_items (filename,path,media_type,file_size,mime_type,creation_date) VALUES (?,?,?,?,?,?)",
            ("foto.jpg", str(existing), "photo", 10, "image/jpeg", "2026-06-19"),
        )
        conn.execute(
            "INSERT INTO photo_items (filename,path,media_type,file_size,mime_type,creation_date) VALUES (?,?,?,?,?,?)",
            ("video.mp4", str(missing), "video", 20, "video/mp4", "2026-06-18"),
        )

    response = client.get("/fotos")

    assert response.status_code == 200
    assert "preview-1" in response.text
    assert "preview-back" in response.text
    assert "foto.jpg" in response.text
    assert "video.mp4" in response.text
    assert "Ausente" in response.text
    assert "/file?path=" in response.text


def test_photos_gallery_filters_and_layout_options(tmp_path: Path):
    client, p = _client(tmp_path)
    keep = p.photos / "2026" / "06" / "praia.jpg"
    keep.parent.mkdir(parents=True, exist_ok=True)
    keep.write_bytes(b"fake image")
    skip = p.photos / "2025" / "01" / "cidade.jpg"
    skip.parent.mkdir(parents=True, exist_ok=True)
    skip.write_bytes(b"fake image")
    with db.connect(p.db) as conn:
        conn.execute(
            "INSERT INTO photo_items (filename,path,media_type,file_size,mime_type,creation_date,album) VALUES (?,?,?,?,?,?,?)",
            ("praia.jpg", str(keep), "photo", 10, "image/jpeg", "2026-06-19", "Ferias"),
        )
        conn.execute(
            "INSERT INTO photo_items (filename,path,media_type,file_size,mime_type,creation_date,album) VALUES (?,?,?,?,?,?,?)",
            ("cidade.jpg", str(skip), "photo", 10, "image/jpeg", "2025-01-01", "Trabalho"),
        )

    response = client.get("/fotos", params={"q": "praia", "album": "Ferias", "date_from": "2026-01-01", "layout": "three"})

    assert response.status_code == 200
    assert "layout-three" in response.text
    assert "praia.jpg" in response.text
    assert "cidade.jpg" not in response.text


def test_photo_detail_returns_metadata_and_404_for_missing_item(tmp_path: Path):
    client, p = _client(tmp_path)
    photo = p.photos / "foto.jpg"
    photo.parent.mkdir(parents=True, exist_ok=True)
    photo.write_bytes(b"fake image")
    with db.connect(p.db) as conn:
        conn.execute(
            "INSERT INTO photo_items (filename,path,media_type,file_size,mime_type,width,height,album) VALUES (?,?,?,?,?,?,?,?)",
            ("foto.jpg", str(photo), "photo", 10, "image/jpeg", 800, 600, "Ferias"),
        )

    response = client.get("/fotos/1")
    missing = client.get("/fotos/999")

    assert response.status_code == 200
    assert "foto.jpg" in response.text
    assert "800 x 600" in response.text
    assert "Ferias" in response.text
    assert missing.status_code == 404


def test_gmail_message_renders_plain_text_and_attachments(tmp_path: Path):
    client, p = _client(tmp_path)
    message_path = p.gmail_messages / "plain.eml"
    message_path.parent.mkdir(parents=True, exist_ok=True)
    msg = EmailMessage()
    msg["Subject"] = "Plain"
    msg["From"] = "alice@example.com"
    msg.set_content("Plain body")
    message_path.write_bytes(msg.as_bytes())
    attachment = p.gmail_attachments / "doc.txt"
    attachment.parent.mkdir(parents=True, exist_ok=True)
    attachment.write_text("doc", encoding="utf-8")
    with db.connect(p.db) as conn:
        conn.execute(
            "INSERT INTO gmail_messages (gmail_id,subject,sender,eml_path,raw_sha256,source) VALUES (?,?,?,?,?,?)",
            ("g1", "Plain", "alice@example.com", str(message_path), "hash1", "gmail_takeout"),
        )
        conn.execute(
            "INSERT INTO gmail_attachments (gmail_message_id,filename,path,mime_type,size,sha256) VALUES (?,?,?,?,?,?)",
            (1, "doc.txt", str(attachment), "text/plain", 3, "hash2"),
        )

    response = client.get("/gmail/1")

    assert response.status_code == 200
    assert "Plain body" in response.text
    assert "doc.txt" in response.text
    assert "/file?path=" in response.text


def test_gmail_message_renders_sanitized_html(tmp_path: Path):
    client, p = _client(tmp_path)
    message_path = p.gmail_messages / "html.eml"
    message_path.parent.mkdir(parents=True, exist_ok=True)
    msg = EmailMessage()
    msg["Subject"] = "HTML"
    msg["From"] = "alice@example.com"
    msg.set_content("Plain fallback")
    msg.add_alternative(
        '<html><body><h1>Hello</h1><script>alert(1)</script><img src="https://example.com/a.png" onerror="alert(2)"></body></html>',
        subtype="html",
    )
    message_path.write_bytes(msg.as_bytes())
    with db.connect(p.db) as conn:
        conn.execute(
            "INSERT INTO gmail_messages (gmail_id,subject,sender,eml_path,raw_sha256,source) VALUES (?,?,?,?,?,?)",
            ("g1", "HTML", "alice@example.com", str(message_path), "hash1", "gmail_takeout"),
        )

    response = client.get("/gmail/1")

    assert response.status_code == 200
    assert "email-frame" in response.text
    assert "Hello" in response.text
    assert "script" not in response.text.lower()
    assert "onerror" not in response.text.lower()
    assert "https://example.com/a.png" not in response.text
    assert "data-remote-image" in response.text


def test_gmail_list_decodes_entities_and_filters_attachments(tmp_path: Path):
    client, p = _client(tmp_path)
    message_path = p.gmail_messages / "html.eml"
    message_path.parent.mkdir(parents=True, exist_ok=True)
    message_path.write_bytes(b"From: alice@example.com\nSubject: Test\n\nBody")
    with db.connect(p.db) as conn:
        conn.execute(
            "INSERT INTO gmail_messages (gmail_id,subject,sender,snippet,eml_path,raw_sha256,source,message_date) VALUES (?,?,?,?,?,?,?,?)",
            ("g1", "Ollama&amp; Team", "alice@example.com", "Team &amp; plan", str(message_path), "hash1", "gmail_takeout", "2026-06-19"),
        )
        conn.execute(
            "INSERT INTO gmail_attachments (gmail_message_id,filename,path,mime_type,size,sha256) VALUES (?,?,?,?,?,?)",
            (1, "doc.txt", str(message_path), "text/plain", 3, "hash2"),
        )

    response = client.get("/gmail", params={"has_attachments": "true", "sender": "alice"})

    assert response.status_code == 200
    assert "Ollama&amp;amp; Team" not in response.text
    assert "Team &amp;amp; plan" not in response.text
    assert "Ollama&amp; Team" in response.text
    assert "Team &amp; plan" in response.text
    assert "1 anexo" in response.text
    assert "menu-popover" in response.text


def test_backups_page_exists(tmp_path: Path):
    client, _p = _client(tmp_path)

    response = client.get("/backups")

    assert response.status_code == 200
    assert "Backups" in response.text
    assert "Importar Takeout/Fotos" in response.text
