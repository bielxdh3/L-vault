from __future__ import annotations

import base64
from email.message import EmailMessage
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from localvault import db
from localvault.config import ensure_directories
from localvault.gmail_api import LAST_INTERNAL_DATE_MS, backup_gmail_api
from localvault.reports import RunReport
from localvault.viewer import create_app
from localvault.auth import set_password


def test_gmail_api_second_run_skips_existing_without_duplicate_files(monkeypatch, tmp_path: Path):
    p = _prepared(tmp_path)
    service = _FakeGmailService([
        _message("m1", "1700000000000", "First"),
        _message("m2", "1700000100000", "Second"),
    ])
    monkeypatch.setattr("localvault.gmail_api._service", lambda credentials, token: service)

    first = backup_gmail_api(p, RunReport(source="gmail", mode="api"))
    second = backup_gmail_api(p, RunReport(source="gmail", mode="api"))

    assert first.imported_count == 2
    assert second.imported_count == 0
    assert second.skipped_duplicates == 2
    with db.connect(p.db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM gmail_messages").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM files WHERE media_type='email'").fetchone()[0] == 2


def test_gmail_api_uses_incremental_query_with_overlap(monkeypatch, tmp_path: Path):
    p = _prepared(tmp_path)
    with db.connect(p.db) as conn:
        conn.execute("INSERT INTO settings (key,value) VALUES (?,?)", (LAST_INTERNAL_DATE_MS, "1700000000000"))
    service = _FakeGmailService([_message("m3", "1700000200000", "Third")])
    monkeypatch.setattr("localvault.gmail_api._service", lambda credentials, token: service)

    backup_gmail_api(p, RunReport(source="gmail", mode="api"))

    assert service.list_queries
    assert service.list_queries[0].startswith("after:")


def test_gmail_api_uses_existing_index_date_when_incremental_setting_missing(monkeypatch, tmp_path: Path):
    p = _prepared(tmp_path)
    with db.connect(p.db) as conn:
        conn.execute("INSERT INTO gmail_messages (gmail_id,message_date,eml_path,raw_sha256,source) VALUES (?,?,?,?,?)", ("old", "Tue, 14 Nov 2023 22:13:20 +0000", str(p.gmail_messages / "old.eml"), "oldraw", "gmail_api"))
    service = _FakeGmailService([_message("m3", "1700000200000", "Third")])
    monkeypatch.setattr("localvault.gmail_api._service", lambda credentials, token: service)

    backup_gmail_api(p, RunReport(source="gmail", mode="api"))

    assert service.list_queries
    assert service.list_queries[0].startswith("after:")


def test_gmail_api_skips_same_raw_message_already_imported_by_takeout(monkeypatch, tmp_path: Path):
    p = _prepared(tmp_path)
    msg = _message("m1", "1700000000000", "First")
    raw = base64.urlsafe_b64decode(msg["raw"].encode("ascii"))
    existing = p.gmail_messages / "takeout.eml"
    existing.parent.mkdir(parents=True, exist_ok=True)
    existing.write_bytes(raw)
    from localvault.utils import sha256_bytes
    digest = sha256_bytes(raw)
    with db.connect(p.db) as conn:
        conn.execute("INSERT INTO gmail_messages (subject,eml_path,raw_sha256,source) VALUES (?,?,?,?)", ("First", str(existing), digest, "gmail_takeout"))
        db.upsert_file(conn, sha256=digest, path=existing, media_type="email", size=len(raw), source="gmail_takeout")
    service = _FakeGmailService([msg])
    monkeypatch.setattr("localvault.gmail_api._service", lambda credentials, token: service)

    report = backup_gmail_api(p, RunReport(source="gmail", mode="api"))

    assert report.imported_count == 0
    assert report.skipped_duplicates == 1
    with db.connect(p.db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM gmail_messages").fetchone()[0] == 1
        assert conn.execute("SELECT gmail_id FROM gmail_messages").fetchone()[0] == "m1"


def test_gmail_api_saves_raw_eml_and_renderable_plain_text(monkeypatch, tmp_path: Path):
    p = _prepared(tmp_path)
    msg = EmailMessage()
    msg["Message-ID"] = "<plain@example.com>"
    msg["Subject"] = "Plain API"
    msg["From"] = "Sender <sender@example.com>"
    msg["To"] = "Receiver <receiver@example.com>"
    msg.set_content("Plain API body")
    service = _FakeGmailService([_message_from_email("plain", "1700000000000", msg)])
    monkeypatch.setattr("localvault.gmail_api._service", lambda credentials, token: service)

    report = backup_gmail_api(p, RunReport(source="gmail", mode="api"))

    assert report.imported_count == 1
    with db.connect(p.db) as conn:
        row = conn.execute("SELECT eml_path FROM gmail_messages WHERE gmail_id='plain'").fetchone()
        body = conn.execute("SELECT body_text FROM gmail_bodies").fetchone()
    assert Path(row["eml_path"]).exists()
    assert body["body_text"].strip() == "Plain API body"
    set_password(p.root, "test-password")
    client = TestClient(create_app(p.root)); client.post("/login", data={"password": "test-password"})
    response = client.get("/gmail/1")
    assert "Plain API body" in response.text


def test_gmail_api_saves_html_body_and_blocks_remote_images(monkeypatch, tmp_path: Path):
    p = _prepared(tmp_path)
    msg = EmailMessage()
    msg["Message-ID"] = "<html@example.com>"
    msg["Subject"] = "HTML API"
    msg["From"] = "Sender <sender@example.com>"
    msg.set_content("Plain fallback")
    msg.add_alternative('<html><body><h1>Hello API</h1><script>alert(1)</script><img src="https://example.com/remote.png"></body></html>', subtype="html")
    service = _FakeGmailService([_message_from_email("html", "1700000000000", msg)])
    monkeypatch.setattr("localvault.gmail_api._service", lambda credentials, token: service)

    backup_gmail_api(p, RunReport(source="gmail", mode="api"))

    with db.connect(p.db) as conn:
        body = conn.execute("SELECT body_html_path FROM gmail_bodies").fetchone()
    assert body["body_html_path"]
    set_password(p.root, "test-password")
    client = TestClient(create_app(p.root)); client.post("/login", data={"password": "test-password"})
    response = client.get("/gmail/1")
    assert "Hello API" in response.text
    assert "script" not in response.text.lower()
    assert "https://example.com/remote.png" not in response.text
    assert "data-remote-image" not in response.text


def test_gmail_api_extracts_attachment(monkeypatch, tmp_path: Path):
    p = _prepared(tmp_path)
    msg = EmailMessage()
    msg["Message-ID"] = "<attach@example.com>"
    msg["Subject"] = "Attachment API"
    msg["From"] = "Sender <sender@example.com>"
    msg.set_content("See attached")
    msg.add_attachment(b"document", maintype="text", subtype="plain", filename="doc.txt")
    service = _FakeGmailService([_message_from_email("attach", "1700000000000", msg)])
    monkeypatch.setattr("localvault.gmail_api._service", lambda credentials, token: service)

    backup_gmail_api(p, RunReport(source="gmail", mode="api"))

    with db.connect(p.db) as conn:
        row = conn.execute("SELECT filename,path,is_inline FROM gmail_attachments").fetchone()
    assert row["filename"] == "doc.txt"
    assert row["is_inline"] == 0
    assert Path(row["path"]).read_bytes() == b"document"
    set_password(p.root, "test-password")
    client = TestClient(create_app(p.root)); client.post("/login", data={"password": "test-password"})
    response = client.get("/gmail/1")
    assert "doc.txt" in response.text


def test_gmail_api_extracts_inline_cid_image_and_rewrites_html(monkeypatch, tmp_path: Path):
    p = _prepared(tmp_path)
    msg = EmailMessage()
    msg["Message-ID"] = "<inline@example.com>"
    msg["Subject"] = "Inline API"
    msg["From"] = "Sender <sender@example.com>"
    msg.set_content("Plain fallback")
    msg.add_alternative('<html><body><p>Logo</p><img src="cid:logo1"></body></html>', subtype="html")
    html_part = msg.get_payload()[1]
    html_part.add_related(b"pngdata", maintype="image", subtype="png", cid="<logo1>", filename="logo.png")
    service = _FakeGmailService([_message_from_email("inline", "1700000000000", msg)])
    monkeypatch.setattr("localvault.gmail_api._service", lambda credentials, token: service)

    backup_gmail_api(p, RunReport(source="gmail", mode="api"))

    with db.connect(p.db) as conn:
        attachment = conn.execute("SELECT content_id,is_inline,path FROM gmail_attachments").fetchone()
        body = conn.execute("SELECT body_html_path FROM gmail_bodies").fetchone()
    assert attachment["content_id"] == "logo1"
    assert attachment["is_inline"] == 1
    assert Path(attachment["path"]).read_bytes() == b"pngdata"
    assert "/file?path=" in Path(body["body_html_path"]).read_text(encoding="utf-8")


def test_gmail_api_backfills_renderable_parts_for_existing_raw_eml(monkeypatch, tmp_path: Path):
    p = _prepared(tmp_path)
    msg = EmailMessage()
    msg["Message-ID"] = "<old@example.com>"
    msg["Subject"] = "Old API"
    msg["From"] = "Sender <sender@example.com>"
    msg.set_content("Old body")
    msg.add_attachment(b"old-doc", maintype="text", subtype="plain", filename="old.txt")
    payload = _message_from_email("old", "1700000000000", msg)
    raw = base64.urlsafe_b64decode(payload["raw"].encode("ascii"))
    eml_path = p.gmail_messages / "old.eml"
    eml_path.parent.mkdir(parents=True, exist_ok=True)
    eml_path.write_bytes(raw)
    from localvault.utils import sha256_bytes

    digest = sha256_bytes(raw)
    with db.connect(p.db) as conn:
        conn.execute(
            "INSERT INTO gmail_messages (gmail_id,subject,eml_path,raw_sha256,source) VALUES (?,?,?,?,?)",
            ("old", "Old API", str(eml_path), digest, "gmail_api"),
        )
    service = _FakeGmailService([payload])
    monkeypatch.setattr("localvault.gmail_api._service", lambda credentials, token: service)

    report = backup_gmail_api(p, RunReport(source="gmail", mode="api"))

    assert report.skipped_duplicates == 1
    with db.connect(p.db) as conn:
        body = conn.execute("SELECT body_text FROM gmail_bodies").fetchone()
        attachment = conn.execute("SELECT filename,path FROM gmail_attachments").fetchone()
    assert body["body_text"].strip() == "Old body"
    assert attachment["filename"] == "old.txt"
    assert Path(attachment["path"]).read_bytes() == b"old-doc"


def _prepared(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    (p.config / "config.yaml").write_text(yaml.safe_dump({
        "gmail": {
            "api_enabled": True,
            "credentials_file": str(p.config / "credentials.json"),
            "token_file": str(p.config / "token.json"),
        }
    }), encoding="utf-8")
    db.init_db(p.db)
    return p


def _message(gmail_id: str, internal_date: str, subject: str) -> dict:
    raw = "\r\n".join([
        f"Message-ID: <{gmail_id}@example.com>",
        f"Subject: {subject}",
        "From: Sender <sender@example.com>",
        "To: Receiver <receiver@example.com>",
        "Date: Tue, 14 Nov 2023 22:13:20 +0000",
        "",
        "body",
    ]).encode("utf-8")
    return {
        "id": gmail_id,
        "threadId": f"t-{gmail_id}",
        "labelIds": ["INBOX"],
        "snippet": "body",
        "internalDate": internal_date,
        "raw": base64.urlsafe_b64encode(raw).decode("ascii"),
    }


def _message_from_email(gmail_id: str, internal_date: str, msg: EmailMessage) -> dict:
    raw = msg.as_bytes()
    return {
        "id": gmail_id,
        "threadId": f"t-{gmail_id}",
        "labelIds": ["INBOX"],
        "snippet": "body",
        "internalDate": internal_date,
        "raw": base64.urlsafe_b64encode(raw).decode("ascii"),
    }


class _FakeGmailService:
    def __init__(self, messages: list[dict]):
        self._messages = {message["id"]: message for message in messages}
        self.list_queries: list[str | None] = []

    def users(self):
        return self

    def messages(self):
        return self

    def list(self, userId: str, pageToken=None, maxResults=100, q=None):
        self.list_queries.append(q)
        ids = [{"id": key} for key in self._messages]
        return _Execute({"messages": ids})

    def get(self, userId: str, id: str, format: str):
        return _Execute(self._messages[id])


class _Execute:
    def __init__(self, payload):
        self.payload = payload

    def execute(self):
        return self.payload
