from __future__ import annotations

import base64
from pathlib import Path

import yaml

from localvault import db
from localvault.config import ensure_directories
from localvault.gmail_api import LAST_INTERNAL_DATE_MS, backup_gmail_api
from localvault.reports import RunReport


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
