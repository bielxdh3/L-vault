from __future__ import annotations

import base64
import email
from datetime import datetime, timedelta, timezone
from email import policy
from email.utils import parsedate_to_datetime
from pathlib import Path

from . import db
from .config import VaultPaths, load_config
from .email_names import unique_friendly_email_path
from .reports import RunReport
from .utils import sha256_bytes, utc_now

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
LAST_BACKUP_AT = "gmail.last_successful_backup_at"
LAST_INTERNAL_DATE_MS = "gmail.last_seen_internal_date_ms"
INCREMENTAL_OVERLAP_DAYS = 1


def backup_gmail_api(p: VaultPaths, report: RunReport, dry_run: bool = False, max_messages: int | None = None) -> RunReport:
    cfg = load_config(p.root)["gmail"]
    if not cfg.get("api_enabled"):
        report.warn("Gmail API disabled in config.yaml.")
        return report
    service = _service(Path(cfg["credentials_file"]), Path(cfg["token_file"]))
    processed = 0
    page_token = None
    max_internal_date_ms = 0
    with db.connect(p.db) as conn:
        query = _incremental_query(conn)
        while True:
            response = service.users().messages().list(userId="me", pageToken=page_token, maxResults=cfg.get("batch_size", 100), q=query).execute()
            for item in response.get("messages", []):
                if max_messages and processed >= max_messages:
                    return report
                internal_date_ms = _save(conn, p, service, item["id"], report, dry_run)
                max_internal_date_ms = max(max_internal_date_ms, internal_date_ms)
                processed += 1
            page_token = response.get("nextPageToken")
            if not page_token:
                break
        if not dry_run and not max_messages:
            _set_setting(conn, LAST_BACKUP_AT, utc_now())
            if max_internal_date_ms:
                _set_setting(conn, LAST_INTERNAL_DATE_MS, str(max_internal_date_ms))
    return report


def _service(credentials_file: Path, token_file: Path):
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    creds = Credentials.from_authorized_user_file(str(token_file), SCOPES) if token_file.exists() else None
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), SCOPES)
            creds = flow.run_local_server(port=0)
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(creds.to_json(), encoding="utf-8")
    return build("gmail", "v1", credentials=creds)


def _save(conn, p: VaultPaths, service, gmail_id: str, report: RunReport, dry_run: bool) -> int:
    existing = conn.execute("SELECT id,eml_path FROM gmail_messages WHERE gmail_id=?", (gmail_id,)).fetchone()
    if existing and existing["eml_path"] and Path(existing["eml_path"]).exists():
        report.skipped_duplicates += 1
        return 0
    msg = service.users().messages().get(userId="me", id=gmail_id, format="raw").execute()
    raw = base64.urlsafe_b64decode(msg["raw"].encode("ascii"))
    digest = sha256_bytes(raw)
    internal_date_ms = int(msg.get("internalDate") or 0)
    existing_hash = conn.execute("SELECT id,gmail_id,eml_path FROM gmail_messages WHERE raw_sha256=?", (digest,)).fetchone()
    if existing_hash and existing_hash["eml_path"] and Path(existing_hash["eml_path"]).exists():
        if not dry_run and not existing_hash["gmail_id"]:
            conn.execute("UPDATE gmail_messages SET gmail_id=?,thread_id=?,labels=?,snippet=? WHERE id=?", (gmail_id, msg.get("threadId"), ",".join(msg.get("labelIds", [])), msg.get("snippet"), existing_hash["id"]))
        report.skipped_duplicates += 1
        return internal_date_ms
    parsed = email.message_from_bytes(raw, policy=policy.default)
    headers = {
        "message-id": parsed.get("Message-ID"),
        "subject": parsed.get("Subject"),
        "from": parsed.get("From"),
        "to": parsed.get("To"),
        "cc": parsed.get("Cc"),
        "bcc": parsed.get("Bcc"),
        "date": parsed.get("Date"),
    }
    dest = unique_friendly_email_path(
        p.gmail_messages,
        message_date=headers.get("date"),
        sender=headers.get("from"),
        subject=headers.get("subject"),
        unique_id=gmail_id,
    )
    if not dry_run:
        dest.write_bytes(raw)
        values = (msg.get("threadId"), headers.get("message-id"), headers.get("subject"), headers.get("from"), headers.get("to"), headers.get("cc"), headers.get("bcc"), headers.get("date"), ",".join(msg.get("labelIds", [])), msg.get("snippet"), str(dest), digest, "gmail_api")
        if existing:
            old_path = existing["eml_path"]
            conn.execute("""UPDATE gmail_messages SET
            thread_id=?,message_id_header=?,subject=?,sender=?,recipients=?,cc=?,bcc=?,
            message_date=?,labels=?,snippet=?,eml_path=?,raw_sha256=?,source=?
            WHERE id=?""", (*values, existing["id"]))
            if old_path:
                updated = conn.execute("UPDATE files SET path=?,sha256=?,size=?,source=? WHERE path=?", (str(dest), digest, len(raw), "gmail_api", old_path)).rowcount
                if not updated:
                    db.upsert_file(conn, sha256=digest, path=dest, media_type="email", mime_type="message/rfc822", size=len(raw), source="gmail_api")
            else:
                db.upsert_file(conn, sha256=digest, path=dest, media_type="email", mime_type="message/rfc822", size=len(raw), source="gmail_api")
        else:
            conn.execute("""INSERT OR IGNORE INTO gmail_messages
            (gmail_id,thread_id,message_id_header,subject,sender,recipients,cc,bcc,message_date,labels,snippet,eml_path,raw_sha256,source)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (gmail_id, *values))
            db.upsert_file(conn, sha256=digest, path=dest, media_type="email", mime_type="message/rfc822", size=len(raw), source="gmail_api")
    report.imported_count += 1
    report.storage_added += len(raw)
    return internal_date_ms


def _incremental_query(conn) -> str | None:
    raw_ms = _get_setting(conn, LAST_INTERNAL_DATE_MS)
    if raw_ms:
        try:
            dt = datetime.fromtimestamp(int(raw_ms) / 1000, timezone.utc) - timedelta(days=INCREMENTAL_OVERLAP_DAYS)
            return f"after:{dt.strftime('%Y/%m/%d')}"
        except Exception:
            return None
    latest = _latest_indexed_message_date(conn)
    if not latest:
        return None
    dt = latest - timedelta(days=INCREMENTAL_OVERLAP_DAYS)
    return f"after:{dt.strftime('%Y/%m/%d')}"


def _get_setting(conn, key: str) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return str(row["value"]) if row and row["value"] is not None else None


def _set_setting(conn, key: str, value: str) -> None:
    conn.execute("""
        INSERT INTO settings (key,value,updated_at) VALUES (?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP
    """, (key, value))


def _latest_indexed_message_date(conn) -> datetime | None:
    latest: datetime | None = None
    rows = conn.execute("SELECT message_date FROM gmail_messages WHERE message_date IS NOT NULL AND message_date != ''").fetchall()
    for row in rows:
        try:
            parsed = parsedate_to_datetime(row["message_date"])
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(timezone.utc)
        except Exception:
            continue
        if latest is None or parsed > latest:
            latest = parsed
    return latest
