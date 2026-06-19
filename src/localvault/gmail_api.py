from __future__ import annotations

import base64
import email
from email import policy
from pathlib import Path

from . import db
from .config import VaultPaths, load_config
from .email_names import unique_friendly_email_path
from .reports import RunReport
from .utils import sha256_bytes

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def backup_gmail_api(p: VaultPaths, report: RunReport, dry_run: bool = False, max_messages: int | None = None) -> RunReport:
    cfg = load_config(p.root)["gmail"]
    if not cfg.get("api_enabled"):
        report.warn("Gmail API disabled in config.yaml.")
        return report
    service = _service(Path(cfg["credentials_file"]), Path(cfg["token_file"]))
    imported = 0
    page_token = None
    with db.connect(p.db) as conn:
        while True:
            response = service.users().messages().list(userId="me", pageToken=page_token, maxResults=cfg.get("batch_size", 100)).execute()
            for item in response.get("messages", []):
                if max_messages and imported >= max_messages:
                    return report
                _save(conn, p, service, item["id"], report, dry_run)
                imported += 1
            page_token = response.get("nextPageToken")
            if not page_token:
                break
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


def _save(conn, p: VaultPaths, service, gmail_id: str, report: RunReport, dry_run: bool) -> None:
    existing = conn.execute("SELECT id,eml_path FROM gmail_messages WHERE gmail_id=?", (gmail_id,)).fetchone()
    if existing and existing["eml_path"] and Path(existing["eml_path"]).exists():
        report.skipped_duplicates += 1
        return
    msg = service.users().messages().get(userId="me", id=gmail_id, format="raw").execute()
    raw = base64.urlsafe_b64decode(msg["raw"].encode("ascii"))
    digest = sha256_bytes(raw)
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
