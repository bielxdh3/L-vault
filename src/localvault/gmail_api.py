from __future__ import annotations

import base64
import email
import mimetypes
import re
from datetime import datetime, timedelta, timezone
from email import policy
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import quote

from . import db
from .config import VaultPaths, load_config
from .email_names import sanitize_filename_component, unique_friendly_email_path
from .reports import RunReport
from .utils import atomic_write_bytes, atomic_write_text, guess_mime, sha256_bytes, unique_path, utc_now

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
        atomic_write_text(token_file, creds.to_json(), encoding="utf-8")
    return build("gmail", "v1", credentials=creds)


def _save(conn, p: VaultPaths, service, gmail_id: str, report: RunReport, dry_run: bool) -> int:
    existing = conn.execute("SELECT id,eml_path,raw_sha256 FROM gmail_messages WHERE gmail_id=?", (gmail_id,)).fetchone()
    if existing and existing["eml_path"] and Path(existing["eml_path"]).exists():
        if not dry_run:
            _ensure_renderable_for_existing(conn, p, int(existing["id"]), Path(existing["eml_path"]), existing["raw_sha256"])
        report.skipped_duplicates += 1
        return 0
    msg = service.users().messages().get(userId="me", id=gmail_id, format="raw").execute()
    raw = base64.urlsafe_b64decode(msg["raw"].encode("ascii"))
    digest = sha256_bytes(raw)
    internal_date_ms = int(msg.get("internalDate") or 0)
    existing_hash = conn.execute("SELECT id,gmail_id,eml_path,raw_sha256 FROM gmail_messages WHERE raw_sha256=?", (digest,)).fetchone()
    if existing_hash and existing_hash["eml_path"] and Path(existing_hash["eml_path"]).exists():
        if not dry_run and not existing_hash["gmail_id"]:
            conn.execute("UPDATE gmail_messages SET gmail_id=?,thread_id=?,labels=?,snippet=? WHERE id=?", (gmail_id, msg.get("threadId"), ",".join(msg.get("labelIds", [])), msg.get("snippet"), existing_hash["id"]))
        if not dry_run:
            _ensure_renderable_for_existing(conn, p, int(existing_hash["id"]), Path(existing_hash["eml_path"]), existing_hash["raw_sha256"] or digest)
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
        atomic_write_bytes(dest, raw)
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
            cur = conn.execute("""INSERT OR IGNORE INTO gmail_messages
            (gmail_id,thread_id,message_id_header,subject,sender,recipients,cc,bcc,message_date,labels,snippet,eml_path,raw_sha256,source)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (gmail_id, *values))
            db.upsert_file(conn, sha256=digest, path=dest, media_type="email", mime_type="message/rfc822", size=len(raw), source="gmail_api")
            if cur.lastrowid:
                existing = conn.execute("SELECT id,eml_path FROM gmail_messages WHERE id=?", (cur.lastrowid,)).fetchone()
        db_id = int((existing or conn.execute("SELECT id,eml_path FROM gmail_messages WHERE gmail_id=?", (gmail_id,)).fetchone())["id"])
        _store_renderable_parts(conn, p, db_id, parsed, digest)
    report.imported_count += 1
    report.storage_added += len(raw)
    return internal_date_ms


def _ensure_renderable_for_existing(conn, p: VaultPaths, message_id: int, eml_path: Path, digest: str | None) -> None:
    if conn.execute("SELECT gmail_message_id FROM gmail_bodies WHERE gmail_message_id=?", (message_id,)).fetchone():
        return
    raw = eml_path.read_bytes()
    parsed = email.message_from_bytes(raw, policy=policy.default)
    _store_renderable_parts(conn, p, message_id, parsed, digest or sha256_bytes(raw))


def _store_renderable_parts(conn, p: VaultPaths, message_id: int, parsed, digest: str) -> None:
    body_text, body_html = _extract_bodies(parsed)
    cid_map = _extract_attachments(conn, p, message_id, parsed, digest)
    body_html_path = None
    if body_html:
        body_html = _rewrite_cid_sources(body_html, cid_map)
        body_html_path = unique_path(p.gmail_messages / "rendered" / digest[:2] / f"{digest}.html")
        atomic_write_text(body_html_path, body_html, encoding="utf-8")
        db.upsert_file(conn, sha256=sha256_bytes(body_html.encode("utf-8")), path=body_html_path, media_type="email_body", mime_type="text/html", size=len(body_html.encode("utf-8")), source="gmail_api_body")
    conn.execute(
        """
        INSERT INTO gmail_bodies (gmail_message_id,body_text,body_html_path)
        VALUES (?,?,?)
        ON CONFLICT(gmail_message_id) DO UPDATE SET body_text=excluded.body_text, body_html_path=excluded.body_html_path, imported_at=CURRENT_TIMESTAMP
        """,
        (message_id, body_text, str(body_html_path) if body_html_path else None),
    )


def _extract_bodies(parsed) -> tuple[str | None, str | None]:
    text_body = None
    html_body = None
    for part in parsed.walk() if parsed.is_multipart() else [parsed]:
        if part.is_multipart() or part.get_content_disposition():
            continue
        try:
            if part.get_content_type() == "text/plain" and text_body is None:
                text_body = str(part.get_content())
            elif part.get_content_type() == "text/html" and html_body is None:
                html_body = str(part.get_content())
        except Exception:
            continue
    return text_body, html_body


def _extract_attachments(conn, p: VaultPaths, message_id: int, parsed, digest: str) -> dict[str, Path]:
    cid_map: dict[str, Path] = {}
    conn.execute("DELETE FROM gmail_attachments WHERE gmail_message_id=?", (message_id,))
    for index, part in enumerate(parsed.walk() if parsed.is_multipart() else [parsed], start=1):
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        content_id = _clean_content_id(part.get("Content-ID"))
        filename = part.get_filename()
        is_inline = disposition == "inline" or bool(content_id)
        if disposition not in {"attachment", "inline"} and not content_id:
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        name = _attachment_name(filename, content_id, part.get_content_type(), index)
        adigest = sha256_bytes(payload)
        adest = unique_path(p.gmail_attachments / digest[:2] / digest / name)
        atomic_write_bytes(adest, payload)
        conn.execute(
            "INSERT INTO gmail_attachments (gmail_message_id,filename,path,sha256,size,mime_type,content_id,is_inline) VALUES (?,?,?,?,?,?,?,?)",
            (message_id, name, str(adest), adigest, len(payload), part.get_content_type(), content_id, 1 if is_inline else 0),
        )
        db.upsert_file(conn, sha256=adigest, path=adest, media_type="gmail_attachment", mime_type=part.get_content_type() or guess_mime(adest), size=len(payload), source="gmail_api_attachment")
        if content_id:
            cid_map[content_id] = adest
    return cid_map


def _attachment_name(filename: str | None, content_id: str | None, content_type: str, index: int) -> str:
    fallback_ext = mimetypes.guess_extension(content_type or "") or ".bin"
    fallback = f"inline_{content_id}{fallback_ext}" if content_id else f"attachment_{index}{fallback_ext}"
    return sanitize_filename_component(filename or fallback, "attachment.bin", max_length=120)


def _clean_content_id(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().strip("<>").strip()
    return cleaned or None


def _rewrite_cid_sources(html: str, cid_map: dict[str, Path]) -> str:
    def replace(match: re.Match[str]) -> str:
        cid = match.group(1)
        path = cid_map.get(cid)
        if not path:
            return match.group(0)
        return f'src="/file?path={quote(str(path))}"'

    return re.sub(r"(?i)src\s*=\s*['\"]cid:([^'\"]+)['\"]", replace, html)


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
