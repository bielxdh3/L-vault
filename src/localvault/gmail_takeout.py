from __future__ import annotations

import email
import mailbox
import zipfile
from email import policy
from pathlib import Path

from . import db
from .config import VaultPaths
from .email_names import sanitize_filename_component, unique_friendly_email_path
from .extract import safe_extract_zip, safe_zip_infos, safe_zip_member_name
from .reports import RunReport
from .utils import guess_mime, sha256_bytes, unique_path


def ingest_gmail_takeout(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    roots = [x for x in p.google_takeout_inbox.iterdir() if x.is_dir()]
    extracted = p.manual_imports_inbox / "extracted_google_takeout"
    for zip_path in sorted(p.google_takeout_inbox.glob("*.zip")):
        try:
            if dry_run:
                _dry_run_gmail_zip(p, zip_path, report)
            else:
                roots.append(safe_extract_zip(zip_path, extracted, dry_run=dry_run))
        except Exception as exc:
            report.error(zip_path, str(exc))
    with db.connect(p.db) as conn:
        for root in roots:
            for mbox in root.rglob("*.mbox"):
                _import_mbox(conn, p, mbox, report, dry_run)
    return report


def _dry_run_gmail_zip(p: VaultPaths, zip_path: Path, report: RunReport) -> None:
    with db.connect(p.db) as conn, zipfile.ZipFile(zip_path) as archive:
        for info in safe_zip_infos(zip_path):
            if info.is_dir():
                continue
            name = safe_zip_member_name(info.filename)
            if Path(name).suffix.lower() != ".mbox":
                continue
            with archive.open(info) as handle:
                _import_messages(conn, p, _messages_from_mbox_bytes(handle.read()), None, report, dry_run=True)


def _import_mbox(conn, p: VaultPaths, mbox_path: Path, report: RunReport, dry_run: bool) -> None:
    box = mailbox.mbox(mbox_path, factory=lambda f: email.message_from_binary_file(f, policy=policy.default))
    _import_messages(conn, p, box, mbox_path, report, dry_run)


def _import_messages(conn, p: VaultPaths, messages, mbox_path: Path | None, report: RunReport, dry_run: bool) -> None:
    for msg in messages:
        raw = msg.as_bytes(policy=policy.default)
        digest = sha256_bytes(raw)
        if conn.execute("SELECT id FROM gmail_messages WHERE raw_sha256=?", (digest,)).fetchone():
            report.skipped_duplicates += 1
            continue
        dest = unique_friendly_email_path(
            p.gmail_messages,
            message_date=_h(msg.get("Date")),
            sender=_h(msg.get("From")),
            subject=_h(msg.get("Subject")),
            unique_id=_h(msg.get("Message-ID")) or digest[:16],
        )
        if not dry_run:
            dest.write_bytes(raw)
            cur = conn.execute("""INSERT OR IGNORE INTO gmail_messages
            (message_id_header,subject,sender,recipients,cc,bcc,message_date,labels,snippet,eml_path,raw_sha256,source)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (_h(msg.get("Message-ID")), _h(msg.get("Subject")), _h(msg.get("From")), _h(msg.get("To")), _h(msg.get("Cc")), _h(msg.get("Bcc")), _h(msg.get("Date")), _h(msg.get("X-Gmail-Labels")), _snippet(msg), str(dest), digest, "gmail_takeout"))
            db_id = int(cur.lastrowid)
            for part in msg.iter_attachments():
                payload = part.get_payload(decode=True)
                if payload:
                    raw_name = part.get_filename() or "attachment.bin"
                    name = sanitize_filename_component(raw_name, "attachment.bin", max_length=120)
                    adigest = sha256_bytes(payload)
                    adest = unique_path(p.gmail_attachments / digest[:2] / digest / name)
                    adest.parent.mkdir(parents=True, exist_ok=True)
                    adest.write_bytes(payload)
                    conn.execute("INSERT INTO gmail_attachments (gmail_message_id,filename,path,sha256,size,mime_type) VALUES (?,?,?,?,?,?)", (db_id, name, str(adest), adigest, len(payload), part.get_content_type()))
                    db.upsert_file(conn, sha256=adigest, path=adest, media_type="gmail_attachment", mime_type=part.get_content_type() or guess_mime(adest), size=len(payload), source="gmail_takeout_attachment")
            db.upsert_file(conn, sha256=digest, path=dest, original_path=mbox_path, media_type="email", mime_type="message/rfc822", size=len(raw), source="gmail_takeout")
        report.imported_count += 1
        report.storage_added += len(raw)


def _messages_from_mbox_bytes(data: bytes):
    current: list[bytes] = []
    for line in data.replace(b"\r\n", b"\n").splitlines(keepends=True):
        if line.startswith(b"From "):
            if current:
                yield email.message_from_bytes(b"".join(current), policy=policy.default)
                current = []
            continue
        current.append(line)
    if current:
        yield email.message_from_bytes(b"".join(current), policy=policy.default)


def _h(value: str | None) -> str | None:
    return " ".join(str(value).split()) if value else None


def _snippet(msg, limit: int = 220) -> str | None:
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    return " ".join(part.get_content().split())[:limit]
        if msg.get_content_type() == "text/plain":
            return " ".join(msg.get_content().split())[:limit]
    except Exception:
        return None
    return None
