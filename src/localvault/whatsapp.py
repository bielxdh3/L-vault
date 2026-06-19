from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from . import db
from .config import VaultPaths
from .extract import safe_extract_zip
from .reports import RunReport
from .utils import copy_preserve, guess_mime, media_kind, sha256_file, unique_path

PATTERNS = [
    re.compile(r"^\[(?P<date>\d{1,2}/\d{1,2}/\d{2,4}),?\s+(?P<time>\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AP]M)?)\]\s(?:(?P<sender>[^:]+):\s)?(?P<text>.*)$", re.I),
    re.compile(r"^(?P<date>\d{1,2}/\d{1,2}/\d{2,4}),?\s+(?P<time>\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AP]M)?)\s+-\s+(?:(?P<sender>[^:]+):\s)?(?P<text>.*)$", re.I),
]


def ingest_whatsapp_exports(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    roots = [p.whatsapp_exports_inbox]
    extracted = p.manual_imports_inbox / "extracted_whatsapp"
    for zip_path in sorted(p.whatsapp_exports_inbox.glob("*.zip")):
        try:
            roots.append(safe_extract_zip(zip_path, extracted, dry_run=dry_run))
        except Exception as exc:
            report.error(zip_path, str(exc))
    with db.connect(p.db) as conn:
        for root in roots:
            for txt in root.rglob("*.txt"):
                try:
                    _import_chat(conn, p, txt, report, dry_run)
                except Exception as exc:
                    report.error(txt, str(exc))
            for media in root.rglob("*"):
                if media.is_file() and media.suffix.lower() not in {".txt", ".zip"}:
                    _copy_media(conn, p, media, report, dry_run)
    return report


def copy_whatsapp_media_folder(p: VaultPaths, source: Path, report: RunReport, dry_run: bool = False) -> RunReport:
    with db.connect(p.db) as conn:
        for media in source.rglob("*"):
            if media.is_file():
                _copy_media(conn, p, media, report, dry_run)
    return report


def parse_chat_text(text: str) -> list[dict]:
    messages, current = [], None
    for line_no, line in enumerate(text.splitlines(), 1):
        parsed = parse_message_line(line)
        if parsed:
            if current:
                messages.append(current)
            current = parsed
            current["source_line"] = line_no
        elif current:
            current["text"] += "\n" + line
    if current:
        messages.append(current)
    return messages


def parse_message_line(line: str) -> dict | None:
    for pattern in PATTERNS:
        match = pattern.match(line)
        if match:
            data = match.groupdict()
            sender = data.get("sender")
            text = data.get("text") or ""
            return {"message_dt": _dt(data["date"], data["time"]), "sender": sender.strip() if sender else None,
                    "text": text, "media_ref": _media_ref(text), "is_system": 0 if sender else 1}
    return None


def _dt(date: str, time: str) -> str | None:
    variants = [f"{date} {time}", f"{date} {time.upper().replace(' ', '')}"]
    formats = ["%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%y %H:%M:%S", "%d/%m/%y %H:%M", "%m/%d/%Y %I:%M %p", "%m/%d/%y %I:%M %p", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%y %I:%M:%S %p"]
    for v in variants:
        for f in formats:
            try:
                return datetime.strptime(v, f).isoformat()
            except ValueError:
                pass
    return None


def _media_ref(text: str) -> str | None:
    if "media omitted" in text.lower() or "mídia oculto" in text.lower():
        return text
    first = text.split(" ", 1)[0]
    return first if re.search(r"\.(jpg|jpeg|png|gif|webp|mp4|mov|opus|ogg|pdf|docx?|xlsx?)$", first, re.I) else None


def _import_chat(conn, p: VaultPaths, txt: Path, report: RunReport, dry_run: bool) -> None:
    digest = sha256_file(txt)
    if conn.execute("SELECT id FROM files WHERE sha256=? AND source='whatsapp_export'", (digest,)).fetchone():
        report.skipped_duplicates += 1
        return
    content = _read_text(txt)
    messages = parse_chat_text(content)
    if dry_run:
        report.imported_count += len(messages)
        return
    copy = unique_path(p.whatsapp_chats / "exports" / txt.name)
    size = copy_preserve(txt, copy)
    db.upsert_file(conn, sha256=digest, path=copy, original_path=txt, media_type="whatsapp_export", mime_type="text/plain", size=size, source="whatsapp_export")
    chat_name = txt.stem.replace("_chat", "").replace("WhatsApp Chat - ", "").strip() or txt.stem
    conn.execute("INSERT OR IGNORE INTO whatsapp_chats (chat_name,source_path) VALUES (?,?)", (chat_name, str(copy)))
    chat_id = int(conn.execute("SELECT id FROM whatsapp_chats WHERE chat_name=? AND source_path=?", (chat_name, str(copy))).fetchone()["id"])
    for m in messages:
        conn.execute("INSERT INTO whatsapp_messages (chat_id,message_dt,sender,text,media_ref,is_system,source_line) VALUES (?,?,?,?,?,?,?)",
                     (chat_id, m["message_dt"], m["sender"], m["text"], m["media_ref"], m["is_system"], m["source_line"]))
    report.imported_count += len(messages)


def _copy_media(conn, p: VaultPaths, media: Path, report: RunReport, dry_run: bool) -> None:
    digest = sha256_file(media)
    if conn.execute("SELECT id FROM files WHERE sha256=? AND source LIKE 'whatsapp%'", (digest,)).fetchone():
        report.skipped_duplicates += 1
        return
    dest = unique_path(p.whatsapp_media / media_kind(media) / media.name)
    size = copy_preserve(media, dest, dry_run)
    if not dry_run:
        db.upsert_file(conn, sha256=digest, path=dest, original_path=media, media_type=media_kind(media), mime_type=guess_mime(dest), size=size, source="whatsapp_media")
    report.imported_count += 1
    report.storage_added += size


def _read_text(path: Path) -> str:
    for enc in ("utf-8-sig", "utf-8", "utf-16", "latin-1"):
        try:
            return path.read_text(encoding=enc)
        except UnicodeDecodeError:
            pass
    return path.read_text(errors="replace")
