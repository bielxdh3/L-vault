from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime, parseaddr
from pathlib import Path

from .utils import unique_path

WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


def sanitize_filename_component(value: str | None, fallback: str, max_length: int = 80) -> str:
    text = " ".join(str(value or "").split())
    text = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", text)
    text = re.sub(r"[\s_]+", "_", text).strip(" ._")
    if not text:
        text = fallback
    if text.upper() in WINDOWS_RESERVED_NAMES:
        text = f"{text}_file"
    return text[:max_length].rstrip(" ._") or fallback


def email_timestamp(value: str | None) -> str:
    if value:
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed.strftime("%Y-%m-%d_%H%M")
        except Exception:
            pass
    return datetime.now().strftime("%Y-%m-%d_%H%M")


def sender_name(value: str | None) -> str:
    display, address = parseaddr(value or "")
    return display or address or "sem_remetente"


def friendly_email_filename(
    *,
    message_date: str | None,
    sender: str | None,
    subject: str | None,
    unique_id: str | None,
    suffix: str = ".eml",
) -> str:
    stamp = email_timestamp(message_date)
    clean_sender = sanitize_filename_component(sender_name(sender), "sem_remetente", max_length=45)
    clean_subject = sanitize_filename_component(subject, "sem_assunto", max_length=95)
    clean_id = sanitize_filename_component(unique_id, "email", max_length=24)
    return f"{stamp}__{clean_sender}__{clean_subject}__{clean_id}{suffix}"


def unique_friendly_email_path(
    messages_dir: Path,
    *,
    message_date: str | None,
    sender: str | None,
    subject: str | None,
    unique_id: str | None,
) -> Path:
    return unique_path(messages_dir / friendly_email_filename(
        message_date=message_date,
        sender=sender,
        subject=subject,
        unique_id=unique_id,
    ))
