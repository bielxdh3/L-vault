from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

from localvault import db
from localvault.config import ensure_directories
from localvault.gmail_takeout import ingest_gmail_takeout
from localvault.reports import RunReport


def test_gmail_takeout_sanitizes_dangerous_attachment_filename(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    takeout = p.google_takeout_inbox / "takeout"
    takeout.mkdir(parents=True)
    mbox = takeout / "mail.mbox"
    mbox.write_text(_mbox_message_with_attachment("../CON?.txt"), encoding="utf-8", newline="\n")

    ingest_gmail_takeout(p, RunReport(source="gmail", mode="takeout"))

    with db.connect(p.db) as conn:
        row = conn.execute("SELECT filename,path FROM gmail_attachments").fetchone()
    attachment_path = Path(row["path"])

    assert row["filename"] != "../CON?.txt"
    assert row["filename"].endswith(".txt")
    assert "/" not in row["filename"]
    assert "\\" not in row["filename"]
    assert ".." not in attachment_path.relative_to(p.gmail_attachments).parts
    assert attachment_path.is_file()
    assert p.gmail_attachments in attachment_path.parents
    assert attachment_path.read_bytes() == b"payload"


def _mbox_message_with_attachment(filename: str) -> str:
    msg = EmailMessage()
    msg["From"] = "Sender <sender@example.com>"
    msg["To"] = "Receiver <receiver@example.com>"
    msg["Subject"] = "Attachment"
    msg["Date"] = "Tue, 14 Nov 2023 22:13:20 +0000"
    msg["Message-ID"] = "<dangerous-attachment@example.com>"
    msg.set_content("Body")
    msg.add_attachment(b"payload", maintype="text", subtype="plain", filename=filename)
    return "From sender@example.com Tue Nov 14 22:13:20 2023\n" + msg.as_string(policy=msg.policy.clone(linesep="\n")) + "\n"
