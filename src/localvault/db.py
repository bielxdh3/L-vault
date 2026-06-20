from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS backup_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, mode TEXT NOT NULL,
  started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL DEFAULT 'running',
  imported_count INTEGER NOT NULL DEFAULT 0, skipped_duplicates INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0, storage_added INTEGER NOT NULL DEFAULT 0,
  warnings TEXT, report_path TEXT
);
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL, path TEXT NOT NULL UNIQUE,
  original_path TEXT, media_type TEXT, mime_type TEXT, size INTEGER NOT NULL DEFAULT 0,
  created_at TEXT, modified_at TEXT, source TEXT, first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS gmail_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, gmail_id TEXT UNIQUE, thread_id TEXT,
  message_id_header TEXT, subject TEXT, sender TEXT, recipients TEXT, cc TEXT, bcc TEXT,
  message_date TEXT, labels TEXT, snippet TEXT, eml_path TEXT, raw_sha256 TEXT UNIQUE,
  source TEXT, imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS gmail_attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT, gmail_message_id INTEGER, filename TEXT, path TEXT,
  sha256 TEXT, size INTEGER, mime_type TEXT, imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS google_photos_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, path TEXT NOT NULL UNIQUE,
  sidecar_path TEXT, original_path TEXT, creation_date TEXT, exif_date TEXT,
  google_metadata_date TEXT, file_size INTEGER, mime_type TEXT, sha256 TEXT,
  width INTEGER, height INTEGER, album TEXT, media_type TEXT, imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS whatsapp_chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT, chat_name TEXT NOT NULL, source_path TEXT,
  imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(chat_name, source_path)
);
CREATE TABLE IF NOT EXISTS whatsapp_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER NOT NULL, message_dt TEXT,
  sender TEXT, text TEXT, media_ref TEXT, is_system INTEGER NOT NULL DEFAULT 0,
  source_line INTEGER, imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS import_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, source TEXT, item_path TEXT,
  error TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS duplicate_groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL UNIQUE, file_count INTEGER NOT NULL,
  total_size INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS duplicate_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER NOT NULL, file_id INTEGER NOT NULL,
  UNIQUE(group_id, file_id)
);
CREATE TABLE IF NOT EXISTS local_source_cleanup_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT, original_path TEXT NOT NULL UNIQUE,
  vault_path TEXT NOT NULL, sha256 TEXT NOT NULL, source TEXT NOT NULL,
  queued_run_id INTEGER, queued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TEXT NOT NULL DEFAULT 'pending', deleted_at TEXT, last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_gmail_sender ON gmail_messages(sender);
CREATE INDEX IF NOT EXISTS idx_gmail_subject ON gmail_messages(subject);
CREATE INDEX IF NOT EXISTS idx_gmail_date ON gmail_messages(message_date);
CREATE INDEX IF NOT EXISTS idx_photos_date ON google_photos_items(creation_date);
CREATE INDEX IF NOT EXISTS idx_photos_hash ON google_photos_items(sha256);
CREATE INDEX IF NOT EXISTS idx_whatsapp_dt ON whatsapp_messages(message_dt);
CREATE INDEX IF NOT EXISTS idx_whatsapp_sender ON whatsapp_messages(sender);
CREATE INDEX IF NOT EXISTS idx_cleanup_status ON local_source_cleanup_queue(status);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def upsert_file(conn: sqlite3.Connection, *, sha256: str, path: Path, original_path: Path | None = None,
                media_type: str | None = None, mime_type: str | None = None, size: int = 0,
                created_at: str | None = None, modified_at: str | None = None, source: str | None = None) -> int:
    conn.execute(
        """
        INSERT INTO files (sha256,path,original_path,media_type,mime_type,size,created_at,modified_at,source)
        VALUES (?,?,?,?,?,?,?,?,?)
        ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256, original_path=excluded.original_path,
        media_type=excluded.media_type, mime_type=excluded.mime_type, size=excluded.size, source=excluded.source
        """,
        (sha256, str(path), str(original_path) if original_path else None, media_type, mime_type, size, created_at, modified_at, source),
    )
    return int(conn.execute("SELECT id FROM files WHERE path=?", (str(path),)).fetchone()["id"])


def scalar(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> Any:
    row = conn.execute(sql, tuple(params)).fetchone()
    return row[0] if row else None
