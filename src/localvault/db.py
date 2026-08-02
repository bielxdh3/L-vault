from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable


class _ClosingConnection(sqlite3.Connection):
    """Close SQLite handles when used with the repository's ``with connect`` pattern."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()

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
  sha256 TEXT, size INTEGER, mime_type TEXT, content_id TEXT, is_inline INTEGER NOT NULL DEFAULT 0,
  imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS gmail_bodies (
  gmail_message_id INTEGER PRIMARY KEY, body_text TEXT, body_html_path TEXT,
  imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS photo_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, path TEXT NOT NULL UNIQUE,
  sidecar_path TEXT, original_path TEXT, creation_date TEXT, exif_date TEXT,
  google_metadata_date TEXT, file_size INTEGER, mime_type TEXT, sha256 TEXT,
  width INTEGER, height INTEGER, album TEXT, media_type TEXT, imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
CREATE TABLE IF NOT EXISTS disk_clone_profile (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  last_verified_at TEXT,
  next_due_at TEXT,
  provider TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS disk_clone_runs (
  run_id TEXT PRIMARY KEY,
  trigger_type TEXT NOT NULL,
  scheduled_at TEXT NOT NULL,
  started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TEXT,
  state TEXT NOT NULL,
  reason TEXT,
  source_label TEXT,
  target_label TEXT,
  source_size_bytes INTEGER,
  target_size_bytes INTEGER,
  provider TEXT,
  provider_version TEXT,
  provider_edition TEXT,
  provider_mode TEXT,
  countdown_outcome TEXT,
  provider_pid INTEGER,
  provider_exit_code INTEGER,
  progress_type TEXT,
  verification_status TEXT,
  target_offline_result TEXT,
  activity_average REAL,
  activity_max REAL,
  activity_samples INTEGER,
  activity_duration INTEGER,
  parent_run_id TEXT,
  local_time_decision TEXT,
  timezone_name TEXT,
  preflight_evidence_hash TEXT,
  activity_sample_json TEXT,
  final_revalidation_result TEXT,
  post_provider_inventory_at TEXT,
  verification_evidence TEXT,
  boot_test_status TEXT NOT NULL DEFAULT 'unverified',
  primary_failure_state TEXT,
  primary_failure_reason TEXT,
  cleanup_failure_reason TEXT,
  retry_run_id TEXT
);
CREATE TABLE IF NOT EXISTS disk_clone_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  state TEXT NOT NULL,
  reason TEXT,
  occurred_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES disk_clone_runs(run_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS disk_clone_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  progress_type TEXT NOT NULL,
  percent REAL,
  copied_bytes INTEGER,
  speed_bytes INTEGER,
  eta_seconds INTEGER,
  phase TEXT,
  recorded_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES disk_clone_runs(run_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS disk_clone_verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  structurally_verified INTEGER NOT NULL DEFAULT 0,
  boot_tested INTEGER NOT NULL DEFAULT 0,
  evidence TEXT,
  verified_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES disk_clone_runs(run_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS disk_clone_controls (
  request_id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  run_id TEXT,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  handled_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_gmail_sender ON gmail_messages(sender);
CREATE INDEX IF NOT EXISTS idx_gmail_subject ON gmail_messages(subject);
CREATE INDEX IF NOT EXISTS idx_gmail_date ON gmail_messages(message_date);
CREATE INDEX IF NOT EXISTS idx_photos_date ON photo_items(creation_date);
CREATE INDEX IF NOT EXISTS idx_photos_hash ON photo_items(sha256);
CREATE INDEX IF NOT EXISTS idx_disk_clone_events_run ON disk_clone_events(run_id, id);
CREATE INDEX IF NOT EXISTS idx_disk_clone_progress_run ON disk_clone_progress(run_id, id);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=60, factory=_ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=60000")
    return conn


def init_db(db_path: Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        _ensure_column(conn, "gmail_attachments", "content_id", "TEXT")
        _ensure_column(conn, "gmail_attachments", "is_inline", "INTEGER NOT NULL DEFAULT 0")
        for column, definition in {
            "source_label": "TEXT",
            "target_label": "TEXT",
            "source_size_bytes": "INTEGER",
            "target_size_bytes": "INTEGER",
            "provider": "TEXT",
            "provider_version": "TEXT",
            "provider_edition": "TEXT",
            "provider_mode": "TEXT",
            "countdown_outcome": "TEXT",
            "provider_pid": "INTEGER",
            "provider_exit_code": "INTEGER",
            "progress_type": "TEXT",
            "verification_status": "TEXT",
            "target_offline_result": "TEXT",
            "parent_run_id": "TEXT",
            "local_time_decision": "TEXT",
            "timezone_name": "TEXT",
            "preflight_evidence_hash": "TEXT",
            "activity_sample_json": "TEXT",
            "final_revalidation_result": "TEXT",
            "post_provider_inventory_at": "TEXT",
            "verification_evidence": "TEXT",
            "boot_test_status": "TEXT NOT NULL DEFAULT 'unverified'",
            "primary_failure_state": "TEXT",
            "primary_failure_reason": "TEXT",
            "cleanup_failure_reason": "TEXT",
            "retry_run_id": "TEXT",
        }.items():
            _ensure_column(conn, "disk_clone_runs", column, definition)


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


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
