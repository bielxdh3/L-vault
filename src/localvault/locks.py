from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class BackupLock:
    def __init__(self, lock_path: Path, stale_after: timedelta = timedelta(hours=12)):
        self.lock_path = lock_path
        self.stale_after = stale_after
        self.acquired = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()

    def acquire(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        if self.lock_path.exists():
            if self.is_stale():
                self.lock_path.unlink(missing_ok=True)
            else:
                raise RuntimeError(f"Another LocalVault backup/import is already running: {self.lock_path}")
        payload = {
            "pid": os.getpid(),
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise RuntimeError(f"Another LocalVault backup/import is already running: {self.lock_path}") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False))
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            self.lock_path.unlink(missing_ok=True)
            raise
        self.acquired = True

    def release(self) -> None:
        if self.acquired:
            self.lock_path.unlink(missing_ok=True)
            self.acquired = False

    def is_stale(self) -> bool:
        return lock_is_stale(self.lock_path, self.stale_after)


def lock_is_stale(lock_path: Path, stale_after: timedelta = timedelta(hours=12)) -> bool:
    started = None
    try:
        payload: dict[str, Any] = json.loads(lock_path.read_text(encoding="utf-8-sig"))
        started = _parse_datetime(payload.get("started_at"))
    except (OSError, json.JSONDecodeError):
        started = None
    if started is None:
        try:
            started = datetime.fromtimestamp(lock_path.stat().st_mtime, timezone.utc)
        except OSError:
            return True
    return datetime.now(timezone.utc) - started > stale_after


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
