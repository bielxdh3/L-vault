import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from localvault.config import ensure_directories
from localvault.control_panel import _backup_running


def test_recent_running_backup_status_blocks_manual_backup(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    _write_status(p.logs / "manual_recent_daily-backup.json", datetime.now(timezone.utc))

    assert _backup_running(p) is True


def test_old_running_backup_status_does_not_block_manual_backup(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    _write_status(p.logs / "manual_old_daily-backup.json", datetime.now(timezone.utc) - timedelta(hours=13))

    assert _backup_running(p) is False


def _write_status(path: Path, started_at: datetime) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "command": "daily-backup",
        "status": "running",
        "started_at": started_at.isoformat(),
    }), encoding="utf-8")
