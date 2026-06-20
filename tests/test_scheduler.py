from pathlib import Path

import yaml

from localvault.config import ensure_directories
from localvault.scheduler import generate_schedule_files


def test_schedule_uses_daily_backup_and_start_when_available(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    (p.config / "config.yaml").write_text(yaml.safe_dump({
        "automation": {
            "tasks": {
                "daily_backup": {
                    "enabled": True,
                    "name": "Daily Backup",
                    "command": "daily-backup",
                    "frequency": "daily",
                    "time": "02:00",
                    "days": [],
                },
                "verify_weekly": {
                    "enabled": True,
                    "name": "Verify Weekly",
                    "command": "verify",
                    "frequency": "weekly",
                    "time": "04:00",
                    "days": ["Sunday"],
                },
            }
        }
    }), encoding="utf-8")

    files = generate_schedule_files(p)
    install = files.install.read_text(encoding="utf-8")
    assert "LocalVault Daily Backup" in install
    assert 'Command="daily-backup"' in install
    assert "-StartWhenAvailable" in install
    assert "-RunLevel Highest" in install
    assert "LocalVault Gmail API Daily" not in install
