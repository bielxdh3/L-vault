from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_ROOT = Path(os.environ.get("LOCALVAULT_ROOT", r"E:\LocalVault"))
DEFAULT_DOWNLOADS = str(Path.home() / "Downloads")

DEFAULT_CONFIG: dict[str, Any] = {
    "vault_root": str(DEFAULT_ROOT),
    "viewer": {"host": "127.0.0.1", "port": 8787, "allow_lan": False, "page_size": 60},
    "gmail": {
        "api_enabled": False,
        "credentials_file": str(DEFAULT_ROOT / "config" / "google_oauth_client_secret.json"),
        "token_file": str(DEFAULT_ROOT / "config" / "gmail_token.json"),
        "modify_remote": False,
        "batch_size": 100,
    },
    "google_photos": {"takeout_only_default": True, "upload_enabled": False, "upload_album": "LocalVault Uploads"},
    "whatsapp": {"copy_media_from": "", "adb_enabled": False},
    "source_sync": {
        "enabled": True,
        "google_takeout_sources": [DEFAULT_DOWNLOADS],
        "whatsapp_export_sources": [DEFAULT_DOWNLOADS],
        "whatsapp_media_sources": [],
    },
    "safety": {"minimum_free_gb": 20, "hash_algorithm": "sha256", "never_delete_sources": True},
    "automation": {
        "task_prefix": "LocalVault",
        "execution_time_limit_hours": 8,
        "tasks": {
            "daily_backup": {"enabled": True, "name": "Daily Backup", "command": "daily-backup", "frequency": "daily", "time": "02:00", "days": []},
            "verify_weekly": {"enabled": True, "name": "Verify Weekly", "command": "verify", "frequency": "weekly", "time": "04:00", "days": ["Sunday"]},
        },
    },
}


@dataclass(frozen=True)
class VaultPaths:
    root: Path
    inbox: Path
    google_takeout_inbox: Path
    whatsapp_exports_inbox: Path
    manual_imports_inbox: Path
    gmail_messages: Path
    gmail_attachments: Path
    photos: Path
    videos: Path
    whatsapp_chats: Path
    whatsapp_media: Path
    db: Path
    logs: Path
    config: Path
    reports: Path


def paths(root: Path = DEFAULT_ROOT) -> VaultPaths:
    root = Path(root)
    return VaultPaths(
        root=root,
        inbox=root / "inbox",
        google_takeout_inbox=root / "inbox" / "google_takeout",
        whatsapp_exports_inbox=root / "inbox" / "whatsapp_exports",
        manual_imports_inbox=root / "inbox" / "manual_imports",
        gmail_messages=root / "vault" / "gmail" / "messages",
        gmail_attachments=root / "vault" / "gmail" / "attachments",
        photos=root / "vault" / "google_photos" / "photos",
        videos=root / "vault" / "google_photos" / "videos",
        whatsapp_chats=root / "vault" / "whatsapp" / "chats",
        whatsapp_media=root / "vault" / "whatsapp" / "media",
        db=root / "db" / "localvault.sqlite",
        logs=root / "logs",
        config=root / "config",
        reports=root / "reports",
    )


def ensure_directories(root: Path = DEFAULT_ROOT) -> VaultPaths:
    p = paths(root)
    for value in p.__dict__.values():
        path = Path(value)
        if path.suffix:
            path.parent.mkdir(parents=True, exist_ok=True)
        else:
            path.mkdir(parents=True, exist_ok=True)
    return p


def write_example_config(root: Path = DEFAULT_ROOT) -> Path:
    p = paths(root)
    p.config.mkdir(parents=True, exist_ok=True)
    example = p.config / "config.example.yaml"
    example.write_text(yaml.safe_dump(DEFAULT_CONFIG, sort_keys=False), encoding="utf-8")
    return example


def ensure_config(root: Path = DEFAULT_ROOT) -> dict[str, Any]:
    p = ensure_directories(root)
    example = write_example_config(root)
    config_file = p.config / "config.yaml"
    if not config_file.exists():
        shutil.copy2(example, config_file)
    return load_config(root)


def load_config(root: Path = DEFAULT_ROOT) -> dict[str, Any]:
    config_file = paths(root).config / "config.yaml"
    if not config_file.exists():
        return DEFAULT_CONFIG.copy()
    return _deep_merge(DEFAULT_CONFIG.copy(), yaml.safe_load(config_file.read_text(encoding="utf-8")) or {})


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _deep_merge(base[key], value)
        else:
            base[key] = value
    return base
