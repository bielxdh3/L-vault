from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from . import db
from .config import VaultPaths, load_config
from .health import health_snapshot
from .vault_index import dashboard_data


ALLOWED_COMMANDS = {
    "daily-backup": "Backup agora",
    "photos-sync-local": "Backup fotos locais",
    "sync-sources": "Sincronizar fontes",
    "ingest-all": "Importar inbox",
    "verify": "Verificar cofre",
    "health-check": "Checar saude",
    "repair-index": "Reparar indice",
    "dedupe": "Relatorio de duplicados",
}


def control_panel_data(p: VaultPaths) -> dict[str, Any]:
    cfg = load_config(p.root)
    dash = dashboard_data(p)
    with db.connect(p.db) as conn:
        runs = conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 8").fetchall()
        errors = conn.execute("SELECT * FROM import_errors ORDER BY id DESC LIMIT 8").fetchall()
    return {
        "stats": dash["stats"],
        "health": health_snapshot(p),
        "gmail_status": _gmail_status(p, cfg),
        "source_status": _source_status(p, cfg),
        "schedule_status": _schedule_status(cfg),
        "runs": runs,
        "errors": errors,
        "commands": ALLOWED_COMMANDS,
        "running_jobs": _running_jobs(p),
    }


def start_background_command(p: VaultPaths, command: str) -> Path:
    if command not in ALLOWED_COMMANDS:
        raise ValueError("Unsupported command.")
    p.logs.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = p.logs / f"manual_{stamp}_{command}.log"
    status_path = p.logs / f"manual_{stamp}_{command}.json"
    python = _python_executable()
    args = [python, "-m", "localvault", command, "--root", str(p.root)]
    script = (
        "$ErrorActionPreference = 'Continue'\n"
        f"$StatusPath = '{status_path}'\n"
        f"$LogPath = '{log_path}'\n"
        f"'{{\"command\":\"{command}\",\"status\":\"running\",\"started_at\":\"' + (Get-Date -Format o) + '\"}}' | Out-File -Encoding utf8 $StatusPath\n"
        f"& '{args[0]}' '{args[1]}' '{args[2]}' '{args[3]}' '{args[4]}' '{args[5]}' 2>&1 | Out-File -Encoding utf8 $LogPath\n"
        "$code = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }\n"
        f"'{{\"command\":\"{command}\",\"status\":\"finished\",\"exit_code\":' + $code + ',\"finished_at\":\"' + (Get-Date -Format o) + '\",\"log\":\"{str(log_path).replace(chr(92), chr(92) + chr(92))}\"}}' | Out-File -Encoding utf8 $StatusPath\n"
    )
    runner = p.logs / f"manual_{stamp}_{command}.ps1"
    runner.write_text(script, encoding="utf-8")
    subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(runner)], cwd=str(p.root), creationflags=_hidden_process_flag())
    return log_path


def _gmail_status(p: VaultPaths, cfg: dict[str, Any]) -> dict[str, Any]:
    gmail = cfg.get("gmail", {})
    token = Path(gmail.get("token_file") or p.config / "gmail_token.json")
    credentials = Path(gmail.get("credentials_file") or p.config / "google_oauth_client_secret.json")
    return {
        "api_enabled": bool(gmail.get("api_enabled")),
        "token_exists": token.exists(),
        "credentials_exists": credentials.exists(),
        "ready": bool(gmail.get("api_enabled")) and token.exists() and credentials.exists(),
    }


def _source_status(p: VaultPaths, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    source_cfg = cfg.get("source_sync", {})
    items = []
    for label, values in [
        ("Google Fotos local", cfg.get("google_photos", {}).get("local_media_sources", [])),
        ("Google Takeout/Drive", source_cfg.get("google_takeout_sources", [])),
        ("WhatsApp exports", source_cfg.get("whatsapp_export_sources", [])),
        ("WhatsApp media", source_cfg.get("whatsapp_media_sources", [])),
    ]:
        for value in values:
            path = Path(value)
            items.append({"label": label, "path": str(path), "exists": path.exists()})
    items.append({"label": "Inbox Google Takeout", "path": str(p.google_takeout_inbox), "exists": p.google_takeout_inbox.exists()})
    items.append({"label": "Inbox WhatsApp", "path": str(p.whatsapp_exports_inbox), "exists": p.whatsapp_exports_inbox.exists()})
    return items


def _schedule_status(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    prefix = cfg.get("automation", {}).get("task_prefix", "LocalVault")
    if os.name != "nt":
        return []
    command = (
        f"Get-ScheduledTask | Where-Object {{$_.TaskName -like '{prefix} *'}} | "
        "Select-Object TaskName,State | ConvertTo-Json"
    )
    result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], text=True, capture_output=True, check=False)
    if result.returncode or not result.stdout.strip():
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        payload = [payload]
    return [{"name": item.get("TaskName", ""), "state": item.get("State", "")} for item in payload]


def _running_jobs(p: VaultPaths) -> list[dict[str, Any]]:
    jobs = []
    for status in sorted(p.logs.glob("manual_*.json"), reverse=True)[:8]:
        try:
            jobs.append(json.loads(status.read_text(encoding="utf-8-sig")))
        except json.JSONDecodeError:
            continue
    return jobs


def _python_executable() -> str:
    return sys.executable or "python"


def _hidden_process_flag() -> int:
    return subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
