from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import db
from .config import VaultPaths, load_config
from .utils import free_space_bytes
from .vault_index import dashboard_data


def health_snapshot(p: VaultPaths) -> dict[str, Any]:
    cfg = load_config(p.root)
    stats = dashboard_data(p)["stats"]
    free_gb = free_space_bytes(p.root) / (1024 ** 3)
    minimum_gb = float(cfg.get("safety", {}).get("minimum_free_gb", 20))
    with db.connect(p.db) as conn:
        last_run = conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 1").fetchone()
        last_ok = conn.execute("SELECT * FROM backup_runs WHERE status='ok' ORDER BY id DESC LIMIT 1").fetchone()
        recent_failures = conn.execute("SELECT * FROM backup_runs WHERE status!='ok' ORDER BY id DESC LIMIT 5").fetchall()
        recent_errors = conn.execute("SELECT * FROM import_errors ORDER BY id DESC LIMIT 5").fetchall()
    checks = [
        _check("Espaco livre", free_gb >= minimum_gb, f"{free_gb:.1f} GB livres; minimo configurado {minimum_gb:.1f} GB"),
        _check("Indice do cofre", int(stats["missing_files"]) == 0, f"{stats['missing_files']} arquivo(s) ausente(s) no indice"),
        _check("Ultimo backup", _last_run_fresh(last_ok), _last_run_message(last_ok)),
        _check("Agendador do Windows", _has_ready_daily_task(cfg), "Tarefa LocalVault Daily Backup encontrada" if os.name == "nt" else "Nao aplicavel fora do Windows"),
    ]
    status = "ok" if all(item["ok"] for item in checks) else "attention"
    return {
        "status": status,
        "checks": checks,
        "free_gb": free_gb,
        "minimum_free_gb": minimum_gb,
        "last_run": last_run,
        "last_ok": last_ok,
        "recent_failures": recent_failures,
        "recent_errors": recent_errors,
    }


def _check(name: str, ok: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "ok": ok, "detail": detail}


def _last_run_fresh(row) -> bool:
    if not row or not row["finished_at"]:
        return False
    try:
        finished = datetime.fromisoformat(str(row["finished_at"]).replace("Z", "+00:00"))
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - finished.astimezone(timezone.utc)).days < 2
    except Exception:
        return False


def _last_run_message(row) -> str:
    if not row:
        return "Nenhum backup ok registrado"
    return f"Ultimo ok: {row['finished_at'] or row['started_at']}"


def _has_ready_daily_task(cfg: dict[str, Any]) -> bool:
    if os.name != "nt":
        return True
    prefix = cfg.get("automation", {}).get("task_prefix", "LocalVault")
    command = f"Get-ScheduledTask -TaskName '{prefix} Daily Backup' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State"
    result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], text=True, capture_output=True, check=False)
    return result.returncode == 0 and bool(result.stdout.strip())
