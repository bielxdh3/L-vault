from __future__ import annotations

import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from shutil import disk_usage
from typing import Any

from . import db
from .config import VaultPaths, load_config
from .disk_clone import disk_clone_dashboard_data
from .locks import lock_is_stale
from .replica import replica_status


RECENT_WINDOW_DAYS = 7
STALE_RUN_HOURS = 12


def health_snapshot(p: VaultPaths) -> dict[str, Any]:
    cfg = load_config(p.root)
    minimum_gb = float(cfg.get("safety", {}).get("minimum_free_gb", 20))
    filesystem = _filesystem_metrics(p.root, minimum_gb)
    with db.connect(p.db) as conn:
        indexed = _indexed_metrics(conn)
        content_counts = _content_counts(conn)
        source_breakdown = _source_breakdown(conn)
        duplicate_metrics = _duplicate_metrics(conn)
        last_run_row = conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT 1").fetchone()
        last_successful_row = conn.execute("SELECT * FROM backup_runs WHERE status='ok' ORDER BY id DESC LIMIT 1").fetchone()
        last_partial_row = conn.execute("SELECT * FROM backup_runs WHERE status='warning' ORDER BY id DESC LIMIT 1").fetchone()
        last_failed_row = conn.execute("SELECT * FROM backup_runs WHERE status='failed' ORDER BY id DESC LIMIT 1").fetchone()
        last_verification_row = conn.execute(
            "SELECT * FROM backup_runs WHERE source='vault' AND mode='verify_full' AND status='ok' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        stale_run_count = _stale_run_count(conn)
        recent_import_error_count = int(conn.execute(
            "SELECT COUNT(*) FROM import_errors WHERE created_at >= datetime('now', ?) ",
            (f"-{RECENT_WINDOW_DAYS} days",),
        ).fetchone()[0])
        recent_growth = _recent_storage_growth(conn)

    clone = disk_clone_dashboard_data(p)
    temp_health = _temp_health(p)
    lock_health = _lock_health(p)
    metrics = {
        "filesystem": filesystem,
        "indexed": indexed,
        "content_counts": content_counts,
        "source_breakdown": source_breakdown,
        "recent_storage_growth": recent_growth,
        "last_runs": {
            "last": _run_summary(last_run_row),
            "successful": _run_summary(last_successful_row),
            "partial": _run_summary(last_partial_row),
            "failed": _run_summary(last_failed_row),
        },
        "last_successful_full_verification": _run_summary(last_verification_row),
        "stale_interrupted_run_count": stale_run_count,
        "recent_import_error_count": recent_import_error_count,
        "duplicates": duplicate_metrics,
        "safe_temp": temp_health,
        "lock": lock_health,
        "future_surfaces": {
            "replica": {"status": "available"},
            "restore": {"status": "available"},
            "clone": {"status": "gated"},
        },
        "replica": replica_status(p),
        "clone": clone,
    }
    checks = [
        _check("Espaco livre", not filesystem["low_space"], f"{filesystem['free_bytes'] / (1024 ** 3):.1f} GB livres; minimo configurado {minimum_gb:.1f} GB"),
        _check("Indice do cofre", indexed["missing_count"] == 0, f"{indexed['missing_count']} arquivo(s) ausente(s) no indice"),
        _check("Ultimo backup", _last_run_fresh(last_successful_row), _last_run_message(last_successful_row)),
        _check("Agendador do Windows", _has_ready_daily_task(cfg), "Tarefa LocalVault Daily Backup encontrada" if os.name == "nt" else "Nao aplicavel fora do Windows"),
        _check("Clone: configuracao", True, clone.get("provider_blocker", "Clonagem habilitada por configuracao.") if not clone.get("enabled") else "Clonagem habilitada por configuracao."),
        _check("Clone: provedor", not clone.get("enabled") or bool(clone.get("provider_supported")), clone.get("provider_blocker", "Capacidade validada")),
        _check("Clone: inscricao", not clone.get("enabled") or clone.get("enrollment") == "valido", str(clone.get("enrollment", "ausente"))),
        _check("Clone: destino offline", not clone.get("enabled") or bool(clone.get("target_offline_expected")), "Destino permanece offline entre execucoes"),
        _check("Arquivos temporarios seguros", temp_health["count"] == 0, temp_health["detail"]),
        _check("Lock de backup", lock_health["status"] != "stale", lock_health["detail"]),
    ]
    status = "ok" if all(item["ok"] for item in checks) else "attention"
    return {
        "status": status,
        "checks": checks,
        "free_gb": filesystem["free_bytes"] / (1024 ** 3),
        "minimum_free_gb": minimum_gb,
        "last_run": _run_summary(last_run_row),
        "last_ok": _run_summary(last_successful_row),
        "recent_failures": [_run_summary(row) for row in (last_partial_row, last_failed_row) if row],
        "recent_errors": recent_import_error_count,
        "metrics": metrics,
    }


def _filesystem_metrics(root: Path, minimum_gb: float) -> dict[str, Any]:
    target = root if root.exists() else root.parent
    while not target.exists() and target.parent != target:
        target = target.parent
    usage = disk_usage(target)
    minimum_bytes = int(minimum_gb * 1024 ** 3)
    return {
        "total_bytes": int(usage.total),
        "used_bytes": int(usage.used),
        "free_bytes": int(usage.free),
        "minimum_free_bytes": minimum_bytes,
        "low_space": usage.free < minimum_bytes,
    }


def _indexed_metrics(conn) -> dict[str, int]:
    rows = conn.execute("SELECT path,size FROM files").fetchall()
    return {
        "file_count": len(rows),
        "bytes": sum(int(row["size"] or 0) for row in rows),
        "missing_count": sum(1 for row in rows if not Path(row["path"]).exists()),
    }


def _content_counts(conn) -> dict[str, int]:
    return {
        "emails": int(conn.execute("SELECT COUNT(*) FROM gmail_messages").fetchone()[0]),
        "attachments": int(conn.execute("SELECT COUNT(*) FROM gmail_attachments").fetchone()[0]),
        "photos": int(conn.execute("SELECT COUNT(*) FROM photo_items WHERE media_type='photo'").fetchone()[0]),
        "videos": int(conn.execute("SELECT COUNT(*) FROM photo_items WHERE media_type='video'").fetchone()[0]),
    }


def _source_breakdown(conn) -> dict[str, dict[str, int]]:
    rows = conn.execute("SELECT COALESCE(source, 'unknown') source, COUNT(*) count, COALESCE(SUM(size), 0) bytes FROM files GROUP BY source ORDER BY source").fetchall()
    return {str(row["source"]): {"count": int(row["count"]), "bytes": int(row["bytes"])} for row in rows}


def _duplicate_metrics(conn) -> dict[str, int]:
    group_count = int(conn.execute("SELECT COUNT(*) FROM duplicate_groups").fetchone()[0])
    estimate = conn.execute(
        """SELECT COALESCE(SUM(g.total_size - COALESCE((SELECT MAX(f.size) FROM duplicate_files d JOIN files f ON f.id=d.file_id WHERE d.group_id=g.id), 0)), 0)
        FROM duplicate_groups g"""
    ).fetchone()[0]
    return {"group_count": group_count, "storage_estimate_bytes": int(estimate or 0)}


def _recent_storage_growth(conn) -> dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_WINDOW_DAYS)
    rows = conn.execute("SELECT started_at,storage_added FROM backup_runs WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 100").fetchall()
    selected = []
    for row in rows:
        started = _parse_datetime(row["started_at"])
        if started and started >= cutoff:
            selected.append(row)
    return {
        "available": bool(selected),
        "bytes": sum(int(row["storage_added"] or 0) for row in selected),
        "run_count": len(selected),
        "window_days": RECENT_WINDOW_DAYS,
    }


def _stale_run_count(conn) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=STALE_RUN_HOURS)
    count = 0
    for row in conn.execute("SELECT status,started_at FROM backup_runs WHERE status IN ('running','interrupted')").fetchall():
        if row["status"] == "interrupted":
            count += 1
        else:
            started = _parse_datetime(row["started_at"])
            if started is None or started <= cutoff:
                count += 1
    return count


def _temp_health(p: VaultPaths) -> dict[str, Any]:
    locations = [p.root, p.config, p.db.parent, p.logs, p.reports, p.inbox, p.root / "vault"]
    count = sum(1 for location in locations if location.exists() for _ in location.glob(".localvault_tmp_*.part"))
    return {"status": "clear" if count == 0 else "attention", "count": count, "scope": "known storage roots", "detail": "Nenhum temporario conhecido" if count == 0 else f"{count} temporario(s) conhecido(s)"}


def _lock_health(p: VaultPaths) -> dict[str, str]:
    lock_path = p.logs / "localvault_backup.lock"
    if not lock_path.exists():
        return {"status": "clear", "detail": "Nenhum lock de backup ativo"}
    status = "stale" if lock_is_stale(lock_path) else "active"
    return {"status": status, "detail": "Lock de backup antigo" if status == "stale" else "Lock de backup ativo"}


def _run_summary(row) -> dict[str, Any] | None:
    if not row:
        return None
    return {key: row[key] for key in ("source", "mode", "status", "started_at", "finished_at", "imported_count", "failed_count", "storage_added")}


def _check(name: str, ok: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "ok": ok, "detail": detail}


def _last_run_fresh(row) -> bool:
    if not row or not row["finished_at"]:
        return False
    finished = _parse_datetime(row["finished_at"])
    return bool(finished and (datetime.now(timezone.utc) - finished).days < 2)


def _last_run_message(row) -> str:
    if not row:
        return "Nenhum backup ok registrado"
    return f"Ultimo ok: {row['finished_at'] or row['started_at']}"


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


def _has_ready_daily_task(cfg: dict[str, Any]) -> bool:
    if os.name != "nt":
        return True
    prefix = cfg.get("automation", {}).get("task_prefix", "LocalVault")
    command = f"Get-ScheduledTask -TaskName '{prefix} Daily Backup' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State"
    result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], text=True, capture_output=True, check=False)
    return result.returncode == 0 and bool(result.stdout.strip())
