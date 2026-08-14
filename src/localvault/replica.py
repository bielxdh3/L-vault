from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import db
from .config import VaultPaths, load_config
from .utils import atomic_copy, atomic_write_text, copy_preserve, sha256_file


MANIFEST_NAME = ".localvault_replica_manifest.json"
STAGING_PREFIX = ".localvault_replica_staging_"
MAX_ITEMS = 10000
SAFE_CONFIG_NAMES = {"config.yaml", "config.example.yaml"}
EXCLUDED_NAMES = {"auth.json", "token.json", "gmail_token.json", "google_oauth_client_secret.json"}


class ReplicaValidationError(ValueError):
    pass


@dataclass
class ReplicaItem:
    relative: str
    source: Path | None
    source_hash: str | None
    size: int
    category: str
    action: str = "copy"
    status: str = "planned"
    error: str | None = None

    def public(self) -> dict[str, Any]:
        item = {
            "path": self.relative,
            "category": self.category,
            "action": self.action,
            "status": self.status,
            "size": self.size,
        }
        if self.source_hash:
            item["sha256"] = self.source_hash
        if self.error:
            item["error"] = self.error[:240]
        return item


@dataclass
class ReplicaPlan:
    source_root: Path
    destination_root: Path
    items: list[ReplicaItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stale: bool = False
    incomplete: bool = False

    def public(self) -> dict[str, Any]:
        counts = _counts(self.items)
        status = "incomplete" if self.errors else ("stale" if self.stale else ("incomplete" if self.incomplete else "planned"))
        return {
            "schema": 1,
            "status": status,
            "source": "vault",
            "destination": str(self.destination_root),
            "counts": counts,
            "stale": self.stale,
            "incomplete": self.incomplete,
            "items": [item.public() for item in self.items[:MAX_ITEMS]],
            "errors": self.errors[:MAX_ITEMS],
        }


@dataclass
class ReplicaResult:
    plan: ReplicaPlan
    status: str
    manifest_path: Path | None = None
    errors: list[str] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        payload = self.plan.public()
        payload["status"] = self.status
        payload["manifest"] = MANIFEST_NAME if self.manifest_path else None
        payload["errors"] = (self.plan.errors + self.errors)[:MAX_ITEMS]
        return payload


def configured_destination(p: VaultPaths) -> Path | None:
    value = load_config(p.root).get("replica", {}).get("destination")
    if not value:
        return None
    candidate = Path(str(value)).expanduser()
    return candidate if candidate.is_absolute() else p.root / candidate


def plan_replica(p: VaultPaths, destination: Path | None = None) -> ReplicaPlan:
    destination = destination or configured_destination(p)
    if destination is None:
        raise ReplicaValidationError("Replica destination is not configured; supply --destination.")
    source_root = _validate_source_root(p.root / "vault")
    destination_root = _validate_destination(destination, source_root)
    items: list[ReplicaItem] = []
    errors: list[str] = []
    for path in _walk_files(source_root):
        try:
            digest = sha256_file(path)
            relative = str(path.relative_to(p.root)).replace("\\", "/")
            items.append(ReplicaItem(relative, path, digest, path.stat().st_size, "vault"))
        except (OSError, ReplicaValidationError) as exc:
            errors.append(str(exc))
    for config_name in sorted(SAFE_CONFIG_NAMES):
        config_path = p.config / config_name
        if config_path.exists():
            try:
                _validate_regular(config_path, "config")
                items.append(ReplicaItem(f"config/{config_name}", config_path, sha256_file(config_path), config_path.stat().st_size, "config"))
            except (OSError, ReplicaValidationError) as exc:
                errors.append(str(exc))
    if p.db.exists():
        _validate_regular(p.db, "database")
        items.append(ReplicaItem("db/localvault.sqlite", p.db, None, p.db.stat().st_size, "sqlite_snapshot", action="snapshot"))
    previous = _read_manifest(destination_root / MANIFEST_NAME)
    current = {item.relative for item in items}
    for old in previous.get("items", []) if isinstance(previous, dict) else []:
        relative = str(old.get("path", ""))
        if relative and not _safe_relative(relative):
            errors.append("Replica manifest contains an unsafe relative path.")
            continue
        if relative and relative not in current:
            target = destination_root / relative
            try:
                _validate_target(target, destination_root, source_root)
                if target.exists():
                    items.append(ReplicaItem(relative, None, old.get("sha256"), int(old.get("size", 0) or 0), str(old.get("category", "vault")), action="preserve", status="source_missing_preserved"))
                else:
                    items.append(ReplicaItem(relative, None, old.get("sha256"), int(old.get("size", 0) or 0), str(old.get("category", "vault")), action="preserve", status="source_missing", error="Source item disappeared and no replica copy exists."))
            except ReplicaValidationError as exc:
                errors.append(str(exc))
    stale = any(item.status.startswith("source_missing") for item in items)
    incomplete = any(destination_root.parent.glob(f"{STAGING_PREFIX}*"))
    return ReplicaPlan(source_root, destination_root, items[:MAX_ITEMS], errors, stale, incomplete)


def execute_replica(p: VaultPaths, plan: ReplicaPlan, *, dry_run: bool = False) -> ReplicaResult:
    _validate_destination(plan.destination_root, plan.source_root)
    if dry_run:
        return ReplicaResult(plan, "dry_run")
    if plan.errors:
        return ReplicaResult(plan, "rejected")
    free = shutil.disk_usage(plan.destination_root.parent).free
    minimum_gb = float(load_config(p.root).get("safety", {}).get("minimum_free_gb", 20))
    required_bytes = sum(item.size for item in plan.items if item.status == "planned")
    if free < max(int(minimum_gb * 1024**3), required_bytes):
        return ReplicaResult(plan, "low_space", errors=["Replica destination is below the configured free-space threshold."])
    stage = plan.destination_root.parent / f"{STAGING_PREFIX}{os.getpid()}_{uuid.uuid4().hex[:8]}"
    stage.mkdir(parents=True)
    promoted = 0
    skipped = 0
    errors: list[str] = []
    try:
        for item in plan.items:
            if item.status.startswith("source_missing"):
                continue
            try:
                if item.category == "sqlite_snapshot":
                    staged = stage / item.relative
                    _snapshot_database(p.db, staged, p.root / "vault", plan.destination_root / "vault")
                    digest = sha256_file(staged)
                    size = staged.stat().st_size
                else:
                    if item.source is None:
                        continue
                    staged = stage / item.relative
                    size = copy_preserve(item.source, staged)
                    digest = sha256_file(staged)
                    if digest != item.source_hash:
                        raise ValueError("Replica copy failed SHA-256 verification.")
                target = plan.destination_root / item.relative
                _validate_target(target, plan.destination_root, plan.source_root)
                if target.is_file() and sha256_file(target) == digest:
                    item.action = "skip"
                    item.status = "skipped"
                    skipped += 1
                    staged.unlink(missing_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(staged, target)
                item.size = size
                item.source_hash = digest
                item.status = "copied"
                promoted += 1
            except (OSError, ValueError, ReplicaValidationError) as exc:
                item.status = "error"
                item.error = str(exc)
                errors.append(str(exc))
        status = "incomplete" if errors else ("stale" if plan.stale else "completed")
        result = ReplicaResult(plan, status, plan.destination_root / MANIFEST_NAME, errors)
        atomic_write_text(result.manifest_path, json.dumps(result.public(), indent=2, ensure_ascii=False), encoding="utf-8")
        return result
    finally:
        if not errors:
            shutil.rmtree(stage, ignore_errors=False)


def replica_status(p: VaultPaths) -> dict[str, Any]:
    destination = configured_destination(p)
    if destination is None:
        return {"status": "not_configured"}
    manifest = destination.expanduser() / MANIFEST_NAME
    if not manifest.is_file():
        return {"status": "unavailable", "configured": True}
    data = _read_manifest(manifest)
    return {"status": str(data.get("status", "stale")), "configured": True, "manifest": MANIFEST_NAME}


def _snapshot_database(source: Path, target: Path, source_vault: Path, replica_vault: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    source_conn = sqlite3.connect(source)
    target_conn = sqlite3.connect(target)
    try:
        source_conn.backup(target_conn)
        target_conn.commit()
    finally:
        target_conn.close()
        source_conn.close()
    check = sqlite3.connect(target)
    try:
        check.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1").fetchone()
    finally:
        check.close()
    rebased = sqlite3.connect(target)
    try:
        rows = rebased.execute("SELECT id,path FROM files").fetchall()
        for file_id, path in rows:
            candidate = Path(str(path))
            try:
                relative = candidate.resolve().relative_to(source_vault.resolve())
            except (OSError, ValueError):
                continue
            rebased.execute("UPDATE files SET path=? WHERE id=?", (str(replica_vault / relative), file_id))
        rebased.commit()
    finally:
        rebased.close()


def _validate_source_root(source: Path) -> Path:
    resolved = source.resolve(strict=False)
    try:
        _validate_regular(source, "Vault source", directory=True)
    except OSError as exc:
        raise ReplicaValidationError("Vault source is not available.") from exc
    return resolved


def _validate_destination(destination: Path, source_root: Path) -> Path:
    raw = Path(destination).expanduser()
    if ".." in raw.parts:
        raise ReplicaValidationError("Replica destination traversal is not allowed.")
    resolved = raw.resolve(strict=False)
    if _overlap(resolved, source_root) or resolved == Path(resolved.anchor):
        raise ReplicaValidationError("Replica destination must be separate from the source vault.")
    _reject_links(raw, "Replica destination")
    if resolved.exists() and not resolved.is_dir():
        raise ReplicaValidationError("Replica destination must be a directory.")
    return resolved


def _validate_target(target: Path, destination: Path, source_root: Path) -> None:
    resolved = target.resolve(strict=False)
    if not _under(resolved, destination) or _overlap(resolved, source_root):
        raise ReplicaValidationError("Replica target escapes the destination or overlaps the source vault.")
    _reject_links(target, "Replica target")
    if target.exists() and not target.is_file():
        raise ReplicaValidationError("Replica target is not a regular file.")


def _walk_files(root: Path):
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories + files:
            path = current_path / name
            try:
                info = os.lstat(path)
            except OSError as exc:
                raise ReplicaValidationError(f"Replica source cannot be inspected safely: {path.name}") from exc
            if _link_or_special(info):
                raise ReplicaValidationError("Replica source contains a symlink, reparse point, or special device.")
        for name in files:
            path = current_path / name
            _validate_regular(path, "Replica source")
            yield path


def _validate_regular(path: Path, label: str, directory: bool = False) -> None:
    info = os.lstat(path)
    if _link_or_special(info) or (stat.S_ISDIR(info.st_mode) != directory) or (not directory and not stat.S_ISREG(info.st_mode)):
        raise ReplicaValidationError(f"{label} is not a safe regular path.")


def _reject_links(path: Path, label: str) -> None:
    current = Path(path.anchor) if path.anchor else Path()
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts:
        current /= part
        if not current.exists():
            break
        try:
            if _link_or_special(os.lstat(current)):
                raise ReplicaValidationError(f"{label} contains a symlink, reparse point, or special device.")
        except OSError as exc:
            raise ReplicaValidationError(f"{label} cannot be inspected safely.") from exc


def _link_or_special(info: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return (
        stat.S_ISLNK(info.st_mode)
        or stat.S_ISCHR(info.st_mode)
        or stat.S_ISBLK(info.st_mode)
        or stat.S_ISFIFO(info.st_mode)
        or bool(getattr(info, "st_file_attributes", 0) & reparse)
    )


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _overlap(first: Path, second: Path) -> bool:
    return _under(first, second) or _under(second, first)


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {"status": "incomplete"}


def _safe_relative(value: str) -> bool:
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts and "\\" not in value


def _counts(items: list[ReplicaItem]) -> dict[str, int]:
    return {
        "selected": len(items),
        "copied": sum(item.status == "copied" for item in items),
        "skipped": sum(item.status == "skipped" for item in items),
        "preserved": sum(item.status == "source_missing_preserved" for item in items),
        "failed": sum(item.status in {"error", "source_missing"} for item in items),
        "bytes": sum(item.size for item in items if item.status == "copied"),
    }
