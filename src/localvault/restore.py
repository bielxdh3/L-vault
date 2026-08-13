from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import db
from .config import VaultPaths
from .utils import atomic_write_text, copy_preserve, sha256_file


MEDIA_TYPES = {"all", "email", "gmail_attachment", "photo", "video"}
CONFLICT_POLICIES = {"skip", "rename", "overwrite"}
MAX_ITEMS = 1000
MANIFEST_NAME = ".localvault_restore_manifest.json"


class RestoreValidationError(ValueError):
    pass


@dataclass
class RestoreItem:
    source_path: Path
    source_hash: str
    destination: Path
    source_size: int
    action: str = "copy"
    status: str = "planned"
    error: str | None = None
    bytes_copied: int = 0

    def public(self, destination_root: Path) -> dict[str, Any]:
        try:
            destination = str(self.destination.relative_to(destination_root))
        except ValueError:
            destination = self.destination.name
        item = {
            "source_hash": self.source_hash,
            "destination": destination,
            "action": self.action,
            "status": self.status,
            "bytes": self.bytes_copied,
        }
        if self.error:
            item["error"] = self.error[:240]
        return item


@dataclass
class RestorePlan:
    destination_root: Path
    media_type: str
    conflict: str
    items: list[RestoreItem] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "status": "planned",
            "media_type": self.media_type,
            "conflict": self.conflict,
            "items": [item.public(self.destination_root) for item in self.items[:MAX_ITEMS]],
            "counts": {"selected": len(self.items), "errors": sum(item.status == "error" for item in self.items)},
        }


@dataclass
class RestoreResult:
    plan: RestorePlan
    status: str
    manifest_path: Path | None = None

    def public(self, include_items: bool = True) -> dict[str, Any]:
        items = self.plan.items[:MAX_ITEMS]
        counts = {
            "selected": len(items),
            "copied": sum(item.status == "copied" for item in items),
            "skipped": sum(item.status == "skipped" for item in items),
            "renamed": sum(item.status == "copied" and item.action == "rename" for item in items),
            "overwritten": sum(item.status == "copied" and item.action == "overwrite" for item in items),
            "errors": sum(item.status == "error" for item in items),
            "bytes": sum(item.bytes_copied for item in items),
        }
        payload = {
            "schema": 1,
            "status": self.status,
            "media_type": self.plan.media_type,
            "conflict": self.plan.conflict,
            "counts": counts,
            "errors": [item.error[:240] for item in items if item.error][:MAX_ITEMS],
        }
        if include_items:
            payload["items"] = [item.public(self.plan.destination_root) for item in items]
        return payload


def plan_restore(
    p: VaultPaths,
    destination: Path,
    *,
    media_type: str = "all",
    limit: int | None = None,
    conflict: str = "skip",
) -> RestorePlan:
    _validate_options(media_type, limit, conflict)
    vault_root = (p.root / "vault").resolve()
    destination_root = _validate_destination(destination, vault_root)
    if not p.db.is_file():
        raise RestoreValidationError("LocalVault index database is not available.")
    items: list[RestoreItem] = []
    with db.connect(p.db) as conn:
        rows = conn.execute(
            "SELECT path,sha256,size,media_type FROM files ORDER BY id"
        ).fetchall()
    for row in rows:
        source = Path(row["path"])
        if not _matches_media(source, row["media_type"], media_type):
            continue
        if len(items) >= (limit if limit is not None else MAX_ITEMS):
            break
        try:
            source = _validate_source(source, vault_root)
            relative = source.relative_to(vault_root)
            target = destination_root / relative
            _validate_target(target, destination_root, vault_root)
            action = "copy"
            if target.exists():
                _validate_existing_target(target)
                if conflict == "skip":
                    action = "skip"
                elif conflict == "overwrite":
                    action = "overwrite"
                else:
                    target = _next_rename_target(target, destination_root, vault_root)
                    action = "rename"
            items.append(RestoreItem(source, str(row["sha256"] or ""), target, int(row["size"] or 0), action=action, status="skipped" if action == "skip" else "planned"))
        except RestoreValidationError as exc:
            items.append(RestoreItem(source, str(row["sha256"] or ""), destination_root, int(row["size"] or 0), action="reject", status="error", error=str(exc)))
    return RestorePlan(destination_root, media_type, conflict, items)


def execute_restore(p: VaultPaths, plan: RestorePlan, *, dry_run: bool = False) -> RestoreResult:
    vault_root = (p.root / "vault").resolve()
    plan.destination_root = _validate_destination(plan.destination_root, vault_root)
    if dry_run:
        return RestoreResult(plan, "dry_run")
    for item in plan.items:
        if item.status in {"error", "skipped"}:
            continue
        try:
            source = _validate_source(item.source_path, vault_root)
            target = item.destination
            _validate_target(target, plan.destination_root, vault_root)
            if target.exists():
                _validate_existing_target(target)
                if plan.conflict == "skip":
                    item.action = "skip"
                    item.status = "skipped"
                    continue
                if plan.conflict == "rename":
                    target = _next_rename_target(target, plan.destination_root, vault_root)
                    item.destination = target
                    item.action = "rename"
                else:
                    item.action = "overwrite"
            actual_source_hash = sha256_file(source)
            if actual_source_hash != item.source_hash:
                raise RestoreValidationError("Indexed source hash does not match the canonical file.")
            target.parent.mkdir(parents=True, exist_ok=True)
            _validate_target(target, plan.destination_root, vault_root)
            copied = copy_preserve(source, target)
            if sha256_file(target) != item.source_hash:
                raise RestoreValidationError("Restored file failed SHA-256 verification.")
            item.bytes_copied = copied
            item.status = "copied"
        except (OSError, RestoreValidationError, ValueError) as exc:
            item.status = "error"
            item.error = str(exc)
    result_status = "completed" if not any(item.status == "error" for item in plan.items) else "partial"
    result = RestoreResult(plan, result_status)
    result.manifest_path = plan.destination_root / MANIFEST_NAME
    atomic_write_text(result.manifest_path, json.dumps(result.public(), indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def _validate_options(media_type: str, limit: int | None, conflict: str) -> None:
    if media_type not in MEDIA_TYPES:
        raise RestoreValidationError(f"Unsupported restore media type: {media_type}")
    if limit is not None and (limit < 1 or limit > MAX_ITEMS):
        raise RestoreValidationError(f"Restore limit must be between 1 and {MAX_ITEMS}.")
    if conflict not in CONFLICT_POLICIES:
        raise RestoreValidationError(f"Unsupported restore conflict policy: {conflict}")


def _matches_media(path: Path, media: str | None, selected: str) -> bool:
    if selected == "all":
        return True
    if selected == "email":
        return media == "email" or path.suffix.lower() == ".eml"
    return media == selected


def _validate_source(source: Path, vault_root: Path) -> Path:
    resolved = source.resolve(strict=False)
    if not _is_under(resolved, vault_root):
        raise RestoreValidationError("Indexed source is outside the vault storage.")
    _reject_link_components(source, "Indexed source")
    try:
        source_stat = os.lstat(source)
    except OSError as exc:
        raise RestoreValidationError("Indexed source is missing.") from exc
    if _is_link_or_reparse(source_stat) or not stat.S_ISREG(source_stat.st_mode):
        raise RestoreValidationError("Indexed source is not a regular non-link file.")
    return resolved


def _validate_destination(destination: Path, vault_root: Path) -> Path:
    raw = Path(destination).expanduser()
    if ".." in raw.parts:
        raise RestoreValidationError("Restore destination traversal is not allowed.")
    resolved = raw.resolve(strict=False)
    if resolved == Path(resolved.anchor) or _paths_overlap(resolved, vault_root):
        raise RestoreValidationError("Restore destination must be separate from the vault.")
    _reject_link_components(raw, "Restore destination")
    if resolved.exists() and not resolved.is_dir():
        raise RestoreValidationError("Restore destination must be a directory.")
    return resolved


def _validate_target(target: Path, destination_root: Path, vault_root: Path) -> None:
    if not _is_under(target.resolve(strict=False), destination_root) or _paths_overlap(target.resolve(strict=False), vault_root):
        raise RestoreValidationError("Restore target escapes the destination or overlaps the vault.")
    _reject_link_components(target, "Restore target")


def _validate_existing_target(target: Path) -> None:
    try:
        target_stat = os.lstat(target)
    except OSError as exc:
        raise RestoreValidationError("Restore target cannot be inspected safely.") from exc
    if _is_link_or_reparse(target_stat) or not stat.S_ISREG(target_stat.st_mode):
        raise RestoreValidationError("Restore target is not a regular non-link file.")


def _next_rename_target(target: Path, destination_root: Path, vault_root: Path) -> Path:
    stem, suffix = target.stem, target.suffix
    for index in range(1, MAX_ITEMS + 1):
        candidate = target.with_name(f"{stem}_{index}{suffix}")
        _validate_target(candidate, destination_root, vault_root)
        if not candidate.exists():
            return candidate
    raise RestoreValidationError("Could not choose a bounded renamed destination.")


def _reject_link_components(path: Path, label: str) -> None:
    current = Path(path.anchor) if path.anchor else Path()
    for part in path.parts[1:] if path.anchor else path.parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError as exc:
            raise RestoreValidationError(f"{label} cannot be inspected safely.") from exc
        if _is_link_or_reparse(info):
            raise RestoreValidationError(f"{label} contains a symlink or reparse point.")


def _is_link_or_reparse(info: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & reparse)


def _is_under(path: Path, root: Path) -> bool:
    try:
        return path == root or root in path.parents
    except (AttributeError, RuntimeError):
        return False


def _paths_overlap(first: Path, second: Path) -> bool:
    return _is_under(first, second) or _is_under(second, first)

