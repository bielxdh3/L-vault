from __future__ import annotations

import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .config import VaultPaths, load_config
from .extract import safe_zip_infos, safe_zip_member_name
from .reports import RunReport
from .utils import sha256_file, unique_path
from .whatsapp import ingest_whatsapp_exports, parse_message_line

INCOMPLETE_SUFFIXES = {".crdownload", ".tmp", ".part"}
EXPORT_SUFFIXES = {".txt", ".zip"}


@dataclass(frozen=True)
class WhatsAppMove:
    source: Path
    dest: Path
    size: int


def auto_whatsapp(p: VaultPaths, report: RunReport, dry_run: bool = False) -> RunReport:
    moves = _planned_moves(p, report)
    if dry_run:
        for move in moves:
            report.warn(f"Would move WhatsApp export: {move.source} -> {move.dest}")
            report.imported_count += 1
            report.storage_added += move.size
        return report

    moved = []
    move_failed = False
    for move in moves:
        try:
            move.dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(move.source), str(move.dest))
            moved.append(move)
            report.imported_count += 1
            report.storage_added += move.dest.stat().st_size
        except OSError as exc:
            move_failed = True
            report.error(move.source, str(exc))
    if moved and not move_failed:
        ingest_whatsapp_exports(p, report, dry_run=False)
    return report


def _planned_moves(p: VaultPaths, report: RunReport) -> list[WhatsAppMove]:
    moves = []
    for source in _source_dirs(p):
        if not source.exists() or not source.is_dir():
            continue
        for export_path in sorted(source.iterdir()):
            if not _candidate_export(export_path):
                continue
            try:
                if not _is_whatsapp_export(export_path):
                    continue
                digest = sha256_file(export_path)
                if _inbox_has_hash(p, digest):
                    report.skipped_duplicates += 1
                    continue
                dest = unique_path(p.whatsapp_exports_inbox / export_path.name)
                moves.append(WhatsAppMove(source=export_path, dest=dest, size=export_path.stat().st_size))
            except zipfile.BadZipFile as exc:
                report.warn(f"Ignored invalid ZIP: {export_path} ({exc})")
            except (OSError, UnicodeError, ValueError) as exc:
                report.error(export_path, str(exc))
    return moves


def _source_dirs(p: VaultPaths) -> list[Path]:
    cfg = load_config(p.root).get("source_sync", {})
    return [Path(value) for value in cfg.get("whatsapp_export_sources", [])]


def _candidate_export(path: Path) -> bool:
    if not path.is_file():
        return False
    suffixes = {suffix.lower() for suffix in path.suffixes}
    if suffixes & INCOMPLETE_SUFFIXES:
        return False
    return path.suffix.lower() in EXPORT_SUFFIXES


def _is_whatsapp_export(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix == ".txt":
        return _looks_like_whatsapp_text(_read_text_preview(path))
    if suffix == ".zip":
        return _zip_has_whatsapp_chat(path)
    return False


def _zip_has_whatsapp_chat(path: Path) -> bool:
    infos = safe_zip_infos(path)
    with zipfile.ZipFile(path) as archive:
        for info in infos:
            if info.is_dir():
                continue
            name = safe_zip_member_name(info.filename)
            if Path(name).suffix.lower() != ".txt":
                continue
            with archive.open(info) as handle:
                if _looks_like_whatsapp_text(_decode_text(handle.read(128 * 1024))):
                    return True
    return False


def _looks_like_whatsapp_text(text: str) -> bool:
    for line in text.splitlines()[:120]:
        parsed = parse_message_line(line)
        if parsed and parsed.get("message_dt"):
            return True
    return False


def _read_text_preview(path: Path) -> str:
    data = path.read_bytes()[:128 * 1024]
    return _decode_text(data)


def _decode_text(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return data.decode(errors="replace")


def _inbox_has_hash(p: VaultPaths, digest: str) -> bool:
    for existing in p.whatsapp_exports_inbox.iterdir():
        if not existing.is_file() or existing.suffix.lower() not in EXPORT_SUFFIXES:
            continue
        try:
            if sha256_file(existing) == digest:
                return True
        except OSError:
            continue
    return False
