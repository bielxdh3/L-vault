from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    for i in range(1, 100000):
        candidate = path.with_name(f"{path.stem}_{i}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not create unique path for {path}")


def temp_path_for(dest: Path) -> Path:
    return dest.with_name(f".localvault_tmp_{os.getpid()}_{dest.name}.part")


def atomic_write_bytes(dest: Path, data: bytes, dry_run: bool = False) -> int:
    if dry_run:
        return len(data)
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = temp_path_for(dest)
    try:
        with temp.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, dest)
        return len(data)
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def atomic_write_text(dest: Path, text: str, encoding: str = "utf-8", dry_run: bool = False) -> int:
    return atomic_write_bytes(dest, text.encode(encoding), dry_run=dry_run)


def atomic_copy(src: Path, dest: Path, dry_run: bool = False) -> int:
    size = src.stat().st_size
    if dry_run:
        return size
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = temp_path_for(dest)
    try:
        with src.open("rb") as in_file, temp.open("wb") as out_file:
            shutil.copyfileobj(in_file, out_file, length=1024 * 1024)
            out_file.flush()
            os.fsync(out_file.fileno())
        shutil.copystat(src, temp, follow_symlinks=True)
        if temp.stat().st_size != size or sha256_file(temp) != sha256_file(src):
            raise ValueError("Copied file failed verification.")
        os.replace(temp, dest)
        return size
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def atomic_write_from_fileobj(dest: Path, src: BinaryIO, expected_size: int | None = None, dry_run: bool = False) -> int:
    if dry_run:
        return int(expected_size or 0)
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = temp_path_for(dest)
    try:
        written = 0
        with temp.open("wb") as out_file:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                out_file.write(chunk)
                written += len(chunk)
            out_file.flush()
            os.fsync(out_file.fileno())
        if expected_size is not None and temp.stat().st_size != expected_size:
            raise ValueError("Extracted file failed size verification.")
        os.replace(temp, dest)
        return written
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def atomic_move_or_copy(src: Path, dest: Path, expected_sha256: str | None = None, dry_run: bool = False) -> int:
    size = src.stat().st_size
    if dry_run:
        return size
    digest = expected_sha256 or sha256_file(src)
    atomic_copy(src, dest, dry_run=False)
    if dest.stat().st_size != size or sha256_file(dest) != digest:
        dest.unlink(missing_ok=True)
        raise ValueError("Moved file failed SHA-256 verification.")
    src.unlink()
    return size


def copy_preserve(src: Path, dest: Path, dry_run: bool = False) -> int:
    return atomic_copy(src, dest, dry_run=dry_run)


def guess_mime(path: Path) -> str:
    return mimetypes.guess_type(str(path))[0] or "application/octet-stream"


def media_kind(path: Path) -> str:
    mime = guess_mime(path)
    if mime.startswith("image/"):
        return "photo"
    if mime.startswith("video/"):
        return "video"
    if mime.startswith("audio/"):
        return "audio"
    if path.suffix.lower() in {".eml", ".mbox"}:
        return "email"
    return "file"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def cleanup_stale_temp_files(root: Path, older_than_hours: int = 24) -> int:
    if not root.exists():
        return 0
    cutoff = datetime.now(timezone.utc).timestamp() - older_than_hours * 3600
    removed = 0
    for temp in root.rglob(".localvault_tmp_*.part"):
        try:
            if temp.stat().st_mtime <= cutoff:
                temp.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def free_space_bytes(path: Path) -> int:
    target = path if path.exists() else path.parent
    while not target.exists() and target.parent != target:
        target = target.parent
    return shutil.disk_usage(target).free
