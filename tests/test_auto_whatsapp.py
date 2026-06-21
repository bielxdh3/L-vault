from __future__ import annotations

import shutil
from pathlib import Path
from zipfile import ZipFile

import yaml

from localvault import db
from localvault.auto_whatsapp import auto_whatsapp
from localvault.config import ensure_directories
from localvault.reports import RunReport

CHAT_TEXT = "[01/05/2026, 09:15:00] Ana: Bom dia\n[01/05/2026, 09:16:00] Bruno: Oi\n"


def test_auto_whatsapp_detects_generic_txt_by_content_and_moves_to_inbox(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    export = downloads / "arquivo.txt"
    export.write_text(CHAT_TEXT, encoding="utf-8")

    report = auto_whatsapp(p, RunReport(source="whatsapp", mode="auto"))

    assert report.imported_count >= 1
    assert not export.exists()
    assert (p.whatsapp_exports_inbox / "arquivo.txt").exists()


def test_auto_whatsapp_ignores_random_txt(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    export = downloads / "notes.txt"
    export.write_text("not a chat", encoding="utf-8")

    report = auto_whatsapp(p, RunReport(source="whatsapp", mode="auto"))

    assert report.imported_count == 0
    assert export.exists()
    assert not (p.whatsapp_exports_inbox / "notes.txt").exists()


def test_auto_whatsapp_detects_zip_with_chat_and_media(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "export.zip"
    _zip(archive, {"chat.txt": CHAT_TEXT.encode("utf-8"), "IMG-001.jpg": b"image"})

    report = auto_whatsapp(p, RunReport(source="whatsapp", mode="auto"))

    assert report.imported_count >= 1
    assert not archive.exists()
    assert (p.whatsapp_exports_inbox / "export.zip").exists()


def test_auto_whatsapp_ignores_random_zip(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "random.zip"
    _zip(archive, {"readme.txt": b"not a chat"})

    report = auto_whatsapp(p, RunReport(source="whatsapp", mode="auto"))

    assert report.imported_count == 0
    assert archive.exists()
    assert not (p.whatsapp_exports_inbox / "random.zip").exists()


def test_auto_whatsapp_ignores_incomplete_downloads(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    for name in ("chat.txt.crdownload", "chat.zip.tmp", "chat.txt.part"):
        (downloads / name).write_bytes(b"not finished")

    report = auto_whatsapp(p, RunReport(source="whatsapp", mode="auto"))

    assert report.imported_count == 0
    assert sorted(path.name for path in downloads.iterdir()) == ["chat.txt.crdownload", "chat.txt.part", "chat.zip.tmp"]


def test_auto_whatsapp_dry_run_does_not_move_or_import(monkeypatch, tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    export = downloads / "chat.txt"
    export.write_text(CHAT_TEXT, encoding="utf-8")
    calls = []
    monkeypatch.setattr("localvault.auto_whatsapp.ingest_whatsapp_exports", lambda *args, **kwargs: calls.append("ingest"))

    report = auto_whatsapp(p, RunReport(source="whatsapp", mode="auto"), dry_run=True)

    assert report.imported_count == 1
    assert export.exists()
    assert not (p.whatsapp_exports_inbox / "chat.txt").exists()
    assert calls == []


def test_auto_whatsapp_does_not_import_if_any_move_fails(monkeypatch, tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    first = downloads / "chat-1.txt"
    second = downloads / "chat-2.txt"
    first.write_text(CHAT_TEXT, encoding="utf-8")
    second.write_text(CHAT_TEXT.replace("Ana", "Carla"), encoding="utf-8")
    calls = []
    original_move = shutil.move

    def flaky_move(src, dest):
        if str(src).endswith("chat-2.txt"):
            raise OSError("disk error")
        return original_move(src, dest)

    monkeypatch.setattr("localvault.auto_whatsapp.shutil.move", flaky_move)
    monkeypatch.setattr("localvault.auto_whatsapp.ingest_whatsapp_exports", lambda *args, **kwargs: calls.append("ingest"))

    report = auto_whatsapp(p, RunReport(source="whatsapp", mode="auto"))

    assert report.failed_count == 1
    assert calls == []
    assert (p.whatsapp_exports_inbox / "chat-1.txt").exists()
    assert second.exists()


def test_auto_whatsapp_skips_duplicate_by_hash(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    export = downloads / "chat.txt"
    existing = p.whatsapp_exports_inbox / "existing.txt"
    export.write_text(CHAT_TEXT, encoding="utf-8")
    existing.write_text(CHAT_TEXT, encoding="utf-8")

    report = auto_whatsapp(p, RunReport(source="whatsapp", mode="auto"))

    assert report.skipped_duplicates == 1
    assert export.exists()


def _prepared(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    (p.config / "config.yaml").write_text(yaml.safe_dump({
        "source_sync": {"whatsapp_export_sources": [str(downloads)]}
    }), encoding="utf-8")
    return p, downloads


def _zip(path: Path, entries: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
