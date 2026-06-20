from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

import yaml

from localvault import db
from localvault.auto_takeout import auto_takeout
from localvault.config import ensure_directories
from localvault.reports import RunReport


def test_auto_takeout_detects_generic_named_takeout_zip_and_moves_to_inbox(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "archive.zip"
    _zip(archive, {"Takeout/Google Photos/photo.jpg": b"photo"})

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.imported_count >= 1
    assert not archive.exists()
    assert (p.google_takeout_inbox / "archive.zip").exists()


def test_auto_takeout_ignores_random_zip(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "random.zip"
    _zip(archive, {"docs/readme.txt": b"hello"})

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.imported_count == 0
    assert archive.exists()
    assert not (p.google_takeout_inbox / "random.zip").exists()


def test_auto_takeout_ignores_incomplete_downloads(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    incomplete = downloads / "takeout.zip.crdownload"
    incomplete.write_bytes(b"not finished")

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.imported_count == 0
    assert incomplete.exists()


def test_auto_takeout_ignores_corrupt_zip(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    broken = downloads / "broken.zip"
    broken.write_bytes(b"not a zip")

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.failed_count == 0
    assert report.imported_count == 0
    assert broken.exists()


def test_auto_takeout_moves_three_split_takeout_zips(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    for index in range(1, 4):
        _zip(downloads / f"takeout-{index:03}.zip", {
            f"Takeout/Google Photos/photo-{index}.jpg": f"photo-{index}".encode("utf-8")
        })

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.imported_count >= 3
    assert not list(downloads.glob("takeout-*.zip"))
    assert sorted(path.name for path in p.google_takeout_inbox.glob("takeout-*.zip")) == [
        "takeout-001.zip",
        "takeout-002.zip",
        "takeout-003.zip",
    ]


def test_auto_takeout_dry_run_does_not_move_or_import(monkeypatch, tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "takeout.zip"
    _zip(archive, {"Takeout/Mail/mail.mbox": b"From sender@example.com Tue Nov 14 22:13:20 2023\nSubject: Hi\n\nBody\n"})
    calls = []
    monkeypatch.setattr("localvault.auto_takeout.ingest_photos_takeout", lambda *args, **kwargs: calls.append("photos"))
    monkeypatch.setattr("localvault.auto_takeout.ingest_gmail_takeout", lambda *args, **kwargs: calls.append("gmail"))

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"), dry_run=True)

    assert report.imported_count == 1
    assert archive.exists()
    assert not (p.google_takeout_inbox / "takeout.zip").exists()
    assert calls == []


def test_auto_takeout_calls_ingests_after_moving_valid_zip(monkeypatch, tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "takeout.zip"
    _zip(archive, {"Takeout/Mail/mail.mbox": b"From sender@example.com Tue Nov 14 22:13:20 2023\nSubject: Hi\n\nBody\n"})
    calls = []
    monkeypatch.setattr("localvault.auto_takeout.ingest_photos_takeout", lambda *args, **kwargs: calls.append("photos"))
    monkeypatch.setattr("localvault.auto_takeout.ingest_gmail_takeout", lambda *args, **kwargs: calls.append("gmail"))

    auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert calls == ["photos", "gmail"]


def test_auto_takeout_skips_duplicate_zip_by_hash(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "takeout.zip"
    existing = p.google_takeout_inbox / "existing.zip"
    payload = {"Takeout/Google Fotos/photo.jpg": b"photo"}
    _zip(archive, payload)
    _zip(existing, payload)

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.skipped_duplicates == 1
    assert archive.exists()


def _prepared(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    (p.config / "config.yaml").write_text(yaml.safe_dump({
        "source_sync": {"google_takeout_sources": [str(downloads)]}
    }), encoding="utf-8")
    return p, downloads


def _zip(path: Path, entries: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
