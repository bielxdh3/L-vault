from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

import yaml

from localvault import db
from localvault.auto_takeout import auto_takeout
from localvault.config import ensure_directories
from localvault.reports import RunReport


def test_auto_takeout_detects_generic_named_takeout_zip_and_preserves_source(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "archive.zip"
    _zip(archive, {"Takeout/Google Photos/photo.jpg": b"photo"})

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.imported_count >= 1
    assert archive.exists()
    assert (p.google_takeout_inbox / "archive.zip").exists()


def test_auto_takeout_ignores_random_zip(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "random.zip"
    _zip(archive, {"docs/readme.txt": b"hello"})

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.imported_count == 0
    assert archive.exists()
    assert not (p.google_takeout_inbox / "random.zip").exists()


def test_auto_takeout_ignores_random_mail_folder_zip(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "mail-archive.zip"
    _zip(archive, {"mail/readme.txt": b"not gmail takeout"})

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.imported_count == 0
    assert archive.exists()
    assert not (p.google_takeout_inbox / "mail-archive.zip").exists()


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


def test_auto_takeout_copies_three_split_takeout_zips_and_preserves_sources(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    for index in range(1, 4):
        _zip(downloads / f"takeout-{index:03}.zip", {
            f"Takeout/Google Photos/photo-{index}.jpg": f"photo-{index}".encode("utf-8")
        })

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.imported_count >= 3
    assert len(list(downloads.glob("takeout-*.zip"))) == 3
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


def test_auto_takeout_moves_source_only_when_never_delete_sources_is_disabled(tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "takeout.zip"
    _zip(archive, {"Takeout/Google Photos/photo.jpg": b"photo"})
    (p.config / "config.yaml").write_text(yaml.safe_dump({
        "source_sync": {"google_takeout_sources": [str(downloads)]},
        "safety": {"never_delete_sources": False},
    }), encoding="utf-8")

    auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert not archive.exists()
    assert (p.google_takeout_inbox / "takeout.zip").exists()


def test_auto_takeout_passes_only_newly_moved_zips_to_ingests(monkeypatch, tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    old_zip = p.google_takeout_inbox / "old.zip"
    _zip(old_zip, {"Takeout/Google Photos/old.jpg": b"old"})
    new_zip = downloads / "new.zip"
    _zip(new_zip, {"Takeout/Google Photos/new.jpg": b"new"})
    calls = []

    def record(_p, _report, **kwargs):
        calls.append(kwargs["zip_paths"])

    monkeypatch.setattr("localvault.auto_takeout.ingest_photos_takeout", record)
    monkeypatch.setattr("localvault.auto_takeout.ingest_gmail_takeout", record)

    auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert calls == [[p.google_takeout_inbox / "new.zip"], [p.google_takeout_inbox / "new.zip"]]


def test_auto_takeout_does_not_import_if_any_move_fails(monkeypatch, tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    first = downloads / "takeout-001.zip"
    second = downloads / "takeout-002.zip"
    _zip(first, {"Takeout/Google Photos/photo-1.jpg": b"photo-1"})
    _zip(second, {"Takeout/Google Photos/photo-2.jpg": b"photo-2"})
    calls = []
    def flaky_copy(src, dest, dry_run=False):
        if str(src).endswith("takeout-002.zip"):
            raise OSError("disk error")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())
        return dest.stat().st_size

    monkeypatch.setattr("localvault.auto_takeout.atomic_copy", flaky_copy)
    monkeypatch.setattr("localvault.auto_takeout.ingest_photos_takeout", lambda *args, **kwargs: calls.append("photos"))
    monkeypatch.setattr("localvault.auto_takeout.ingest_gmail_takeout", lambda *args, **kwargs: calls.append("gmail"))

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.failed_count == 1
    assert calls == []
    assert (p.google_takeout_inbox / "takeout-001.zip").exists()
    assert second.exists()


def test_auto_takeout_does_not_remove_original_if_safe_move_fails(monkeypatch, tmp_path: Path):
    p, downloads = _prepared(tmp_path)
    archive = downloads / "takeout.zip"
    _zip(archive, {"Takeout/Google Photos/photo.jpg": b"photo"})
    calls = []

    def fail_copy(*args, **kwargs):
        raise ValueError("verification failed")

    monkeypatch.setattr("localvault.auto_takeout.atomic_copy", fail_copy)
    monkeypatch.setattr("localvault.auto_takeout.ingest_photos_takeout", lambda *args, **kwargs: calls.append("photos"))
    monkeypatch.setattr("localvault.auto_takeout.ingest_gmail_takeout", lambda *args, **kwargs: calls.append("gmail"))

    report = auto_takeout(p, RunReport(source="google_takeout", mode="auto"))

    assert report.failed_count == 1
    assert archive.exists()
    assert not (p.google_takeout_inbox / "takeout.zip").exists()
    assert calls == []


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
