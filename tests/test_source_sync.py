from pathlib import Path

import yaml

from localvault import db
from localvault.config import ensure_directories
from localvault.reports import RunReport
from localvault.source_sync import sync_sources


def test_sync_sources_copies_matching_files(tmp_path: Path):
    root = tmp_path / "vault"
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    (downloads / "takeout-20260619.zip").write_bytes(b"zip")
    (downloads / "ignore.zip").write_bytes(b"ignore")
    p = ensure_directories(root)
    (p.config / "config.yaml").write_text(yaml.safe_dump({"source_sync": {"enabled": True, "google_takeout_sources": [str(downloads)]}}), encoding="utf-8")
    db.init_db(p.db)
    report = sync_sources(p, RunReport(source="test", mode="sync"))
    assert report.imported_count == 1
    assert (p.google_takeout_inbox / "takeout-20260619.zip").exists()
    assert not (p.google_takeout_inbox / "ignore.zip").exists()
