from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from localvault import db
from localvault.cli import app
from localvault.config import ensure_directories
from localvault.reports import RunReport
from localvault.verify import verify_vault


runner = CliRunner()


def _index_file(p, path: Path, data: bytes, *, indexed_digest: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    digest = indexed_digest if indexed_digest is not None else hashlib.sha256(data).hexdigest()
    with db.connect(p.db) as conn:
        db.upsert_file(conn, sha256=digest, path=path, media_type="photo", size=len(data), source="synthetic")


def test_verify_sample_limit_counts_successful_rows_only(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    vault = p.root / "vault" / "synthetic"
    missing = vault / "missing.bin"
    corrupt = vault / "corrupt.bin"
    valid = vault / "valid.bin"
    later_corrupt = vault / "later-corrupt.bin"

    with db.connect(p.db) as conn:
        db.upsert_file(
            conn,
            sha256=hashlib.sha256(b"expected-missing").hexdigest(),
            path=missing,
            media_type="photo",
            size=16,
            source="synthetic",
        )
    _index_file(p, corrupt, b"changed", indexed_digest=hashlib.sha256(b"original").hexdigest())
    _index_file(p, valid, b"valid")
    _index_file(p, later_corrupt, b"also-changed", indexed_digest=hashlib.sha256(b"later-original").hexdigest())

    report = verify_vault(p, RunReport(source="vault", mode="verify_sample"), sample_limit=1)

    assert report.imported_count == 1
    assert report.failed_count == 2
    assert report.errors == [
        {"item_path": str(missing), "error": "Indexed file is missing"},
        {"item_path": str(corrupt), "error": "SHA-256 mismatch"},
    ]


def test_verify_zero_sample_limit_remains_unlimited(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    vault = p.root / "vault" / "synthetic"
    _index_file(p, vault / "valid.bin", b"valid")
    _index_file(p, vault / "corrupt.bin", b"changed", indexed_digest=hashlib.sha256(b"original").hexdigest())

    report = verify_vault(p, RunReport(source="vault", mode="verify_sample"), sample_limit=0)

    assert report.imported_count == 1
    assert report.failed_count == 1
    assert report.errors[0]["error"] == "SHA-256 mismatch"


def test_verify_cli_preserves_full_and_sample_report_modes(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    _index_file(p, p.root / "vault" / "synthetic" / "valid.bin", b"valid")

    for options, expected_mode in (([], "verify_full"), (["--sample-limit", "1"], "verify_sample")):
        result = runner.invoke(app, ["verify", "--root", str(p.root), *options])

        assert result.exit_code == 0
        assert "Status: ok" in result.output
        assert "Imported/indexed: 1" in result.output
        with db.connect(p.db) as conn:
            row = conn.execute("SELECT mode,report_path FROM backup_runs ORDER BY id DESC LIMIT 1").fetchone()
        assert row["mode"] == expected_mode
        report = json.loads(Path(row["report_path"]).read_text(encoding="utf-8"))
        assert report["mode"] == expected_mode
