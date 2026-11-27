from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
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


def test_verify_matches_native_catalog_projection_fixture(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    vault = p.root / "vault" / "synthetic"
    missing = vault / "missing.bin"
    same_size_mismatch = vault / "same-size-mismatch.bin"
    matching = vault / "matching.bin"
    later_missing = vault / "later-missing.bin"

    with db.connect(p.db) as conn:
        db.upsert_file(
            conn,
            sha256=hashlib.sha256(b"expected-missing").hexdigest(),
            path=missing,
            media_type="photo",
            size=16,
            source="synthetic",
        )
    # The indexed bytes are `right`; the present bytes are `wrong`, both five bytes long.
    _index_file(
        p,
        same_size_mismatch,
        b"wrong",
        indexed_digest=hashlib.sha256(b"right").hexdigest(),
    )
    _index_file(p, matching, b"match")
    with db.connect(p.db) as conn:
        db.upsert_file(
            conn,
            sha256=hashlib.sha256(b"later missing").hexdigest(),
            path=later_missing,
            media_type="photo",
            size=len(b"later missing"),
            source="synthetic",
        )

    full_report = verify_vault(p, RunReport(source="vault", mode="verify_full"), sample_limit=None)
    sample_report = verify_vault(p, RunReport(source="vault", mode="verify_sample"), sample_limit=1)

    expected_errors = [
        {"item_path": str(missing), "error": "Indexed file is missing"},
        {"item_path": str(same_size_mismatch), "error": "SHA-256 mismatch"},
        {"item_path": str(later_missing), "error": "Indexed file is missing"},
    ]
    assert full_report.imported_count == 1
    assert full_report.failed_count == 3
    assert full_report.errors == expected_errors
    assert sample_report.imported_count == 1
    assert sample_report.failed_count == 2
    assert sample_report.errors == expected_errors[:2]


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


def test_verify_propagates_non_missing_read_errors(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    directory = p.root / "vault" / "synthetic" / "not-a-file"
    directory.mkdir(parents=True)
    with db.connect(p.db) as conn:
        db.upsert_file(
            conn,
            sha256="0" * 64,
            path=directory,
            media_type="photo",
            size=0,
            source="synthetic",
        )

    with pytest.raises(OSError):
        verify_vault(p, RunReport(source="vault", mode="verify_full"), sample_limit=None)


def test_verify_accepts_caller_hash_callable_and_keeps_partial_report_on_error(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    vault = p.root / "vault" / "synthetic"
    first = vault / "first.bin"
    fatal = vault / "fatal.bin"
    _index_file(p, first, b"first", indexed_digest="not-the-digest")
    _index_file(p, fatal, b"fatal")
    calls: list[Path] = []

    def injected_hash(path: Path) -> str:
        calls.append(path)
        if path == fatal:
            raise RuntimeError("synthetic hash failure")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    report = RunReport(source="vault", mode="verify_full")
    with pytest.raises(RuntimeError, match="synthetic hash failure"):
        verify_vault(p, report, hash_file=injected_hash)

    assert calls == [first, fatal]
    assert report.errors == [{"item_path": str(first), "error": "SHA-256 mismatch"}]


def test_verify_default_hash_matches_injected_python_hasher(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    vault = p.root / "vault" / "synthetic"
    _index_file(p, vault / "one.bin", b"one")
    _index_file(p, vault / "two.bin", b"two")

    default = verify_vault(p, RunReport(source="vault", mode="verify_full"))
    injected = verify_vault(
        p,
        RunReport(source="vault", mode="verify_full"),
        hash_file=lambda path: hashlib.sha256(path.read_bytes()).hexdigest(),
    )

    assert default.imported_count == injected.imported_count == 2


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
