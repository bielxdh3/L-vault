from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from localvault import db
from localvault.config import ensure_directories
from localvault.native_integrity import NativeIntegrityHashSession
from localvault.recovery import run_recovery_test
from localvault.reports import RunReport
from localvault.verify import verify_vault


_BINARY_ENV = "LVAULT_INTEGRITY_SESSION_EXE"
_BINARY_SHA256 = "960fb0aa1c4a6984721e1297cec7a1c5372fa60df25248ab3d5b45181736490b"


@pytest.fixture
def pinned_integrity_binary() -> Path:
    value = os.environ.get(_BINARY_ENV)
    if value is None:
        pytest.skip(f"optional native integrity integration skipped: set {_BINARY_ENV}")
    if not value or not Path(value).is_absolute():
        pytest.fail(f"{_BINARY_ENV} must be an absolute executable path")

    executable = Path(value)
    if not executable.is_file():
        pytest.fail(f"{_BINARY_ENV} must name an existing regular file")

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for component in (executable, *executable.parents):
        try:
            if component.is_symlink() or getattr(component, "is_junction", lambda: False)():
                pytest.fail(f"{_BINARY_ENV} cannot resolve through a link")
            if component.stat(follow_symlinks=False).st_file_attributes & reparse_flag:
                pytest.fail(f"{_BINARY_ENV} cannot resolve through a reparse point")
        except OSError as error:
            pytest.fail(f"cannot inspect {_BINARY_ENV}: {error}")

    try:
        with executable.open("rb") as artifact:
            digest = hashlib.file_digest(artifact, "sha256").hexdigest()
    except OSError as error:
        pytest.fail(f"cannot hash {_BINARY_ENV}: {error}")
    if digest.casefold() != _BINARY_SHA256:
        pytest.fail(f"{_BINARY_ENV} SHA-256 does not match the pinned executable")
    return executable


def _normalized_recovery(report: dict[str, object]) -> str:
    return json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _normalized_verification(report: RunReport) -> tuple[object, ...]:
    return (
        report.source,
        report.mode,
        report.imported_count,
        report.failed_count,
        tuple((error["item_path"], error["error"]) for error in report.errors),
    )


def _sampled_fixture(tmp_path: Path):
    paths = ensure_directories(tmp_path / "vault")
    db.init_db(paths.db)
    vault = paths.root / "vault" / "synthetic"
    entries = (
        (vault / "sampled-first.bin", b"sampled first", b"sampled first"),
        (vault / "outside-sample.bin", b"corrupt second", b"expected second"),
    )
    with db.connect(paths.db) as conn:
        for path, content, indexed_content in entries:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            db.upsert_file(
                conn,
                sha256=hashlib.sha256(indexed_content).hexdigest(),
                path=path,
                media_type="photo",
                size=len(content),
                source="synthetic",
            )
    return paths


@pytest.mark.skipif(os.name != "nt", reason="the pinned integrity executable is Windows-only")
def test_native_session_matches_python_recovery_and_sampled_verification(
    pinned_integrity_binary: Path, tmp_path: Path
):
    python_recovery = run_recovery_test()
    paths = _sampled_fixture(tmp_path)
    python_sample = verify_vault(
        paths,
        RunReport(source="vault", mode="verify_sample"),
        sample_limit=1,
    )

    with NativeIntegrityHashSession(pinned_integrity_binary) as native_hash:
        native_recovery = run_recovery_test(hash_file=native_hash)
        native_sample = verify_vault(
            paths,
            RunReport(source="vault", mode="verify_sample"),
            sample_limit=1,
            hash_file=native_hash,
        )

    assert python_recovery["status"] == "passed"
    assert _normalized_recovery(native_recovery) == _normalized_recovery(python_recovery)
    assert _normalized_verification(python_sample) == _normalized_verification(native_sample)
    assert python_sample.imported_count == 1
    assert python_sample.failed_count == 0
    assert python_sample.errors == []
