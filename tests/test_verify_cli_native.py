from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from localvault import db
from localvault.cli import app
from localvault.config import ensure_directories


runner = CliRunner()


def _indexed_file(paths, path: Path, content: bytes, *, indexed_content: bytes | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    digest_content = content if indexed_content is None else indexed_content
    with db.connect(paths.db) as conn:
        db.upsert_file(
            conn,
            sha256=hashlib.sha256(digest_content).hexdigest(),
            path=path,
            media_type="photo",
            size=len(content),
            source="synthetic",
        )


def _latest_report(paths) -> dict[str, object]:
    with db.connect(paths.db) as conn:
        row = conn.execute("SELECT report_path FROM backup_runs ORDER BY id DESC LIMIT 1").fetchone()
    return json.loads(Path(row["report_path"]).read_text(encoding="utf-8"))


def test_verify_cli_uses_explicit_native_session_and_keeps_sample_limit(tmp_path, monkeypatch):
    paths = ensure_directories(tmp_path / "vault")
    db.init_db(paths.db)
    first = paths.root / "vault" / "synthetic" / "first.bin"
    second = paths.root / "vault" / "synthetic" / "corrupt-outside-sample.bin"
    _indexed_file(paths, first, b"first")
    _indexed_file(paths, second, b"changed", indexed_content=b"expected")
    executable = tmp_path / "lvault-integrity.exe"
    executable.write_bytes(b"synthetic executable")
    pin = hashlib.sha256(executable.read_bytes()).hexdigest()
    events: list[str] = []
    hashed: list[Path] = []

    class Session:
        def __init__(self, trusted_executable: Path):
            assert trusted_executable == executable
            events.append("constructed")

        def __enter__(self):
            events.append("entered")

            def hash_file(path: Path) -> str:
                hashed.append(path)
                return hashlib.sha256(path.read_bytes()).hexdigest()

            return hash_file

        def __exit__(self, exc_type, exc_value, traceback):
            events.append("closed")
            return False

    monkeypatch.setattr("localvault.cli.NativeIntegrityHashSession", Session, raising=False)

    result = runner.invoke(
        app,
        [
            "verify",
            "--root",
            str(paths.root),
            "--sample-limit",
            "1",
            "--native-exe",
            str(executable),
            "--native-sha256",
            pin,
        ],
    )

    assert result.exit_code == 0, result.output
    assert events == ["constructed", "entered", "closed"]
    assert hashed == [first]
    report = _latest_report(paths)
    assert report["mode"] == "verify_sample"
    assert report["status"] == "ok"
    assert report["imported_count"] == 1
    assert report["failed_count"] == 0


def test_verify_cli_keeps_python_hasher_as_the_default(tmp_path, monkeypatch):
    paths = ensure_directories(tmp_path / "vault")
    db.init_db(paths.db)
    _indexed_file(paths, paths.root / "vault" / "synthetic" / "valid.bin", b"valid")
    launches: list[Path] = []

    class Session:
        def __init__(self, executable: Path):
            launches.append(executable)
            raise AssertionError("native hashing must remain opt-in")

    monkeypatch.setattr("localvault.cli.NativeIntegrityHashSession", Session, raising=False)

    result = runner.invoke(app, ["verify", "--root", str(paths.root)])

    assert result.exit_code == 0, result.output
    assert launches == []
    report = _latest_report(paths)
    assert report["mode"] == "verify_full"
    assert report["status"] == "ok"
    assert report["imported_count"] == 1


@pytest.mark.parametrize(
    "invalid_input",
    [
        "missing-pin",
        "missing-executable",
        "malformed-pin",
        "mismatched-pin",
        "relative-path",
        "symlink-path",
    ],
)
def test_verify_cli_rejects_untrusted_native_options_before_launch(
    invalid_input, tmp_path, monkeypatch
):
    paths = ensure_directories(tmp_path / "vault")
    db.init_db(paths.db)
    _indexed_file(paths, paths.root / "vault" / "synthetic" / "valid.bin", b"valid")
    executable = tmp_path / "lvault-integrity.exe"
    executable.write_bytes(b"synthetic executable")
    pin = hashlib.sha256(executable.read_bytes()).hexdigest()
    arguments = ["verify", "--root", str(paths.root)]
    if invalid_input != "missing-executable":
        arguments.extend(["--native-exe", str(executable)])
    if invalid_input != "missing-pin":
        arguments.extend(
            [
                "--native-sha256",
                {
                    "malformed-pin": "not-a-sha256-pin",
                    "mismatched-pin": "0" * 64,
                    "relative-path": pin,
                }.get(invalid_input, pin),
            ]
        )
    if invalid_input == "relative-path":
        arguments[arguments.index(str(executable))] = "relative.exe"
    if invalid_input == "symlink-path":
        original_is_symlink = Path.is_symlink
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda path: path == executable or original_is_symlink(path),
        )
    launches: list[Path] = []

    class Session:
        def __init__(self, trusted_executable: Path):
            launches.append(trusted_executable)

    monkeypatch.setattr("localvault.cli.NativeIntegrityHashSession", Session, raising=False)

    result = runner.invoke(app, arguments)

    assert result.exit_code == 1, result.output
    assert "Status: failed" in result.output
    assert launches == []
    report = _latest_report(paths)
    assert report["status"] == "failed"
    assert report["failed_count"] == 1
    assert "native" in report["errors"][0]["error"].lower()


def test_verify_cli_persists_native_launch_failure(tmp_path, monkeypatch):
    paths = ensure_directories(tmp_path / "vault")
    db.init_db(paths.db)
    _indexed_file(paths, paths.root / "vault" / "synthetic" / "valid.bin", b"valid")
    executable = tmp_path / "lvault-integrity.exe"
    executable.write_bytes(b"synthetic executable")
    pin = hashlib.sha256(executable.read_bytes()).hexdigest()
    launches: list[list[str]] = []

    def fail_to_launch(arguments, **kwargs):
        launches.append(arguments)
        raise OSError("synthetic launch failure")

    monkeypatch.setattr("localvault.native_integrity.Popen", fail_to_launch)

    result = runner.invoke(
        app,
        [
            "verify",
            "--root",
            str(paths.root),
            "--native-exe",
            str(executable),
            "--native-sha256",
            pin,
        ],
    )

    assert result.exit_code == 1, result.output
    assert "Status: failed" in result.output
    assert launches == [[str(executable), "hash-session-v2"]]
    report = _latest_report(paths)
    assert report["status"] == "failed"
    assert report["failed_count"] == 1
    assert report["errors"][0]["error"] == "synthetic launch failure"


def test_verify_cli_persists_teardown_failure_after_successful_verification(tmp_path, monkeypatch):
    paths = ensure_directories(tmp_path / "vault")
    db.init_db(paths.db)
    file_path = paths.root / "vault" / "synthetic" / "valid.bin"
    _indexed_file(paths, file_path, b"valid")
    executable = tmp_path / "lvault-integrity.exe"
    executable.write_bytes(b"synthetic executable")
    pin = hashlib.sha256(executable.read_bytes()).hexdigest()
    events: list[str] = []

    class Session:
        def __init__(self, trusted_executable: Path):
            assert trusted_executable == executable

        def __enter__(self):
            events.append("entered")
            return lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

        def __exit__(self, exc_type, exc_value, traceback):
            events.append("teardown")
            raise OSError("synthetic teardown failure")

    monkeypatch.setattr("localvault.cli.NativeIntegrityHashSession", Session, raising=False)

    result = runner.invoke(
        app,
        [
            "verify",
            "--root",
            str(paths.root),
            "--native-exe",
            str(executable),
            "--native-sha256",
            pin,
        ],
    )

    assert result.exit_code == 1, result.output
    assert events == ["entered", "teardown"]
    report = _latest_report(paths)
    assert report["status"] == "failed"
    assert report["imported_count"] == 1
    assert report["failed_count"] == 1
    assert report["errors"][0]["error"] == "synthetic teardown failure"
