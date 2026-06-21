from typer.testing import CliRunner

from localvault.cli import app


runner = CliRunner()


def test_run_with_report_command_exits_one_when_report_failed(monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("localvault.cli.scan_existing_media", fail)

    result = runner.invoke(app, ["scan-media", "--root", str(tmp_path)])

    assert result.exit_code == 1
    assert "Status: failed" in result.output


def test_manual_report_command_exits_one_when_report_failed(monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("localvault.cli.ingest_photos_takeout", fail)

    result = runner.invoke(app, ["ingest-all", "--root", str(tmp_path), "--skip-sync"])

    assert result.exit_code == 1
    assert "Status: failed" in result.output


def test_warning_report_still_exits_zero(monkeypatch, tmp_path):
    def warn(_paths, report, dry_run=False):
        report.warn("minor issue")

    monkeypatch.setattr("localvault.cli.scan_existing_media", warn)

    result = runner.invoke(app, ["scan-media", "--root", str(tmp_path)])

    assert result.exit_code == 0
    assert "Status: warning" in result.output


def test_daily_backup_calls_verify_once_with_full_check(monkeypatch, tmp_path):
    def noop(*args, **kwargs):
        return None

    calls = []

    def verify(*args, **kwargs):
        calls.append(kwargs.get("sample_limit"))

    monkeypatch.setattr("localvault.cli.cleanup_missing_index_entries", lambda *args, **kwargs: 0)
    monkeypatch.setattr("localvault.cli.run_gmail_api", noop)
    monkeypatch.setattr("localvault.cli.run_source_sync", noop)
    monkeypatch.setattr("localvault.cli.ingest_photos_takeout", noop)
    monkeypatch.setattr("localvault.cli.ingest_gmail_takeout", noop)
    monkeypatch.setattr("localvault.cli.build_duplicate_report", noop)
    monkeypatch.setattr("localvault.cli.verify_vault", verify)

    result = runner.invoke(app, ["daily-backup", "--root", str(tmp_path)])

    assert result.exit_code == 0
    assert calls == [None]


def test_removed_legacy_import_commands_are_absent():
    result = runner.invoke(app, ["--help"])
    removed_commands = ["ingest-" + "what" + "sapp", "auto-" + "what" + "sapp"]

    assert result.exit_code == 0
    for command in removed_commands:
        assert command not in result.output
