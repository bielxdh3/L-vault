from pathlib import Path

import yaml
from typer.testing import CliRunner

from localvault.auth import auth_path, load_auth, verify_password
from localvault.cli import app


runner = CliRunner()


def test_setup_fresh_root_uses_safe_defaults_and_password_stdin(tmp_path: Path):
    root = tmp_path / "vault"

    result = runner.invoke(app, ["setup", "--root", str(root), "--password-stdin"], input="first-password\n")

    assert result.exit_code == 0
    assert (root / "config" / "config.yaml").exists()
    assert (root / "db" / "localvault.sqlite").exists()
    config = yaml.safe_load((root / "config" / "config.yaml").read_text(encoding="utf-8"))
    assert config["vault_root"] == str(root)
    assert config["gmail"]["credentials_file"] == str(root / "config" / "google_oauth_client_secret.json")
    assert verify_password(load_auth(root), "first-password")
    assert "Gmail API: DESATIVADA" in result.output
    assert "loopback" in result.output
    assert "schedule-install" in result.output
    assert "first-password" not in result.output
    assert not (root / "schedule_tasks.ps1").exists()


def test_setup_rerun_preserves_config_and_password(tmp_path: Path):
    root = tmp_path / "vault"
    first = runner.invoke(app, ["setup", "--root", str(root), "--password-stdin"], input="keep-me\n")
    assert first.exit_code == 0
    config_path = root / "config" / "config.yaml"
    config_path.write_text(config_path.read_text(encoding="utf-8") + "\ncustom_marker: preserved\n", encoding="utf-8")
    before_auth = auth_path(root).read_text(encoding="utf-8")
    before_config = config_path.read_text(encoding="utf-8")

    second = runner.invoke(app, ["setup", "--root", str(root), "--non-interactive"])

    assert second.exit_code == 0
    assert config_path.read_text(encoding="utf-8") == before_config
    assert auth_path(root).read_text(encoding="utf-8") == before_auth
    assert "preservada" in second.output


def test_setup_rejects_file_as_root(tmp_path: Path):
    root_file = tmp_path / "not-a-directory"
    root_file.write_text("x", encoding="utf-8")

    result = runner.invoke(app, ["setup", "--root", str(root_file), "--non-interactive"])

    assert result.exit_code != 0
    assert "directory" in result.output.lower()


def test_setup_reports_password_required_without_prompt(tmp_path: Path):
    result = runner.invoke(app, ["setup", "--root", str(tmp_path / "vault"), "--non-interactive"])

    assert result.exit_code == 2
    assert "REQUIRED" in result.output
    assert "Senha do painel" in result.output


def test_setup_previews_takeout_schedule_and_lan_warning(tmp_path: Path):
    root = tmp_path / "vault"
    source = tmp_path / "Downloads"
    source.mkdir()
    config_dir = root / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "config.yaml").write_text(yaml.safe_dump({
        "viewer": {"host": "192.0.2.10", "allow_lan": True},
        "source_sync": {"google_takeout_sources": [str(source)]},
        "automation": {"tasks": {"daily_backup": {"time": "02:15"}}},
    }), encoding="utf-8")

    result = runner.invoke(app, ["setup", "--root", str(root), "--password-stdin"], input="lan-password\n")

    assert result.exit_code == 0
    assert "LAN" in result.output
    assert "HTTP sem criptografia" in result.output
    assert str(source) in result.output
    assert "02:15" in result.output
    assert "conteudo nao lido" in result.output


def test_setup_scheduler_preview_does_not_install_or_generate_tasks(tmp_path: Path, monkeypatch):
    calls = []
    monkeypatch.setattr("localvault.cli.run_powershell_script", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr("localvault.cli.generate_schedule_files", lambda *args, **kwargs: calls.append(args))

    result = runner.invoke(app, ["setup", "--root", str(tmp_path / "vault"), "--password-stdin"], input="safe-password\n")

    assert result.exit_code == 0
    assert calls == []

