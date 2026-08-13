from pathlib import Path

import yaml

from localvault.config import DEFAULT_CONFIG
from localvault.scheduler import generate_schedule_files


ROOT = Path(__file__).resolve().parents[1]


def test_config_example_and_docs_match_current_defaults(tmp_path: Path):
    example = yaml.safe_load((ROOT / "config" / "config.example.yaml").read_text(encoding="utf-8"))
    assert example["viewer"]["tls_enabled"] is False
    assert example["viewer"]["tls_certfile"] == ""
    assert example["viewer"]["tls_keyfile"] == ""
    assert example["automation"] == DEFAULT_CONFIG["automation"]
    assert "auth.json" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "recovery-test" in (ROOT / "SETUP_WINDOWS.md").read_text(encoding="utf-8")

    files = generate_schedule_files(type("Paths", (), {"root": tmp_path})())
    install = files.install.read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    setup = (ROOT / "SETUP_WINDOWS.md").read_text(encoding="utf-8")
    for task in DEFAULT_CONFIG["automation"]["tasks"].values():
        assert task["name"] in install
        assert task["time"] in install
        assert task["name"] in readme
        assert task["time"] in readme
        assert task["name"] in setup
        assert task["time"] in setup


def test_setup_template_is_utf8_and_exposes_safe_operational_states():
    template = (ROOT / "src" / "localvault" / "templates" / "setup.html").read_text(encoding="utf-8")
    assert "ConfiguraÃ§Ã£o" in template
    assert "TLS" in template
    assert "nÃ£o instala" in template
    assert "senha" in template.lower()
    assert "ConfiguraÃƒ" not in template
