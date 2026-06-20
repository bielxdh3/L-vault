from pathlib import Path

from localvault.config import DEFAULT_DOWNLOADS, load_config


def test_load_config_does_not_mutate_default_config(tmp_path: Path):
    first = load_config(tmp_path / "vault")
    first["source_sync"]["google_takeout_sources"].append("C:\\Temp\\Takeout")

    second = load_config(tmp_path / "vault")

    assert second["source_sync"]["google_takeout_sources"] == [DEFAULT_DOWNLOADS]
