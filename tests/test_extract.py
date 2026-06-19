from pathlib import Path
from zipfile import ZipFile

import pytest

from localvault.extract import safe_extract_zip


def test_safe_extract_blocks_zip_slip(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", "nope")
    with pytest.raises(ValueError):
        safe_extract_zip(archive, tmp_path / "out")


def test_safe_extract_normal(tmp_path: Path):
    archive = tmp_path / "good.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("Takeout/photo.jpg", "fake")
    out = safe_extract_zip(archive, tmp_path / "out")
    assert (out / "Takeout" / "photo.jpg").exists()
