from pathlib import Path
from zipfile import ZipFile

import pytest

from localvault.extract import MAX_ZIP_ENTRIES, MAX_ZIP_MEMBER_BYTES, safe_extract_zip, safe_zip_infos


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


def test_safe_zip_rejects_reserved_colliding_and_oversized_entries(monkeypatch, tmp_path: Path):
    reserved = tmp_path / "reserved.zip"
    with ZipFile(reserved, "w") as zf:
        zf.writestr("Takeout/CON.txt", "unsafe")
    with pytest.raises(ValueError):
        safe_zip_infos(reserved)

    collision = tmp_path / "collision.zip"
    with ZipFile(collision, "w") as zf:
        zf.writestr("Takeout/photo.jpg", "one")
        zf.writestr("Takeout/PHOTO.JPG", "two")
    with pytest.raises(ValueError):
        safe_zip_infos(collision)

    too_many = tmp_path / "too-many.zip"
    with ZipFile(too_many, "w") as zf:
        zf.writestr("Takeout/photo.jpg", "small")
    original = ZipFile.infolist

    def too_many_infos(archive):
        infos = original(archive)
        return infos * (MAX_ZIP_ENTRIES + 1)

    monkeypatch.setattr(ZipFile, "infolist", too_many_infos)
    with pytest.raises(ValueError):
        safe_zip_infos(too_many)

    oversized = tmp_path / "oversized.zip"
    with ZipFile(oversized, "w") as zf:
        zf.writestr("Takeout/photo.jpg", "small")

    def oversized_infos(archive):
        infos = original(archive)
        infos[0].file_size = MAX_ZIP_MEMBER_BYTES + 1
        return infos

    monkeypatch.setattr(ZipFile, "infolist", oversized_infos)
    with pytest.raises(ValueError):
        safe_zip_infos(oversized)

    assert MAX_ZIP_ENTRIES > 0
