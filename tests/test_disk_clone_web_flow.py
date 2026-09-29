from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from localvault import db
from localvault.auth import set_password
from localvault.config import ensure_directories
from localvault.disk_clone import FakeDiskInventory
from localvault.diskgenius_assisted import DiskGeniusNormalProvider
from localvault.viewer import create_app


def _authenticated_client(root: Path, inventory=None, provider=None) -> TestClient:
    p = ensure_directories(root)
    db.init_db(p.db)
    set_password(root, "test-password")
    client = TestClient(create_app(root, disk_inventory=inventory, diskgenius_provider=provider))
    client.post("/login", data={"password": "test-password"})
    return client


def test_normal_clone_page_shows_fixed_diskgenius_roles_without_candidate_or_clonezilla_flow(tmp_path: Path):
    client = _authenticated_client(tmp_path / "normal", FakeDiskInventory([]))
    page = client.get("/disk-clone?refresh=1")
    assert page.status_code == 200
    assert "KINGSTON SNV2S1000G" in page.text
    assert "ST1000VM002-1CT162" in page.text
    assert "HGST HTS541010A9E680" in page.text
    assert "DiskGenius 6.1.1" in page.text
    assert "Clone do sistema" in page.text
    assert "Clonezilla" not in page.text
    assert "BIOS" not in page.text
    assert "/dev/sd" not in page.text


def test_normal_page_does_not_enumerate_disks_until_owner_starts_clone(tmp_path: Path, monkeypatch):
    client = _authenticated_client(tmp_path / "no-refresh", None)

    def forbidden_inventory():
        raise AssertionError("inventory must be resolved at the clone action boundary")

    monkeypatch.setattr("localvault.viewer.WindowsDiskInventory", forbidden_inventory)
    page = client.get("/disk-clone")
    assert page.status_code == 200
    assert "Clone now" in page.text


def test_clone_action_keeps_login_and_csrf_and_never_starts_from_get(tmp_path: Path):
    root = tmp_path / "protected"
    p = ensure_directories(root)
    db.init_db(p.db)
    set_password(root, "test-password")
    provider = DiskGeniusNormalProvider(
        root,
        inventory=FakeDiskInventory([]),
        executable=tmp_path / "missing-DiskGenius.exe",
    )
    client = TestClient(create_app(root, diskgenius_provider=provider))
    assert client.get("/disk-clone", follow_redirects=False).status_code == 303
    client.post("/login", data={"password": "test-password"})
    assert client.get("/disk-clone/launch").status_code == 405
    assert client.post("/disk-clone/launch").status_code == 403
    page = client.get("/disk-clone")
    assert page.status_code == 200
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    # This test host is intentionally not given the authorized inventory; the provider fails closed.
    response = client.post("/disk-clone/launch", data={"csrf_token": csrf}, follow_redirects=False)
    assert response.status_code == 409
    assert "KINGSTON" in response.text
