from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from localvault import db
from localvault.auth import set_password
from localvault.config import ensure_directories
from localvault.viewer import create_app


class FakeDataCloneProvider:
    def __init__(self):
        self.launch_calls: list[str] = []
        self.cancel_calls = 0
        self.recovery_calls = 0
        self.vss_recovery_required = False
        self.state = "ready"

    def preflight(self):
        return {"ready": True}

    def launch(self, *, confirmation: str):
        self.launch_calls.append(confirmation)
        self.state = "copy"
        return self.monitor()

    def cancel(self):
        self.cancel_calls += 1
        self.state = "cancelling"
        return self.monitor()

    def recover_vss(self):
        self.recovery_calls += 1
        self.vss_recovery_required = False
        return self.monitor()

    def monitor(self):
        return {
            "state": self.state,
            "phase": "COPY" if self.state == "copy" else "PRECHECK",
            "source": {"model": "spoofed", "serial": "RAW-SOURCE-SERIAL", "disk_number": 88, "volume_labels": ["C:"]},
            "target": {"model": "spoofed", "serial": "RAW-TARGET-SERIAL", "identity_sha256": "secret-hash"},
            "protected": {"model": "spoofed", "unique_id": "5000CC8AD6DC50FE"},
            "progress": {"files": 3, "bytes": 1200, "expected_files": 10, "expected_bytes": 2400, "current_volume": "\\\\?\\Volume{secret-guid}\\"},
            "target_destroyed": self.state in {"copy", "cancelling"},
            "vss_recovery_required": self.vss_recovery_required,
            "snapshot_id": "secret-snapshot-id",
            "target_volume": {"volume_guid": "secret-target-volume"},
            "result": {
                "verified": False,
                "file_count": 10,
                "logical_bytes": 2400,
                "exclusions": [{"path": "C:\\Users\\owner\\private.txt"}],
                "metadata_limits": ["C:\\Users\\owner\\private.txt", "NTFS hard-link relationships are copied as independent files."],
                "content_hash_samples": [{"path": "C:\\Users\\owner\\private.txt", "sha256": "private-digest"}],
            },
            "error": "\\\\?\\Volume{secret-guid}\\ C:\\Users\\owner\\private.txt",
        }


def _authenticated_client(root: Path, provider: FakeDataCloneProvider | None = None) -> TestClient:
    p = ensure_directories(root)
    db.init_db(p.db)
    set_password(root, "test-password")
    client = TestClient(create_app(root, data_clone_provider=provider or FakeDataCloneProvider()))
    client.post("/login", data={"password": "test-password"})
    return client


def _csrf(page: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert match
    return match.group(1)


def test_normal_clone_page_shows_first_party_roles_and_no_external_clone_flow(tmp_path: Path):
    provider = FakeDataCloneProvider()
    client = _authenticated_client(tmp_path / "normal", provider)
    page = client.get("/disk-clone?refresh=1")
    assert page.status_code == 200
    assert "KINGSTON SNV2S1000G" in page.text
    assert "****775." in page.text
    assert "ST1000VM002-1CT162" in page.text
    assert "****4EM2" in page.text
    assert "HGST HTS541010A9E680" in page.text
    assert "****91NS" in page.text
    assert "L-vault Data Clone" in page.text
    assert "Bootable" in page.text and "No · this is a data clone" in page.text
    assert "ALL DATA ON TARGET WILL BE ERASED" in page.text
    assert "Clone now" in page.text
    assert "DiskGenius" not in page.text
    assert "Clonezilla" not in page.text
    assert "BIOS" not in page.text
    assert "/dev/sd" not in page.text
    assert provider.launch_calls == []
    assert provider.cancel_calls == 0


def test_get_only_performs_read_only_preflight_and_monitor(tmp_path: Path):
    provider = FakeDataCloneProvider()
    client = _authenticated_client(tmp_path / "get", provider)
    page = client.get("/disk-clone")
    assert page.status_code == 200
    assert provider.launch_calls == []
    assert provider.cancel_calls == 0


def test_clone_start_requires_auth_csrf_and_exact_typed_confirmation(tmp_path: Path):
    root = tmp_path / "auth"
    p = ensure_directories(root)
    db.init_db(p.db)
    set_password(root, "test-password")
    provider = FakeDataCloneProvider()
    client = TestClient(create_app(root, data_clone_provider=provider))

    assert client.get("/disk-clone", follow_redirects=False).status_code == 303
    assert client.post("/disk-clone/start", data={"confirmation": "CLONE"}).status_code == 401
    client.post("/login", data={"password": "test-password"})
    page = client.get("/disk-clone")
    csrf = _csrf(page.text)

    assert client.post("/disk-clone/start", data={"confirmation": "CLONE"}).status_code == 403
    invalid = client.post("/disk-clone/start", data={"confirmation": "clone", "csrf_token": csrf})
    assert invalid.status_code == 400
    assert provider.launch_calls == []

    started = client.post("/disk-clone/start", data={"confirmation": "CLONE", "csrf_token": csrf})
    assert started.status_code == 202
    assert provider.launch_calls == ["CLONE"]
    assert started.json()["state"] == "copy"


def test_status_is_authenticated_and_does_not_expose_worker_identity_or_paths(tmp_path: Path):
    root = tmp_path / "privacy"
    p = ensure_directories(root)
    db.init_db(p.db)
    set_password(root, "test-password")
    provider = FakeDataCloneProvider()
    client = TestClient(create_app(root, data_clone_provider=provider))

    assert client.get("/disk-clone/status", follow_redirects=False).status_code == 303
    client.post("/login", data={"password": "test-password"})
    response = client.get("/disk-clone/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["source"]["model"] == "KINGSTON SNV2S1000G"
    assert payload["target"]["model"] == "ST1000VM002-1CT162"
    assert payload["protected"]["model"] == "HGST HTS541010A9E680"
    assert payload["progress"] == {"files": 3, "bytes": 1200, "expected_files": 10, "expected_bytes": 2400}
    body = response.text
    for private_value in (
        "RAW-SOURCE-SERIAL", "RAW-TARGET-SERIAL", "secret-hash", "secret-guid", "secret-snapshot-id",
        "secret-target-volume", "C:\\Users\\owner", "private-digest", "current_volume", "disk_number", "identity_sha256",
    ):
        assert private_value not in body
    assert payload["result"]["metadata_limits"] == ["NTFS hard-link relationships are copied as independent files."]


def test_cancel_uses_authenticated_csrf_protected_post(tmp_path: Path):
    root = tmp_path / "cancel"
    p = ensure_directories(root)
    db.init_db(p.db)
    set_password(root, "test-password")
    provider = FakeDataCloneProvider()
    provider.state = "copy"
    client = TestClient(create_app(root, data_clone_provider=provider))
    client.post("/login", data={"password": "test-password"})
    page = client.get("/disk-clone")

    assert client.post("/disk-clone/cancel").status_code == 403
    response = client.post("/disk-clone/cancel", data={"csrf_token": _csrf(page.text)})
    assert response.status_code == 202
    assert provider.cancel_calls == 1
    assert response.json()["state"] == "cancelling"


def test_interrupted_vss_cleanup_is_available_inside_l_vault(tmp_path: Path):
    root = tmp_path / "recover-vss"
    provider = FakeDataCloneProvider()
    provider.state = "failed"
    provider.vss_recovery_required = True
    client = _authenticated_client(root, provider)
    page = client.get("/disk-clone")
    assert page.status_code == 200
    assert "Clean up interrupted snapshot" in page.text
    assert 'id="clone-vss-recovery"' in page.text

    response = client.post("/disk-clone/recover-vss", data={"csrf_token": _csrf(page.text)})
    assert response.status_code == 202
    assert provider.recovery_calls == 1
    assert response.json()["vss_recovery_required"] is False
