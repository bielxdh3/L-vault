from __future__ import annotations

import re
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from localvault import db
from localvault.auth import set_password
from localvault.config import ensure_directories, load_config
from localvault.disk_clone import DiskIdentity, EnrollmentStore, FakeDiskInventory, PartitionIdentity
from localvault.viewer import create_app


def _disk(number: int, serial: str, *, system: bool = False, size: int = 2000) -> DiskIdentity:
    return DiskIdentity(
        number=number,
        model="Synthetic Disk",
        serial=serial,
        pnp_device_id=f"PNP-{serial}",
        storage_unique_id=f"UID-{serial}",
        runtime_selector=rf"\\.\PHYSICALDRIVE{number}",
        bus_type="SATA",
        size_bytes=size,
        partition_style="GPT",
        is_system=system,
        is_boot=system,
        partitions=(PartitionIdentity(1, "efi"), PartitionIdentity(2, "windows")),
    )


def test_disk_clone_form_enrolls_target_and_persists_enabled_interval(tmp_path: Path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    set_password(root, "test-password")
    (p.config / "config.yaml").write_text(yaml.safe_dump({"disk_clone": {"provider": "fake", "enabled": False}}), encoding="utf-8")
    source, target = _disk(0, "SOURCE-1234", system=True), _disk(1, "TARGET-5678", size=2200)
    client = TestClient(create_app(root, disk_inventory=FakeDiskInventory([source, target])))
    client.post("/login", data={"password": "test-password"})

    page = client.get("/disk-clone")
    assert page.status_code == 200
    assert target.masked_serial in page.text
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    enrolled = client.post(
        "/disk-clone/enroll",
        data={"csrf_token": csrf, "target_number": str(target.number), "confirmation": target.confirmation_phrase()},
        follow_redirects=False,
    )
    assert enrolled.status_code == 303
    assert EnrollmentStore(root).load() is not None

    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/disk-clone").text).group(1)
    disabled = client.post("/disk-clone/settings", data={"csrf_token": csrf, "interval_days": "14", "enabled": "false"}, follow_redirects=False)
    assert disabled.status_code == 303
    assert load_config(root)["disk_clone"]["interval_days"] == 14
    assert load_config(root)["disk_clone"]["enabled"] is False

    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/disk-clone").text).group(1)
    enabled = client.post("/disk-clone/settings", data={"csrf_token": csrf, "interval_days": "21", "enabled": "true"}, follow_redirects=False)
    assert enabled.status_code == 303
    saved = load_config(root)["disk_clone"]
    assert saved["interval_days"] == 21
    assert saved["enabled"] is True
