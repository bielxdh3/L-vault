from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from localvault import db
from localvault.auth import set_password
from localvault.config import ensure_directories
from localvault.disk_clone import (
    ActivitySample,
    CloneService,
    DiskCloneBlocked,
    DiskIdentity,
    EnrollmentStore,
    FakeActivitySampler,
    FakeDiskInventory,
    FakeDiskLifecycle,
    FakeProvider,
    FakeStructuralVerifier,
    PartitionIdentity,
    ProviderResult,
    VerificationResult,
    clone_is_due,
    protected_path_conflicts,
    validate_disk_clone_config,
    within_clone_window,
)
from localvault.disk_clone_ui import CountdownController
from localvault.scheduler import generate_schedule_files
from localvault.viewer import create_app


def _disk(number: int, serial: str, *, system: bool = False, size: int = 1000, mounts=()):
    return DiskIdentity(
        number=number,
        model="Test Disk",
        serial=serial,
        pnp_device_id=f"PNP-{serial}",
        storage_unique_id=f"UID-{serial}",
        physical_id=f"PHY-{serial}",
        bus_type="SATA",
        size_bytes=size,
        partition_style="GPT",
        is_system=system,
        is_boot=system,
        online=not mounts,
        mount_points=tuple(mounts),
        partitions=(PartitionIdentity(1, "efi"), PartitionIdentity(2, "windows")),
    )


def _service(tmp_path: Path, *, provider=None, target_size=1000, activity=None, verifier=None):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    cfg = {"disk_clone": {"enabled": True, "provider": "fake", "countdown_seconds": 0}}
    (p.config / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    source = _disk(0, "SRC-1234", system=True)
    target = _disk(1, "DST-5678", size=target_size)
    EnrollmentStore(root).save(source, target, "fake", "disk_intelligent")
    service = CloneService(
        p,
        inventory=FakeDiskInventory([source, target]),
        provider=provider or FakeProvider(),
        lifecycle=FakeDiskLifecycle(),
        sampler=FakeActivitySampler(activity or ActivitySample(10, 20, 2, 2)),
        verifier=verifier or FakeStructuralVerifier(),
        clock=lambda: datetime(2026, 8, 1, 3, 10, tzinfo=timezone.utc),
        is_admin=lambda: True,
        session_available=lambda: True,
    )
    return service, source, target


def test_identity_matches_after_disk_number_and_mount_change():
    enrolled = _disk(0, "SERIAL-1")
    current = _disk(4, "SERIAL-1", mounts=("X:\\",))
    assert current.matches(enrolled)


def test_weak_bridge_serial_blocks_automatic_identity():
    assert _disk(1, "").identity_strength() == "weak"
    assert not _disk(1, "").matches(_disk(8, ""), require_strong=True)


def test_enrollment_hmac_tamper_is_rejected(tmp_path: Path):
    root = tmp_path / "vault"
    ensure_directories(root)
    store = EnrollmentStore(root)
    store.save(_disk(0, "SRC-1", system=True), _disk(1, "DST-1"), "fake", "disk_intelligent")
    manifest = store.manifest_path.read_text(encoding="utf-8").replace("disk_intelligent", "disk_sector")
    store.manifest_path.write_text(manifest, encoding="utf-8")
    with pytest.raises(DiskCloneBlocked, match="adulterado"):
        store.load()


def test_protected_path_conflict_uses_mount_not_disk_number(tmp_path: Path):
    target = _disk(9, "DST-9", mounts=("E:\\",))
    assert protected_path_conflicts(target, [tmp_path / "file.txt", Path("E:\\LocalVault\\db")]) == ["E:\\LocalVault\\db"]


def test_exact_size_shortfall_blocks_even_when_mode_is_intelligent(tmp_path: Path):
    service, _, _ = _service(tmp_path, target_size=999)
    result = service.preflight(perform_activity=False)
    assert result.state == "blocked_size"


def test_window_and_due_boundaries_are_exact():
    assert within_clone_window(datetime(2026, 8, 1, 3, 0), "03:00", "04:00")
    assert within_clone_window(datetime(2026, 8, 1, 3, 59), "03:00", "04:00")
    assert not within_clone_window(datetime(2026, 8, 1, 4, 0), "03:00", "04:00")
    assert clone_is_due(None, 30, datetime(2026, 8, 1, tzinfo=timezone.utc))


def test_fake_success_records_structure_and_returns_target_offline(tmp_path: Path):
    service, _, _ = _service(tmp_path)
    result = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    assert result["state"] == "success"
    assert result["boot_tested"] is False
    lifecycle = service.lifecycle
    assert lifecycle.offline_calls
    with db.connect(service.p.db) as conn:
        row = conn.execute("SELECT state FROM disk_clone_runs WHERE run_id=?", (result["run_id"],)).fetchone()
        verification = conn.execute("SELECT structurally_verified,boot_tested FROM disk_clone_verifications WHERE run_id=?", (result["run_id"],)).fetchone()
    assert row["state"] == "success"
    assert tuple(verification) == (1, 0)


def test_provider_failure_returns_target_offline_and_keeps_due(tmp_path: Path):
    provider = FakeProvider(result=ProviderResult(False, exit_code=5, reason="fake failure"))
    service, _, _ = _service(tmp_path, provider=provider)
    result = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    assert result["state"] == "failed_provider"
    assert service.lifecycle.offline_calls
    assert service._profile() is None or service._profile().get("last_verified_at") is None


def test_default_config_is_fail_closed_and_interval_is_bounded():
    assert validate_disk_clone_config({})["interval_days"] == 30
    with pytest.raises(DiskCloneBlocked):
        validate_disk_clone_config({"interval_days": 0})


def test_countdown_controller_confirm_and_cancel_are_explicit():
    events = []
    controller = CountdownController(300, on_confirm=lambda: events.append("confirm"), on_cancel=lambda: events.append("cancel"))
    controller.hide()
    assert controller.hidden is True
    assert controller.confirm() == "confirm"
    assert controller.cancel() == "cancel"
    assert events == ["confirm", "cancel"]


def test_pre_feature_database_migrates_clone_tables(tmp_path: Path):
    db_path = tmp_path / "old.sqlite"
    with db.connect(db_path) as conn:
        conn.execute("CREATE TABLE backup_runs (id INTEGER PRIMARY KEY, source TEXT, mode TEXT, started_at TEXT, finished_at TEXT, status TEXT, imported_count INTEGER, skipped_duplicates INTEGER, failed_count INTEGER, storage_added INTEGER, warnings TEXT, report_path TEXT)")
    db.init_db(db_path)
    with db.connect(db_path) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='disk_clone_runs'").fetchone()
        assert conn.execute("PRAGMA table_info(disk_clone_runs)").fetchall()


def test_clone_scheduler_omits_catch_up_only_for_clone(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    files = generate_schedule_files(p)
    install = files.install.read_text(encoding="utf-8")
    assert 'Key="disk_clone"' in install
    assert 'StartWhenAvailable=$false' in install
    assert 'StartWhenAvailable=$true' in install


def test_disk_clone_page_and_actions_keep_authentication_and_csrf(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    set_password(p.root, "password")
    client = TestClient(create_app(p.root))
    assert client.get("/disk-clone", follow_redirects=False).status_code == 303
    assert client.post("/login", data={"password": "password"}, follow_redirects=False).status_code == 303
    assert client.post("/disk-clone/action?action=simulate").status_code == 403
    page = client.get("/disk-clone")
    import re

    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    assert client.post("/disk-clone/action?action=invalid", data={"csrf_token": csrf}).status_code == 400
    assert client.post("/disk-clone/action?action=simulate", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
