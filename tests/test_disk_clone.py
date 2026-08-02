from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from localvault import db
from localvault.auth import set_password
from localvault.config import ensure_directories
from localvault.disk_clone import (
    ActivitySample,
    AOMEIProvider,
    CloneService,
    DiskCloneBlocked,
    DiskIdentity,
    EnrollmentStore,
    FakeActivitySampler,
    FakeDiskInventory,
    FakeDiskLifecycle,
    FakeProvider,
    FakeProtectedPathResolver,
    FakeStructuralVerifier,
    DiskGeniusProvider,
    PartitionIdentity,
    ProviderResult,
    VerificationResult,
    WindowsStructuralVerifier,
    clone_is_due,
    protected_path_conflicts,
    validate_disk_clone_config,
    within_clone_window,
    provider_for_config,
)
from localvault.disk_clone_ui import CloneUIController, CountdownController
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


def test_utc_minus_four_wall_clock_window_is_local_and_utc_conversion_would_fail():
    local = timezone(timedelta(hours=-4))
    at_three = datetime(2026, 8, 1, 3, 0, tzinfo=local)
    at_four = datetime(2026, 8, 1, 4, 0, tzinfo=local)
    assert within_clone_window(at_three, "03:00", "04:00")
    assert within_clone_window(datetime(2026, 8, 1, 3, 59, tzinfo=local), "03:00", "04:00")
    assert not within_clone_window(at_four, "03:00", "04:00")
    assert not within_clone_window(at_three.astimezone(timezone.utc), "03:00", "04:00")


def test_simulation_uses_deterministic_local_clock(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("localvault.disk_clone.datetime", datetime)
    result = __import__("localvault.disk_clone", fromlist=["simulate_state_machine"]).simulate_state_machine(tmp_path / "simulation")
    assert result["state"] == "success"


class _SequenceInventory:
    def __init__(self, snapshots):
        self.snapshots = list(snapshots)
        self.calls = 0

    def list_disks(self):
        index = min(self.calls, len(self.snapshots) - 1)
        self.calls += 1
        return list(self.snapshots[index])


def test_disk_number_change_after_countdown_rebuilds_plan_from_identity(tmp_path: Path):
    service, source, target = _service(tmp_path)
    moved_source = _disk(4, source.serial, system=True)
    moved_target = _disk(7, target.serial)
    service.inventory = _SequenceInventory([[source, target], [moved_source, moved_target]])
    result = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    assert result["state"] == "success"
    assert service.provider.plans[-1].source_selector == "4"
    assert service.provider.plans[-1].target_selector == "7"


def test_target_replacement_after_countdown_blocks_provider(tmp_path: Path):
    service, source, target = _service(tmp_path)
    replacement = _disk(7, "REPLACED")
    service.inventory = _SequenceInventory([[source, target], [source, replacement]])
    result = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    assert result["state"] == "blocked_identity"
    assert service.provider.started == 0


def test_fresh_post_provider_inventory_is_used_for_verification(tmp_path: Path):
    service, source, target = _service(tmp_path, verifier=WindowsStructuralVerifier())
    invalid_target = _disk(1, target.serial)
    invalid_target = DiskIdentity.from_dict(invalid_target.to_dict() | {"partitions": [asdict(PartitionIdentity(1, "basic"))]})
    service.inventory = _SequenceInventory([[source, target], [source, target], [source, target], [source, target], [source, invalid_target]])
    result = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    assert result["state"] == "failed_verification"
    assert service._profile() is None or service._profile().get("last_verified_at") is None


def test_protected_path_resolver_uses_physical_identity_even_when_target_is_offline():
    target = _disk(9, "DST-9")
    source = _disk(0, "SRC-0", system=True)
    resolver = FakeProtectedPathResolver({"E:\\LocalVault": target, "C:\\LocalVault": source})
    from localvault.disk_clone import resolved_protected_path_conflicts
    conflicts, _ = resolved_protected_path_conflicts(target, ["E:\\LocalVault"], resolver)
    assert conflicts == ["E:\\LocalVault"]
    conflicts, _ = resolved_protected_path_conflicts(target, ["C:\\LocalVault"], resolver)
    assert conflicts == []


def test_unresolvable_protected_path_blocks_instead_of_guessing():
    target = _disk(9, "DST-9")
    resolver = FakeProtectedPathResolver()
    from localvault.disk_clone import resolved_protected_path_conflicts
    conflicts, resolutions = resolved_protected_path_conflicts(target, ["Z:\\missing"], resolver)
    assert conflicts and not resolutions[0].resolved


def test_partition_roles_use_gpt_guids_and_running_os_volume():
    assert PartitionIdentity.from_dict({"gpt_type": "{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}", "type": "System"}).canonical_role == "efi"
    assert PartitionIdentity.from_dict({"gpt_type": "E3C9E316-0B5C-4DB8-817D-F92DF00215AE", "type": "Reserved"}).canonical_role == "msr"
    assert PartitionIdentity.from_dict({"gpt_type": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "type": "Basic"}).canonical_role == "basic_data"
    assert PartitionIdentity.from_dict({"gpt_type": "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC", "type": "Recovery"}).canonical_role == "recovery"
    assert PartitionIdentity.from_dict({"type": "Localized display string", "is_os_volume": True}).canonical_role == "windows"


def test_mbr_roles_do_not_require_gpt_efi():
    source = _disk(0, "SRC", system=True)
    source = DiskIdentity.from_dict(source.to_dict() | {"partition_style": "MBR", "partitions": [asdict(PartitionIdentity(1, "Active", is_active=True)), asdict(PartitionIdentity(2, "Basic"))]})
    target = _disk(1, "DST")
    target = DiskIdentity.from_dict(target.to_dict() | {"partition_style": "MBR", "partitions": source.to_dict()["partitions"]})
    assert {part.canonical_role for part in source.partitions} == {"active", "basic_data"}
    assert WindowsStructuralVerifier().verify(source, target).structurally_verified


def test_provider_selection_is_configured_and_real_adapters_stay_blocked(monkeypatch):
    assert isinstance(provider_for_config({"provider": "diskgenius"}), DiskGeniusProvider)
    assert isinstance(provider_for_config({"provider": "aomei"}), AOMEIProvider)
    assert not DiskGeniusProvider().validate_capabilities().supported
    monkeypatch.setattr("localvault.disk_clone._find_aomei_executable", lambda: None)
    assert not AOMEIProvider().validate_capabilities().supported
    assert provider_for_config({"provider": "fake"}).validate_capabilities().simulation_only


def test_ui_controller_covers_run_states_hide_restore_error_retry_and_safe_cancel():
    events = []
    controller = CloneUIController(2, on_confirm=lambda: events.append("confirm"), on_cancel=lambda: events.append("cancel"))
    assert controller.tick() == "countdown"
    controller.hide(); controller.restore()
    assert controller.hidden is False
    assert controller.tick() == "countdown"
    assert controller.tick() == "confirm"
    controller.progress({"progress_type": "estimated", "percent": 40, "phase": "cloning"})
    assert controller.cancel() == "unsupported_cancel"
    controller.error("provider failed")
    assert controller.retry() == "retry"
    assert events == ["confirm"]


def test_ui_controller_consumes_durable_progress_and_error_states():
    controller = CloneUIController(0, on_confirm=lambda: None, on_cancel=lambda: None)
    assert controller.apply_durable_state("cloning", progress={"progress_type": "exact", "percent": 25, "phase": "copying"}) == "cloning"
    assert controller.state.percent == 25
    assert controller.apply_durable_state("failed_verification", reason="fresh target invalid") == "error"
    assert controller.state.error == "fresh target invalid"


def test_explicit_retry_creates_a_new_linked_run(tmp_path: Path):
    provider = FakeProvider(result=ProviderResult(False, exit_code=5, reason="first attempt failed"))
    service, _, _ = _service(tmp_path, provider=provider)
    first = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    provider.result = ProviderResult(False, exit_code=6, reason="second attempt failed")
    second = service.retry(first["run_id"], countdown=lambda _: "confirm", simulation=True)
    assert second["run_id"] != first["run_id"]
    with db.connect(service.p.db) as conn:
        row = conn.execute("SELECT trigger_type,parent_run_id FROM disk_clone_runs WHERE run_id=?", (second["run_id"],)).fetchone()
    assert tuple(row) == ("retry", first["run_id"])


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


def test_primary_failure_is_preserved_when_offline_cleanup_also_fails(tmp_path: Path):
    class FailingCleanup(FakeDiskLifecycle):
        def set_offline(self, disk):
            super().set_offline(disk)
            raise RuntimeError("offline cleanup failed")

    provider = FakeProvider(result=ProviderResult(False, exit_code=5, reason="provider failed"))
    service, _, _ = _service(tmp_path, provider=provider)
    service.lifecycle = FailingCleanup()
    result = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    assert result["state"] == "failed_offline_cleanup"
    with db.connect(service.p.db) as conn:
        row = conn.execute("SELECT state,primary_failure_state,primary_failure_reason,cleanup_failure_reason FROM disk_clone_runs WHERE run_id=?", (result["run_id"],)).fetchone()
    assert tuple(row) == ("failed_offline_cleanup", "failed_provider", "provider failed", "offline cleanup failed")


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
