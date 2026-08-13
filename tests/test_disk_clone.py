from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path

import pytest
import typer
import yaml
from fastapi.testclient import TestClient

from localvault import db
from localvault.auth import set_password
from localvault.cli import _enroll_disk_clone, app
from localvault.config import ensure_directories, load_config
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
    _source_paths,
    protected_path_conflicts,
    validate_disk_clone_config,
    validated_disk_clone_config,
    within_clone_window,
    provider_for_config,
    DiskCloneConfigError,
    canonical_json,
    claim_control_request,
    claim_monitor_owner,
    create_control_request,
    release_monitor_owner,
    active_clone_run_id,
)
from localvault.disk_clone_ui import CloneUIController, CountdownController, _hide_window, _restore_window
from localvault.offline_clone import simulate_offline_round_trip
from localvault.scheduler import generate_schedule_files
from localvault.viewer import create_app
from localvault.health import health_snapshot
from typer.testing import CliRunner

runner = CliRunner()


def _disk(number: int, serial: str, *, system: bool = False, size: int = 1000, mounts=()):
    return DiskIdentity(
        number=number,
        model="Test Disk",
        serial=serial,
        pnp_device_id=f"PNP-{serial}",
        storage_unique_id=f"UID-{serial}",
        runtime_selector=rf"\\.\PHYSICALDRIVE{number}",
        bus_type="SATA",
        size_bytes=size,
        partition_style="GPT",
        is_system=system,
        is_boot=system,
        online=not mounts,
        mount_points=tuple(mounts),
        partitions=(PartitionIdentity(1, "efi"), PartitionIdentity(2, "windows")),
    )


def _service(tmp_path: Path, *, provider=None, target_size=1000, activity=None, verifier=None, clock=None):
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
        clock=clock or (lambda: datetime(2026, 8, 1, 3, 10, tzinfo=timezone.utc)),
        is_admin=lambda: True,
        session_available=lambda: True,
    )
    return service, source, target


def test_identity_matches_after_disk_number_and_mount_change():
    enrolled = _disk(0, "SERIAL-1")
    current = _disk(4, "SERIAL-1", mounts=("X:\\",))
    assert current.runtime_selector != enrolled.runtime_selector
    assert current.matches(enrolled)


def test_enrollment_confirmation_binds_exact_capacity_and_masked_serial():
    disk = _disk(1, "DST-123456")
    phrase = disk.confirmation_phrase()
    assert phrase == "APAGAR Test Disk 1000 ****3456"
    assert disk.serial not in phrase
    assert "1000" in phrase


@pytest.mark.parametrize("field", ["serial", "pnp_device_id", "storage_unique_id"])
def test_persistent_identity_change_blocks_matching(field):
    enrolled = _disk(0, "SERIAL-1")
    current = DiskIdentity.from_dict(enrolled.to_dict() | {field: f"CHANGED-{field}"})
    assert not current.matches(enrolled)


def test_weak_bridge_serial_blocks_automatic_identity():
    assert _disk(1, "").identity_strength() == "weak"
    assert not _disk(1, "").matches(_disk(8, ""), require_strong=True)


def test_weak_usb_bridge_identity_is_blocked():
    usb = DiskIdentity.from_dict(_disk(1, "USB-SERIAL").to_dict() | {"bus_type": "USB", "storage_unique_id": ""})
    assert usb.identity_strength() == "weak"


def test_enrollment_hmac_tamper_is_rejected(tmp_path: Path):
    root = tmp_path / "vault"
    ensure_directories(root)
    store = EnrollmentStore(root)
    store.save(_disk(0, "SRC-1", system=True), _disk(1, "DST-1"), "fake", "disk_intelligent")
    manifest = store.manifest_path.read_text(encoding="utf-8").replace("disk_intelligent", "disk_sector")
    store.manifest_path.write_text(manifest, encoding="utf-8")
    with pytest.raises(DiskCloneBlocked, match="adulterado"):
        store.load()


def test_enrollment_manifest_signs_persistent_identity_only(tmp_path: Path):
    root = tmp_path / "vault"
    ensure_directories(root)
    store = EnrollmentStore(root)
    store.save(_disk(0, "SRC-1", system=True), _disk(1, "DST-1"), "fake", "disk_intelligent")
    payload = json.loads(store.manifest_path.read_text(encoding="utf-8"))["payload"]
    assert "number" not in payload["source"]
    assert "runtime_selector" not in payload["source"]
    assert "signature" not in payload["target"]


def test_old_enrollment_schema_requires_reenrollment(tmp_path: Path):
    root = tmp_path / "vault"
    ensure_directories(root)
    store = EnrollmentStore(root)
    store.save(_disk(0, "SRC-1", system=True), _disk(1, "DST-1"), "fake", "disk_intelligent")
    signed = json.loads(store.manifest_path.read_text(encoding="utf-8"))
    signed["payload"]["schema"] = 1
    signed["hmac"] = hmac.new(store.secret_path.read_bytes(), canonical_json(signed["payload"]), hashlib.sha256).hexdigest()
    store.manifest_path.write_text(json.dumps(signed), encoding="utf-8")
    with pytest.raises(DiskCloneBlocked) as exc:
        store.load()
    assert exc.value.state == "re_enrollment_required"


def test_reenrollment_required_run_is_terminal_and_fail_closed(tmp_path: Path):
    current = [datetime(2026, 8, 1, 3, 10, tzinfo=timezone.utc)]
    service, _, _ = _service(tmp_path, clock=lambda: current[0])
    signed = json.loads(service.enrollment.manifest_path.read_text(encoding="utf-8"))
    signed["payload"]["schema"] = 1
    signed["hmac"] = hmac.new(service.enrollment.secret_path.read_bytes(), canonical_json(signed["payload"]), hashlib.sha256).hexdigest()
    service.enrollment.manifest_path.write_text(json.dumps(signed), encoding="utf-8")

    result = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)

    assert result["state"] == "re_enrollment_required"
    assert active_clone_run_id(service.p.db) is None
    assert service.retry(result["run_id"])["state"] == "retry_rejected"
    assert service.provider.started == 0
    assert service.lifecycle.online_calls == []
    assert service.lifecycle.offline_calls == []

    current[0] = datetime(2026, 8, 2, 3, 10, tzinfo=timezone.utc)
    assert service.reconcile_interrupted() == 0
    with db.connect(service.p.db) as conn:
        row = conn.execute("SELECT state FROM disk_clone_runs WHERE run_id=?", (result["run_id"],)).fetchone()
    assert row["state"] == "re_enrollment_required"


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


def test_countdown_crossing_window_never_starts_provider_or_brings_target_online(tmp_path: Path):
    current = [datetime(2026, 8, 1, 3, 59, tzinfo=timezone(timedelta(hours=-4)))]
    provider = FakeProvider()
    service, _, _ = _service(tmp_path, provider=provider, clock=lambda: current[0])
    result = service.execute(trigger="simulation", countdown=lambda _: (current.__setitem__(0, datetime(2026, 8, 1, 4, 0, tzinfo=current[0].tzinfo)) or "confirm"), simulation=True)
    assert result["state"] == "skipped_window_expired_before_start"
    assert provider.started == 0
    assert service.lifecycle.online_calls == []
    with db.connect(service.p.db) as conn:
        row = conn.execute("SELECT start_window_local_time,start_window_timezone,start_window_decision FROM disk_clone_runs WHERE run_id=?", (result["run_id"],)).fetchone()
    assert datetime.fromisoformat(row["start_window_local_time"]).tzinfo is not None
    assert "-04:00" in row["start_window_timezone"]
    assert row["start_window_decision"] == "deferred"


def test_final_start_check_at_last_second_starts_provider(tmp_path: Path):
    now = datetime(2026, 8, 1, 3, 59, 59, tzinfo=timezone.utc)
    service, _, _ = _service(tmp_path, clock=lambda: now)
    result = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    assert result["state"] == "success"
    assert service.provider.started == 1


def test_provider_started_inside_window_is_not_cancelled_after_window_ends(tmp_path: Path):
    current = [datetime(2026, 8, 1, 3, 59, 59, tzinfo=timezone.utc)]

    class Provider(FakeProvider):
        def start(self, plan, event_sink=None):
            result = super().start(plan, event_sink)
            current[0] = datetime(2026, 8, 1, 4, 1, tzinfo=timezone.utc)
            return result

    service, _, _ = _service(tmp_path, provider=Provider(), clock=lambda: current[0])
    result = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    assert result["state"] == "success"


def test_window_expiration_does_not_advance_due_or_create_same_night_retry(tmp_path: Path):
    current = [datetime(2026, 8, 1, 3, 59, tzinfo=timezone.utc)]
    service, _, _ = _service(tmp_path, clock=lambda: current[0])
    with db.connect(service.p.db) as conn:
        conn.execute("INSERT INTO disk_clone_profile(id,last_verified_at,next_due_at,provider) VALUES(1,?,?,?)", ("2026-07-01T03:00:00+00:00", "2026-08-01T03:00:00+00:00", "fake"))
    result = service.execute(trigger="simulation", countdown=lambda _: (current.__setitem__(0, datetime(2026, 8, 1, 4, 0, tzinfo=timezone.utc)) or "confirm"), simulation=True)
    with db.connect(service.p.db) as conn:
        profile = conn.execute("SELECT next_due_at FROM disk_clone_profile WHERE id=1").fetchone()
        runs = conn.execute("SELECT COUNT(*) AS count FROM disk_clone_runs").fetchone()
    assert result["state"] == "skipped_window_expired_before_start"
    assert profile["next_due_at"] == "2026-08-01T03:00:00+00:00"
    assert runs["count"] == 1


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


class _SequenceResolver:
    def __init__(self, mappings):
        self.mappings = list(mappings)
        self.calls = 0

    def resolve(self, protected_paths):
        index = min(self.calls, len(self.mappings) - 1)
        self.calls += 1
        return FakeProtectedPathResolver(self.mappings[index]).resolve(protected_paths)


class _Prompt:
    def __init__(self, values):
        self.values = list(values)
        self.calls = []

    def __call__(self, message, **kwargs):
        self.calls.append((message, kwargs))
        return self.values.pop(0)


class _RecordingLifecycle(FakeDiskLifecycle):
    def __init__(self, events):
        super().__init__()
        self.events = events
        self.last_offline = None

    def set_offline(self, disk):
        self.events.append("offline")
        self.last_offline = disk
        super().set_offline(disk)


class _RecordingEnrollmentStore:
    def __init__(self, root, events):
        self.delegate = EnrollmentStore(root)
        self.events = events
        self.calls = []

    def save(self, source, target, provider, mode):
        self.events.append("save")
        self.calls.append((source, target, provider, mode))
        return self.delegate.save(source, target, provider, mode)


def _enrollment_context(tmp_path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    protected = p.root / "protected-data"
    (p.config / "config.yaml").write_text(
        yaml.safe_dump({"disk_clone": {"enabled": True, "provider": "fake", "protected_paths": [str(protected)]}}),
        encoding="utf-8",
    )
    source = _disk(0, "SRC-ENROLL", system=True)
    target = _disk(1, "DST-ENROLL")
    return p, source, target, protected


def _protected_mapping(p, protected, default_disk, protected_disk=None, *, omit=False):
    mapping = {str(path): default_disk for path in _source_paths(p, load_config(p.root))}
    if omit:
        mapping.pop(str(protected), None)
    else:
        mapping[str(protected)] = protected_disk or default_disk
    return mapping


def _enrollment_components(p, snapshots, resolver_mappings, prompt_values):
    events = []
    inventory = _SequenceInventory(snapshots)
    resolver = _SequenceResolver([resolver_mappings[0]] * len(snapshots[0]) + resolver_mappings[1:])
    lifecycle = _RecordingLifecycle(events)
    store = _RecordingEnrollmentStore(p.root, events)
    prompt = _Prompt(prompt_values)
    return inventory, resolver, lifecycle, store, prompt, events


def test_enrollment_protected_target_after_refresh_blocks_before_confirmation(tmp_path):
    p, source, target, protected = _enrollment_context(tmp_path)
    mapping = _protected_mapping(p, protected, source, target)
    prompt = _Prompt([1, target.confirmation_phrase()])
    inventory = _SequenceInventory([[source, target], [source, target]])
    lifecycle = _RecordingLifecycle([])
    store = _RecordingEnrollmentStore(p.root, [])

    with pytest.raises(typer.BadParameter, match="dados protegidos"):
        _enroll_disk_clone(p, FakeProvider(), inventory=inventory, resolver=_SequenceResolver([mapping, mapping, mapping, mapping]), lifecycle=lifecycle, store=store, prompt=prompt)

    assert len(prompt.calls) == 1
    assert inventory.calls == 2
    assert lifecycle.offline_calls == []
    assert store.calls == []


def test_enrollment_conflict_appearing_after_confirmation_blocks_without_mutation(tmp_path):
    p, source, target, protected = _enrollment_context(tmp_path)
    safe = _protected_mapping(p, protected, source)
    conflict = _protected_mapping(p, protected, source, target)
    events = []
    inventory = _SequenceInventory([[source, target], [source, target], [source, target]])
    lifecycle = _RecordingLifecycle(events)
    store = _RecordingEnrollmentStore(p.root, events)
    prompt = _Prompt([1, target.confirmation_phrase()])

    with pytest.raises(typer.BadParameter, match="dados protegidos"):
        _enroll_disk_clone(
            p,
            FakeProvider(),
            inventory=inventory,
            resolver=_SequenceResolver([safe, safe, safe, conflict]),
            lifecycle=lifecycle,
            store=store,
            prompt=prompt,
        )

    assert len(prompt.calls) == 2
    assert inventory.calls == 3
    assert lifecycle.offline_calls == []
    assert store.calls == []
    assert events == []


@pytest.mark.parametrize("resolver_mode", ["unresolved", "ambiguous"])
def test_enrollment_unresolved_or_ambiguous_protected_path_blocks(tmp_path, resolver_mode):
    p, source, target, protected = _enrollment_context(tmp_path)
    protected_disk = _disk(2, "PROTECTED-ENROLL")
    duplicate = _disk(3, "PROTECTED-ENROLL")
    disks = [source, target] if resolver_mode == "unresolved" else [source, target, protected_disk, duplicate]
    mapping = _protected_mapping(p, protected, source, protected_disk if resolver_mode == "ambiguous" else None, omit=resolver_mode == "unresolved")
    inventory, resolver, lifecycle, store, prompt, events = _enrollment_components(
        p,
        [disks, disks],
        [mapping, mapping],
        [1, target.confirmation_phrase()],
    )

    with pytest.raises(typer.BadParameter, match="dados protegidos"):
        _enroll_disk_clone(p, FakeProvider(), inventory=inventory, resolver=resolver, lifecycle=lifecycle, store=store, prompt=prompt)

    assert len(prompt.calls) == 1
    assert lifecycle.offline_calls == []
    assert store.calls == []
    assert events == []


def test_enrollment_disk_number_change_during_confirmation_is_safe(tmp_path):
    p, source, target, protected = _enrollment_context(tmp_path)
    refreshed_source = _disk(4, source.serial, system=True)
    refreshed_target = _disk(7, target.serial)
    final_source = _disk(5, source.serial, system=True)
    final_target = _disk(8, target.serial)
    mapping = _protected_mapping(p, protected, source)
    inventory, resolver, lifecycle, store, prompt, events = _enrollment_components(
        p,
        [[source, target], [refreshed_source, refreshed_target], [final_source, final_target]],
        [mapping, mapping],
        [1, refreshed_target.confirmation_phrase()],
    )

    _enroll_disk_clone(p, FakeProvider(), inventory=inventory, resolver=resolver, lifecycle=lifecycle, store=store, prompt=prompt)

    assert lifecycle.offline_calls == [8]
    assert store.calls and store.calls[0][1].number == 8
    assert events == ["offline", "save"]


@pytest.mark.parametrize("change", ["serial", "capacity", "model", "duplicate", "missing", "critical"])
def test_enrollment_identity_or_critical_change_during_confirmation_blocks(tmp_path, change):
    p, source, target, protected = _enrollment_context(tmp_path)
    refreshed_target = _disk(7, target.serial)
    if change == "serial":
        final_disks = [source, _disk(8, "CHANGED-ENROLL")]
    elif change == "capacity":
        final_disks = [source, _disk(8, target.serial, size=1001)]
    elif change == "model":
        final_disks = [source, DiskIdentity.from_dict(_disk(8, target.serial).to_dict() | {"model": "Different Disk"})]
    elif change == "duplicate":
        final_disks = [source, _disk(8, target.serial), _disk(9, target.serial)]
    elif change == "missing":
        final_disks = [source]
    else:
        final_disks = [source, _disk(8, target.serial, system=True)]
    mapping = _protected_mapping(p, protected, source)
    inventory, resolver, lifecycle, store, prompt, events = _enrollment_components(
        p,
        [[source, target], [source, refreshed_target], final_disks],
        [mapping, mapping],
        [1, refreshed_target.confirmation_phrase()],
    )

    with pytest.raises(typer.BadParameter):
        _enroll_disk_clone(p, FakeProvider(), inventory=inventory, resolver=resolver, lifecycle=lifecycle, store=store, prompt=prompt)

    assert len(prompt.calls) == 2
    assert inventory.calls == 3
    assert lifecycle.offline_calls == []
    assert store.calls == []
    assert events == []


def test_enrollment_incorrect_confirmation_phrase_never_rechecks_or_mutates(tmp_path):
    p, source, target, protected = _enrollment_context(tmp_path)
    mapping = _protected_mapping(p, protected, source)
    inventory, resolver, lifecycle, store, prompt, events = _enrollment_components(
        p,
        [[source, target], [source, target], [source, target]],
        [mapping, mapping],
        [1, "APAGAR errado"],
    )

    with pytest.raises(typer.BadParameter, match="Confirmacao destrutiva incorreta"):
        _enroll_disk_clone(p, FakeProvider(), inventory=inventory, resolver=resolver, lifecycle=lifecycle, store=store, prompt=prompt)

    assert inventory.calls == 2
    assert lifecycle.offline_calls == []
    assert store.calls == []
    assert events == []


def test_enrollment_safe_fake_success_offlines_final_target_before_saving(tmp_path):
    p, source, target, protected = _enrollment_context(tmp_path)
    refreshed_source = _disk(4, source.serial, system=True)
    refreshed_target = _disk(7, target.serial)
    mapping = _protected_mapping(p, protected, source)
    provider = FakeProvider()
    inventory, resolver, lifecycle, store, prompt, events = _enrollment_components(
        p,
        [[source, target], [refreshed_source, refreshed_target], [refreshed_source, refreshed_target], [refreshed_source, refreshed_target]],
        [mapping, mapping, mapping, mapping],
        [1, refreshed_target.confirmation_phrase()],
    )

    _enroll_disk_clone(p, provider, inventory=inventory, resolver=resolver, lifecycle=lifecycle, store=store, prompt=prompt)

    assert provider.started == 0
    assert inventory.calls == 4
    assert lifecycle.offline_calls == [7]
    assert store.calls and store.calls[0][1].number == 7
    assert events == ["offline", "save"]
    assert store.delegate.manifest_path.exists()


@pytest.mark.parametrize("post_state", ["conflict", "unresolved", "ambiguous", "missing", "identity"])
def test_enrollment_post_transition_recheck_blocks_without_saving_or_provider(tmp_path, post_state):
    p, source, target, protected = _enrollment_context(tmp_path)
    safe = _protected_mapping(p, protected, source)
    protected_disk = _disk(2, "PROTECTED-POST")
    duplicate = _disk(3, "PROTECTED-POST")
    post_disks = [source, target]
    post_mapping = safe
    if post_state == "conflict":
        post_mapping = _protected_mapping(p, protected, source, target)
    elif post_state == "unresolved":
        post_mapping = _protected_mapping(p, protected, source, omit=True)
    elif post_state == "ambiguous":
        post_disks += [protected_disk, duplicate]
        post_mapping = _protected_mapping(p, protected, source, protected_disk)
    elif post_state == "missing":
        post_disks = [source]
    elif post_state == "identity":
        post_disks = [source, _disk(1, "CHANGED-POST")]

    provider = FakeProvider()
    inventory, resolver, lifecycle, store, prompt, events = _enrollment_components(
        p,
        [[source, target], [source, target], [source, target], post_disks],
        [safe, safe, safe, post_mapping],
        [1, target.confirmation_phrase()],
    )

    with pytest.raises(typer.BadParameter):
        _enroll_disk_clone(p, provider, inventory=inventory, resolver=resolver, lifecycle=lifecycle, store=store, prompt=prompt)

    assert inventory.calls == 4
    assert lifecycle.offline_calls == [1]
    assert provider.started == 0
    assert provider.plans == []
    assert store.calls == []
    assert events == ["offline"]
    assert not store.delegate.manifest_path.exists()


def test_enrollment_unsupported_provider_blocks_before_target_authorization(tmp_path):
    p, source, target, protected = _enrollment_context(tmp_path)
    mapping = _protected_mapping(p, protected, source)
    inventory, resolver, lifecycle, store, prompt, events = _enrollment_components(
        p,
        [[source, target]],
        [mapping],
        [1, target.confirmation_phrase()],
    )

    with pytest.raises(typer.BadParameter, match="Inscricao bloqueada"):
        _enroll_disk_clone(p, DiskGeniusProvider(), inventory=inventory, resolver=resolver, lifecycle=lifecycle, store=store, prompt=prompt)

    assert inventory.calls == 0
    assert prompt.calls == []
    assert lifecycle.offline_calls == []
    assert store.calls == []
    assert events == []


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


def test_duplicate_persistent_target_matches_block_execution(tmp_path: Path):
    service, source, target = _service(tmp_path)
    duplicate = DiskIdentity.from_dict(target.to_dict() | {"number": 7, "runtime_selector": r"\\.\PHYSICALDRIVE7"})
    service.inventory = FakeDiskInventory([source, target, duplicate])
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


def _gpt_disk(number, serial, partitions, *, system=False):
    disk = _disk(number, serial, system=system)
    return DiskIdentity.from_dict(disk.to_dict() | {"partitions": [asdict(part) for part in partitions]})


def test_gpt_windows_source_matches_basic_data_target():
    efi = PartitionIdentity(1, "", 100 * 1024 * 1024, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
    msr = PartitionIdentity(2, "", 16 * 1024 * 1024, "E3C9E316-0B5C-4DB8-817D-F92DF00215AE")
    source_os = PartitionIdentity(3, "", 500 * 1024 * 1024, "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", is_os_volume=True, filesystem="NTFS")
    recovery = PartitionIdentity(4, "", 50 * 1024 * 1024, "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC")
    target_os = PartitionIdentity(3, "", source_os.size_bytes, source_os.gpt_type, filesystem="NTFS")
    source = _gpt_disk(0, "SRC-GPT", [efi, msr, source_os, recovery], system=True)
    target = _gpt_disk(1, "DST-GPT", [efi, msr, target_os, recovery])
    result = WindowsStructuralVerifier().verify(source, target)
    assert result.structurally_verified
    assert result.boot_tested is False


def test_gpt_missing_required_roles_or_material_size_fails():
    efi = PartitionIdentity(1, "", 100 * 1024 * 1024, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
    msr = PartitionIdentity(2, "", 16 * 1024 * 1024, "E3C9E316-0B5C-4DB8-817D-F92DF00215AE")
    source_os = PartitionIdentity(3, "", 500 * 1024 * 1024, "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", is_os_volume=True)
    recovery = PartitionIdentity(4, "", 50 * 1024 * 1024, "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC")
    source = _gpt_disk(0, "SRC-GPT", [efi, msr, source_os, recovery], system=True)
    assert not WindowsStructuralVerifier().verify(source, _gpt_disk(1, "DST-GPT", [msr, source_os, recovery])).structurally_verified
    assert not WindowsStructuralVerifier().verify(source, _gpt_disk(1, "DST-GPT", [efi, source_os, recovery])).structurally_verified
    assert not WindowsStructuralVerifier().verify(source, _gpt_disk(1, "DST-GPT", [efi, msr, source_os])).structurally_verified
    wrong_size = PartitionIdentity(3, "", 200 * 1024 * 1024, source_os.gpt_type, is_os_volume=False)
    assert not WindowsStructuralVerifier().verify(source, _gpt_disk(1, "DST-GPT", [efi, msr, wrong_size, recovery])).structurally_verified


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


@pytest.mark.parametrize("name", ["fake", "clonezilla_offline", "offline", "auto", "aomei", "diskgenius"])
def test_provider_selection_accepts_only_explicit_provider_names(name):
    assert provider_for_config({"provider": name}).discover().name == ("clonezilla_offline" if name in {"clonezilla_offline", "offline", "auto"} else name)


@pytest.mark.parametrize("name", ["", "unknown", "aomei-or-diskgenius", None])
def test_unknown_provider_fails_closed_without_substitution(name):
    with pytest.raises(DiskCloneConfigError):
        provider_for_config({"provider": name})
    with pytest.raises(DiskCloneConfigError):
        validate_disk_clone_config({"provider": name})


def test_unknown_provider_does_not_probe_or_substitute_adapters(monkeypatch):
    def fail_probe(*args, **kwargs):
        raise AssertionError("adapter probing is not allowed for an unknown provider")

    monkeypatch.setattr(AOMEIProvider, "discover", fail_probe)
    monkeypatch.setattr(DiskGeniusProvider, "discover", fail_probe)
    with pytest.raises(DiskCloneConfigError):
        provider_for_config({"provider": "unknown"})


def test_malformed_disk_clone_config_fails_closed():
    with pytest.raises(DiskCloneConfigError):
        provider_for_config(None)
    with pytest.raises(DiskCloneConfigError):
        validate_disk_clone_config({"provider": {"name": "fake"}})


def test_disabled_clone_blocks_real_run_but_leaves_static_status_and_simulation_available(tmp_path):
    root = tmp_path / "vault"
    p = ensure_directories(root)
    db.init_db(p.db)
    (p.config / "config.yaml").write_text(yaml.safe_dump({"disk_clone": {"enabled": False, "provider": "fake"}}), encoding="utf-8")
    service = CloneService(p, provider=FakeProvider())
    result = service.execute(countdown=lambda _: "confirm")
    assert result["state"] == "blocked_configuration"
    assert service.provider.started == 0
    assert service.status()["current_state"] == "blocked_configuration"
    assert simulate_offline_round_trip(tmp_path / "simulation")["state"] == "offline_simulation_completed"
    health = health_snapshot(p)
    config_check = next(check for check in health["checks"] if check["name"] == "Clone: configuracao")
    assert config_check["ok"] and "desativada" in config_check["detail"]


def test_enabled_clone_still_blocks_real_execution_without_stronger_gate(tmp_path):
    service, _, _ = _service(tmp_path)
    result = service.execute(countdown=lambda _: "confirm")
    assert result["state"] == "blocked_provider"
    assert service.provider.started == 0


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


class _Window:
    def __init__(self):
        self.calls = []

    def withdraw(self):
        self.calls.append("withdraw")

    def deiconify(self):
        self.calls.append("deiconify")

    def lift(self):
        self.calls.append("lift")

    def focus_force(self):
        self.calls.append("focus_force")


def test_ui_hide_and_restore_call_window_operations():
    controller = CountdownController(5, on_confirm=lambda: None, on_cancel=lambda: None)
    window = _Window()
    _hide_window(window, controller)
    assert controller.hidden is True
    assert window.calls == ["withdraw"]
    _restore_window(window, controller)
    assert controller.hidden is False
    assert window.calls == ["withdraw", "deiconify", "lift", "focus_force"]


def test_stale_show_request_does_not_claim_another_run(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    create_control_request(p.db, "show", run_id="old-run")
    assert claim_control_request(p.db, "show", run_id="new-run") is None
    assert claim_control_request(p.db, "show", run_id="old-run") is not None


def test_one_monitor_owner_per_run(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    db.init_db(p.db)
    assert claim_monitor_owner(p.db, "run-1", owner_pid=os.getpid())
    assert not claim_monitor_owner(p.db, "run-1", owner_pid=os.getpid())
    with db.connect(p.db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM disk_clone_monitor_owners WHERE run_id='run-1'").fetchone()[0] == 1
    release_monitor_owner(p.db, "run-1", owner_pid=os.getpid())


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


def test_retry_request_is_claimed_once_and_duplicate_clicks_create_one_child(tmp_path: Path):
    provider = FakeProvider(result=ProviderResult(False, exit_code=5, reason="first attempt failed"))
    service, _, _ = _service(tmp_path, provider=provider)
    first = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    request_id = create_control_request(service.p.db, "retry", run_id=first["run_id"])
    provider.result = ProviderResult(False, exit_code=6, reason="retry failed")
    accepted = service.consume_retry_request(request_id=request_id, countdown=lambda _: "confirm", simulation=True)
    assert accepted["state"] == "retry_accepted"
    assert service.consume_retry_request(request_id=request_id, countdown=lambda _: "confirm", simulation=True)["state"] == "retry_not_claimed"
    duplicate_request = create_control_request(service.p.db, "retry", run_id=first["run_id"])
    rejected = service.consume_retry_request(request_id=duplicate_request, countdown=lambda _: "confirm", simulation=True)
    assert rejected["state"] == "retry_rejected"
    with db.connect(service.p.db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM disk_clone_runs WHERE parent_run_id=?", (first["run_id"],)).fetchone()[0] == 1


def test_non_retryable_parent_is_rejected(tmp_path: Path):
    service, _, _ = _service(tmp_path)
    first = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    request_id = create_control_request(service.p.db, "retry", run_id=first["run_id"])
    result = service.consume_retry_request(request_id=request_id, countdown=lambda _: "confirm", simulation=True)
    assert result["state"] == "retry_rejected"


def test_retry_still_obeys_local_window(tmp_path: Path):
    current = [datetime(2026, 8, 1, 3, 10, tzinfo=timezone.utc)]
    provider = FakeProvider(result=ProviderResult(False, exit_code=5, reason="first attempt failed"))
    service, _, _ = _service(tmp_path, provider=provider, clock=lambda: current[0])
    first = service.execute(trigger="simulation", countdown=lambda _: "confirm", simulation=True)
    request_id = create_control_request(service.p.db, "retry", run_id=first["run_id"])
    current[0] = datetime(2026, 8, 1, 4, 0, tzinfo=timezone.utc)
    result = service.consume_retry_request(request_id=request_id, countdown=lambda _: "confirm", simulation=True)
    assert result["state"] == "retry_accepted"
    assert result["result"]["state"] == "skipped_outside_window"
    assert provider.started == 1


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
    (p.config / "config.yaml").write_text(yaml.safe_dump({"disk_clone": {"enabled": True, "provider": "fake"}}), encoding="utf-8")
    files = generate_schedule_files(p)
    install = files.install.read_text(encoding="utf-8")
    assert 'Key="disk_clone"' in install
    assert 'StartWhenAvailable=$false' in install
    assert 'StartWhenAvailable=$true' in install


def test_clone_scheduler_omits_disabled_disk_clone_task_even_when_automation_task_enabled(tmp_path: Path):
    p = ensure_directories(tmp_path / "vault")
    (p.config / "config.yaml").write_text(yaml.safe_dump({"disk_clone": {"enabled": False, "provider": "fake"}, "automation": {"tasks": {"disk_clone": {"enabled": True}}}}), encoding="utf-8")
    install = generate_schedule_files(p).install.read_text(encoding="utf-8")
    assert 'Key="disk_clone"' not in install


def test_disk_clone_run_is_blocked_when_disabled(tmp_path: Path):
    root = tmp_path / "vault"
    ensure_directories(root)
    result = runner.invoke(app, ["disk-clone-run", "--root", str(root)])
    assert result.exit_code != 0


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
    assert client.post("/disk-clone/action?action=preflight", data={"csrf_token": csrf}).status_code == 400
    assert client.post("/disk-clone/action?action=cancel", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
    assert client.post("/disk-clone/action?action=simulate", data={"csrf_token": csrf}, follow_redirects=False).status_code == 303
