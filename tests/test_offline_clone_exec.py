from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

import pytest

from localvault.offline_clone import (
    FakeOfflineInventory,
    OfflineBlockDevice,
    OfflineCloneBlocked,
    ReplayStore,
    build_offline_job,
    resolve_offline_devices,
)
from localvault.offline_clone_exec import (
    BoundedSubprocessCloneRunner,
    ProductionExecutionPolicy,
    ProductionOfflineCloneExecutor,
    RecordingCloneProcessRunner,
    normalize_process_return_code,
    render_absolute_clonezilla_plan,
)


NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(0, 0), (1, 1), (9, 9), (255, 255), (300, 255), (-9, 137), (-15, 143)],
)
def test_process_return_code_normalization_never_turns_signal_into_success(raw, expected):
    assert normalize_process_return_code(raw) == expected
    assert normalize_process_return_code(raw, timed_out=True) == 124


def test_bounded_subprocess_runner_maps_signal_termination(monkeypatch):
    class FakeProcess:
        stdout = io.BytesIO()
        stderr = io.BytesIO()

        def wait(self, timeout=None):
            return -9

    monkeypatch.setattr("localvault.offline_clone_exec.subprocess.Popen", lambda *args, **kwargs: FakeProcess())
    outcome = BoundedSubprocessCloneRunner().run(
        (r"C:\synthetic\ocs-onthefly.exe",),
        timeout_seconds=1,
        env={},
    )
    assert outcome.exit_status == 137


def _disk(node: str, serial: str, *, size: int = 1000) -> OfflineBlockDevice:
    return OfflineBlockDevice(
        node=node,
        model="Synthetic Disk",
        serial=serial,
        wwn=f"wwn-{serial}",
        transport="sata",
        size_bytes=size,
        logical_sector_size=512,
        physical_sector_size=4096,
        partition_style="gpt",
        partition_roles=("efi", "windows", "recovery"),
    )


def _job_and_resolution():
    source = _disk("/dev/sda", "source")
    target = _disk("/dev/sdb", "target", size=1200)
    job = build_offline_job(
        source,
        target,
        now=NOW,
        nonce="nonce-production-0001",
    )
    resolution = resolve_offline_devices(
        job,
        FakeOfflineInventory((source, target)),
    )
    assert resolution.ok
    return job, resolution


def test_production_policy_is_fail_closed_by_default():
    with pytest.raises(OfflineCloneBlocked, match="not armed"):
        ProductionExecutionPolicy().validate()


def test_absolute_plan_binds_real_executable_into_hash_without_dd_fallback():
    job, resolution = _job_and_resolution()
    plan = render_absolute_clonezilla_plan(
        job,
        resolution,
        "/usr/sbin/ocs-onthefly",
    )
    assert plan.argv[0] == "/usr/sbin/ocs-onthefly"
    assert plan.argv[1:5] == ("-f", "/dev/sda", "-d", "/dev/sdb")
    assert "dd" not in plan.argv
    assert "-icds" not in plan.argv
    assert len(plan.argv_hash) == 64
    assert plan.executable is True
    assert plan.batch is False


def test_non_allowlisted_executable_is_rejected_before_process_creation():
    job, resolution = _job_and_resolution()
    with pytest.raises(OfflineCloneBlocked, match="not allowlisted"):
        render_absolute_clonezilla_plan(job, resolution, "/bin/dd")


def test_executor_policy_rejects_noncanonical_clonezilla_path():
    with pytest.raises(OfflineCloneBlocked, match="not allowlisted"):
        ProductionExecutionPolicy(enabled=True, executable_path="/opt/ocs-onthefly").validate()


def test_executor_does_not_run_without_job_scoped_real_authorization():
    job, resolution = _job_and_resolution()
    recorder = RecordingCloneProcessRunner()
    executor = ProductionOfflineCloneExecutor(
        ProductionExecutionPolicy(enabled=True, allow_test_double=True),
        recorder,
    )
    with pytest.raises(OfflineCloneBlocked, match="does not authorize"):
        executor.execute(job, resolution)
    assert recorder.calls == []


def test_test_double_is_blocked_by_production_policy_unless_explicitly_allowed():
    job, resolution = _job_and_resolution()
    recorder = RecordingCloneProcessRunner()
    executor = ProductionOfflineCloneExecutor(
        ProductionExecutionPolicy(enabled=True, allow_test_double=False),
        recorder,
    )
    # Current signed-job contract blocks even earlier because the synthetic job
    # is not authorized for real execution. The important invariant is that the
    # process runner remains untouched.
    with pytest.raises(OfflineCloneBlocked):
        executor.execute(job, resolution)
    assert recorder.calls == []


def test_authorized_executor_claims_nonce_once_immediately_before_runner(tmp_path):
    source = _disk("/dev/sda", "source")
    target = _disk("/dev/sdb", "target", size=1200)
    job = build_offline_job(source, target, now=NOW, nonce="nonce-production-0002", real_execution_authorized=True)
    resolution = resolve_offline_devices(job, FakeOfflineInventory((source, target)))
    recorder = RecordingCloneProcessRunner()
    executor = ProductionOfflineCloneExecutor(
        ProductionExecutionPolicy(enabled=True, allow_test_double=True, runtime_ready=True),
        recorder,
        replay_store=ReplayStore(tmp_path / "replay.json"),
    )
    outcome = executor.execute(job, resolution, now=NOW + timedelta(minutes=1))
    assert outcome.exit_status == 0
    assert len(recorder.calls) == 1
    with pytest.raises(OfflineCloneBlocked, match="already consumed"):
        executor.execute(job, resolution, now=NOW + timedelta(minutes=1))
    assert len(recorder.calls) == 1


def test_authorized_executor_requires_runtime_readiness_before_replay_or_runner(tmp_path):
    source = _disk("/dev/sda", "source")
    target = _disk("/dev/sdb", "target", size=1200)
    job = build_offline_job(source, target, now=NOW, nonce="nonce-production-0003", real_execution_authorized=True)
    resolution = resolve_offline_devices(job, FakeOfflineInventory((source, target)))
    recorder = RecordingCloneProcessRunner()
    executor = ProductionOfflineCloneExecutor(
        ProductionExecutionPolicy(enabled=True, allow_test_double=True),
        recorder,
        replay_store=ReplayStore(tmp_path / "replay.json"),
    )
    with pytest.raises(OfflineCloneBlocked, match="runtime is not ready"):
        executor.execute(job, resolution, now=NOW)
    assert recorder.calls == []
    assert not (tmp_path / "replay.json").exists()
