from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from localvault.offline_clone import (
    FakeDetachedSigner,
    FakeDetachedVerifier,
    OfflineBlockDevice,
    OfflineCloneBlocked,
    ReplayStore,
    build_offline_job,
)
from localvault.offline_clone_exec import (
    ProcessOutcome,
    ProductionExecutionPolicy,
    ProductionOfflineCloneExecutor,
    RecordingCloneProcessRunner,
)
from localvault.offline_runtime import ProductionOfflineRunner, VirtualReturnChannel


def _devices() -> tuple[OfflineBlockDevice, OfflineBlockDevice]:
    return (
        OfflineBlockDevice("/dev/sda", "Source", "SOURCE-1234", wwn="WWN-SOURCE", transport="sata", size_bytes=1000, partition_style="gpt", partition_roles=("efi", "windows")),
        OfflineBlockDevice("/dev/sdb", "Target", "TARGET-1234", wwn="WWN-TARGET", transport="sata", size_bytes=1200, partition_style="gpt", partition_roles=("efi", "windows")),
    )


def _runner(tmp_path: Path, *, structural: bool = True, offline: bool = True, outcome: ProcessOutcome | None = None, clock=None, ttl=timedelta(minutes=15)):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    source, target = _devices()
    job = build_offline_job(source, target, now=now, ttl=ttl, nonce="production-runner-nonce-01", real_execution_authorized=True)
    signer = FakeDetachedSigner()
    recorder = RecordingCloneProcessRunner(outcome)
    executor = ProductionOfflineCloneExecutor(
        ProductionExecutionPolicy(enabled=True, runtime_ready=True, allow_test_double=True),
        recorder,
        replay_store=ReplayStore(tmp_path / "replay.json"),
    )
    channel = VirtualReturnChannel(tmp_path / "channel")
    runner = ProductionOfflineRunner(
        executor,
        channel,
        signer,
        FakeDetachedVerifier(),
        inventory_provider=lambda: (source, target),
        structural_verifier=lambda _source, _target: structural,
        target_offline_checker=lambda _target: offline,
        clock=clock,
    )
    return now, job, signer, runner, recorder, channel, executor


def test_production_runner_requires_verified_signed_job(tmp_path):
    now, job, _signer, runner, recorder, _channel, _executor = _runner(tmp_path)
    with pytest.raises(OfflineCloneBlocked, match="verified signed offline job"):
        runner.run(job, now=now)
    assert recorder.calls == []


def test_production_runner_publishes_terminal_result_only_after_post_checks(tmp_path):
    now, job, signer, runner, recorder, channel, executor = _runner(tmp_path)
    report = runner.run(job, now=now, job_signature=signer.sign(job.canonical_bytes()))
    assert report["command_executed"] is True
    assert report["structurally_verified"] is True
    assert report["target_offline"] == "confirmed_offline"
    assert len(recorder.calls) == 1
    consumed = channel.consume(
        job,
        FakeDetachedVerifier(),
        expected_command_hash=executor.last_plan.argv_hash,
        command_plan=executor.last_plan,
        now=now,
        profile="production",
    )
    assert consumed.state == "consumed"
    assert consumed.result is not None and consumed.result.boot_tested is False


@pytest.mark.parametrize("structural,offline", [(False, True), (True, False)])
def test_production_runner_never_reports_success_from_exit_zero_alone(tmp_path, structural, offline):
    now, job, signer, runner, _recorder, channel, _executor = _runner(tmp_path, structural=structural, offline=offline)
    report = runner.run(job, now=now, job_signature=signer.sign(job.canonical_bytes()))
    assert report["structurally_verified"] is structural
    assert report["target_offline"] in {"confirmed_offline", "unknown"}
    assert report["state"] == "result"
    assert channel.status().state == "result"


def test_post_inventory_failure_publishes_signed_failure_result(tmp_path):
    now, job, signer, runner, _recorder, channel, executor = _runner(tmp_path)
    source, target = _devices()
    calls = [0]

    def inventory():
        calls[0] += 1
        if calls[0] == 1:
            return (source, target)
        raise RuntimeError("post inventory /dev/sdb unavailable")

    runner.inventory_provider = inventory
    report = runner.run(job, now=now, job_signature=signer.sign(job.canonical_bytes()))
    assert report["state"] == "result"
    assert report["structurally_verified"] is False
    consumed = channel.consume(
        job,
        FakeDetachedVerifier(),
        expected_command_hash=executor.last_plan.argv_hash,
        command_plan=executor.last_plan,
        now=now,
        profile="production",
    )
    assert consumed.state == "consumed"
    assert consumed.result is not None and consumed.result.phase == "clone_failed"
    assert "/dev/sdb" not in consumed.result.sanitized_error


def test_signaled_process_publishes_nonzero_production_failure(tmp_path):
    now, job, signer, runner, recorder, channel, executor = _runner(tmp_path, outcome=ProcessOutcome(exit_status=-9))
    report = runner.run(job, now=now, job_signature=signer.sign(job.canonical_bytes()))
    assert report["exit_status"] == 137
    assert len(recorder.calls) == 1
    consumed = channel.consume(
        job,
        FakeDetachedVerifier(),
        expected_command_hash=executor.last_plan.argv_hash,
        command_plan=executor.last_plan,
        now=now,
        profile="production",
    )
    assert consumed.state == "consumed"
    assert consumed.result is not None
    assert consumed.result.phase == "clone_failed"
    assert consumed.result.exit_status == 137


def test_production_runner_uses_injected_clock_and_allows_bounded_finish_after_expiry(tmp_path):
    base = datetime.now(timezone.utc).replace(microsecond=0)
    ticks = iter((base + timedelta(seconds=30), base + timedelta(minutes=2)))
    now, job, signer, runner, _recorder, channel, executor = _runner(
        tmp_path,
        ttl=timedelta(minutes=1),
        clock=lambda: next(ticks),
    )
    report = runner.run(job, job_signature=signer.sign(job.canonical_bytes()))
    assert report["started_at"] == (base + timedelta(seconds=30)).isoformat()
    assert report["ended_at"] == (base + timedelta(minutes=2)).isoformat()
    assert report["started_at"] != report["ended_at"]
    consumed = channel.consume(
        job,
        FakeDetachedVerifier(),
        expected_command_hash=executor.last_plan.argv_hash,
        command_plan=executor.last_plan,
        now=base + timedelta(minutes=2),
        profile="production",
    )
    assert consumed.state == "consumed"


def test_production_runner_rejects_start_after_expiry_before_process(tmp_path):
    base = datetime.now(timezone.utc).replace(microsecond=0)
    ticks = iter((base + timedelta(minutes=2),))
    _now, job, signer, runner, recorder, _channel, _executor = _runner(tmp_path, ttl=timedelta(minutes=1), clock=lambda: next(ticks))
    with pytest.raises(OfflineCloneBlocked, match="expired"):
        runner.run(job, job_signature=signer.sign(job.canonical_bytes()))
    assert recorder.calls == []


def test_production_runner_rejects_end_before_start_and_runtime_over_max(tmp_path):
    base = datetime.now(timezone.utc).replace(microsecond=0)
    ticks = iter((base + timedelta(seconds=30), base + timedelta(seconds=29)))
    _now, job, signer, runner, _recorder, _channel, _executor = _runner(tmp_path, clock=lambda: next(ticks))
    with pytest.raises(OfflineCloneBlocked, match="precedes"):
        runner.run(job, job_signature=signer.sign(job.canonical_bytes()))

    base = datetime.now(timezone.utc).replace(microsecond=0)
    ticks = iter((base + timedelta(seconds=30), base + timedelta(hours=25)))
    _now, job, signer, runner, _recorder, _channel, _executor = _runner(tmp_path / "long", clock=lambda: next(ticks))
    with pytest.raises(OfflineCloneBlocked, match="maximum"):
        runner.run(job, job_signature=signer.sign(job.canonical_bytes()))


def test_replay_is_rejected_after_a_late_but_bounded_first_result(tmp_path):
    base = datetime.now(timezone.utc).replace(microsecond=0)
    ticks = iter((base + timedelta(seconds=30), base + timedelta(minutes=2)))
    _now, job, signer, runner, recorder, _channel, _executor = _runner(tmp_path, ttl=timedelta(minutes=1), clock=lambda: next(ticks, base + timedelta(minutes=2)))
    runner.run(job, job_signature=signer.sign(job.canonical_bytes()))
    with pytest.raises(OfflineCloneBlocked):
        runner.run(job, now=base + timedelta(minutes=2), job_signature=signer.sign(job.canonical_bytes()))
    assert len(recorder.calls) == 1
