"""Guarded production Clonezilla execution seam.

This module is deliberately fail-closed. Importing it never touches storage and
constructing a runner never starts Clonezilla. Real execution requires an
explicitly enabled policy, a signed job whose contract permits real execution,
a fresh strong source/target resolution, and a non-test subprocess runner.

The current repository still rejects ``real_execution_authorized=True`` inside
``OfflineJob.validate()``. That is intentional for this draft: this module
provides the production boundary and tests without silently weakening the
existing signed-job contract. The remaining integration must widen that
contract explicitly and preserve signature/replay protections.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .offline_clone import (
    ClonezillaCommandPlan,
    ClonezillaCommandRenderer,
    OfflineCloneBlocked,
    OfflineJob,
    OfflineResolution,
    canonical_json,
)


@dataclass(frozen=True)
class ProcessOutcome:
    exit_status: int
    stdout: bytes = b""
    stderr: bytes = b""
    log_hash: str = ""
    timed_out: bool = False
    output_truncated: bool = False


class CloneProcessRunner(Protocol):
    is_test_double: bool

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: int,
        env: dict[str, str],
    ) -> ProcessOutcome: ...


@dataclass(frozen=True)
class ProductionExecutionPolicy:
    """Global capability gate. Defaults are always non-destructive."""

    enabled: bool = False
    executable_path: str = "/usr/sbin/ocs-onthefly"
    timeout_seconds: int = 12 * 60 * 60
    max_captured_output_bytes: int = 1024 * 1024
    allow_test_double: bool = False

    def validate(self) -> None:
        if not self.enabled:
            raise OfflineCloneBlocked(
                "production offline execution is not armed",
                "offline_execution_disabled",
            )
        executable = Path(self.executable_path)
        if not executable.is_absolute() or executable.name != "ocs-onthefly" or ".." in executable.parts:
            raise OfflineCloneBlocked(
                "production Clonezilla executable is not allowlisted",
                "offline_execution_disabled",
            )
        if not 1 <= int(self.timeout_seconds) <= 24 * 60 * 60:
            raise OfflineCloneBlocked(
                "production clone timeout is outside policy",
                "offline_execution_disabled",
            )
        if not 4096 <= int(self.max_captured_output_bytes) <= 16 * 1024 * 1024:
            raise OfflineCloneBlocked(
                "production output bound is invalid",
                "offline_execution_disabled",
            )


class RecordingCloneProcessRunner:
    """Test double: records argv and never creates a subprocess."""

    is_test_double = True

    def __init__(self, outcome: ProcessOutcome | None = None):
        self.outcome = outcome or ProcessOutcome(
            exit_status=0,
            stdout=b"synthetic clone completed",
            log_hash=hashlib.sha256(b"synthetic clone completed").hexdigest(),
        )
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: int,
        env: dict[str, str],
    ) -> ProcessOutcome:
        self.calls.append(tuple(argv))
        return self.outcome


class BoundedSubprocessCloneRunner:
    """Real subprocess seam for a trusted offline Clonezilla environment only."""

    is_test_double = False

    def __init__(self, *, max_captured_output_bytes: int = 1024 * 1024):
        self.max_captured_output_bytes = int(max_captured_output_bytes)

    @staticmethod
    def _reader(pipe, limit: int, sink: bytearray, digest, truncated: list[bool]) -> None:
        try:
            while True:
                chunk = pipe.read(64 * 1024)
                if not chunk:
                    return
                digest.update(chunk)
                remaining = max(0, limit - len(sink))
                if remaining:
                    sink.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated[0] = True
        finally:
            pipe.close()

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: int,
        env: dict[str, str],
    ) -> ProcessOutcome:
        if not argv or not Path(argv[0]).is_absolute():
            raise OfflineCloneBlocked(
                "clone runner requires an absolute executable path",
                "offline_execution_disabled",
            )

        process = subprocess.Popen(
            list(argv),
            cwd="/",
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout = bytearray()
        stderr = bytearray()
        digest = hashlib.sha256()
        truncated = [False]
        readers = (
            threading.Thread(
                target=self._reader,
                args=(process.stdout, self.max_captured_output_bytes, stdout, digest, truncated),
                daemon=True,
            ),
            threading.Thread(
                target=self._reader,
                args=(process.stderr, self.max_captured_output_bytes, stderr, digest, truncated),
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()

        timed_out = False
        try:
            exit_status = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            exit_status = process.wait(timeout=10)

        for reader in readers:
            reader.join(timeout=10)

        if timed_out:
            exit_status = 124
        exit_status = max(0, min(255, int(exit_status)))
        return ProcessOutcome(
            exit_status=exit_status,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            log_hash=digest.hexdigest(),
            timed_out=timed_out,
            output_truncated=truncated[0],
        )


def _verify_real_executable(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise OfflineCloneBlocked(
            "allowlisted Clonezilla executable is missing",
            "offline_execution_disabled",
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise OfflineCloneBlocked(
            "allowlisted Clonezilla executable is not a regular non-symlink file",
            "offline_execution_disabled",
        )
    if not os.access(path, os.X_OK):
        raise OfflineCloneBlocked(
            "allowlisted Clonezilla executable is not executable",
            "offline_execution_disabled",
        )


def render_absolute_clonezilla_plan(
    job: OfflineJob,
    resolution: OfflineResolution,
    executable_path: str,
) -> ClonezillaCommandPlan:
    """Bind the trusted absolute executable into argv and the command hash.

    The existing renderer remains the source of Clonezilla flags. This helper
    only replaces argv[0] after validating the executable path and then hashes
    the exact final argv. No shell command string is produced.
    """

    executable = Path(executable_path)
    if not executable.is_absolute() or executable.name != "ocs-onthefly" or ".." in executable.parts:
        raise OfflineCloneBlocked(
            "Clonezilla executable path is not allowlisted",
            "offline_execution_disabled",
        )
    rendered = ClonezillaCommandRenderer().render(job, resolution)
    argv = (str(executable), *rendered.argv[1:])
    return ClonezillaCommandPlan(
        argv=argv,
        displayed_argv=rendered.displayed_argv,
        argv_hash=hashlib.sha256(canonical_json(list(argv))).hexdigest(),
        executable=True,
        batch=False,
    )


class ProductionOfflineCloneExecutor:
    """Small, fail-closed boundary around the real process runner.

    This draft intentionally stops before process creation while the signed job
    model rejects ``real_execution_authorized=True``. Once that contract is
    widened and covered by signature/replay tests, this class can be integrated
    into the trusted offline runtime without changing its safety shape.
    """

    def __init__(self, policy: ProductionExecutionPolicy, runner: CloneProcessRunner):
        self.policy = policy
        self.runner = runner

    def execute(self, job: OfflineJob, resolution: OfflineResolution) -> ProcessOutcome:
        self.policy.validate()
        job.validate()
        if not job.real_execution_authorized:
            raise OfflineCloneBlocked(
                "signed offline job does not authorize real execution",
                "offline_execution_disabled",
            )
        if not resolution.ok or not resolution.source_node or not resolution.target_node:
            raise OfflineCloneBlocked(
                "fresh offline source/target resolution is required",
                "offline_identity_blocked",
            )
        if self.runner.is_test_double and not self.policy.allow_test_double:
            raise OfflineCloneBlocked(
                "test-double runner is forbidden by production policy",
                "offline_execution_disabled",
            )
        if not self.runner.is_test_double:
            _verify_real_executable(Path(self.policy.executable_path))

        plan = render_absolute_clonezilla_plan(job, resolution, self.policy.executable_path)
        env = {
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        }
        return self.runner.run(
            plan.argv,
            timeout_seconds=self.policy.timeout_seconds,
            env=env,
        )
