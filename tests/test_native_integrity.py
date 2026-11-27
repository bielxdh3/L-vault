from __future__ import annotations

import hashlib
import subprocess
import sys
import threading
from pathlib import Path
from queue import Queue

import pytest


class _SyntheticStdout:
    def __init__(self) -> None:
        self._chunks: Queue[bytes | None] = Queue()
        self._buffer = bytearray()
        self._ended = False

    def feed(self, value: bytes) -> None:
        self._chunks.put(value)

    def end(self) -> None:
        if not self._ended:
            self._ended = True
            self._chunks.put(None)

    def close(self) -> None:
        self.end()

    def read(self, size: int = 1) -> bytes:
        while not self._buffer:
            chunk = self._chunks.get()
            if chunk is None:
                return b""
            self._buffer.extend(chunk)
        value = bytes(self._buffer[:size])
        del self._buffer[:size]
        return value


class _SyntheticStdin:
    def __init__(self, process: _SyntheticProcess) -> None:
        self._process = process
        self._buffer = bytearray()
        self.closed = False

    def write(self, value: bytes | memoryview) -> int:
        if self._process.block_write:
            self._process.write_gate.wait()
        if self._process.killed:
            raise BrokenPipeError()
        piece = bytes(value[:7])
        self._buffer.extend(piece)
        while len(self._buffer) >= 5:
            length = int.from_bytes(self._buffer[1:5], "big")
            frame_length = 5 + length
            if len(self._buffer) < frame_length:
                break
            frame = bytes(self._buffer[:frame_length])
            del self._buffer[:frame_length]
            self._process.frames.append(frame)
            response = self._process.respond(frame, len(self._process.frames) - 1)
            if response is not None:
                self._process.stdout.feed(response)
                if b"\tmissing\t" in response or b"\tio\t" in response:
                    self._process.file_error_seen = True
                if self._process.end_after_reply:
                    self._process.stdout.end()
        return len(piece)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._process.stdin_closed = True
            self._process.stdout.end()


class _SyntheticProcess:
    def __init__(
        self,
        respond,
        *,
        block_write: bool = False,
        end_after_reply: bool = False,
        hang_on_close: bool = False,
        exit_code: int | None = None,
    ) -> None:
        self.respond = respond
        self.block_write = block_write
        self.end_after_reply = end_after_reply
        self.hang_on_close = hang_on_close
        self.exit_code = exit_code
        self.stdout = _SyntheticStdout()
        self.stdin = _SyntheticStdin(self)
        self.write_gate = threading.Event()
        self.frames: list[bytes] = []
        self.file_error_seen = False
        self.stdin_closed = False
        self.killed = False
        self.returncode: int | None = None
        self.wait_timeouts: list[float | None] = []

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self.write_gate.set()
        self.stdout.end()

    def wait(self, timeout: float | None = None) -> int:
        self.wait_timeouts.append(timeout)
        if timeout is None:
            raise AssertionError("process waits must be bounded")
        if self.hang_on_close and not self.killed:
            raise subprocess.TimeoutExpired("synthetic child", timeout)
        if self.returncode is None:
            if not self.stdin_closed:
                raise subprocess.TimeoutExpired("synthetic child", timeout)
            self.returncode = self.exit_code if self.exit_code is not None else (1 if self.file_error_seen else 0)
        return self.returncode


def _install_process(monkeypatch, process: _SyntheticProcess):
    from localvault import native_integrity

    launches = []

    def start(argv, **kwargs):
        launches.append((argv, kwargs))
        return process

    monkeypatch.setattr(native_integrity, "Popen", start)
    return launches, native_integrity


def test_session_sends_one_utf8_frame_per_call_and_checks_reply_before_next_call(tmp_path, monkeypatch):
    try:
        from localvault.native_integrity import NativeIntegrityHashSession
    except ImportError as error:
        pytest.fail("the native integrity hash session is not implemented")

    digests = ["a" * 64, "b" * 64]
    process = _SyntheticProcess(
        lambda _frame, index: f"v2\t{index}\tok\t{digests[index]}\n".encode("ascii")
    )
    launches, native_integrity = _install_process(monkeypatch, process)
    executable = tmp_path / "trusted lvault-integrity.exe"
    first = Path("synthetic Ω first.bin")
    second = Path("synthetic second.bin")

    with NativeIntegrityHashSession(executable) as hash_file:
        assert hash_file(first) == digests[0]
        assert process.frames == [b"\x02" + len(str(first).encode("utf-8")).to_bytes(4, "big") + str(first).encode("utf-8")]
        assert hash_file(second) == digests[1]
        assert len(process.frames) == 2

    argv, options = launches[0]
    assert argv == [str(executable), "hash-session-v2"]
    assert options["shell"] is False
    assert options["stdin"] == subprocess.PIPE
    assert options["stdout"] == subprocess.PIPE
    assert options["stderr"] == subprocess.DEVNULL
    assert options["bufsize"] == 0
    assert process.stdin.closed
    assert process.wait_timeouts and all(timeout is not None for timeout in process.wait_timeouts)


@pytest.mark.parametrize(
    ("status", "raw_code", "error_type", "expected_errno"),
    [
        ("missing", "2", FileNotFoundError, 2),
        ("missing", "3", FileNotFoundError, 2),
        ("io", "13", OSError, 13),
        ("io", "-2147483648", OSError, -2147483648),
        ("io", "-", OSError, None),
    ],
)
def test_native_file_errors_preserve_os_code_without_echoing_path(
    status, raw_code, error_type, expected_errno, tmp_path, monkeypatch
):
    from localvault.native_integrity import NativeIntegrityHashSession

    error_path = Path("synthetic private Ω missing.bin")
    good_path = Path("synthetic later.bin")
    process = _SyntheticProcess(
        lambda _frame, index: (
            f"v2\t{index}\t{status}\t{raw_code}\n".encode("ascii")
            if index == 0
            else f"v2\t{index}\tok\t{'b' * 64}\n".encode("ascii")
        )
    )
    _install_process(monkeypatch, process)

    with NativeIntegrityHashSession(tmp_path / "trusted.exe") as hash_file:
        with pytest.raises(error_type) as failure:
            hash_file(error_path)
        if sys.platform == "win32" and status == "missing" and raw_code != "-":
            assert isinstance(failure.value, FileNotFoundError)
            assert failure.value.errno == 2
            assert failure.value.winerror == int(raw_code)
        elif sys.platform == "win32" and status == "io" and raw_code != "-":
            assert failure.value.winerror == int(raw_code)
        else:
            assert failure.value.errno == expected_errno
        assert failure.value.filename is None
        assert str(error_path) not in str(failure.value)
        assert hash_file(good_path) == "b" * 64

    assert len(process.frames) == 2


def test_file_error_escaping_context_preserves_error_and_reaps_expected_exit(tmp_path, monkeypatch):
    from localvault.native_integrity import NativeIntegrityHashSession

    process = _SyntheticProcess(lambda _frame, index: f"v2\t{index}\tio\t5\n".encode("ascii"))
    _, native_integrity = _install_process(monkeypatch, process)
    monkeypatch.setattr(native_integrity, "sys", sys)

    with pytest.raises(OSError, match="native integrity file operation failed") as failure:
        with NativeIntegrityHashSession(tmp_path / "trusted.exe") as hash_file:
            hash_file(Path("private path.bin"))

    if sys.platform == "win32":
        assert isinstance(failure.value, PermissionError)
        assert failure.value.errno == 13
        assert failure.value.winerror == 5
    else:
        assert failure.value.errno == 5
    assert process.returncode == 1
    assert not process.killed
    assert process.wait_timeouts


def test_unexpected_child_exit_after_successful_reply_is_reported(tmp_path, monkeypatch):
    from localvault.native_integrity import NativeIntegrityHashSession

    process = _SyntheticProcess(
        lambda _frame, index: f"v2\t{index}\tok\t{'a' * 64}\n".encode("ascii"),
        exit_code=1,
    )
    _install_process(monkeypatch, process)

    with pytest.raises(OSError, match="session exited unsuccessfully"):
        with NativeIntegrityHashSession(tmp_path / "trusted.exe") as hash_file:
            assert hash_file(Path("private path.bin")) == "a" * 64

    assert process.returncode == 1
    assert not process.killed


def test_session_counts_utf8_bytes_and_allows_the_maximum_frame(tmp_path, monkeypatch):
    from localvault.native_integrity import NativeIntegrityHashSession

    process = _SyntheticProcess(lambda _frame, index: f"v2\t{index}\tok\t{'c' * 64}\n".encode("ascii"))
    _install_process(monkeypatch, process)
    maximum = Path("x" * 65_534 + "Ω")
    oversized = Path("x" * 65_535 + "Ω")

    with NativeIntegrityHashSession(tmp_path / "trusted.exe") as hash_file:
        assert hash_file(maximum) == "c" * 64
        with pytest.raises(ValueError, match="frame limit"):
            hash_file(oversized)

    assert process.frames[0][:5] == b"\x02\x00\x01\x00\x00"
    assert len(process.frames[0]) == 65_541
    assert len(process.frames) == 1


@pytest.mark.parametrize(
    ("reply", "end_after_reply"),
    [
        (b"v1\t0\tok\t" + b"a" * 64 + b"\n", False),
        (b"v2\t1\tok\t" + b"a" * 64 + b"\n", False),
        (b"v2\t0\tunknown\t-\n", False),
        (b"v2\t0\tok\t" + b"A" * 64 + b"\n", False),
        (b"v2\t0\tok\t" + b"a" * 64, True),
        (b"v2\t0\tok\t" + b"a" * 128 + b"\n", False),
        (b"v2\t0\tmissing\tnot-a-number\n", False),
        (b"v2\t0\tio\t2147483648\n", False),
        (b"v2\t0\tok\t" + b"\xff\n", False),
    ],
)
def test_session_rejects_malformed_replies_without_echoing_path(reply, end_after_reply, tmp_path, monkeypatch):
    from localvault.native_integrity import NativeIntegrityHashSession

    process = _SyntheticProcess(lambda _frame, _index: reply, end_after_reply=end_after_reply)
    _install_process(monkeypatch, process)
    path = Path("synthetic private Ω path.bin")

    with NativeIntegrityHashSession(tmp_path / "trusted.exe") as hash_file:
        with pytest.raises(OSError, match="response is invalid") as failure:
            hash_file(path)

    assert str(path) not in str(failure.value)
    assert process.killed


def test_session_requires_an_explicit_absolute_executable(monkeypatch):
    from localvault.native_integrity import NativeIntegrityHashSession

    process = _SyntheticProcess(lambda _frame, _index: None)
    launches, _ = _install_process(monkeypatch, process)

    with pytest.raises(ValueError, match="absolute path"):
        NativeIntegrityHashSession(Path("lvault-integrity.exe"))

    assert launches == []


def test_session_rejects_unencodable_path_without_poisoning_later_requests(tmp_path, monkeypatch):
    from localvault.native_integrity import NativeIntegrityHashSession

    process = _SyntheticProcess(lambda _frame, index: f"v2\t{index}\tok\t{'d' * 64}\n".encode("ascii"))
    _install_process(monkeypatch, process)

    with NativeIntegrityHashSession(tmp_path / "trusted.exe") as hash_file:
        with pytest.raises(ValueError, match="UTF-8"):
            hash_file(Path("synthetic \ud800.bin"))
        assert process.frames == []
        assert hash_file(Path("synthetic later Ω.bin")) == "d" * 64

    assert len(process.frames) == 1


@pytest.mark.parametrize("block_write", [False, True])
def test_session_request_timeout_kills_child_and_joins_worker(block_write, tmp_path, monkeypatch):
    from localvault.native_integrity import NativeIntegrityHashSession

    process = _SyntheticProcess(lambda _frame, _index: None, block_write=block_write)
    _, native_integrity = _install_process(monkeypatch, process)
    monkeypatch.setattr(native_integrity, "_REQUEST_TIMEOUT_SECONDS", 0.05)
    session = NativeIntegrityHashSession(tmp_path / "trusted.exe")

    with session as hash_file:
        with pytest.raises(TimeoutError, match="request timed out"):
            hash_file(Path("synthetic timeout Ω.bin"))

    assert process.killed
    assert session._worker is not None and not session._worker.is_alive()
    assert process.wait_timeouts and all(timeout is not None for timeout in process.wait_timeouts)


def test_close_timeout_is_bounded_and_preserves_the_primary_error(tmp_path, monkeypatch):
    from localvault.native_integrity import NativeIntegrityHashSession

    process = _SyntheticProcess(lambda _frame, _index: None, hang_on_close=True)
    _, native_integrity = _install_process(monkeypatch, process)
    monkeypatch.setattr(native_integrity, "_CLOSE_TIMEOUT_SECONDS", 0.05)

    with pytest.raises(RuntimeError, match="primary synthetic failure"):
        with NativeIntegrityHashSession(tmp_path / "trusted.exe"):
            raise RuntimeError("primary synthetic failure")

    assert process.killed
    assert process.wait_timeouts and all(timeout is not None for timeout in process.wait_timeouts)


def test_close_timeout_is_reported_without_a_primary_error(tmp_path, monkeypatch):
    from localvault.native_integrity import NativeIntegrityHashSession

    process = _SyntheticProcess(lambda _frame, _index: None, hang_on_close=True)
    _, native_integrity = _install_process(monkeypatch, process)
    monkeypatch.setattr(native_integrity, "_CLOSE_TIMEOUT_SECONDS", 0.05)

    with pytest.raises(TimeoutError, match="did not exit"):
        with NativeIntegrityHashSession(tmp_path / "trusted.exe"):
            pass

    assert process.killed
    assert process.wait_timeouts and all(timeout is not None for timeout in process.wait_timeouts)


def test_verify_sample_limit_does_not_submit_unsampled_paths(tmp_path, monkeypatch):
    from localvault import db
    from localvault.config import ensure_directories
    from localvault.native_integrity import NativeIntegrityHashSession
    from localvault.reports import RunReport
    from localvault.verify import verify_vault

    paths = ensure_directories(tmp_path / "vault")
    db.init_db(paths.db)
    first = paths.root / "vault" / "synthetic" / "first.bin"
    second = paths.root / "vault" / "synthetic" / "second.bin"
    for path, data in ((first, b"first"), (second, b"second")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        with db.connect(paths.db) as conn:
            db.upsert_file(
                conn,
                sha256=hashlib.sha256(data).hexdigest(),
                path=path,
                media_type="photo",
                size=len(data),
                source="synthetic",
            )

    def respond(frame: bytes, index: int) -> bytes:
        path = Path(frame[5:].decode("utf-8"))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return f"v2\t{index}\tok\t{digest}\n".encode("ascii")

    process = _SyntheticProcess(respond)
    _install_process(monkeypatch, process)
    with NativeIntegrityHashSession(tmp_path / "trusted.exe") as hash_file:
        report = verify_vault(
            paths,
            RunReport(source="vault", mode="verify_sample"),
            sample_limit=1,
            hash_file=hash_file,
        )

    assert report.imported_count == 1
    assert len(process.frames) == 1
    assert process.frames[0][5:].decode("utf-8") == str(first)
