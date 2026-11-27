from __future__ import annotations

import errno
from dataclasses import dataclass, field
from os import PathLike, fspath
from pathlib import Path
from queue import Full, Queue
import re
import sys
from subprocess import DEVNULL, PIPE, Popen, TimeoutExpired
from threading import Event, Lock, Thread, current_thread
from typing import BinaryIO


_SESSION_COMMAND = "hash-session-v2"
_FRAME_VERSION = 2
_MAX_PATH_BYTES = 65_536
_MAX_RESPONSE_BYTES = 128
_REQUEST_TIMEOUT_SECONDS = 900.0
_CLOSE_TIMEOUT_SECONDS = 2.0
_TERMINATE_TIMEOUT_SECONDS = 2.0
_WORKER_JOIN_TIMEOUT_SECONDS = 2.0
_STOP = object()


class _ProtocolError(Exception):
    pass


class _CommunicationError(Exception):
    pass


@dataclass
class _Request:
    frame: bytes
    complete: Event = field(default_factory=Event)
    reply: bytes | None = None
    error: Exception | None = None


def _encode_request(path: Path) -> bytes:
    path_text = fspath(path)
    if not isinstance(path_text, str):
        raise TypeError("hash path must be text")
    if not path_text:
        raise ValueError("hash path is empty")
    try:
        path_bytes = path_text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("hash path cannot be encoded as UTF-8") from None
    if len(path_bytes) > _MAX_PATH_BYTES:
        raise ValueError("hash path exceeds the session frame limit")
    return bytes((_FRAME_VERSION,)) + len(path_bytes).to_bytes(4, "big") + path_bytes


def _write_all(stream: BinaryIO, value: bytes) -> None:
    pending = memoryview(value)
    while pending:
        written = stream.write(pending)
        if not written:
            raise _CommunicationError
        pending = pending[written:]
    stream.flush()


def _read_line(stream: BinaryIO) -> bytes:
    value = bytearray()
    for _ in range(_MAX_RESPONSE_BYTES):
        piece = stream.read(1)
        if not piece:
            if value:
                raise _ProtocolError
            raise _CommunicationError
        value.extend(piece)
        if piece == b"\n":
            return bytes(value)
    raise _ProtocolError


def _parse_reply(line: bytes, expected_index: int) -> tuple[str, str]:
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        raise _ProtocolError from None
    if not text.endswith("\n"):
        raise _ProtocolError
    fields = text[:-1].split("\t")
    if len(fields) != 4 or fields[0] != "v2" or fields[1] != str(expected_index):
        raise _ProtocolError
    status, value = fields[2:]
    if status == "ok" and re.fullmatch(r"[0-9a-f]{64}", value) is not None:
        return status, value
    if status not in {"missing", "io"}:
        raise _ProtocolError
    if value == "-":
        return status, value
    if re.fullmatch(r"(?:0|-?[1-9][0-9]*)", value) is None:
        raise _ProtocolError
    raw_code = int(value)
    if not -(2**31) <= raw_code <= 2**31 - 1:
        raise _ProtocolError
    return status, value


class NativeIntegrityHashSession:
    """Call a trusted absolute ``lvault-integrity`` binary one path at a time."""

    def __init__(self, executable: str | PathLike[str]) -> None:
        executable_text = fspath(executable)
        if not isinstance(executable_text, str) or not Path(executable_text).is_absolute():
            raise ValueError("native integrity executable must be an absolute path")
        self._executable = executable_text
        self._process: Popen[bytes] | None = None
        self._worker: Thread | None = None
        self._requests: Queue[object] = Queue(maxsize=1)
        self._worker_stopped = Event()
        self._operation_lock = Lock()
        self._entered = False
        self._closed = False
        self._index = 0
        self._file_error_seen = False

    def __enter__(self) -> NativeIntegrityHashSession:
        if self._entered or self._closed:
            raise RuntimeError("native integrity session cannot be re-entered")
        self._process = Popen(
            [self._executable, _SESSION_COMMAND],
            stdin=PIPE,
            stdout=PIPE,
            stderr=DEVNULL,
            shell=False,
            bufsize=0,
        )
        if self._process.stdin is None or self._process.stdout is None:
            self._abort()
            raise OSError("native integrity session pipes are unavailable")
        # Keep blocking pipe I/O off the caller thread so request deadlines can abort it.
        self._worker = Thread(target=self._run_requests, name="lvault-integrity-session", daemon=True)
        try:
            self._worker.start()
        except BaseException:
            self._abort()
            raise
        self._entered = True
        return self

    def __call__(self, path: Path) -> str:
        if not self._operation_lock.acquire(blocking=False):
            raise RuntimeError("native integrity session requests must be sequential")
        try:
            if not self._entered or self._closed or self._process is None:
                raise RuntimeError("native integrity session is not open")
            request = _Request(_encode_request(path))
            try:
                self._requests.put(request, timeout=_REQUEST_TIMEOUT_SECONDS)
            except Full:
                self._abort()
                raise TimeoutError("native integrity session request timed out") from None
            if not request.complete.wait(_REQUEST_TIMEOUT_SECONDS):
                self._abort()
                raise TimeoutError("native integrity session request timed out")
            if request.error is not None:
                self._abort()
                if isinstance(request.error, _ProtocolError):
                    raise OSError("native integrity session response is invalid") from None
                raise OSError("native integrity session communication failed") from None
            if request.reply is None:
                self._abort()
                raise OSError("native integrity session response is invalid")
            try:
                status, value = _parse_reply(request.reply, self._index)
            except _ProtocolError:
                self._abort()
                raise OSError("native integrity session response is invalid") from None
            self._index += 1
            if status == "ok":
                return value
            self._file_error_seen = True
            message = "native integrity file operation failed"
            raw_code = None if value == "-" else int(value)
            if status == "missing":
                if raw_code is None:
                    raise FileNotFoundError(message)
                if sys.platform == "win32":
                    error = FileNotFoundError(errno.ENOENT, message, None, raw_code)
                    error.errno = errno.ENOENT
                    raise error
                raise FileNotFoundError(raw_code, message)
            if raw_code is None:
                raise OSError(message)
            if sys.platform == "win32":
                raise OSError(0, message, None, raw_code)
            raise OSError(raw_code, message)
        finally:
            self._operation_lock.release()

    def _run_requests(self) -> None:
        process = self._process
        try:
            if process is None or process.stdin is None or process.stdout is None:
                return
            while True:
                item = self._requests.get()
                if item is _STOP:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass
                    return
                if not isinstance(item, _Request):
                    return
                try:
                    _write_all(process.stdin, item.frame)
                    item.reply = _read_line(process.stdout)
                except Exception as error:
                    item.error = error if isinstance(error, _ProtocolError) else _CommunicationError()
                    item.complete.set()
                    return
                item.complete.set()
        finally:
            self._worker_stopped.set()

    def _close_pipes(self) -> None:
        if self._process is None:
            return
        for stream in (self._process.stdin, self._process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def _abort(self) -> None:
        self._closed = True
        process = self._process
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=_TERMINATE_TIMEOUT_SECONDS)
            except (OSError, TimeoutExpired):
                pass
        try:
            self._requests.put_nowait(_STOP)
        except Full:
            pass
        worker = self._worker
        if worker is not None and worker is not current_thread():
            try:
                worker.join(timeout=_WORKER_JOIN_TIMEOUT_SECONDS)
            except RuntimeError:
                pass
        self._close_pipes()

    def close(self) -> None:
        if self._closed:
            return
        if not self._operation_lock.acquire(timeout=_CLOSE_TIMEOUT_SECONDS):
            self._abort()
            raise TimeoutError("native integrity session did not close")
        try:
            if self._closed:
                return
            self._closed = True
            process = self._process
            if process is None:
                return
            try:
                self._requests.put(_STOP, timeout=_CLOSE_TIMEOUT_SECONDS)
            except Full:
                self._abort()
                raise TimeoutError("native integrity session did not close") from None
            if not self._worker_stopped.wait(_CLOSE_TIMEOUT_SECONDS):
                self._abort()
                raise TimeoutError("native integrity session did not close")
            worker = self._worker
            if worker is not None:
                worker.join(timeout=_WORKER_JOIN_TIMEOUT_SECONDS)
                if worker.is_alive():
                    self._abort()
                    raise TimeoutError("native integrity session did not close")
            try:
                exit_code = process.wait(timeout=_CLOSE_TIMEOUT_SECONDS)
            except TimeoutExpired:
                self._abort()
                raise TimeoutError("native integrity session did not exit") from None
            finally:
                self._close_pipes()
            expected_exit_code = 1 if self._file_error_seen else 0
            if exit_code != expected_exit_code:
                raise OSError("native integrity session exited unsuccessfully")
        finally:
            self._operation_lock.release()

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            self.close()
        except BaseException:
            if exc_type is None:
                raise
        return False
