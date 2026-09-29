"""Narrow cross-process cancellation gate for a destructive clone job."""

from __future__ import annotations

import ctypes
import os
import re
import threading
from contextlib import contextmanager
from typing import Iterator


JOB_ID_PATTERN = re.compile(r"[a-f0-9]{32}\Z")
SID_PATTERN = re.compile(r"S-1-\d+(?:-\d+)+\Z")
MUTEX_MODIFY_STATE = 0x00000001
SYNCHRONIZE = 0x00100000
MUTEX_ALL_ACCESS = 0x001F0001
EVENT_MODIFY_STATE = 0x00000002
EVENT_ALL_ACCESS = 0x001F0003
WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF
ERROR_ALREADY_EXISTS = 183


class CloneCancelGateError(RuntimeError):
    """Raised when the cross-process destructive-boundary gate is unavailable."""


def _mutex_name(job_id: str) -> str:
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise CloneCancelGateError("invalid clone job id")
    return f"Local\\L-vault-CloneCancel-{job_id}"


def _mutex_sddl(owner_sid: str) -> str:
    if not SID_PATTERN.fullmatch(owner_sid) or owner_sid in {
        "S-1-1-0",  # Everyone
        "S-1-5-18",  # Local System
        "S-1-5-32-544",  # Builtin Administrators
        "S-1-5-32-545",  # Builtin Users
    }:
        raise CloneCancelGateError("invalid installed owner SID")
    return f"D:P(A;;0x{MUTEX_ALL_ACCESS:08X};;;SY)(A;;0x{MUTEX_ALL_ACCESS:08X};;;BA)(A;;0x{SYNCHRONIZE | MUTEX_MODIFY_STATE:08X};;;{owner_sid})"


def _event_name(job_id: str) -> str:
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise CloneCancelGateError("invalid clone job id")
    return f"Local\\L-vault-CloneCancelSignal-{job_id}"


def _event_sddl(owner_sid: str) -> str:
    _mutex_sddl(owner_sid)  # Apply the same strict owner-SID validation.
    return f"D:P(A;;0x{EVENT_ALL_ACCESS:08X};;;SY)(A;;0x{EVENT_ALL_ACCESS:08X};;;BA)(A;;0x{SYNCHRONIZE | EVENT_MODIFY_STATE:08X};;;{owner_sid})"


def _close_native_handle(kernel, handle) -> None:
    close = kernel.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = ctypes.c_int
    close(ctypes.c_void_p(int(handle)))


class CloneCancelGate:
    """Owner-restricted cancellation event plus mutex for phase serialization."""

    def __init__(self, job_id: str, owner_sid: str, *, create: bool):
        self.name = _mutex_name(job_id)
        self.event_name = _event_name(job_id)
        self._handle: int | None = None
        self._event_handle: int | None = None
        self._lock: threading.RLock | None = None
        self._cancelled = False
        if os.name != "nt":
            self._lock = threading.RLock()
            return

        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel = kernel
        if create:
            sddl = _mutex_sddl(owner_sid)
            descriptor = ctypes.c_void_p()
            convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
            convert.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
            convert.restype = ctypes.c_int
            if not convert(sddl, 1, ctypes.byref(descriptor), None):
                raise ctypes.WinError(ctypes.get_last_error())

            class SecurityAttributes(ctypes.Structure):
                _fields_ = [("nLength", ctypes.c_uint32), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", ctypes.c_int)]

            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, 0)
            try:
                create_mutex = kernel.CreateMutexW
                create_mutex.argtypes = [ctypes.POINTER(SecurityAttributes), ctypes.c_int, ctypes.c_wchar_p]
                create_mutex.restype = ctypes.c_void_p
                ctypes.set_last_error(0)
                handle = create_mutex(ctypes.byref(attributes), 0, self.name)
                error = ctypes.get_last_error()
                if not handle:
                    raise ctypes.WinError(error)
                if error == ERROR_ALREADY_EXISTS:
                    _close_native_handle(kernel, handle)
                    raise CloneCancelGateError("clone cancellation mutex already exists")
                self._handle = int(handle)

                create_event = kernel.CreateEventW
                create_event.argtypes = [ctypes.POINTER(SecurityAttributes), ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
                create_event.restype = ctypes.c_void_p
                ctypes.set_last_error(0)
                event_handle = create_event(ctypes.byref(attributes), 1, 0, self.event_name)
                error = ctypes.get_last_error()
                if not event_handle:
                    raise ctypes.WinError(error)
                if error == ERROR_ALREADY_EXISTS:
                    _close_native_handle(kernel, event_handle)
                    raise CloneCancelGateError("clone cancellation event already exists")
                self._event_handle = int(event_handle)
            except Exception:
                self.close()
                raise
            finally:
                kernel.LocalFree.argtypes = [ctypes.c_void_p]
                kernel.LocalFree.restype = ctypes.c_void_p
                kernel.LocalFree(descriptor)
        else:
            open_mutex = kernel.OpenMutexW
            open_mutex.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
            open_mutex.restype = ctypes.c_void_p
            handle = open_mutex(SYNCHRONIZE | MUTEX_MODIFY_STATE, 0, self.name)
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            self._handle = int(handle)
            open_event = kernel.OpenEventW
            open_event.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
            open_event.restype = ctypes.c_void_p
            event_handle = open_event(SYNCHRONIZE | EVENT_MODIFY_STATE, 0, self.event_name)
            if not event_handle:
                self.close()
                raise ctypes.WinError(ctypes.get_last_error())
            self._event_handle = int(event_handle)

    @contextmanager
    def locked(self) -> Iterator[None]:
        if self._lock is not None:
            with self._lock:
                yield
            return
        if self._handle is None:
            raise CloneCancelGateError("clone cancellation mutex is closed")
        wait = self._kernel.WaitForSingleObject
        wait.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        wait.restype = ctypes.c_uint32
        result = int(wait(ctypes.c_void_p(self._handle), INFINITE))
        if result not in (WAIT_OBJECT_0, WAIT_ABANDONED):
            if result == WAIT_FAILED:
                raise ctypes.WinError(ctypes.get_last_error())
            raise CloneCancelGateError("clone cancellation mutex wait failed")
        try:
            yield
        finally:
            release = self._kernel.ReleaseMutex
            release.argtypes = [ctypes.c_void_p]
            release.restype = ctypes.c_int
            if not release(ctypes.c_void_p(self._handle)):
                raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self._event_handle is not None:
            close = self._kernel.CloseHandle
            close.argtypes = [ctypes.c_void_p]
            close.restype = ctypes.c_int
            close(ctypes.c_void_p(self._event_handle))
            self._event_handle = None
        if self._handle is not None:
            close = self._kernel.CloseHandle
            close.argtypes = [ctypes.c_void_p]
            close.restype = ctypes.c_int
            close(ctypes.c_void_p(self._handle))
            self._handle = None

    def signal_cancel(self) -> None:
        if self._lock is not None:
            self._cancelled = True
            return
        if self._event_handle is None:
            raise CloneCancelGateError("clone cancellation event is closed")
        set_event = self._kernel.SetEvent
        set_event.argtypes = [ctypes.c_void_p]
        set_event.restype = ctypes.c_int
        if not set_event(ctypes.c_void_p(self._event_handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def is_cancelled(self) -> bool:
        if self._lock is not None:
            return self._cancelled
        if self._event_handle is None:
            raise CloneCancelGateError("clone cancellation event is closed")
        wait = self._kernel.WaitForSingleObject
        wait.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        wait.restype = ctypes.c_uint32
        result = int(wait(ctypes.c_void_p(self._event_handle), 0))
        if result == WAIT_OBJECT_0:
            return True
        if result == WAIT_TIMEOUT:
            return False
        if result == WAIT_FAILED:
            raise ctypes.WinError(ctypes.get_last_error())
        raise CloneCancelGateError("clone cancellation event wait failed")

    def __enter__(self) -> "CloneCancelGate":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()
