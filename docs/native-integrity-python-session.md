# Python native integrity session client

`NativeIntegrityHashSession` is an opt-in capability for passing a caller-selected trusted absolute `lvault-integrity` executable to `verify_vault` as its `hash_file` callable. The default hasher, configuration, packaging, and recovery flow remain unchanged.

## Usage

Choose the executable in trusted caller code and pass it directly. The client does not search PATH or configuration, resolve a substitute, or fall back to Python hashing.

```python
from pathlib import Path

from localvault.native_integrity import NativeIntegrityHashSession
from localvault.verify import verify_vault

trusted_executable = Path(r"E:\build\lvault-integrity.exe")
with NativeIntegrityHashSession(trusted_executable) as hash_file:
    report = verify_vault(
        paths,
        report,
        sample_limit=sample_limit,
        hash_file=hash_file,
    )
```

Each callable invocation hashes exactly one path and waits for its reply before returning. `verify_vault` controls which paths it visits, including its existing sample limit; the client does not queue or prefetch paths. Use the context manager so stdin receives EOF and the child process is closed within bounded waits. If verification raises an exception, a cleanup error does not replace that original exception.

## Verify CLI opt-in

The `verify` command can opt into the persistent Rust session by receiving both an explicit absolute executable path and its SHA-256 pin:

```text
localvault verify --root E:\LocalVault --sample-limit 1 --native-exe E:\build\lvault-integrity.exe --native-sha256 <64-hex-digest>
```

Both `--native-exe` and `--native-sha256` are required together. The command rejects malformed pins, non-matching files, relative or non-normalized paths, non-regular files, and paths that traverse symlinks, junctions, or reparse points before starting the executable. It does not search PATH or configuration and does not fall back to Python hashing when native verification is requested. Without either option, the existing Python hasher remains the default.

Native validation, session startup, hashing, and teardown run inside the normal persisted verify report boundary. A startup or teardown error is recorded as a failed report and produces the existing failed-command exit code. Full and sampled verification keep their existing modes, sampling rules, and report format.

## Protocol and errors

The client invokes the absolute executable as `hash-session-v2` with `shell=False`. A request contains version byte `0x02`, an unsigned four-byte big-endian UTF-8 byte length, and one path of 1 through 65,536 bytes. Paths are encoded strictly as UTF-8, including Unicode; lossy conversion is not used.

For every request, the client validates the response version, zero-based index, status, digest or raw OS code, and the bounded response line. `ok` returns a lowercase SHA-256 digest. `missing` raises `FileNotFoundError`; `io` raises `OSError`. On POSIX, the raw OS code is preserved in `errno`. On Windows, the raw OS code is preserved in `winerror`, while `missing` keeps `errno` set to `ENOENT`. Error messages are fixed and do not include the path. Native file errors do not poison a valid session, though `verify_vault` itself propagates the error as it does for its current hash callback.

Each request has a 15-minute timeout. Session close, process termination waits, and worker joins are also bounded. If the executable is unavailable or speaks a different protocol, the call fails; no alternate hasher is selected.

## Scope

This client only reads the explicit paths passed to its callable. It does not modify files. It remains a capability for a trusted caller and does not activate native hashing in application defaults or user-facing commands.
