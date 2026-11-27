# Native integrity CLI contract

## Usage

```text
lvault-integrity hash-v1 <path> [<path> ...]
```

Pass 1–256 paths as separate arguments. Paths may contain spaces or Unicode. Output is tab-separated, in input order, and does not echo paths:

```text
v1<TAB>index<TAB>ok<TAB>lowercase-sha256
v1<TAB>index<TAB>missing<TAB>raw-os-error-or--
v1<TAB>index<TAB>io<TAB>raw-os-error-or--
```

Exit status is `0` when every file is hashed, `1` when a file operation fails, and `64` for an invalid command or path count. Result indices are zero-based.

## Session mode

`hash-session-v2` keeps one process open for multiple paths. Send each path on stdin as a frame containing a version byte (`0x02`), an unsigned 4-byte big-endian UTF-8 byte length, then exactly that many path bytes. Lengths must be 1 through 65,536 bytes. The process reads one frame, hashes only that path, writes and flushes its reply, and then waits for the next frame. Send the next request only after receiving the prior reply.

Valid UTF-8 path text, including spaces and Unicode, is passed directly to the platform path API. Invalid UTF-8 is rejected; paths that cannot be represented as UTF-8 are unsupported rather than converted lossily. The protocol does not normalize path text or echo paths.

Each valid request gets one zero-based response line:

```text
v2<TAB>index<TAB>ok<TAB>lowercase-sha256
v2<TAB>index<TAB>missing<TAB>raw-os-error-or--
v2<TAB>index<TAB>io<TAB>raw-os-error-or--
```

EOF between frames ends the session cleanly. A truncated frame, unsupported version, empty path, oversized path, or invalid UTF-8 exits with status `64` and a fixed diagnostic on stderr. File operation errors are reported in their response and do not prevent later requests; after clean EOF, the process exits `1` if any file operation failed and `0` otherwise. A stdin I/O error exits `1` and reports its raw OS code on stderr.

Build and run the crate checks from the repository root:

```powershell
cargo fmt --check --manifest-path native/integrity/Cargo.toml
cargo test --locked --offline --manifest-path native/integrity/Cargo.toml
```

See the [prototype engineering notes](native-integrity-prototype.md) for implementation measurements, local validation context, and future packaging considerations.
