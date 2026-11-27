# L-Vault integrity session v2 design

## Intent

Add an opt-in long-running mode to `lvault-integrity` so a caller can hash multiple explicit paths without starting a process for each file. `hash-v1` keeps its current arguments, output, and exit behavior. The new mode remains a standalone CLI with no production application wiring.

## Goals and constraints

- Read one path frame, hash that path, write and flush one result, then read another frame.
- Bound each UTF-8 path payload at 65,536 bytes; reject malformed, unsupported, oversized, or truncated frames deterministically.
- Preserve valid Windows path text as Unicode without lossy conversions. Reject non-UTF-8 input rather than guessing; valid UTF-8 is converted directly to the platform path representation.
- Preserve native file I/O error kinds and raw OS codes in the result record.
- Use synthetic process integration tests, existing dependencies, and E:-only task outputs/caches/temp files.
- Do not touch real vault data, devices, accounts, protected cloning, or production app paths.

## Approaches

- Newline-delimited paths would be simple to inspect but require escaping to represent all supported path text safely.
- A versioned length-prefixed frame is bounded and unambiguous. This design selects it and keeps the existing tab-separated, path-free output style for responses.

## Protocol

Invoke `lvault-integrity hash-session-v2`. Each request is one frame:

```text
version: 1 byte (0x02)
length:  4 bytes, unsigned big-endian UTF-8 byte count (1..=65,536)
path:    exactly `length` bytes of valid UTF-8
```

The process handles one frame at a time. It does not queue decoded paths; after each result it flushes stdout before it reads the next frame. A caller should wait for that reply before sending its next path. EOF between frames is a clean stop; EOF inside a frame is a protocol error. Unsupported version, empty/oversized frame, invalid UTF-8, and truncation produce a fixed stderr diagnostic and exit code 64. A file operation error produces a result and the process continues; after clean EOF, its exit code is 1 if any file operation failed, otherwise 0.

Each valid request gets exactly one response line, with a zero-based index:

```text
v2<TAB>index<TAB>ok<TAB>lowercase-sha256<LF>
v2<TAB>index<TAB>missing<TAB>raw-os-error-or--<LF>
v2<TAB>index<TAB>io<TAB>raw-os-error-or--<LF>
```

The path is never echoed. UTF-8 supports ordinary Windows path text, including spaces and Unicode scalar values. Ill-formed UTF-16 values and non-UTF-8 Unix path bytes cannot be represented by this protocol and are rejected rather than translated lossily. Platform-specific path length and file-access limits remain native I/O errors.

## Acceptance and non-goals

Process tests will prove multiple lockstep requests, spaces and Unicode, exact digest and native error output, clean EOF after an early stop, and deterministic rejection of malformed, oversized, and truncated frames. `hash-v1` regressions stay covered by its existing tests. Performance measurement and Python/application integration are out of scope; the mode only removes repeated process startup when a caller opts into a persistent session.
