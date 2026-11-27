# L-Vault integrity session v2 implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add a backward-compatible lockstep stdin session to `lvault-integrity`.

**Architecture:** Add a separate `hash-session-v2` command that reads a version byte, bounded big-endian UTF-8 length, and one path payload at a time. It reuses `sha256_file`, flushes the existing path-free tab-separated result shape after every request, and leaves `hash-v1` behavior unchanged.

**Tech Stack:** Rust 2024, standard library stdin/stdout/process APIs, existing `sha2` dependency.

**Spec:** [L-Vault integrity session v2 design](../specs/2026-11-26-lvault-integrity-session-v2-design.md)

## Global Constraints

- Frame version is `0x02`; the unsigned big-endian UTF-8 path length is 1 through 65,536 bytes.
- Read, hash, reply, and flush each path before reading the next frame.
- Preserve native file I/O status and raw OS error code; do not echo paths or perform lossy conversion.
- Add no dependencies or application wiring; keep all generated work on E:.
- Commit locally with exactly one `Co-authored-by: Codex <codex@openai.com>` trailer; do not push, create a PR, merge, release, or deploy.

## Review Focus

- A frame with exactly 65,536 bytes must be accepted; 65,537 must be rejected before payload allocation or path access.
- Valid Unicode path text must reach native path handling without normalization or replacement characters.
- A request following a file error must still be read and receive its own ordered response.
- EOF is valid only at a frame boundary; partial header and partial payload must fail deterministically.
- Existing `hash-v1` results and argument-count rejection must remain unchanged.

---

### Task 1: Add the session protocol and document it

**Files:**
- Create: `native/integrity/tests/session_contract.rs`
- Modify: `native/integrity/src/main.rs`
- Modify: `native/integrity/README.md`
- Preserve: `native/integrity/src/lib.rs` hashing behavior and existing `hash-v1` contract

**Interfaces:**
- Consumes: `lvault_integrity::sha256_file` and the `hash-v1` command contract.
- Produces: `lvault-integrity hash-session-v2`, request frame `[0x02][u32 BE byte length][UTF-8 path]`, and one flushed `v2\t<index>\t<status>\t<value>\n` result per valid frame.

- [x] Write process integration tests for lockstep multiple requests with spaces and Unicode, exact SHA-256 output, clean EOF after an early stop, native error-code output followed by a later successful path, and malformed/oversized/truncated/invalid-UTF-8 frames.
- [x] Run `cargo test --locked --offline --manifest-path native/integrity/Cargo.toml --test session_contract`; observe a behavioral failure because `hash-session-v2` is not implemented.
- [x] Implement dispatch and the incremental session loop in `native/integrity/src/main.rs`; reject unsupported input with fixed stderr diagnostics and exit code 64, preserve native file errors, and flush each result before reading another frame.
- [x] Document the command, frame bounds, UTF-8 limitation, clean/truncated EOF rules, response records, and lockstep requirement in `native/integrity/README.md`.
- [x] Run `cargo fmt --check --manifest-path native/integrity/Cargo.toml` and `cargo test --locked --offline --manifest-path native/integrity/Cargo.toml`; formatting and the complete crate test suite passed, including existing `hash-v1` tests.
- [x] Review and commit the verified task with the exact attribution trailer; confirm the commit SHA and trailer, then complete the whole-branch review.

## Review record

- Implementation commit reviewed: `1e6ce8e1d3a737543480eeb1431f51622a6099bb`.
- Independent review: approved; no critical or important findings.
- Deferred minor: the lockstep integration tests use blocking `read_line`; a future regression that waits for the next request before replying could leave that test waiting.
- Validation ran on Windows: `cargo fmt --check --manifest-path native/integrity/Cargo.toml` passed; `cargo test --locked --offline --manifest-path native/integrity/Cargo.toml` passed 17 tests.
- Linux parity, throughput benchmarking, and remote CI were not run.
