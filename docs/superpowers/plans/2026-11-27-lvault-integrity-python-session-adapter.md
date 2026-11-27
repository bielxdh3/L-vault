# L-Vault Python Session Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task by task. Steps use checkbox syntax for tracking.

**Goal:** Add a caller-opted, context-managed Python callable that uses the existing Rust `hash-session-v2` protocol as `verify_vault(hash_file=...)`.

**Architecture:** Add one standard-library-only module that accepts an already-trusted absolute executable, sends one bounded UTF-8 request, and validates one bounded response before returning or raising a path-free `OSError`. The capability is not wired into defaults, CLI, packaging, verification, or recovery; focused synthetic tests and a specialized usage document are the only other deliverables.

**Tech Stack:** Python standard library, pytest, existing Rust `lvault-integrity` executable when already built.

**Spec:** User-approved implementation request; wire contract in `native/integrity/README.md` and `docs/superpowers/specs/2026-11-26-lvault-integrity-session-v2-design.md`.

## Global Constraints

- Use only the checked out E: worktree and already available toolchain/cache; do not install dependencies.
- Do not change defaults, CLI, `verify.py`, recovery, release, packaging, or installer code.
- Do not access real vault data, accounts, devices, protected cloning, permissions, or security settings.
- Spawn the trusted absolute binary directly with `shell=False`; do not discover it through PATH/config or fall back to Python hashing.
- Send requests sequentially, only when the callable is invoked; preserve the exact `verify_vault` sampling boundary.
- Bound path/reply sizes and every request, close, process wait, and thread join; preserve a primary exception if cleanup also fails.
- Make one local commit with exactly one `Co-authored-by: Codex <codex@openai.com>` trailer; do not push, merge, release, or publish.

## Review Focus

- Relative executable paths must fail before process creation.
- UTF-8 byte lengths, Unicode, the 65,536-byte limit, and oversize paths must be handled without lossy conversion.
- Version, index, status, digest, raw OS code, truncation, and oversized output must be rejected on malformed replies.
- Missing and I/O replies must preserve the raw code in path-free Python `OSError` semantics.
- Blocked reads/writes and close must time out, terminate the child, and keep cleanup bounded without masking the original exception.

---

### Task 1: Add the opt-in Python hash-session client

**Files:**
- Create: `src/localvault/native_integrity.py`
- Test: `tests/test_native_integrity.py`
- Create: `docs/native-integrity-python-session.md`
- Create: this implementation plan and its ignored SDD ledger.

**Interfaces:**
- Consumes: `lvault-integrity hash-session-v2`; `verify_vault(..., hash_file: Callable[[Path], str])`.
- Produces: `NativeIntegrityHashSession(executable)` with `__enter__`, `__exit__`, `close`, and `__call__(path: Path) -> str`.

- [x] Write and run a failing test for explicit absolute executable launch, one-request/one-reply framing, and zero-based sequencing.
- [x] Implement the minimum launch and lockstep callable path; run the focused test green.
- [x] Add and run failing tests for Unicode/maximum/oversize request bytes, malformed response fields, and raw OS error mapping; implement bounded parsing and path-free errors; rerun green.
- [x] Add and run failing tests for sample-limit sequencing, normal close, blocked-response timeout, close timeout, and primary-error preservation; implement bounded cleanup and rerun green.
- [x] Add the specialized doc describing explicit opt-in construction, safe `verify_vault` usage, protocol limits, and the absence of default activation.
- [x] Run the focused synthetic tests and `git diff --check`; no already-built local locked executable was available, so no native executable validation was run.
- [x] Review the final diff, commit the scoped files with the exact trailer, and verify commit metadata. Do not push or merge.
