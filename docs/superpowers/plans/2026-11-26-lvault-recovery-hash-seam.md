# L-Vault recovery hash seam implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task by task. Steps use checkbox syntax for tracking.

**Goal:** Let the existing synthetic recovery drill exercise a caller-provided hash function through source verification and copied-fixture verification, while retaining the default Python behavior.

**Architecture:** Add one keyword-only callable seam to `run_recovery_test` and pass it to `verify_vault` and `_restore_matches_index`. Tests compare the canonical public report from the default, an injected Python hasher, and—when the exact local Cargo output exists—the actual `hash-v1` binary. No executable resolver, CLI option, production binary selection, or report change is introduced.

**Tech Stack:** Python 3.12+, pytest, existing Rust `lvault-integrity` binary contract.

**Spec:** User-approved recovery hash seam request in this task; base commit `63901460eaa19a3f1e045f57c3bdcb67909c2b0b`.

## Approaches

1. Leave recovery verification entirely on its default hasher. This preserves current behavior but cannot exercise caller-provided hashing through the existing drill.
2. Add a keyword-only callable seam and pass it through the two existing hash boundaries. This is the selected design: it changes no CLI, report, or runtime-selection contract.
3. Resolve or select the Rust executable from application settings or paths. This is excluded because no production packaging/trust decision is authorized.

## Global Constraints

- Work only in `E:\WorkTrees\gptop02-lvault-rust-recovery` on `gptop02/rust-recovery-parity`.
- Limit tracked changes to `src/localvault/recovery.py`, directly related tests, and specialized docs.
- Keep CLI, default Python hasher, report schema, ingest, restore control, and security/path checks unchanged.
- Do not expose an executable path or add device, user, settings, or production runtime-selection behavior.
- Use only bounded synthetic fixtures and keep temporary files/build outputs on E:; do not install tools or dependencies.
- No push, merge, protected clone, authentication, or live-vault access.
- Make one local commit with exactly one `Co-authored-by: Codex <codex@openai.com>` trailer.

## Review Focus

- An injected callable is used for both indexed source files and restored copies; assert observed call paths include both sides of the synthetic drill.
- Hash exceptions still propagate from the recovery drill instead of being converted into a passing report.
- Public output remains byte-for-byte equivalent between default and injected hashing.
- Optional binary parity runs only when the exact local crate build artifact exists; otherwise pytest records an intentional skip.
- The recovery CLI and existing path-containment checks remain on their current default path.

---

### Task 1: Inject the recovery hash function and prove report parity

**Files:**

- Modify: `src/localvault/recovery.py`
- Test: `tests/test_recovery.py`
- Modify: this specialized plan with final evidence

**Interfaces:**

- Produces: `run_recovery_test(*, hash_file: Callable[[Path], str] = sha256_file) -> dict[str, object]`.
- The same callable verifies indexed vault files and restored fixture files.

- [x] Add a recovery test comparing the complete default and injected public reports and asserting the injected callable saw both source and restored paths.
- [x] Run the focused test and confirm it fails because `run_recovery_test` does not accept injection.
- [x] Add a failure-propagation test that raises only while hashing a restored copy; confirm it also fails before the seam exists.
- [x] Add the keyword-only argument and pass it through both verification points.
- [x] Run the two new seam tests and confirm both pass.
- [x] Add an optional binary parity test for the exact `native/integrity/target/debug/lvault-integrity[.exe]` output, with a two-second subprocess bound and synthetic fixture paths. Skip when no regular local build exists or the exact path is a symlink.
- [x] Confirm the optional binary test skips because that exact local build is absent; no binary was resolved elsewhere or built through a C:-hosted Cargo cache.
- [x] Run the directly related recovery and verifier tests, record exact skip reasons, inspect scope and Git status, then create the authorized local commit.

## Verification and limitations

- RED: each new recovery seam test failed before implementation with `TypeError: run_recovery_test() got an unexpected keyword argument 'hash_file'`.
- GREEN: both seam tests passed after forwarding the callable through `verify_vault` and `_restore_matches_index`.
- Focused recovery and verifier files: **20 passed, 2 skipped**. Skips: the optional binary comparison had no exact local debug build at `native/integrity/target/debug`; the existing Windows short-name test skipped because the E: volume does not provide a distinct 8.3 alias.
- Final serialization assertion check: **2 passed, 1 skipped**; the skip was the same absent local debug build.
- The Rust binary comparison is implemented but was not exercised. No binary was available; a Cargo build was not attempted because the installed Cargo home is unset and its default cache would be on C:, outside the E:-only task boundary.
- The full repository pytest suite was not run; validation stayed on the directly affected recovery and verifier files.
- Author self-review found no blocking issues. A separate reviewer was not dispatched because the user explicitly prohibited nested workers.
