# L-Vault Rust integrity slice implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task by task. Steps use checkbox syntax.

**Goal:** Add an independently testable, portable Rust library for read-only streaming SHA-256 file verification while leaving Python CLI, reporting, restore writes, and runtime selection unchanged.

**Architecture:** Put a small library crate in `native/integrity` and use RustCrypto `sha2` for SHA-256. The Python package is setuptools-only and has no Rust packaging path, so this slice will not build, discover, or invoke a Rust executable. Python remains the runtime source of truth until a later, separately gated packaging decision.

**Tech Stack:** Existing Python 3.12+ CLI; Rust 1.88+ library using `sha2 = 0.11.2`; synthetic pytest and Cargo tests. The crate version is pinned in its manifest and lockfile. Cargo confirmed that this sha2 release requires Rust 1.88. The official [sha2 crate docs](https://docs.rs/crate/sha2/0.11.2) describe the maintained RustCrypto implementation as pure Rust with a portable software backend.

**Spec:** Current user request; base commit `7a214f1cee0eba481b00f1bf5ea46409e77cd798` on `gptop02/rust-integrity-foundation`.

## Global constraints

- Work only in `E:\WorkTrees\gptop02-lvault-rust-integrity`; preserve the supplied worktree and all evidence.
- No system software installation, live-vault or personal-data access, original checkout access, device access, network/service changes, credentials, or agents.
- Keep task temp roots, Cargo registry/build output, Python bytecode, and pytest temp/cache roots on E:.
- Use synthetic fixtures. Production verification opens and reads files only; it does not write, copy, create directories, invoke processes, or fall back after errors.
- Leave SQLite, Python restore writes, auth/TLS, ingestion, scheduling, clone worker, and `native/vss_snapshot` unchanged.
- Preserve exact lowercase 64-character SHA-256 output, missing-file errors, corruption mismatch behavior, and current Python sample/report/CLI semantics.
- Do not integrate a Rust binary unless its selection and packaging are fixed, trusted, and straightforward. No arbitrary executable discovery or implicit fallback.
- No pure language rewrite and no unmeasured performance or safety claims. Parent reviews and publishes; do not push, merge, post, or change protections.

## Approaches

1. **Package and opt in to a Rust binary.** This would require a Python build hook, platform-specific artifacts, and a trusted exact binary-selection rule that the current setuptools package does not have. It adds packaging and integrity risk to a first slice.
2. **Add an independent Rust library and parity tests.** It proves the streaming hash boundary without changing Python behavior or selecting an executable. This is the recommended choice and the user's specified fallback when equivalence or packaging is not straightforward.

## Review focus

- Empty, short, and multi-chunk files produce exactly 64 lowercase hex characters matching Python `hashlib` vectors.
- Correct expected digests return true; changed contents and case-different or malformed digest strings return false; absent files preserve `NotFound` as an I/O error.
- Verifying a file leaves its contents unchanged and creates no additional files.
- Python sample limits continue counting successful verifications: missing/corrupt rows do not consume the limit, and `sample_limit=0` retains its current unlimited behavior.
- Python `verify_full` / `verify_sample`, report error strings, and restore partial-failure behavior remain unchanged.

---

## Baseline and source distribution

Checkout before edits: clean at `7a214f1cee0eba481b00f1bf5ea46409e77cd798`. The installed Windows toolchain is Python 3.14.4, pytest 9.0.3, Rust 1.97.1, Cargo 1.97.1, and rustfmt 1.9.0. No package was installed. Python 3.12 itself is absent, but 3.14.4 satisfies the repository's Python 3.12+ floor.

| Tracked production-source language | Files | Physical lines |
|---|---:|---:|
| Python | 44 | 17,060 |
| Rust | 5 | 1,240 |
| PowerShell | 5 | 1,152 |
| HTML | 14 | 782 |
| CSS | 2 | 376 |
| JavaScript | 1 | 98 |
| **Total** | **71** | **20,708** |

Post-change tracked production-source distribution, counted with the same git ls-files extension and path-component method after staging the integrity library source:

| Tracked production-source language | Files | Physical lines |
|---|---:|---:|
| Python | 44 | 17,060 |
| Rust | 6 | 1,278 |
| PowerShell | 5 | 1,152 |
| HTML | 14 | 782 |
| CSS | 2 | 376 |
| JavaScript | 1 | 98 |
| **Total** | **72** | **20,746** |

The added Rust integration tests remain excluded because their path contains tests; manifests, lockfiles, documentation, task caches, and evidence are excluded from source counts.

Method: enumerate paths with `git ls-files`; count only `.py`, `.rs`, `.ps1`, `.psm1`, `.cs`, `.c`, `.h`, `.cpp`, `.hpp`, `.js`, `.jsx`, `.ts`, `.tsx`, `.html`, `.css`, `.sh`, `.bash`, `.bat`, `.cmd`, and `.sql` files; exclude any tracked path containing a `tests`, `docs`, or `.github` component. File counts and physical lines are grouped by language; line totals include blank and comment lines. Untracked caches and fixtures are not in the input. The five Rust files at baseline belong to `native/vss_snapshot` and are out of scope.

Baseline commands and results:

- `py -3.14 -m compileall -q src tests` — exit 0.
- `py -3.14 -m pytest -q` — collection failed because this checkout is not installed into the interpreter (`ModuleNotFoundError: localvault`). No install was attempted.
- With process-scoped `PYTHONPATH=src`, the full suite reached 82%, showed five failures, and stopped making output progress during the bounded observation window; that task-specific process was stopped. It did not produce a final summary, so the full pre-change pytest result is incomplete.
- Focused synthetic contract baseline: `tests/test_atomic_safety.py`, `tests/test_recovery.py`, `tests/test_restore.py`, `tests/test_reports.py`, and `tests/test_cli_exit_codes.py` — **33 passed, 1 skipped** in 92.46 seconds.

Verified Python contracts: indexed missing paths report `Indexed file is missing`; changed bytes report `SHA-256 mismatch`; corrupt/missing restore sources produce a partial result and are not restored; restore planning and dry run do not create the destination; conflicts skip by default; full verification is the daily-backup behavior. Sampling stops after the requested number of successful indexed files, so errors do not consume the sample count; zero remains unlimited because the current verifier tests the limit by truthiness. No Python behavior change is planned.

## Task 1: characterize the Python verification contract

**Files:**

- Create: `tests/test_verify.py`
- Existing contracts exercised: `tests/test_recovery.py`, `tests/test_restore.py`, `tests/test_reports.py`, `tests/test_cli_exit_codes.py`

**Interfaces:** Existing `verify_vault(VaultPaths, RunReport, dry_run=False, sample_limit=None)` and CLI `verify --root ... [--sample-limit N]` remain unchanged.

- [x] Add `test_verify_sample_limit_counts_successful_rows_only`: index, in order, a missing file, a corrupt file, one valid file, and a later corrupt file; call `verify_vault(..., sample_limit=1)` and assert one imported, two failures with the exact existing messages/paths, and no failure for the later row.
- [x] Add `test_verify_zero_sample_limit_remains_unlimited`: call `verify_vault(..., sample_limit=0)` over one valid and one corrupt row; assert both are visited, with one imported and one failure.
- [x] Add `test_verify_cli_preserves_full_and_sample_report_modes`: invoke `verify` with and without `--sample-limit 1`, assert summary output and persisted run modes `verify_full` and `verify_sample`.
- [x] Run the focused Python contract tests with `PYTHONPATH=src`, Python bytecode cache, pytest cache, and pytest temp root on E:. Result: **36 passed, 1 skipped**; no Python implementation change is included.
- [x] Commit the characterization tests and this initial plan as one local, validated checkpoint with the exact Codex co-author trailer.

## Task 2: add the standalone Rust verifier and migration roadmap

**Files:**

- Create: `native/integrity/Cargo.toml`
- Create: `native/integrity/Cargo.lock`
- Create: `native/integrity/src/lib.rs`
- Create: `native/integrity/tests/file_verification.rs`
- Update: this plan with final source counts and verification evidence.

**Interfaces:**

- `sha256_file(path: impl AsRef<Path>) -> io::Result<String>` returns lowercase SHA-256 hex.
- `verify_file(path: impl AsRef<Path>, expected_sha256: &str) -> io::Result<bool>` returns false on any exact-string digest mismatch; file-open/read failures remain I/O errors, including `NotFound`.

- [x] Add an empty `src/lib.rs` scaffold and write `hashes_empty_and_abc_as_lowercase_sha256` (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` and `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`), `hashes_multichunk_fixture_to_python_hashlib_vector` (`b'a'` repeated 2,097,169 times → `c2273a45bd6d19d2714b8279b1fd1123bb746e7f7f6331085fb6ecaa30164546`, with a matching `verify_file` result), `verify_file_returns_mismatch_without_error` (wrong, uppercase, and malformed expected values return `false`), `verify_file_returns_not_found` (`ErrorKind::NotFound`), and `verify_file_leaves_fixture_unchanged` (same bytes and directory entries) in `native/integrity/tests/file_verification.rs`.
- [x] Run the Cargo test target before adding either public function; RED was exit 101 from unresolved sha256_file and verify_file imports. No existing Python behavior bug was changed or claimed.
- [x] Implement a read-only `File::open` streaming loop using a 1 MiB buffer and `sha2::Sha256`; add no CLI, process invocation, file creation, Python binding, or fallback behavior.
- [x] Run cargo fmt --check, cargo check --locked, and cargo test --locked for native/integrity, with Cargo caches and build output under E:. Final result: fmt and check exit 0; 5 Rust tests passed.
- [x] Run the existing native/vss_snapshot format/check/test gates without editing that component; fmt and check exited 0, and its 3 Rust tests passed. Windows Python compile exited 0; the focused integrity/restore/CLI contracts passed: 36 passed, 1 skipped. The repository-wide pytest outcome and E:-only temp-root limitations are recorded below.
- [x] Recount tracked source files with the baseline method and inspect the staged source changes; the post-change index count is 72 files / 20,746 physical lines.
- [x] Create one coherent local Task 2 commit with the exact Codex co-author trailer; do not push or publish.
- [x] Record verification, source counts, and commit evidence in this plan and the task ledger; retain the worktree and evidence for parent review.

## Post-change verification and limits

- The full Windows Python run completed: 431 passed, 5 failed, 2 skipped in 558.42 seconds. Four failures in tests/test_offline_preparation.py were caused by its synthetic signer home inheriting a tmp_path under the repository and tripping the existing outside-repository guard. Rerunning those four tests once with an E-hosted temporary root outside the checkout passed: 4 passed.
- tests/test_disk_clone.py::test_protected_path_conflict_uses_mount_not_disk_number still fails because its synthetic target mounts E: while tmp_path must also be on E: under the task constraint; the production path-conflict function therefore correctly sees that file as on the target volume. No test or production behavior was changed to hide this conflict.
- The pre-change full pytest run was incomplete: it showed five failures at 82% but produced no final summary before its bounded stop. The equal failure count is not proof the failing cases are identical.
- New Rust parity tests followed RED-to-GREEN: the test-only crate failed to compile with unresolved public imports (exit 101), then the implemented crate passed all five tests. No pre-existing behavior bug was fixed.
- native/vss_snapshot was not edited. No performance benefit was measured or claimed.

## Sequential migration candidates and retention gates

1. **Read-only catalog/reporting (candidate after this slice):** expose existing indexed file metadata and summary/report calculations as a read-only Rust boundary. Python retains SQLite ownership, schema/migrations, report persistence, CLI, and error formatting. Require exact row-order, count, missing/corrupt, and serialized-report parity using synthetic fixtures before considering opt-in use.
2. **Recovery planning (candidate after catalog parity):** calculate restore candidates and conflict decisions from a read-only catalog snapshot. Keep destination validation, staging, copy/overwrite/rename, manifests, and all restore writes in Python. Require deterministic plan parity for traversal, links/reparse points, missing/corrupt files, conflicts, and low-space outcomes before any further decision.

Retain Python for SQLite writes/schema, ingest, scheduling, auth/TLS, UI/CLI/report contracts, restore and replica writes, and all clone/VSS behavior unless a later slice demonstrates complete behavioral parity and a trusted, supported packaging path. A future integration must use an exact package-contained artifact with verified build provenance and no path search or fallback; it must retain Python error mapping and be opt-in until all supported-platform gates pass. Gate each candidate on Python 3.12+ Windows compile/full pytest, Rust fmt/check/test on Windows, and portable Rust compile/test on Linux and macOS; run minimum-supported Rust 1.88 and current stable. Measure equivalent synthetic workloads before making any performance claim. Do not plan a pure-language rewrite.
