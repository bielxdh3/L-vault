# L-Vault integrity executable prototype

This crate remains an opt-in local prototype. The Python application, its catalog API, and its current verification flow are unchanged. The executable reads only the explicit file paths passed to it; it does not search for paths, invoke a shell, or write to the files it hashes.

## Version 1 interface

```text
lvault-integrity hash-v1 <path> [<path> ...]
```

Pass paths as separate process arguments. Up to 256 paths are accepted per process, including paths containing spaces or Unicode. The output has one tab-separated record per input, in input order, without echoing the path:

```text
v1<TAB>index<TAB>ok<TAB>lowercase-sha256
v1<TAB>index<TAB>missing<TAB>raw-os-error-or--
v1<TAB>index<TAB>io<TAB>raw-os-error-or--
```

Exit status is `0` when every path hashes, `1` when one or more file operations fail, and `64` for an invalid command or a batch outside the 1–256 path bound. The zero-based index maps each result to its argument. `missing` means a file operation returned `NotFound`; other file errors use `io`. Raw OS codes are decimal, with `-` only when the platform supplies no raw code. A caller can batch paths in one direct process invocation and avoid one process launch per file.

## Local batch launch measurement

On Windows 11 with Python 3.14.4, seven timed repetitions per mode compared one process for a batch of synthetic 4 KiB files with one direct `subprocess.run(..., shell=False)` per file. The warm-up hashed the fixtures before timing. Elapsed time includes Python and executable process startup; it is a local warm-cache measurement, not a general performance guarantee.

| Files | One batch median | One process per file median | Batch elapsed reduction |
| ---: | ---: | ---: | ---: |
| 1 | 7.320 ms | 7.536 ms | 2.9% |
| 8 | 9.469 ms | 60.247 ms | 84.3% |
| 32 | 14.342 ms | 247.374 ms | 94.2% |

This measures launch amortization and does not remeasure the earlier hash-only benchmark, which excluded process startup.

## Local checks

Run the Rust crate checks without resolving or changing dependencies:

```powershell
cargo fmt --check --manifest-path native/integrity/Cargo.toml
cargo test --locked --offline --manifest-path native/integrity/Cargo.toml
```

The final Python application boundary remains `python -m localvault verify --root <synthetic-vault> [--sample-limit N]`. Run it against disposable synthetic data on every supported Python runtime. In particular, keep Python's existing `Path.exists()` probe in the adapter: Python 3.12 and 3.14 do not have identical existence-probe behavior, and Rust tests after that probe do not establish parity. The current checkout has no Python 3.12 interpreter installed, so local validation can cover only the installed Python 3.14 runtime.

## Minimal packaging plan for a later integration

Keep the Rust crate independent and prebuild a platform-specific executable as an optional package artifact in the matching Python wheel. Enable it only through an explicit user opt-in; call it with an argument list and no shell. Do not compile, download, or silently fall back at runtime. Leave the default Python path and its existence check authoritative. If an opted-in artifact is absent or has an unsupported protocol version, report that condition instead of changing behavior. Validate the final installed entry point with `python -m localvault verify --root <synthetic-vault>` on Python 3.12 and 3.14 before enabling packaging; no Python adapter or packaging change is part of this prototype.
