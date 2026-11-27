# Native integrity prototype engineering notes

This document records local engineering evidence and future integration considerations for the standalone Rust integrity crate. It is not a performance guarantee or a release plan.

## Local batch launch measurement

On Windows 11 with Python 3.14.4, seven timed repetitions per mode compared one process for a batch of synthetic 4 KiB files with one direct `subprocess.run(..., shell=False)` per file. The warm-up hashed the fixtures before timing. Elapsed time includes Python and executable process startup; this is a local warm-cache measurement.

| Files | One batch median | One process per file median | Batch elapsed reduction |
| ---: | ---: | ---: | ---: |
| 1 | 7.320 ms | 7.536 ms | 2.9% |
| 8 | 9.469 ms | 60.247 ms | 84.3% |
| 32 | 14.342 ms | 247.374 ms | 94.2% |

This measures launch amortization and does not remeasure the earlier hash-only benchmark, which excluded process startup.

## Local validation context

The final Python application boundary remains `python -m localvault verify --root <synthetic-vault> [--sample-limit N]`. Run it against disposable synthetic data on every supported Python runtime. Python's existing `Path.exists()` probe must remain in the adapter: Python 3.12 and 3.14 do not have identical existence-probe behavior, and Rust tests after that probe do not establish parity. The recorded checkout did not have Python 3.12 installed, so its local validation covered only Python 3.14.

## Packaging proposal for a later integration

Keep the Rust crate independent and prebuild a platform-specific executable as an optional package artifact in the matching Python wheel. Enable it only through an explicit user opt-in; call it with an argument list and no shell. Do not compile, download, or silently fall back at runtime. Leave the default Python path and its existence check authoritative. If an opted-in artifact is absent or has an unsupported protocol version, report that condition instead of changing behavior.

Before enabling packaging, validate the final installed entry point with `python -m localvault verify --root <synthetic-vault>` on Python 3.12 and 3.14. No Python adapter or packaging change is part of this prototype.
