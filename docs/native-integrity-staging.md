# Local staging proof for the Rust integrity binary

This procedure builds the standalone `native/integrity` binary from a verified Git revision and places the executable, Cargo target output, and provenance manifest in a fresh run directory under an E: scratch root.

The helper is limited to the installed native Windows target. It checks that the requested source commit is an ancestor of `HEAD`, that every tracked crate file matches that commit, and that the crate has no untracked or ignored files. It requires the requested target to match the host reported by `rustc -vV`, invokes the existing lockfile with Cargo's `--locked --offline` flags, and checks that the emitted file is a PE executable for that target.

## Run the local build

From the repository root in PowerShell, choose the host target reported by Rust and an E: scratch directory outside this checkout:

```powershell
$target = (rustc -vV | Select-String '^host: ').ToString().Substring(6)
$scratch = Join-Path 'E:\WorkTrees' ('lvault-integrity-scratch-' + [guid]::NewGuid().ToString('N'))
$registry = 'E:\WorkTrees\gptop02-lvault-rust-spike\_spike\lvault-integrity\.task-cache\cargo-home\registry'
py -3.14 tools/build_native_integrity.py `
  --source-revision 6ade1303d5ccf76e3ac9523932d40624ab722162 `
  --target $target `
  --scratch-root $scratch `
  --cargo-registry-source $registry
```

The helper creates a unique `lvault-integrity-*` run directory under `$scratch`. Cargo's home, `TEMP`, `TMP`, and target directory all live inside that run directory. The helper removes inherited environment variables whose names start with `CARGO_` and sets its task-local home, offline mode, target directory, `TEMP`, and `TMP`. See [Trust the build host and configuration](#trust-the-build-host-and-configuration) for the remaining host variables and Cargo config discovery.

For a crate with registry dependencies, pass `--cargo-registry-source` with an existing `registry` directory on E: outside this checkout. The helper checks the path root, its ancestors, and every descendant without descending into symbolic links or Windows reparse points such as junctions, then copies that directory into the isolated Cargo home. Keep the supplied seed trusted and unchanged during validation and copying. Without this option, the Cargo home starts empty. The helper keeps Cargo's target directory there, copies only the resulting `.exe` into `stage`, and writes `provenance.json`. The JSON returned on stdout gives the manifest and staged executable paths.

The supplied registry directory must already contain the locked crate dependencies. Cargo receives `--locked --offline`, so Cargo does not fetch dependencies or update the lockfile; the helper does not install toolchains or other software. Cargo build scripts and native tools are not sandboxed, however, and can perform I/O outside Cargo. This procedure does not provide a host-level network isolation guarantee. It does not write build output into the checkout.

## Trust the build host and configuration

This is local build evidence, not a hermetic or independently attested build. The helper trusts the Windows host, `cargo` and `rustc` selected from `PATH`, the selected Rust toolchain, linker and SDK, crate build scripts, and Cargo configuration. It compares the requested target with `rustc -vV`, but does not pin or authenticate those tools.

The helper removes inherited environment variables whose names start with `CARGO_`, then sets a task-local `CARGO_HOME`, target directory, offline mode, `TEMP`, and `TMP`. The exact `CARGO` variable, `PATH`, `RUST*`, and `RUSTUP_*` variables remain inherited. Cargo's new `CARGO_HOME` starts without the caller's Cargo config or credentials, but Cargo can also discover `.cargo/config` or `.cargo/config.toml` files in the working directory's ancestors. Trust those host variables and configuration for this local build. The helper does not change host settings or credentials.

## Run the synthetic entry-point tests

The tests create a disposable Git repository and minimal Rust crate, then invoke the same Python staging entry point. Use a fresh test root under E: because pytest clears its `--basetemp` directory before running:

```powershell
$testRoot = Join-Path 'E:\WorkTrees' ('lvault-integrity-tests-' + [guid]::NewGuid().ToString('N'))
$env:PYTHONDONTWRITEBYTECODE = '1'
& 'C:\Python314\python.exe' -m pytest -q -p no:cacheprovider --basetemp=$testRoot tests/test_native_integrity_staging.py
```

The tests cover the source revision and Git tree, lockfile digest, target and PE format, staged executable checksum, offline/locked build flags, clean checkout, rejection of ignored source files, rejection of non-E: or non-host targets before output is created, isolation of Cargo home and temporary paths, and rejection of symbolic-link and reparse-point metadata on the registry root or descendants before traversal. The reparse-point cases use mocked Windows metadata; they do not create a real junction. Cargo environment isolation is exercised with synthetic config and credential files and a synthetic registry source.

## Read the provenance limits

The manifest records the source revision, checkout revision, Git tree for `native/integrity`, Cargo manifest and lockfile SHA-256 values, host and target triples, PE format, and the staged executable SHA-256. The staged checksum is recomputed against Cargo's output before the manifest is written.

The manifest is **unsigned local build evidence**. Its checksum detects accidental changes to the staged bytes; it does not establish who built them, provide a trusted release attestation, or authorize publishing or runtime use. This procedure does not package the executable, alter runtime selection, add an installer, or change production defaults.
