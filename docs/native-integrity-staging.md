# Local staging proof for the Rust integrity binary

This procedure builds the standalone `native/integrity` binary from a verified Git revision and places the executable, Cargo target output, and provenance manifest in a fresh run directory under an E: scratch root.

The helper is limited to the installed native Windows target. It checks that the requested source commit is an ancestor of `HEAD`, that every tracked crate file matches that commit, and that the crate has no untracked or ignored files. It requires the requested target to match `rustc -vV`, invokes the existing lockfile with Cargo's `--locked --offline` flags, and checks that the emitted file is a PE executable for that target.

## Run the local build

From the repository root in PowerShell, choose the host target reported by Rust and an E: scratch directory outside this checkout:

```powershell
$target = (rustc -vV | Select-String '^host: ').ToString().Substring(6)
$scratch = 'E:\WorkTrees\lvault-integrity-scratch'
py -3.14 tools/build_native_integrity.py `
  --source-revision 6ade1303d5ccf76e3ac9523932d40624ab722162 `
  --target $target `
  --scratch-root $scratch
```

The helper creates a unique `lvault-integrity-*` run directory under `$scratch`. It keeps Cargo's target directory there, copies only the resulting `.exe` into `stage`, and writes `provenance.json`. The JSON returned on stdout gives the manifest and staged executable paths.

Cargo must already have the locked crate dependencies in its local cache. The helper does not install software or dependencies, does not contact the network, and fails if the offline locked build cannot complete. It does not write build output into the checkout.

## Run the synthetic entry-point tests

The tests create a disposable Git repository and minimal Rust crate, then invoke the same Python staging entry point. Use a fresh test root under E: because pytest clears its `--basetemp` directory before running:

```powershell
$testRoot = Join-Path 'E:\WorkTrees' ('lvault-integrity-tests-' + [guid]::NewGuid().ToString('N'))
$env:PYTHONDONTWRITEBYTECODE = '1'
py -3.14 -m pytest -q -p no:cacheprovider --basetemp=$testRoot tests/test_native_integrity_staging.py
```

The tests cover the source revision and Git tree, lockfile digest, target and PE format, staged executable checksum, offline/locked build flags, clean checkout, rejection of ignored source files, and rejection of non-E: or non-host targets before output is created.

## Read the provenance limits

The manifest records the source revision, checkout revision, Git tree for `native/integrity`, Cargo manifest and lockfile SHA-256 values, host and target triples, PE format, and the staged executable SHA-256. The staged checksum is recomputed against Cargo's output before the manifest is written.

The manifest is **unsigned local build evidence**. Its checksum detects accidental changes to the staged bytes; it does not establish who built them, provide a trusted release attestation, or authorize publishing or runtime use. This procedure does not package the executable, alter runtime selection, add an installer, or change production defaults.
