# L-Vault integrity

This crate provides a standalone command-line tool for hashing explicit file paths with SHA-256. It reads the supplied files and writes one result per argument; it does not search for paths or invoke a shell.

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

Build and run the crate checks from the repository root:

```powershell
cargo fmt --check --manifest-path native/integrity/Cargo.toml
cargo test --locked --offline --manifest-path native/integrity/Cargo.toml
```

See the [prototype engineering notes](../../docs/native-integrity-prototype.md) for implementation measurements, local validation context, and future packaging considerations.
