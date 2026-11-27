# L-Vault integrity

This crate provides a standalone command-line tool for hashing explicit file paths with SHA-256. It reads the supplied files and writes one result per argument; it does not search for paths or invoke a shell.

The command supports one-shot hashing and a persistent session for sequential requests. See the [CLI contract](../../docs/native-integrity-cli.md) for protocol details and validation commands.
