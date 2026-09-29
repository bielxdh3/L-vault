# L-vault VSS requester helper

This small Windows helper uses the inbox VSS requester COM API. It creates persistent snapshots with `VSS_CTX_APP_ROLLBACK`, reports the exact snapshot ID, original volume, and device object, and deletes one exact snapshot ID during cleanup. The worker reads the snapshot through its stable `GLOBALROOT\\Device\\HarddiskVolumeShadowCopyN` object path; it never assigns a drive letter. It gathers and checks writer status after `PrepareForBackup`, `DoSnapshotSet`, and `BackupComplete`; missing status, a nonzero writer failure HRESULT, or an unexpected writer state fails the request. The normal post-snapshot `WAITING_FOR_BACKUP_COMPLETE` state is accepted until `BackupComplete` is sent. All VSS asynchronous waits share a 12-minute deadline, leaving the Python supervisor time to run journal-based recovery before its 15-minute process timeout.

It does not prepare or write disks. `snapshot` can read-snapshot any canonical volume GUID supplied to it, so the privileged L-vault worker must resolve and authorize the physical source independently before invoking it. Every snapshot request requires a new `vss_snapshot_journal.json` under the worker-created protected job directory. The helper exclusively creates the regular, non-reparse journal with `create_new`, then atomically persists the exact registered snapshot IDs as `{"snapshot_ids":["{GUID}", ...]}` immediately after each `AddToSnapshotSet` call and before preparation/creation. The worker can use this per-job list to clean only the operation's exact IDs after interruption. `cleanup` accepts only a GUID and deletes that exact VSS snapshot.

## Build and test

Requires Rust 1.95+, the `x86_64-pc-windows-msvc` target, Visual Studio C++ Build Tools, and the Windows SDK (including `VssApi.lib`). No VSS request is run by tests or build.

```powershell
rustup target add x86_64-pc-windows-msvc
cargo test --target x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

The binary imports Windows' inbox `VssApi.dll`. The release artifact is `target\x86_64-pc-windows-msvc\release\LVaultVssSnapshot.exe`. The intended installed location is beside the protected worker at `C:\ProgramData\L-vault\clone-runtime\LVaultVssSnapshot.exe`; installation must be performed by the L-vault installer and retain an ACL that denies standard users write/replace access. This project does not install or elevate the helper. Run operations only through the L-vault trusted/elevated worker boundary, and verify the installed file's signature/hash as part of packaging.

## Commands

```text
LVaultVssSnapshot snapshot --journal <protected-job-dir>\vss_snapshot_journal.json --volume \\?\Volume{GUID}\ [--volume \\?\Volume{GUID}\ ...]
LVaultVssSnapshot cleanup --snapshot-id {GUID}
```

Snapshot IDs are persistent until explicitly cleaned up. The caller supplies the per-job `vss_snapshot_journal.json` path; L-vault must read and compare that journal against the helper result, then attempt exact-ID cleanup after success/failure and during safe recovery. The protected job directory and its ACL are owned by L-vault; the helper rejects a missing/reparse parent and will not overwrite an existing journal. Journal tests use ordinary temporary files only. No live VSS snapshot validation has been performed.
