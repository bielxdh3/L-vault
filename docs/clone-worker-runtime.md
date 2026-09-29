# Protected first-party clone runtime

L-vault owns runtime preparation, elevation, cloning, progress, verification,
and cleanup. The normal owner flow does not open a separate cloning product or
ask for manual shell, firmware, or USB steps.

## Fixed protected paths

| Purpose | Path |
| --- | --- |
| Worker | `C:\ProgramData\L-vault\clone-runtime\LocalVaultCloneWorker.exe` |
| Native VSS requester | `C:\ProgramData\L-vault\clone-runtime\LVaultVssSnapshot.exe` |
| One-file extraction | `C:\ProgramData\L-vault\clone-runtime\Temp` |
| Operation state and audit | `C:\ProgramData\L-vault\clone-state` |
| Owner binding | `C:\ProgramData\L-vault\clone-state\owner.sid` |
| Runtime manifest | `C:\ProgramData\L-vault\clone-state\runtime-install.json` |

The installer creates fixed directories with protected DACLs, rejects reparse
points, and refuses unsafe existing paths. SYSTEM and Administrators receive
Full Control, Users receive Read and Execute, and Owner Rights deny ownership or
DACL changes. The read-only runtime verifier checks these objects and their
`C:\` and `C:\ProgramData` ancestors before the app enables cloning or the
worker proceeds.

## Local integrity trust

The normal path supports local builds without a commercial signing certificate.
The first clone request rebuilds the worker/helper bundle without elevation. L-vault
requires a clean Git checkout for the worker/helper inputs, pins existing input
files while building, pins the installer to a hash carried by the running
application, and holds the installer and staged artifact files against
write/delete sharing through UAC. The owner-approved UAC prompt is the local
build's trust bootstrap. L-vault measures the three runtime hashes while those
staged-file locks remain held. The elevated installer
checks those exact values before copying into protected ProgramData, verifies
readback hashes, writes an owner-SID-bound SHA-256 manifest, and starts only the
protected worker. The local staging manifest is checked as build evidence; it is
not the source of the hashes passed to the elevated installer. Authenticode is
additionally verified when the release has a configured trusted-publisher
thumbprint. Existing build-input files are held against replacement while the
non-elevated worker/helper build runs; Git cleanliness is checked before and
afterward. The helper uses an isolated per-build Cargo target directory so stale
native outputs are not reused.

Runtime updates use a protected journal and same-volume rollback backups. The
manifest is promoted last. If an update is interrupted, the next installer
invocation either finishes cleanup for a validated committed update or restores
the previous worker, helper, and manifest. A pending journal disables worker
execution until recovery succeeds. Runtime installation refuses to run while a
clone or VSS recovery is active.

## Worker contract

The only operational worker argument is a random 32-character lowercase
hexadecimal job ID. It does not accept a disk number, drive letter, source or
target identity, repository root, arbitrary plan, or helper path. The worker
resolves the Kingston, Seagate, and protected HGST from a fresh Windows disk
inventory and repeats persistent identity checks immediately before destructive
target preparation. Job status, snapshot records, manifests, and audit data
remain under the protected ProgramData state directory.

The worker reads the Kingston through Windows snapshots, uses inbox Windows
storage tools to prepare one NTFS target volume, and invokes the inbox Robocopy
program with fixed arguments for each source data volume. Reparse points are
treated as filesystem objects; mount-point destinations are not traversed.
Runtime-only Windows files and boot/recovery partitions are explicitly
excluded and reported. The result is a data copy, not a bootable system disk.

## Cancellation and recovery

The UI and worker share a per-job named event and mutex whose DACLs grant the
interactive owner, SYSTEM, and Administrators the required access. Cancellation
and the transition to target preparation serialize on that mutex. If cancellation
wins first, the target is not changed. After target preparation begins, the UI
refuses cancellation. An interrupted clone is marked incomplete and cannot be
retried until reviewed. VSS cleanup uses only snapshot IDs journaled by that
operation.
