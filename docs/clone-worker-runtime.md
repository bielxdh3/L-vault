# Protected clone worker runtime contract

This packaging spike provides a first-party, single elevated worker with a native
Windows VSS requester. It does not invoke a separate cloning application and does
not touch a physical disk during build or installation.

## Fixed paths

| Purpose | Path |
| --- | --- |
| Worker | `C:\ProgramData\L-vault\clone-runtime\LocalVaultCloneWorker.exe` |
| Native VSS requester | `C:\ProgramData\L-vault\clone-runtime\LVaultVssSnapshot.exe` |
| One-file extraction | `C:\ProgramData\L-vault\clone-runtime\Temp` |
| Protected operation state and audit | `C:\ProgramData\L-vault\clone-state` |
| Owner binding | `C:\ProgramData\L-vault\clone-state\owner.sid` |

The installer creates the L-vault directories with a protected DACL: SYSTEM and
Administrators have Full Control; Users have Read and Execute. It verifies these
rules, rejects reparse points in all managed paths, and fails rather than taking
over an existing user-writable runtime or state directory. The worker repeats
the path, reparse-point, and DACL checks before it imports the bundled clone
modules. PyInstaller one-file extraction is restricted to the protected `Temp`
directory so an unelevated user cannot replace extracted Python modules.

`localvault.clone_runtime_security.verify_clone_runtime_security()` is the
read-only verifier for both the app capability gate and worker startup. It
checks `C:\` and `C:\ProgramData` as well as every fixed runtime/state object.
It rejects a standard principal that can delete, replace, or take over a child
through `DELETE_CHILD`, `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_WRITE`, or
`GENERIC_ALL`. ProgramData may grant ordinary create-subdirectory rights, so the
installer creates `L-vault` with an explicit protected DACL in one directory
creation call and fails if an unsafe preexisting child wins that name. The
managed DACL also limits implicit owner rights, so a standard account that
created the process cannot change the runtime's DACL through object ownership.

## Request and trust boundary

The only operational worker argument is:

```text
LocalVaultCloneWorker.exe --job-id <32 lowercase hexadecimal characters>
```

The job ID is an untrusted selector for one operation. The worker does not accept
a repository root, disk number, drive letter, source/target identity, plan file,
snapshot path, or script path. It derives the authorized physical roles from a
fresh Windows inventory, resolves current selectors itself, and uses the bundled
L-vault worker code. Persistent job status, snapshot records, manifests, markers,
and worker lock stay under `clone-state`. `E:\LocalVault` is fixed in the
packaged code and is used only for the protected-repository-to-HGST exclusion
check; it is not used as a job-plan or script input.

The bundled worker launches the co-located `LVaultVssSnapshot.exe` by absolute
path for VSS operations. The helper path is fixed beside the worker and both
executables must pass signature checks at installation. The worker rechecks the
helper's path, reparse status, and ACL before execution. The target and source
identity checks remain in L-vault's worker; the VSS helper only accepts canonical
volume GUIDs and exact snapshot IDs passed by that worker.

## Installation and build

The installer and worker self-checks do not inspect physical disks or write files:

```powershell
.\tools\install_clone_worker.ps1 -SelfCheck
py -3 .\tools\clone_worker_entry.py --self-check
```

Build development artifacts as a **non-elevated** user. BuildOnly invokes
PyInstaller and Cargo without running the resulting worker or VSS helper:

```powershell
.\tools\install_clone_worker.ps1 -BuildOnly
```

Build prerequisites are 64-bit Windows PowerShell, Python with PyInstaller,
64-bit Rust/Cargo, the `x86_64-pc-windows-msvc` Rust target, Visual Studio C++
Build Tools, and the Windows SDK/VssApi import library. The build bundle is
written to `E:\LocalVault\.build\clone-runtime-stage\bundle`. The one-file
worker embeds `C:\ProgramData\L-vault\clone-runtime\Temp` as its extraction
directory.

The current script deliberately refuses installation until the production
Authenticode certificate thumbprint is pinned in the release build. The local
development artifacts are unsigned and are not suitable for an elevated install.
The signed release process must Authenticode-sign both executables with the
approved L-vault publisher, pin that exact certificate thumbprint in
`tools/install_clone_worker.ps1`, place those signed files in the fixed bundle,
then install from one elevated PowerShell session:

```powershell
.\tools\install_clone_worker.ps1 -Install
```

Installation verifies signatures before creating managed directories, verifies
them again after copying, checks copied hashes, writes a protected install audit,
and does not launch either executable. The helper is therefore never run by the
installer.

## Status and cancellation

The clone provider can read `clone-state\active.json`. Worker state is not read from or written to the
user-writable repository tree.

Cancellation stays available from the normal UI without a second elevation
prompt. It uses a per-job named Windows event and mutex. Their DACLs grant
access only to SYSTEM, Administrators, and the exact interactive owner SID
recorded by the protected installer. Cancellation and the worker's transition
to target preparation serialize through that mutex: if cancellation wins first,
target preparation is skipped; after the destructive boundary, cancellation is
refused. No cancellation marker or clone state is read from the repository
tree; status, identities, manifests, journals, and audit remain in protected
ProgramData.

The current host has no L-vault code-signing certificate with a private key.
Its user-installed PyInstaller and Rust toolchain are suitable only for
`-BuildOnly`. Production installation requires signed release binaries from a
pinned, trusted publisher. Until that release trust material and artifacts are
available, the runtime capability gate keeps Clone disabled. No clone, VSS
request, or physical-disk action was performed by this implementation.
