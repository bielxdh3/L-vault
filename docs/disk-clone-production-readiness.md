# Physical disk clone — production-readiness boundary

This document describes the state of the physical-disk clone work in this draft branch. It is intentionally conservative: **no physical clone, boot mutation, USB preparation, or block-device write was executed while preparing this change.**

## What is already present

The repository already contains substantial fail-closed clone architecture:

- strong/persistent source and target identity rules;
- signed enrollment data;
- source/target revalidation;
- exact target-size checks;
- protected/live/read-only/mounted-device rejection logic;
- offline job and result schemas;
- detached signature verification;
- replay protection;
- Clonezilla command rendering;
- structural verification semantics separated from `boot_tested`;
- return-channel and simulation infrastructure;
- schedule/window/state tracking.

## What this draft adds

### Product UI

The dedicated Disk Clone screen now explains that it is a **physical full-disk recovery clone**, distinct from the non-destructive File Replica feature. The screen separates source, target, readiness, schedule, structural verification, target-offline state, safe preflight/simulation actions, and the explicit destructive boundary.

### Production execution seam

`src/localvault/offline_clone_exec.py` adds a fail-closed execution boundary for the trusted offline environment:

- disabled by default;
- absolute allowlisted `ocs-onthefly` path;
- `shell=False` subprocess execution;
- bounded timeout and captured output;
- no `dd` fallback;
- test-double runner that never spawns a subprocess;
- final argv hash includes the absolute executable path;
- no process creation unless the signed job authorizes real execution, runtime readiness is trusted, replay is claimed, and fresh resolution exists;
- post-run inventory, structural verification, target-offline confirmation, and a signed production result are mandatory.

`real_execution_authorized=true` is now accepted only as a signed, expiring, nonce-bound job capability. Persistent configuration remains default-off and cannot grant standing destructive consent. The executor claims replay immediately before process creation and the trusted `ProductionOfflineRunner` verifies the job signature, inventories before and after execution, and publishes a signed result only after terminal checks.

### Read-only Linux inventory collector

`src/localvault/offline_linux_inventory.py` keeps the pure parser and adds `LinuxOfflineInventoryCollector`: a bounded `shell=False` call to an exact `/.../lsblk` path, with normalized identity/geometry/partition/mount/removable/read-only evidence. Runtime live-root, boot-medium, and protected-device classification is supplied independently and remains a required gate.

## Remaining human/runtime validation before a real clone

The guarded production path is implemented and tested with synthetic devices, but this checkout is **not evidence that a physical clone is ready or has occurred**. The remaining validation is deliberately outside this mission:

1. provision and independently attest the pinned Clonezilla Live image and required tools;
2. configure the dedicated exchange medium and manually boot the owner-approved offline runtime;
3. perform any real clone only after a human reviews the exact signed job and physical source/target labels;
4. inspect the signed result and structural evidence on Windows;
5. keep `boot_tested=false` until a human actually boots the cloned disk.

## Safety invariant

The repository remains unable to perform a real destructive clone by default:
the production runner requires a separately enabled runtime policy and a fresh
signed one-shot job, while the application and CLI keep the boot handoff
unconfigured. A green simulation/static validation result must never be
presented as evidence that a physical disk was cloned or boot-tested.
