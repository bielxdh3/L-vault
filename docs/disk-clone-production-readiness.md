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
- no process creation unless the signed job authorizes real execution and fresh resolution exists.

The module deliberately does **not** bypass the current `OfflineJob.validate()` blocker. At the time of this draft, the signed-job model still rejects `real_execution_authorized=True` with `offline_execution_disabled`. That blocker must be removed only as part of an explicit signed one-shot authorization change, with tampering/replay tests.

### Read-only Linux inventory parser

`src/localvault/offline_linux_inventory.py` adds a pure parser for deterministic `lsblk --json --bytes` style fixtures. It normalizes top-level physical-disk evidence into `OfflineBlockDevice` without touching the host. Runtime live-root, boot-medium, and protected-device classification still needs independent trusted evidence before a destructive operation.

## Remaining integration before production use

The feature is **not ready for a real clone yet**. The remaining production integration must be completed and tested locally/offline without weakening existing safety rules:

1. widen the signed `OfflineJob` contract so one specific expiring, nonce-bound job may carry `real_execution_authorized=true`;
2. keep global capability default-off and avoid persistent one-click destructive consent;
3. bind that authorization to source identity, target identity, engine, release, expiry, nonce, and policy under the existing signature/replay model;
4. integrate the production executor into the trusted Clonezilla Live runtime;
5. add a bounded read-only Linux collector around the pure inventory parser using exact allowlisted binaries from the verified runtime;
6. independently classify live root, boot medium, mounted/read-only/protected devices;
7. perform fresh post-run inventory and structural verification;
8. confirm target-offline state before publishing success;
9. publish and consume the signed production result through the existing return channel;
10. keep `boot_tested=false` until a human actually boots the cloned disk;
11. add the normal source/target enrollment/configuration UI using injected fake inventories in tests;
12. run the full repository suite and a real browser smoke test before marking this PR ready.

## Safety invariant

Until the integration above is complete, the repository must remain unable to perform a real destructive clone by default. A green simulation/static validation result must never be presented as evidence that a physical disk was cloned or boot-tested.
