# L-vault offline clone architecture

Status: fake-only prototype. Real offline execution, boot handoff, media setup, and disk mutation are disabled.

## Decision

L-vault uses a two-stage boundary:

1. Windows performs due/window/session/protected-path checks and, in a future authorized phase, writes a signed job package to its normal runtime area.
2. Clonezilla Live boots manually from a dedicated USB, verifies the package, inventories Linux block devices, resolves enrolled fingerprints to fresh device nodes, and only then renders the engine argv.

The USB path is intentionally manual and not configured by this repository. It avoids permanent boot-order changes and makes the return to Windows a human action. No BCD, UEFI NVRAM, BootNext, recovery partition, PXE configuration, USB device, or reboot is touched here.

The implementation keeps the private signing key outside the package. The production verifier is an explicit blocked interface because availability and key provisioning in the selected Clonezilla Live runtime have not been proven. Tests use an in-memory fake signer/verifier only.

## Identity and package safety

The job contains hashed persistent evidence, exact capacity and sector geometry, normalized model/transport/partition-style fingerprints, policy names, protected-device exclusions, expiry, a one-time nonce, and `real_execution_authorized=false`. Raw serials, WWNs, udev IDs, and device nodes are not serialized into the job or result display.

The Linux resolver requires exactly one strong source and one strong target match. It rejects duplicates, weak USB bridge identity, changed identity or geometry, mounted devices, the live root, the Clonezilla boot medium, protected ambiguity, read-only targets, undersized targets, partition-style changes, source/target equality, invalid device nodes, and stale/replayed jobs. The current device node is a runtime selector only.

Results contain the job ID, engine/version, timestamps, masked labels, command hash, exit status, phase, structural verification, target-offline outcome, bounded sanitized error, log hash, and `boot_tested=false`. A result with a mismatched job ID, bad signature, or tampered canonical JSON is rejected.

Signed transport integrity is only the first boundary. Result consumption also requires the already verified `OfflineJob`, the trusted rendered command plan (or its trusted lowercase SHA-256 `argv_hash`), the detached verifier, and a deterministic current time when testing. Semantic validation then binds the result to the job schema, engine release, masked labels, command hash, timestamps, allowlisted phase/outcome, safe error text, and `boot_tested=false`; a valid signer cannot authorize inconsistent fields.

The fake path uses only `fake_engine_rendered_only` and returns `offline_simulation_completed`. It does not claim a clone or structural verification and is accepted only by the explicit simulation consumer. A future production result must use the terminal `clone_completed_structurally_verified` phase, `confirmed_offline`, exit status zero, and `structurally_verified=true`; only that bound result can become `offline_clone_structurally_verified`. A production consumer never treats the fake phase as clone evidence. Structural verification still does not mean bootability: manual boot testing remains a separate, unperformed human gate.

## Clonezilla contract examined

Access date: 2026-08-02.

- [Clonezilla project](https://clonezilla.org/): Clonezilla Live is intended for a single machine; whole-disk cloning is supported; online cloning is not implemented and the source partition must be unmounted; GPT/MBR and BIOS/uEFI are supported; GPLv2 applies to Clonezilla itself.
- [Clonezilla downloads](https://clonezilla.org/downloads.php): current stable Debian-based Live release examined was `3.3.3-15`; the page notes AMD64 for UEFI Secure Boot machines and publishes checksum/GPG verification guidance. This does not prove the exact Secure Boot path for this machine.
- [Clonezilla source information](https://clonezilla.org/downloads/src/): Clonezilla's running programs are Bash/Perl source; dependent projects such as Partclone have their own sources. The official source page timed out once during access but was independently returned by official search results and recorded here for applicability.
- [Clonezilla boot parameters](https://clonezilla.org/show-live-doc-content.php?topic=clonezilla-live/doc/99_Misc): `ocs_live_run` can run a clone command; `ocs_live_batch` controls batch mode; `ocs_prerun`/`ocs_postrun` run around the operation; `ocs_overwrite_postaction` can override post-actions. These are future boot-environment controls, not Windows subprocess APIs.
- [Clonezilla preseed options](https://clonezilla.org/show-live-doc-content.php?topic=clonezilla-live/doc/05_Preseed_options_to_do_job_after_booting): unattended/preseed operation is possible and `ocs_live_run` examples use `ocs-sr`; this is why L-vault keeps batch mode blocked until every offline guard succeeds.
- [`ocs-onthefly` manual](https://clonezilla.org/fine-print-live-doc.php?path=./clonezilla-live/doc/98_ocs_related_command_manpages/02-ocs-onthefly.doc): local source and target are passed as `-f DEV` and `-d DEV`; `-r` resizes to the target partition size; `-j2` clones hidden data; `-iefi` skips EFI NVRAM updates; `-p true` avoids reboot/poweroff; `-icds` disables the destination-size check and is therefore not used; `--batch` is explicitly dangerous. No persistent `SERIALNO=` form is documented here.
- [`ocs-sr` manual](https://clonezilla.org/fine-print-live-doc.php?fullmode=0&path=./clonezilla-live/doc/98_ocs_related_command_manpages/01-ocs-sr.doc): `SERIALNO=` selection is documented for `ocs-sr` device arguments. That evidence is not transferred to `ocs-onthefly`.
- [Partclone usage](https://partclone.org/usage/partclone.php): Partclone supports device-to-device and filesystem-aware operations, but this project does not reimplement Clonezilla's partition-table, boot-sector, filesystem, or post-clone handling.
- [Clonezilla release notes](https://clonezilla.org/downloads/alternative/release-notes.php): the current alternative stable release was also examined, but this implementation pins the Debian-based `3.3.3-15` compatibility label pending runtime validation.

## Renderer flags and unresolved choices

The fake renderer emits an argv tuple equivalent to:

```text
ocs-onthefly -f <fresh-source-node> -d <fresh-target-node> -k0 -j2 -r -iefi -p true -nogui
```

`-k0` makes the documented default partition-table behavior explicit, `-j2` preserves the documented hidden-data copy behavior, `-r` covers a larger target, `-iefi` prevents EFI NVRAM updates, and `-p true` avoids an automatic reboot or poweroff. `-icds` is omitted because it disables a safety check. Checksum mode remains unresolved because the official `ocs-onthefly` contract does not establish the required source-side checksum preparation for this whole-disk flow; it is not guessed into the command. Batch mode and execution are blocked.

## Safe next phase

Only after separate user authorization should a future phase prove the offline verifier/runtime, sign and verify a real package, validate the dedicated USB image and GPG checksums, manually boot Clonezilla, exercise fresh inventory on fake or disposable media, and design the result return channel. It must still keep a human confirmation before any real disk writer and must not claim a boot test without a separate human boot test.
