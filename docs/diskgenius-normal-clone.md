# DiskGenius normal Windows clone path

The normal owner path is **L-vault → Clone do sistema → Clone now**, followed by a few assisted DiskGenius GUI selections. It does not require Clonezilla, USB media, firmware navigation, or a Linux shell.

## Selected mode

L-vault uses **DiskGenius System Migration · Hot Migration**. The known source layout has one Windows partition and four ESP-typed 100 MiB partitions. The current Windows boot audit identifies partition 2 as the active ESP; partitions 3–5 are historical. System Migration copies the selected boot/system partitions instead of reproducing all disk layout clutter. The owner must leave DiskGenius's default system/boot selection intact, confirm Kingston as source and Seagate as target, and choose Hot Migration. Do not enable any option that changes boot order.

The installed executable checked for this implementation is `C:\Program Files\DiskGenius\DiskGenius.exe`, Product Version `6.1.1`, SHA-256 `4061DCDD0A1FDD9609300298E7D2EABFA58330F49671E0BD5BF01F6F61A5394B`, signed by `Qinhuangdao Yizhishu Software Development Co., Ltd.`. The executable is launched from this fixed path with Windows elevation; L-vault does not search `PATH` for it.

DiskGenius's official [System Migration guide](https://www.diskgenius.com/manual/system-migration.php) describes a Windows-running migration and its Hot Migration mode. Its [BitLocker cloning guide](https://www.diskgenius.com/how-to/clone-bitlocker-drive.php) says DiskGenius can clone encrypted partitions and explains sector-copy behavior for locked volumes. The [version history](https://www.diskgenius.com/version-history.php) records System Migration and Clone Disk BitLocker improvements. Those vendor statements establish product capability, not an independent guarantee of the result on this specific machine.

Hot Migration is described by DiskGenius as snapshot-based. Public documentation inspected for this implementation does not identify which VSS writers, if any, it uses. L-vault records the source BitLocker status when Windows exposes it through `Get-BitLockerVolume`; `unknown` remains visible in the audit and is not presented as “decrypted.” The actual status must be checked before the first real destructive run if the query is unavailable. DiskGenius's public [Free Edition page](https://www.diskgenius.com/free.php) and System Migration guide describe migration in the Free edition; the local executable's edition/license is not present in uninstall metadata. A license dialog or purchase request is a stop condition.

## Identity and destructive boundary

L-vault resolves each role afresh using exact model, masked serial suffix, PNP device ID, storage UniqueId, exact byte size, bus type, system/boot flags, partition layout, and volume letters. The Seagate must remain a distinct, non-system, online, writable physical disk with the authorized size and matching sector geometry. The HGST's persistent identity and the physical disk containing `E:\LocalVault` must both resolve to the protected role. Missing, stale, conflicting, or ambiguous evidence blocks launch.

The vendor interface exposes no control contract that L-vault can use to inspect its source/target rows. The normal flow therefore uses assisted GUI selection: the owner visually chooses the Kingston and Seagate in DiskGenius, then confirms that selection in L-vault. Immediately before the destructive confirmation, L-vault repeats disk inventory and checks physical identities, current DiskNumbers, volume mappings, system roles, and protected-disk exclusion. The two-minute revalidation window is displayed. This is owner-attested GUI state; it is not a machine-readable attestation from DiskGenius.

The Seagate is authorized for complete overwrite. The Kingston is source-only and its partition layout is checked against the audited five-partition layout before and after migration. The HGST is excluded by L-vault's own source/target mapping and protected-path resolution. The owner must not select it manually in DiskGenius. The audit comparison for HGST covers disk identity, partition/layout metadata, online/read-only state, and mount points; it does not hash all payload sectors and is not proof that no sector write occurred.

L-vault's audit is HMAC-protected and records identity preflight, DiskGenius launch, owner GUI-selection attestation, final revalidation, cancellation/completion attestation, and verification evidence. L-vault does not infer clone completion from the GUI process opening or closing. Before marking a run verified, the owner must confirm DiskGenius reported success and close the GUI; the verifier then requires the target layout to differ from the initial layout and checks GPT, one FAT32 ESP, one NTFS Windows partition, expected Windows files, target EFI boot files, target BCD binding, unchanged source layout, and unchanged protected-disk metadata.

## Result classification and limits

Structural verification checks the cloned target without setting a permanent firmware boot order or changing the source boot layout. It does not start the cloned Windows installation. A successful structural result is reported as `structurally_bootable`, with `boot_tested=false`; physical boot remains untested unless separately performed by the owner.

DiskGenius owns progress display and its internal cancellation behavior. If the GUI closes unexpectedly, verification fails, target identity changes, or a prior run may have partially overwritten the Seagate, L-vault does not automatically retry. A failed partial target requires fresh inspection and a new owner-started session. Source mutation, use of the HGST as scratch, or firmware-order changes are outside this workflow.

## Historical path

The detailed Clonezilla offline prototype remains in [disk-clone-offline.md](disk-clone-offline.md) for recovery/reference. It is not the normal owner-facing clone path.
