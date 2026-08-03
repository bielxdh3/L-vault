# L-vault offline clone architecture

Status: validated offline contract with static artifact inspection and disposable virtual return-channel tests. Real offline execution, boot handoff, media setup, and disk mutation remain disabled.

## Decision

L-vault uses a two-stage boundary:

1. Windows performs due/window/session/protected-path checks and, in a future authorized phase, writes a signed job package to its normal runtime area.
2. Clonezilla Live boots manually from a dedicated USB, verifies the package, inventories Linux block devices, resolves enrolled fingerprints to fresh device nodes, and only then renders the engine argv.

The USB path is intentionally manual and not configured by this repository. It avoids permanent boot-order changes and makes the return to Windows a human action. No BCD, UEFI NVRAM, BootNext, recovery partition, PXE configuration, USB device, or reboot is touched here.

The implementation keeps the private signing key outside the package. Official publisher provenance and local extraction attestation are separate trust domains: `OfficialChecksumVerifier` accepts only the pinned DRBL/Clonezilla fingerprint `54C0821A48715DAFD61BFCAF667857D045599AFD`, while `LocalExtractionAttestationVerifier` accepts only a separately configured L-vault attestor. The production trust policy also pins the exact `clonezilla-live-3.3.3-15-amd64.iso` digest `482518ea32af3b82ed15d09e2e7714806775deb62aeed81491e534f6cc6bbc47`; CLI, configuration, manifests, and normal constructors cannot replace either value. Synthetic digest overrides are available only through the explicit synthetic-test validator factory. The validator rejects shared fingerprints, shared derived keyring digests, role substitution, missing derived evidence, and legacy collapsed signer fields. Production detached verification uses explicitly supplied `gpgv` binaries and read-only pinned public keyrings; no key discovery or private-key operation is performed.

## Identity and package safety

The job contains hashed persistent evidence, exact capacity and sector geometry, normalized model/transport/partition-style fingerprints, policy names, protected-device exclusions, expiry, a one-time nonce, and `real_execution_authorized=false`. Raw serials, WWNs, udev IDs, and device nodes are not serialized into the job or result display.

The Linux resolver requires exactly one strong source and one strong target match. It rejects duplicates, weak USB bridge identity, changed identity or geometry, mounted devices, the live root, the Clonezilla boot medium, protected ambiguity, read-only targets, undersized targets, partition-style changes, source/target equality, invalid device nodes, and stale/replayed jobs. The current device node is a runtime selector only.

Results contain the job ID, engine/version, timestamps, masked labels, command hash, exit status, phase, structural verification, target-offline outcome, bounded sanitized error, log hash, and `boot_tested=false`. A result with a mismatched job ID, bad signature, or tampered canonical JSON is rejected.

Signed transport integrity is only the first boundary. Result consumption also requires the already verified `OfflineJob`, the trusted rendered command plan (or its trusted lowercase SHA-256 `argv_hash`), the detached verifier, and a deterministic current time when testing. Semantic validation then binds the result to the job schema, engine release, masked labels, command hash, timestamps, allowlisted phase/outcome, safe error text, and `boot_tested=false`; a valid signer cannot authorize inconsistent fields.

The fake path uses only `fake_engine_rendered_only` and returns `offline_simulation_completed`. It does not claim a clone or structural verification and is accepted only by the explicit simulation consumer. A future production result must use the terminal `clone_completed_structurally_verified` phase, `confirmed_offline`, exit status zero, and `structurally_verified=true`; only that bound result can become `offline_clone_structurally_verified`. A production consumer never treats the fake phase as clone evidence. Structural verification still does not mean bootability: manual boot testing remains a separate, unperformed human gate.

## Clonezilla contract examined

Access date: 2026-08-02.

- [Clonezilla project](https://clonezilla.org/): Clonezilla Live is intended for a single machine; whole-disk cloning is supported; online cloning is not implemented and the source partition must be unmounted; GPT/MBR and BIOS/uEFI are supported; GPLv2 applies to Clonezilla itself.
- [Clonezilla downloads](https://clonezilla.org/downloads.php): current stable Debian-based Live release examined was `3.3.3-15` (testing `3.3.3-18` was also listed); the page notes AMD64 for UEFI Secure Boot machines and publishes checksum/GPG verification guidance. This does not prove the exact Secure Boot path for this machine.
- [Official stable checksums](https://clonezilla.org/downloads/stable/checksums.php): pinned AMD64 ISO SHA-256 is `482518ea32af3b82ed15d09e2e7714806775deb62aeed81491e534f6cc6bbc47`. The official page says the checksum files are GPG-signed by DRBL fingerprint `54C0821A48715DAFD61BFCAF667857D045599AFD`; this key is not provisioned in this checkout.
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

## Virtual runtime contract

`OfflineRuntimeManifest` is the authoritative runtime-artifact evidence object. It separately records official checksum-manifest/signature/fingerprint/keyring evidence and local attestation scheme/domain/fingerprint/keyring, extraction policy, signed manifest/inventory digests, exact ISO binding, strict required-tool evidence, job/result schemas, renderer policy, return-channel type, and explicit `vm_boot_completed=false`/`physical_boot_completed=false`. It is canonical JSON with a detached signature and rejects unsafe paths, release drift, extra fields, legacy collapsed signer fields, and tampering.

`OfflineRuntimeValidator` only reads a caller-supplied ISO, official checksum manifest, local signed extraction attestation, and extracted tree. A directory containing files with the right names is never enough: the attestation must use the fixed `localvault.clonezilla.extraction-attestation.v1` domain, canonical signed payload, exact ISO filename/digest, and complete inventory match. `synthetic_test` is selected only through its explicit test-only factory and can return only `offline_runtime_synthetic_validation_passed`; the production validator has no digest-override parameter and rejects synthetic methods, fake verifiers, and fixture-only overrides. Required tools must be exactly one regular, non-empty, bounded, executable candidate at an allowlisted image path; they are reported as `present_unexecuted` and are never executed. Symlinks, special files, overlays, traversal, duplicate candidates, altered digests, stale signatures, and unrelated trees block the state. On this machine the official ISO, extracted tree, and trusted local attestor were not present, so the honest state is `offline_runtime_blocked`; no VM boot occurred.

`VirtualReturnChannel` is a temporary-directory fixture for the future dedicated FAT exchange volume. Its durable states are `pending -> running -> result -> consumed`, with `failed` as a terminal fail-closed state. Result and binding manifests are signed, atomically published, nonce/job-bound, bounded, replay-resistant across restart, and recovered as failed after partial publication. `VirtualOfflineRunner` accepts only the structural `VirtualSimulationPolicy`; it resolves synthetic devices, renders argv, and publishes a fake result without an engine subprocess. A production consumer rejects that fake result.

The safe command is:

```powershell
python -m localvault disk-clone-runtime-validate --root <vault-root> --iso <official.iso> --extracted-tree <tree> --checksums <SHA256SUMS> --checksums-signature <SHA256SUMS.sig> --extraction-manifest <extraction-manifest.json> --extraction-signature <extraction-manifest.sig> --official-verifier-binary <gpgv> --official-public-keyring <drbl-public.gpg> --local-attestation-verifier-binary <gpgv> --local-attestation-public-keyring <local-attestor-public.gpg>
```

The virtual-only return-channel fixture remains separate:

```powershell
python -m localvault disk-clone-virtual-roundtrip --root <vault-root>
```

The first command defaults to `production_static` and reports whether official publisher provenance, local extraction attestation, exact ISO/tree binding, and static tool policy passed. `--profile synthetic_test` is test-only and cannot produce production static success. A local signature attests that the trusted local extraction workflow signed the manifest; it is not Clonezilla/DRBL provenance and does not prove arbitrary extraction correctness. The second command uses only synthetic devices and temporary files and reports `consumed` only after the signed result has completed the durable virtual round trip. Neither command proves bootability, Secure Boot operation on this machine, VM boot, physical boot, or a real clone.

## Safe next phase

Before any future disposable-disk clone test, a separately authorized phase must supply and verify the official ISO and detached checksum signature, provision a read-only pinned public keyring in the Live environment, complete a safely isolated VM or manual Live boot, validate the actual package/return-channel path, and independently review source/target guards. It must still keep a human confirmation before any real disk writer and must not claim a boot test without a separate human boot test.
