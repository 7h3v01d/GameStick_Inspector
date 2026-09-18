
## Bounded directory enumeration (0.3.4 branch)

All untrusted GameStick directory enumeration is streaming and capped before full materialization. A sample limit of `N` consumes at most `N + 1` iterator advances, with the extra operation used only to detect truncation/end/error. This prevents a pathological directory from forcing an unbounded `list(os.scandir())` allocation before a display/scan limit is applied. Bounded samples are sorted only after capture and may therefore represent a filesystem-order sample rather than the global lexicographic first `N` names. User-reachable Auto-detect is bounded as well: Linux consumes a capped `/proc/self/mountinfo` stream instead of recursively walking mount trees, its fallback has a global enumeration budget, macOS `/Volumes` uses bounded scandir, and at most 512 unique candidates are profile-probed.

## Device Profile candidate synthesis (0.4.0)

Device Profile and launcher/index ranking is derived entirely from evidence already collected by the bounded read-only probe. The discovery layer performs no additional filesystem traversal and does not read SQLite rows, CSV data rows, JSON values, or ROM filenames. It uses only structural evidence already present in the probe model: profile markers, candidate paths/formats, SQLite schema/table/column names, privacy-safe derived CSV structural terms, JSON key names, XML root names, config key names, bounded directory snapshots, and integrity hashes.

The resulting profile is explicitly marked `CANDIDATE`. A high-ranked launcher artifact is evidence for further analysis, not authority to modify the card. Transactional GameStick writes remain disabled until a real-card launcher/index parser and consistency model are separately designed and reviewed.

# Safety Model

## Primary invariant

**Inspection, discovery, catalogue analysis and raw imaging remain strictly read-only.**

The only selected-GameStick write authority is the separately gated **TEST/CLONE customization transaction**. It is constrained to independently re-derived launcher-control bytes for an exact `catalogue code + ROM filename`, requires mandatory rollback/receipt artifacts on a different verified physical disk, rebinds the selected physical target immediately before writes, and reread-verifies the resulting coherent state. Raw restore, formatting/repartitioning, firmware flashing and physical ROM-payload add/delete remain unavailable.

## Read-side filesystem containment

Mounted GameStick content is untrusted evidence. Forensic traversal never follows symlinks or Windows reparse points/junctions. On the supported Python 3.10/3.11 floor, the application uses non-following `lstat` metadata and `FILE_ATTRIBUTE_REPARSE_POINT` rather than relying on `Path.is_symlink()`.

Before any candidate is hashed or parsed, every path component from the selected root is checked for reparse indirection and the candidate is canonically resolved; the resolved path must remain under the resolved selected root. The same boundary is used by root enumeration, metadata discovery, directory snapshots, profile matching and the GUI Browser.

A reparse-backed entry is skipped rather than followed. This preserves the evidence boundary even when a crafted removable filesystem points toward host directories.

## Physical-image gates

Before raw acquisition, the application requires:

1. physical Windows disk mapping succeeds;
2. disk number and byte size are known;
3. `IsBoot == False` and `IsSystem == False` (unknown rejects);
4. source is not offline;
5. external/removable evidence exists (`USB`, `SD`, `MMC`, or removable volume);
6. selected drive letter belongs to the resolved disk;
7. GameStick profile confidence meets threshold;
8. destination is outside the selected volume;
9. destination local drive is proven to be on a **different physical disk**;
10. destination capacity is sufficient;
11. user confirms `IMAGE DISK N`;
12. immediately before acquisition, physical identity is independently re-queried and compared with the imaging plan;
13. after `CreateFileW`, Windows IOCTLs verify the opened handle's disk number and byte length.

The raw source is opened with `GENERIC_READ` only. `GENERIC_WRITE` is not requested.

## Bound source identity

The plan records/binds:

- disk number;
- total byte size;
- bus type;
- partition style;
- selected partition number/offset/size;
- logical/physical sector sizes;
- SHA-256 of serial and disk unique ID when available;
- SHA-256 of the observed partition topology;
- a composite source-identity SHA-256.

Any revalidation mismatch refuses acquisition and requires a fresh probe.

## Transactional image + manifest

A recovery image and its success manifest are one authoritative artifact set.

On Windows, the new image is first written to an unpredictable staging object created directly on a stable, proven-safe destination volume GUID. It is flushed/fsynced and reread in full. The matching manifest is then staged on that same bound volume. Existing canonical artifacts are not touched until both new staging objects are ready.

When replacing an existing pair:

1. old manifest is moved to rollback first;
2. old image is moved to rollback;
3. new image is promoted;
4. new matching manifest is promoted;
5. rollback files are removed after commit.

If promotion fails, the application attempts to remove the partially promoted new pair from canonical names and restore the previous matching pair.

## Transfer verification vs source consistency

Current verification proves:

> The destination image exactly matches the bytes observed during the acquisition pass.

It does not prove:

> The physical source card was unchanged throughout that pass.

The manifest therefore records `status: transfer-verified` and `source_snapshot_consistency_verified: false`. Alpha7 can optionally perform a second complete **read-only** source pass. When both complete source hashes match it records `source_static_media_consistency_verified: true`; a mismatch, early EOF, or read error is recorded separately without being mislabeled as a transfer failure. Because the reads are sequential rather than atomic, `source_snapshot_consistency_verified` remains false even when they match.

## PowerShell trust policy

Physical mapping uses only trusted absolute Windows PowerShell locations resolved from the Windows directory returned by `GetWindowsDirectoryW`. PATH-resolved PowerShell executables are never eligible, preventing helper execution through a poisoned inherited PATH.

## Generated-output invariant

On Windows, **unknown or stale source physical identity fails closed**. No JSON, evidence ZIP, image or manifest write begins until the selected GameStick root has been freshly re-resolved and its physical identity still matches the probe/acquisition identity.

Every generated local-drive output must satisfy:

```text
destination PhysicalDisk != source PhysicalDisk
```

The canonical/resolved output path is authoritative. UNC/network destinations are refused. The selected destination drive is then bound to a stable Windows volume GUID, and that volume GUID is independently queried for its physical disk number; a drive/volume disagreement refuses output.

Windows staging is created with unpredictable exclusive names **directly on the bound safe volume**, not in the user-supplied destination directory. This prevents a directory/junction swap from redirecting staging onto the GameStick after validation. Immediately before promotion, source identity and destination binding are revalidated. Promotion is a same-volume rename; if the final pathname has been redirected to another volume such as the GameStick, the rename fails rather than copying staged content across volumes.

Legacy predictable `.tmp` objects are never overwritten. Non-Windows portable/test operation retains path-level staging because physical Windows disk guarantees do not apply there.

## Privilege scope

0.3.3-alpha5 still elevates the whole GUI for raw imaging. This remains a known medium-priority architectural hardening item. The target design is a standard-user GUI with a minimal elevated raw-reader helper.

## Future restore requirements

A future write operation must independently validate physical target identity, dismount/lock appropriately, verify source image/manifest authority, journal the operation, stream/flush safely, reread the target, and survive cancellation/power-loss testing. No raw restore implementation exists in this release.
## Bounded DAT binary fingerprinting (0.5.0-alpha2)

The 0.5 binary fingerprint layer is read-only and sample-bounded. It opens only exact numbered-DAT structural paths already identified by the bounded root probe, reads at most five 64 KiB fingerprint windows per DAT, never extracts/decompresses a DAT member, never exports raw sampled bytes/arbitrary strings, and never grants write authority. Prefix/tail digests and other content-dependent metrics are excluded from structural profile identity. Binary fingerprint evidence can rank an unknown numbered-DAT layout as a candidate, but cannot independently produce a `probable` launcher resolution.



## Catalogue consistency audit (0.5.0-alpha4)

The consistency auditor is read-only and intentionally separate from the frozen imaging/output path. It performs one bounded, non-recursive enumeration of each observed three-digit catalogue directory (maximum 64 catalogues and 10,000 entries per catalogue). Names are used only in memory for case-insensitive comparison with private WQW catalogue sets. Exported evidence contains counts, status labels, safe numeric limits and sanitized error types only.

The audit does not open ROM payloads, does not hash or export private filenames, does not recurse into subdirectories, and does not alter Device Profile structural identity. Reparse points remain rejected by the existing forensic-path boundary. A partial/truncated enumeration is explicitly labelled `PARTIAL` and cannot be presented as a complete consistency result.


## Read stability and cross-catalogue alias audit (0.5.0-alpha5)

The read-stability auditor is read-only and bounded. It reopens each exact structural DAT three times and reads at most 64 KiB from each canonical region per attempt. For large central/control regions, the bounded sample covers both ends of the region. The implementation compares SHA-256 digests only in memory; digest values and sampled bytes are never exported. A stability result is evidence about the sampled reads only and is **not** equivalent to a full physical-source reread.

Cross-catalogue alias resolution reuses the same bounded top-level directory observations and private WQW filename sets already held in memory. It performs no recursive traversal and opens no ROM payload. Exported alias evidence is limited to three-digit catalogue codes and counts. Reparse/junction protections remain enforced by the existing forensic path layer.


## Longitudinal evidence baseline (0.5.0-alpha6)

Baseline comparison is read-only and host-side. A prior evidence ZIP is never extracted and is accepted only after bounded archive validation plus manifest verification of the enclosed probe JSON. JSON and ZIP member sizes are capped, encrypted/unexpected/traversal members are rejected, and the baseline host pathname is not exported.

Cross-run comparison reuses previously exported prefix/tail fingerprint commitments and privacy-safe structural/control metadata. Alpha6 does not add new DAT sampled-region digest commitments. The result therefore distinguishes current-session read stability from evidence changes observed between probe sessions without granting any source-write authority.

Dominant-alias classification is also counts-only. Catalogue filenames remain private in memory; only three-digit catalogue codes, counts and bounded rate fields leave the process.


## Bounded customisation apply (alpha13)

The only selected-GameStick write authority in alpha13 is the `.gscustom` apply path. It is intentionally narrower than raw restore: the target must be an explicitly selected TEST/CLONE mounted card; a healthy source image and overlay provenance are revalidated; exact existing target bytes must match; a host rollback archive is committed before first write; file sizes and FAT allocation are not changed; and replacement bytes plus WQW controls are reread/verified. Raw restore, format/repartition, firmware flash and ROM-payload add/delete remain unavailable.


## ROM Manager (alpha14)

The ROM Manager is read-only while scanning. It reads the healthy reference image FAT and launcher control members, and optionally opens mounted numbered DAT/ROOT controls read-only to classify exact ROM identities as visible/hidden/inconsistent. It does not read ROM payload files. Hide still produces a host-side `.gscustom`; target modification remains exclusively the alpha13 bounded apply path. Manager unhide delegates to the existing verified `.gsrollback` path and additionally requires the sibling apply receipt to match the selected `catalogue code + filename` identity.

## Transaction authority hardening (alpha15)

A `.gscustom` archive is untrusted input and never grants write authority by itself. Apply re-derives the canonical hide operation from the healthy image plus exact ROM identity and requires the workspace patch topology, source/replacement bytes, ranges, payloads and provenance to match exactly. For the current Hide-ROM operation the only authorized topology is one numbered `NNN/NNN.DAT` control change plus the matching `ROOT.DAT` mirror change, represented by exactly four fixed-size ranges total.

Production apply/rollback is Windows-only. The TEST/CLONE target is bound to physical disk/partition identity and re-queried after the exact target files are opened; write authority is then exercised through those already-open handles. Rollback and receipt outputs must resolve to a different verified physical disk from the target and are bound to a stable host volume.

Receipt commitment is part of the apply transaction. The destination is reserved before target mutation; an existing receipt requires explicit overwrite authority. If final receipt commit fails after target writes, the original target bytes are restored and reread-verified before failure returns. Rollback is itself compensating: if restoration fails partway, already-restored ranges are returned to the captured customized state and reread-verified. If coherent compensation cannot be established, the operation reports **RECOVERY REQUIRED** and retains the host rollback archive.

Both `.gscustom` and `.gsrollback` enforce ZIP member/count/expanded-size/compression/encryption bounds from `ZipInfo` metadata before member decompression. ROM Manager casefold resolution reuses bounded forensic directory enumeration. Receipt-bound unhide provenance is verified in backend code against the actual rollback SHA-256, exact ROM identity, receipt state and target identity where available.



## Rollback authority / partial-write hardening (alpha16)

A `.gsrollback` archive is untrusted evidence and cannot authorize its own writes. Normal rollback requires rollback-v2 provenance and then independently proves authority from the live customized target plus the archive's claimed original bytes. Inspector virtually reconstructs the pre-hide `filelist.txt` and `ROOT.DAT/fileinfo.txt`, proves that exactly one `catalogue code + filename` was removed by the canonical hide transformation, and re-derives the exact fixed-slot write ranges. Authority is granted only when the claim equals one numbered DAT plus `ROOT.DAT`, two ranges each, four ranges total, with exact current/original bytes. Receipt/hash provenance supplements this proof but never substitutes for it.

Rollback-v1 is legacy recovery only and is refused by default. An explicit legacy-recovery opt-in is required, and the same semantic inverse proof remains mandatory before any write. ROM Manager, general GUI rollback and CLI rollback share the same backend authority model.

For apply, the target transaction is considered potentially destructive immediately before the first writable mutation call. Any subsequent short write, partial-write exception, flush/fsync error, verification failure or receipt-commit failure enters restoration. Success after failure requires reread-verification of the complete original state; otherwise the result is **RECOVERY REQUIRED**. This rule deliberately assumes removable-media writes may have altered bytes even when the write API reports failure.


## Opened-handle binding / durable recovery identity (alpha17)

A drive-letter/root revalidation is not sufficient write authority. On Windows, after each target DAT/ROOT file is opened, Inspector resolves the **already-open OS handle** with `GetFinalPathNameByHandleW` using Volume-GUID naming and requires an exact match to the verified target Volume GUID and exact relative file. Both target handles must pass this check before apply or rollback can mutate bytes. The existing physical-disk/root requery remains mandatory as a second independent layer.

Rollback provenance now separates two identity concepts. **Attachment identity** is session-specific and includes the current `PhysicalDriveN`; it is used for immediate transaction rebinding. **Durable media identity** is stored for recovery ownership and excludes `disk_number` and drive-letter attachment state. It retains disk/partition size and geometry, stable partition-layout data with drive letters removed, serial/unique-ID hashes where available, and the stable Volume-GUID identity. This permits the same physical card to be safely recognized after unplug/replug or reboot while still refusing a different device.

New rollback archives use rollback-v3 and new apply receipts use receipt-v2. Rollback-v1/v2 is explicit legacy recovery only and remains subject to the same canonical semantic inverse proof before any write.
