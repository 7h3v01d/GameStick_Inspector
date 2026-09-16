
## Bounded directory enumeration (0.3.4 branch)

All untrusted GameStick directory enumeration is streaming and capped before full materialization. A sample limit of `N` consumes at most `N + 1` iterator advances, with the extra operation used only to detect truncation/end/error. This prevents a pathological directory from forcing an unbounded `list(os.scandir())` allocation before a display/scan limit is applied. Bounded samples are sorted only after capture and may therefore represent a filesystem-order sample rather than the global lexicographic first `N` names. User-reachable Auto-detect is bounded as well: Linux consumes a capped `/proc/self/mountinfo` stream instead of recursively walking mount trees, its fallback has a global enumeration budget, macOS `/Volumes` uses bounded scandir, and at most 512 unique candidates are profile-probed.

## Device Profile candidate synthesis (0.4.0)

Device Profile and launcher/index ranking is derived entirely from evidence already collected by the bounded read-only probe. The discovery layer performs no additional filesystem traversal and does not read SQLite rows, CSV data rows, JSON values, or ROM filenames. It uses only structural evidence already present in the probe model: profile markers, candidate paths/formats, SQLite schema/table/column names, privacy-safe derived CSV structural terms, JSON key names, XML root names, config key names, bounded directory snapshots, and integrity hashes.

The resulting profile is explicitly marked `CANDIDATE`. A high-ranked launcher artifact is evidence for further analysis, not authority to modify the card. Transactional GameStick writes remain disabled until a real-card launcher/index parser and consistency model are separately designed and reviewed.

# Safety Model

## Primary invariant

**The GameStick is a read-only evidence source until its exact layout and consistency model are understood.**

No active code path restores, formats, flashes, modifies ROMs, edits launcher metadata, or opens the GameStick raw device for write access.

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
