
## Bounded directory enumeration (0.3.4 branch)

All untrusted GameStick directory enumeration is streaming and capped before full materialization. A sample limit of `N` consumes at most `N + 1` iterator advances, with the extra operation used only to detect truncation/end/error. This prevents a pathological directory from forcing an unbounded `list(os.scandir())` allocation before a display/scan limit is applied. Bounded samples are sorted only after capture and may therefore represent a filesystem-order sample rather than the global lexicographic first `N` names. User-reachable Auto-detect is bounded as well: Linux consumes a capped `/proc/self/mountinfo` stream instead of recursively walking mount trees, its fallback has a global enumeration budget, macOS `/Volumes` uses bounded scandir, and at most 512 unique candidates are profile-probed.

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

The manifest therefore records `status: transfer-verified` and `source_snapshot_consistency_verified: false`. A future optional second complete source read is planned for static-media comparison.

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
