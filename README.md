# GameStick Inspector 0.3.4-alpha2

Safety-first GameStick SD-card inspector and **verified-transfer** full-card imager.

The original prototype treated a GameStick as a mounted collection of files. This rebuild treats it as a **bootable block device plus firmware-specific filesystems and launcher metadata**.

## 0.3.4-alpha2 — bounded/streaming enumeration

This is the first post-freeze hardening branch after the 0.3.3-alpha5 PASS/FREEZE baseline. It addresses the reviewer's medium robustness finding that previous limits bounded output/processing but could still enumerate and sort an entire hostile directory first.

Directory traversal now uses a central streaming `bounded_scandir_names()` primitive. A requested sample of `N` entries performs at most `N + 1` directory-iterator advances; the extra operation is only an end/truncation/error probe. Mid-enumeration filesystem errors preserve and charge that partial work instead of losing it. Only a complete bounded sample is trusted and sorted.

Applied boundaries include:

- Browser: 1,000 entries per directory plus a 5,000-node whole-tree budget;
- directory snapshots: 500 entries per directory;
- top-level snapshot discovery: at most 2,048 root entries and 32 snapshot directories;
- metadata discovery: at most 4,097 iterator advances for one directory sample and 20,000 directory-enumeration operations globally;
- root evidence/profile discovery: bounded top-level samples rather than exhaustive `list(os.scandir(...))`.

A truncated sample is reported as truncated. It is deliberately **not** described as a complete lexicographic census: exhaustive global ordering would require enumerating the entire untrusted directory and would defeat the robustness boundary.

## 0.3.3-alpha5 frozen baseline

The 0.3.3-alpha5 read-only recovery-imaging stage received **PASS / FREEZE** after the adversarial cycle. Its SHA-256 remains the frozen baseline and this 0.3.4 branch does not modify that artifact.

## 0.3.3-alpha5 hardening

This release remains feature-frozen. It closes the Windows reparse/junction traversal HOLD finding from the alpha4 adversarial review:

1. all forensic traversal now uses one central non-following reparse-point guard compatible with Python 3.10/3.11;
2. Windows `FILE_ATTRIBUTE_REPARSE_POINT` objects, symlinks, junctions and other reparse entries are skipped before ordinary directory/file inspection;
3. every candidate opened for hashing or parsing receives a second canonical-containment check and must still resolve beneath the selected GameStick root;
4. root enumeration, metadata discovery, directory snapshots, profile markers and the GUI Browser all use the same boundary;
5. profile markers such as `Roms`, `cubegm` and `image` now count only when they are real non-reparse directories rather than merely matching names.

The rule is deliberately conservative: the Inspector does not need to understand which kind of reparse point it encountered. Reparse-backed objects are evidence-boundary indirections and are not followed.

## What this build can do

- Probe a mounted GameStick volume without modifying it.
- Tolerate individual corrupt/unreadable filesystem entries and complete a `DEGRADED` probe.
- Map a Windows drive letter to its physical disk and visible partitions.
- Score evidence-backed GameStick filesystem profiles.
- Inspect likely SQLite/CSV/JSON/XML/config launcher metadata conservatively.
- Export privacy-bounded diagnostic JSON/evidence ZIPs.
- Verify existing `.img` / `.bin` files with SHA-256.
- Create a **sector-for-sector physical SD image** using read-only raw-device access.
- SHA-256 the acquired bytes, reread the staged destination, and require both hashes to match.
- Emit the success manifest only as part of the same committed artifact pair as its image.

## Verification terminology

A successful image is a **verified transfer image**:

```text
physical source read
        ↓
stream bytes + SHA-256 A
        ↓
staged image
        ↓
full destination reread + SHA-256 B
        ↓
A == B + exact byte count
        ↓
TRANSFER VERIFIED
```

This proves that the destination contains exactly the bytes observed during the acquisition pass. It does **not yet prove that the physical card remained unchanged for the entire acquisition**. A future optional second full source read is planned for static-media comparison.

## What remains disabled

This build cannot:

- restore a raw image to an SD card;
- format or repartition media;
- flash firmware;
- add/remove/rename ROMs;
- edit the launcher database;
- write any file or sector to the selected GameStick.

## Windows venv workflow

The supplied local-venv workflow remains canonical.

```bat
setup.bat
run.bat
test.bat
```

`setup.bat`, `run.bat`, and `test.bat` are retained unchanged from the versions supplied for the project.

For raw physical-device reads Windows normally requires elevation. Use the Recovery tab's UAC relaunch, or:

```bat
run_admin.bat
```

The elevated process must perform a fresh probe; probe state is not transferred across the UAC boundary.

## Recommended real-card workflow

1. Prefer a known-good restored card or clone.
2. Run `setup.bat` once.
3. Run `run.bat`.
4. **Auto-detect → Probe Read-Only**.
5. Export the evidence bundle to a different physical disk.
6. Open **Recovery & Images** and choose a host `.img` destination on a different physical disk.
7. Relaunch elevated when prompted and probe again.
8. Create the verified-transfer image.
9. Check the generated `.img.manifest.json` and preserve the pair together.

## Raw acquisition identity binding

The imaging plan binds to observed source identity including:

- physical disk number and byte size;
- bus and partition style;
- selected partition number, offset and size;
- logical/physical sector sizes;
- hashed serial and unique ID when available;
- SHA-256 of the observed partition topology.

Immediately before raw acquisition, those properties are independently re-queried. Any mismatch refuses imaging and requests a fresh probe. After the raw Windows handle is opened, the handle itself is checked for expected disk number and length before sector reads begin.

## Transactional recovery pair

During overwrite, the old image/manifest pair remains authoritative while the new image is staged, reread-verified and given a staged manifest. At commit time, the previous pair is moved to rollback names and the new pair is promoted. If promotion fails, the previous matching pair is restored where possible.

The key invariant is:

> An old VERIFIED manifest must never remain beside a replacement image that it does not describe.

## Physical-destination invariant

For local Windows drives the rule is:

```text
fresh source identity is proven
        AND
destination PhysicalDisk != source PhysicalDisk
        AND
destination volume GUID -> same proven-safe PhysicalDisk
```

not merely “destination path is outside `H:\`”. Another mounted partition of the same SD card is rejected for image, manifest, JSON and evidence-ZIP output. Unknown/stale source identity fails closed. Staging is created on the bound safe volume rather than under the mutable final pathname.

## Optional CLI

After setup:

```bat
image.bat E:\ D:\Backups\gamestick_factory.img
```

The CLI uses the same preflight, device-identity revalidation, physical-destination checks, source confirmation and transactional artifact commit as the GUI.

## Release hygiene

Executable legacy destructive prototype files are intentionally **not included** in this release archive. Historical implementation details belong in source control/separate archival material, not beside the active safety-first application.

Runtime/dev dependencies are pinned in `requirements.txt` / `requirements-dev.txt`.

## Validation

Current suite: **109/109 passing** before the final packaging audit.

See `docs/SAFETY.md`, `docs/DESIGN.md` and `docs/ROADMAP.md`.
