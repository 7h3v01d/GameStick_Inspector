# GameStick Inspector 0.4.0-alpha6

Safety-first GameStick SD-card inspector and **verified-transfer** full-card imager.

The original prototype treated a GameStick as a mounted collection of files. This rebuild treats it as a **bootable block device plus firmware-specific filesystems and launcher metadata**.



## 0.4.0-alpha6 — snapshot-name privacy hardening

- ROM-like and artwork-like library roots now treat arbitrary child file **and directory** names as private by default.
- Artwork filenames such as `image/Secret Game Name.png` are redacted from default probe/evidence output just like ROM filenames.
- First-level names beneath privacy library roots are no longer exported verbatim merely because they occupy a structural-looking position.
- Recognized platform evidence is derived only through an exact conservative allowlist/canonicalizer (for example `FC`, `SFC`, `PS1`, `GBA`); unknown names remain local and do not enter `DirectorySnapshot`, Device Profile `platform_directories`, or `profile_signature_sha256`.
- Filesystem diagnostics beneath artwork roots now use the same `<redacted>` path treatment already used for ROM roots.
- Probe schema is now **v9**; Device Profile candidate schema is **v4**; structural-signature input schema is **v3** to make the tightened snapshot semantics explicit.
- Frozen recovery/imaging safety modules remain unchanged from the 0.3.4-alpha3 baseline.

## 0.4.0-alpha5 — privacy-safe filesystem diagnostics

- Exported filesystem warnings now use a central evidence-safe path/error formatter.
- Entries beneath privacy-redacted ROM-like roots are represented as `Roms/<redacted>` (or the corresponding top-level ROM-like root); filenames never escape through warning/read-error text.
- Raw `OSError` / `ForensicPathError` text is not serialized in filesystem diagnostics because operating-system messages can repeat media-controlled paths. Evidence retains the exception type and safe `errno` where available.
- Reparse and unreadable-ROM regressions verify filename absence from `ProbeReport.to_dict()`, `gamestick_probe.json`, `SUMMARY.txt`, and the evidence ZIP while still recording the skip/error and DEGRADED state when appropriate.
- XML launcher corroboration means a genuine root **start element** was observed within the bounded sample; it does not claim the XML document was fully parsed or well-formed.
- Probe schema is now **v8**. Device Profile candidate schema remains **v3**.
- Frozen recovery/imaging safety modules remain unchanged from the 0.3.4-alpha3 baseline.

## 0.4.0-alpha4 — parser-error privacy and XML structural hardening

- Parser/library exception text is no longer serialized into privacy-bounded evidence. Error evidence records only a boolean state, exception type, and safe numeric/symbolic codes where available.
- Malformed SQLite schema identifiers therefore cannot escape through `str(sqlite3.Error)`.
- XML root discovery now uses a bounded `ElementTree.XMLParser` and the first legitimate start-element event; regex-based XML structure detection has been removed.
- Element-like text inside comments/DOCTYPE/entity declarations cannot manufacture launcher-schema evidence.
- Probe schema is now **v7**. Device Profile candidate schema remains **v3** and structural-signature input schema remains **v2** because their serialized fields are unchanged.
- Frozen recovery/imaging safety modules remain unchanged from the 0.3.4-alpha3 baseline.

## 0.4.0-alpha3 — interpretation privacy/corroboration hardening

This patch keeps the frozen **0.3.4-alpha3 PASS/FREEZE** recovery/imaging baseline unchanged and closes the fresh interpretation/privacy findings from the alpha2 adversarial review.

- CSV first-row semantics are now explicitly **corroborated**, not verified. Up to three bounded rows are inspected locally, but CSV-derived terms are **heuristic-only** and cannot independently elevate a launcher/index candidate to `probable` until a real GameStick CSV format is observed and frozen.
- JSON no longer exports arbitrary source key names. It exports bounded counts plus allowlisted derived semantic terms only.
- INI/CFG no longer exports arbitrary section/key names. It exports sampled counts plus allowlisted semantic terms only.
- The same privacy rule is applied defensively to SQLite schema/column names and XML root names: arbitrary source strings stay local; exported evidence contains bounded counts and derived allowlisted terms.
- Opaque/non-SQLite header bytes are no longer exported as reversible hex; only a SHA-256 of the bounded header prefix and the sampled-byte count are emitted.
- Launcher/profile scores are presented as **heuristic scores (`N/100`)**, not percentages/probabilities.
- Probe schema is now **v6** and the Device Profile candidate payload is **schema v3**, making the changed evidence semantics explicit.

The default evidence bundle therefore follows one interpretation rule across structured metadata: **position alone does not make an arbitrary string schema**. Unknown names contribute counts, not raw text.

## 0.4.0-alpha2 — interpretation-layer privacy/determinism hardening

This patch keeps the frozen **0.3.4-alpha3 PASS/FREEZE** recovery/imaging baseline unchanged while hardening the new Device Profile interpretation layer introduced in alpha1.

The Device Profile candidate is still synthesized entirely from evidence already collected by the bounded read-only probe; it performs **no additional filesystem traversal**. Alpha2 adds:

- privacy-safe CSV structural analysis: arbitrary first-record values are never exported; only allowlisted, exact identifier-style structural terms such as `title`, `rom`, `path`, `image`, `system` and `platform` may be emitted;
- an end-to-end headerless-CSV privacy boundary so game titles, ROM paths and artwork paths cannot leak into the probe/evidence bundle merely because they occupy the first CSV row;
- total deterministic ordering for all evidence-bearing case-insensitive sorts, including case collisions such as `FC` / `fc`;
- `probable` launcher resolution only when internal schema/header/key evidence corroborates the filename/location/format heuristic; path/format-only candidates are capped below the high-confidence threshold;
- `profile_signature_sha256` terminology for the structural Device Profile signature. This signature is intentionally stable across catalog-row/content changes and is **not** presented as a source-evidence/content hash;
- genuinely bounded SQLite column introspection via `fetchmany(80)` rather than materializing all columns before slicing;
- probe schema **v5** and Device Profile candidate payload schema **v2** to make the serialized field/meaning changes explicit.

This remains a **candidate**, not a frozen hardware profile. The next step is still to run the inspector against a known-good real GameStick and use the resulting evidence bundle to identify the authoritative launcher/index format before correlation or modification code is added.

## 0.3.4-alpha3 — frozen hostile-filesystem/resource-hardening baseline

This PASS/FREEZE branch keeps the 0.3.3-alpha5 recovery-imaging architecture unchanged while completing the bounded-enumeration model across user-reachable Auto-detect paths.

Directory traversal uses the central streaming `bounded_scandir_names()` primitive. A requested sample of `N` entries performs at most `N + 1` iterator advances; mid-enumeration filesystem errors preserve and charge partial work, and incomplete samples are not trusted as evidence.

Applied boundaries now include:

- Browser: 1,000 entries per directory plus a 5,000-node whole-tree budget; corrupt enumeration is surfaced explicitly rather than presented as an empty directory;
- directory snapshots: 500 entries per directory;
- top-level snapshot discovery: at most 2,048 root entries and 32 snapshot directories;
- metadata discovery: at most 4,097 iterator advances for one directory sample and 20,000 directory-enumeration operations globally;
- root evidence/profile discovery: bounded top-level samples;
- Linux Auto-detect: actual mount points from `/proc/self/mountinfo`, at most 2,048 mount-table lines and at most 512 candidate/profile probes;
- Linux no-`/proc` fallback: no recursive `os.walk()`, at most 4,096 directory-enumeration operations globally;
- macOS Auto-detect: bounded `/Volumes` sampling (512 retained entries, at most 513 iterator advances);
- Auto-detect globally profiles at most 512 unique candidate roots.

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

Current suite: **147/147 passing** before the final packaging audit.

See `docs/SAFETY.md`, `docs/DESIGN.md` and `docs/ROADMAP.md`.
