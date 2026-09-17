# GameStick Inspector 0.5.0-alpha11


> **alpha11 Fast Repair Workspace:** turn verified golden catalogue data into a small host-side repair overlay without copying or modifying either 60 GB image. The builder auto-selects only catalogues that are VERIFIED in the golden image and damaged/unreadable in the repair base, requires an identical DAT file size, and revalidates the replacement WQW/filelist before packaging it.

## 0.5.0-alpha11 — Fast Repair Workspace

- Adds **FAST Repair Workspace — Host-side overlay only** to Recovery & Images.
- Automatically detects repair candidates from the existing surgical catalogue comparison semantics; no catalogue code is hard-coded.
- A candidate qualifies only when the golden catalogue control is `VERIFIED`, the repair-base control is not verified, and the corresponding DAT files are exactly the same size.
- Reads only the qualifying DAT payloads plus bounded FAT/catalogue metadata; it does not copy either complete raw image.
- Creates a `.gsworkspace` ZIP container with `manifest.json` and exact replacement DAT payload(s).
- Records the damaged base DAT SHA-256, replacement SHA-256, target FAT-chain fingerprint, cluster count, replacement `filelist.txt` SHA-256, and ROM-name count so a future apply step can fail closed against the wrong base.
- Reopens and verifies the completed workspace archive before promotion.
- Both source images are opened read-only; no source image, SD card, FAT, DAT, or GameStick media is modified.
- CLI: `repair_workspace.bat <golden.img> <base.img> --output gamestick_repair.gsworkspace`.

> **alpha10 Surgical Catalogue Lab:** compare two existing raw images without another full-card pass. The recommended comparator reads only the FAT32 allocation table, WQW central directories, `filelist.txt` from `000`–`014`, and `fileinfo.txt` from `ROOT.DAT`. ROM payloads and artwork are never scanned.

## 0.5.0-alpha10 — Surgical Catalogue Lab

- Adds **SURGICAL Catalogue Lab — RECOMMENDED NEXT** to Recovery & Images.
- Directly locates `ROOT.DAT` and `000/000.DAT` through `014/014.DAT` inside raw FAT32 images.
- Reads only WQW central-directory metadata plus canonical `filelist.txt` / `fileinfo.txt` controls.
- Reports exact bounded ROM-name additions/removals from the catalogue lists.
- Damaged/unreadable DAT controls are reported per catalogue without aborting the whole comparison.
- Source images remain read-only; no ROM payload scan, image mutation, DAT regeneration, restore, or GameStick write authority is introduced.
- CLI: `catalogue_compare.bat <golden.img> <original.img> --report gamestick_catalogue_compare.json`.


## 0.5.0-alpha9 — Fast Image Lab

- Adds **FAST Image Lab — Golden vs Original** to Recovery Images.
- Reads MBR/FAT32 metadata directly from `.img`/`.bin` files without mounting or rescanning the physical SD card.
- Enumerates logical paths/sizes and hashes only bounded launcher/control files (`root.dat`, `NNN/NNN.dat`, and small `cubegm` control/config files).
- Produces a structural SHA-256 that deliberately ignores physical cluster placement, so logically equivalent FAT32 images compare equal even when allocation differs.
- Classifies comparisons as `LOGICALLY_IDENTICAL`, `CONTENT_LAYOUT_DIFFERS_CONTROLS_MATCH`, or `LAUNCHER_OR_CONTROL_DIFFERENCE`.
- Adds `fast_compare.bat` / `src/fast_compare_cli.py`.
- Full-image byte/sector comparison remains available but is now labelled **optional / slow**.
- No new GameStick write authority is introduced. Input images remain read-only.


> **alpha8.3 late-revalidation resilience:** PowerShell storage mapping now has bounded timeout retry, and once an image has passed destination reread verification a later mapping/commit failure preserves the verified staged image instead of deleting hours of acquisition work.

## 0.5.0-alpha8.3 — late source-revalidation resilience

- Windows Storage/PowerShell mapping now allows up to **30 seconds per attempt with two bounded attempts** instead of one brittle 12-second timeout.
- A timeout is still not treated as identity success; source identity remains fail-closed.
- If a source-identity revalidation fails **after the staged image has already passed its complete destination reread SHA-256 verification**, Inspector preserves that verified staging file on the already-proven safe output volume instead of deleting hours of acquisition work.
- Preserved staging is deliberately not promoted to the requested canonical `.img`; the failure text reports its exact path.
- Destination-volume identity failures, promotion failures, pre-verification failures, and explicit cancellation retain strict cleanup/rollback behaviour.
- **226 automated tests passed; 1 Qt smoke test skipped in this packaging environment because PyQt5 is unavailable.**

> **alpha8.2 fresh-extract launcher fix:** a newly extracted release no longer assumes `.venv` already exists. The Windows launchers bootstrap the local environment through `setup.bat` when required and fail with explicit diagnostics instead of `The system cannot find the path specified.`

## 0.5.0-alpha8.2 — Windows launcher/bootstrap hardening

- `run.bat` now works from a fresh extraction: if `.venv\Scripts\python.exe` is absent it runs `setup.bat`, verifies success, then launches the GUI.
- `setup.bat` discovers the Windows Python launcher (`py -3`) first and falls back to `python`, with quoted paths and explicit failure messages.
- CLI, administrator and test launchers use the same missing-environment bootstrap guard.
- Existing alpha8.1 large-device progress telemetry hardening remains unchanged.
- No GameStick write authority is introduced.
- **221 automated tests passed; 1 Qt smoke test skipped in this packaging environment because PyQt5 is unavailable.**

> **alpha8.1 large-device progress fix:** Qt progress signals now carry Python integer objects instead of 32-bit signed integers, preventing byte counters from wrapping negative above 2 GiB/4 GiB-scale boundaries. Imaging/comparison data paths were already using Python integers; this fixes the GUI telemetry only. Pass and overall progress are now shown separately.

## 0.5.0-alpha8.1 — large-device progress telemetry hardening

- Fixes a real Windows GUI defect observed on a ~59.35 GB GameStick image: `pyqtSignal(..., int, int)` truncated/wrapped large byte counts into signed 32-bit values, producing negative counters and apparent progress resets.
- Raw-image and full-image-comparison worker progress signals now use Qt `object` payloads so Python's arbitrary-precision integers survive thread delivery unchanged.
- The imaging engine itself already tracked offsets, hashes and file lengths with Python integers; no acquired bytes or SHA-256 state were being truncated by this UI defect.
- Progress text now distinguishes **pass progress** from **overall progress**, making the intentional start of Pass 2/3 and Pass 3/3 clearer.
- No GameStick write authority is introduced.

> **alpha8 full-image consistency mapping:** Inspector can now compare two or more equal-sized full SD acquisitions entirely read-only, hash every input, localize differing 512-byte sectors, and report strict-majority consensus coverage when three or more acquisitions are available. It never silently chooses between a two-image disagreement and does not materialize a consensus image.

## 0.5.0-alpha8 — full-image disagreement mapping

- Adds read-only comparison of **2+ equal-sized `.img`/`.bin` acquisitions** using a streaming 4 MiB chunk pass and 512-byte disagreement refinement.
- Every input receives a complete SHA-256 during the comparison. Input files are opened read-only and the exported report contains basenames, hashes and structural disagreement metadata, not raw payload bytes.
- Two-image disagreements are always `SPLIT`: neither image is silently treated as authoritative.
- With **3+ images**, a sector is `MAJORITY` only when one byte-identical variant has a strict >50% vote. Ties and multi-way disagreements remain `SPLIT`/ambiguous.
- Reports overall states: `IDENTICAL`, `TWO_IMAGE_DIFFERENCE`, `CONSENSUS_WITH_DISAGREEMENTS`, or `AMBIGUOUS_DISAGREEMENTS`.
- Disagreement ranges are coalesced and bounded to prevent pathological reports from exploding in size; full aggregate sector counts remain accurate even when the range list is truncated.
- Adds `compare.bat` / `python src\compare_cli.py` and a Recovery & Images GUI panel for selecting multiple acquisitions, cancelling a long comparison, and writing a host-side JSON consistency map.
- The report explicitly records `source_writes_performed=false`, `consensus_image_created=false`, and `payload_bytes_exported=false`.
- No raw restore, consensus-image materialization, DAT regeneration, ROM modification, firmware flashing, or GameStick write authority is introduced.
- **219 automated tests passed; 1 Qt smoke test skipped in this packaging environment because PyQt5 is unavailable.**


> **alpha7 static-media consistency reread:** verified raw imaging can now optionally perform an independent second complete read of the same physical source after the first image has transfer-verified. Matching full-read hashes provide repeatability evidence; mismatches or incomplete rereads are preserved as source-instability evidence rather than being confused with transfer failure.

## 0.5.0-alpha7 — optional second full source reread

- Adds an opt-in second complete physical-source read after the staged image has passed destination reread verification.
- The second pass opens the GameStick read-only again and hashes exactly the expected physical-device byte length; it never creates or writes a second image on the GameStick.
- `MATCHED` means the first acquisition hash and independent second full-source hash are identical.
- `MISMATCH` means both full reads completed but produced different SHA-256 values; the first image remains a valid **transfer-verified acquisition**, while the source is explicitly classified as not static across the two reads.
- `SECOND_READ_INCOMPLETE` and `SECOND_READ_ERROR` preserve degraded-media evidence without discarding an already transfer-verified first image.
- Manifest schema advances to **v3** with a dedicated `source_consistency` block. `source_snapshot_consistency_verified` remains `false` because two sequential reads are not an atomic snapshot guarantee; `source_static_media_consistency_verified` is true only when the two complete reads match.
- GUI adds an optional second-source-read checkbox and a third progress pass. CLI adds `--second-source-read`. The option defaults off to avoid doubling reads on suspect media unless explicitly requested.
- Raw restore, firmware flashing, DAT regeneration, ROM modification and every GameStick write path remain disabled.
- **210 automated tests passed; 1 Qt smoke test skipped in this packaging environment because PyQt5 is unavailable.**

## 0.5.0-alpha6.3 — control-payload stability hardening

- Canonical `fileinfo.txt` / `filelist.txt` compressed payload ranges are located from corroborated WQW local/central headers **before** decompression or CRC checking and are independently reread up to three times.
- `READ_STABLE_WITH_CORRUPT_CONTROL` means the sampled compressed control range itself was repeatable but the control failed integrity/decoding validation. This distinguishes stable corruption from unstable media reads.
- `READ_STABLE_PARTIAL` means the bounded reads were repeatable but the WQW/container/control structure was incomplete, policy-limited, or otherwise not fully usable.
- Read-stability evidence exports only canonical status/count metadata. Raw bytes, comparison digests, private filenames and control offsets are not serialized.
- Longitudinal comparison now surfaces `CURRENT_CONTROL_CORRUPT` and `CURRENT_READ_PARTIAL` rather than collapsing both into `CURRENT_READ_INCOMPLETE`.
- Probe schema **v17**; numbered-DAT profile schema **v7**; read-stability schema **v2**; longitudinal-integrity schema **v2**. Device Profile candidate/signature contracts remain v10/v9 and the numbered-DAT structural-signature input remains v5.
- Raw restore, DAT regeneration, ROM modification and every GameStick write path remain disabled.
- **206 automated tests passed; 1 Qt smoke test skipped in this packaging environment because PyQt5 is unavailable.**

## 0.5.0-alpha6.2 — GUI startup regression hotfix

- Fixes the `AttributeError: 'BrowserTab' object has no attribute 'clear_view'` crash during `MainWindow()` construction.
- Changing the device path or baseline now clears stale Read-Only Browser results as originally intended.
- Adds a platform-independent AST regression for the signal target plus a real offscreen Qt `MainWindow()` construction smoke test on hosts with PyQt5.
- No production probing, WQW, longitudinal comparison, imaging, reporting or safety semantics changed.

## 0.5.0-alpha6.1 — baseline UI stale-report hotfix

- **Hotfix:** selecting or changing the device/baseline after a probe invalidates the old report. Profile Evidence and evidence exports refuse stale reports until **Probe Read-Only** is rerun.
- **Fail-loud invariant:** if a baseline is selected but a completed numbered-DAT probe unexpectedly contains no longitudinal result, the GUI rejects the report rather than silently showing an empty baseline table.
- Adds an optional **prior evidence baseline** (`gamestick_evidence.zip` or `gamestick_probe.json`) to the GUI and `probe_cli --baseline`. ZIP baselines are read without extraction and their `MANIFEST.json` commitment for `gamestick_probe.json` must verify before comparison.
- Baseline input is bounded to 16 MiB of probe JSON, 256 KiB manifest data, 32 ZIP members and a conservative compression-ratio ceiling. Unexpected archive members, traversal paths, encryption, malformed JSON and unsupported probe schemas fail closed.
- Longitudinal comparison reuses the already-exported binary fingerprint prefix/tail commitments plus privacy-safe WQW/catalogue structure. It adds **no new sampled-byte digest values** and never serializes the host path of the selected baseline.
- Per-DAT longitudinal states include `UNCHANGED_SINCE_BASELINE`, `CONTENT_REGION_CHANGED_SINCE_BASELINE`, `STRUCTURE_OR_CATALOGUE_CHANGED_SINCE_BASELINE`, `CURRENT_READ_UNSTABLE`, `CURRENT_READ_INCOMPLETE`, and bounded added/missing/not-comparable states.
- Current-session read stability remains authoritative: a DAT that is unstable or incomplete now cannot be presented as merely “changed since baseline.”
- Cross-catalogue auditing now calculates resolution rate, primary target code/count and primary-target share. A dominant alias with a small unresolved remainder is classified as `CROSS_CATALOGUE_ALIAS_WITH_RESIDUAL_GAP` instead of generic `MISMATCH_OBSERVED`. Thresholds are explicit and exported as policy: at least 95% of missing names resolved and at least 95% of those resolutions attributable to the primary target.
- The numbered-DAT structural-signature input intentionally remains **v5**; longitudinal/health diagnostics are excluded from firmware identity. Device Profile candidate/signature contracts also remain v10/v9.
- Probe schema **v16**; numbered-DAT profile schema **v6**; consistency-audit schema **v3**; longitudinal-integrity schema **v1**; read-stability schema remains **v1**.
- Raw restore, DAT regeneration, ROM modification and every GameStick write path remain disabled. Frozen imaging/reporting/safety modules remain unchanged.
- **199/199 automated tests passing** before final packaging audit.

## 0.5.0-alpha5 — read stability & catalogue alias auditor

- Reopens every exact `root.dat` / `NNN/NNN.dat` up to **3 independent times** and compares bounded structural samples: prefix, tail, WQW central-directory region, and verified control-member compressed region when available.
- Read-stability evidence exports only `READ_STABLE`, `READ_UNSTABLE`, or `READ_INCOMPLETE`, region counts and short/error counts. Sampled bytes and digest values never leave memory.
- Stability sampling is capped at **64 KiB per structural region per attempt** and at 65 DAT files (root + 64 numbered catalogues); it is not a full-media reread and does not grant write authority.
- Adds privacy-preserving **cross-catalogue alias resolution**. A local filelist entry absent from its own directory may be resolved against readable entries in other numbered directories; only catalogue-code/count edges are exported.
- Adds `CROSS_CATALOGUE_ALIAS` and `READ_ERRORS_AND_ALIAS_ACCOUNT_FOR_GAP` descriptive statuses. Unresolved local names, unreferenced physical extras, or local/global disagreements remain `MISMATCH_OBSERVED`.
- Physical files not in a catalogue are also checked privately against other local filelists so shared content is distinguished from genuinely unreferenced top-level files.
- Read stability and alias/consistency results are excluded from numbered-DAT structural identity and Device Profile identity.
- Probe schema **v15**; Device Profile candidate schema **v10**; Device Profile signature input **v9**; numbered-DAT profile schema **v5**; consistency-audit schema **v2**; read-stability schema **v1**.
- Raw restore, DAT regeneration, ROM modification and every GameStick write path remain disabled.
- Frozen raw-imaging/output safety modules remain unchanged.
- **193/193 automated tests passing** before final packaging audit.

## 0.5.0-alpha4 — catalogue consistency auditor

- Adds a **read-only, top-level-only filesystem consistency audit** for numbered catalogue roots. The audit is bounded to 64 catalogues and 10,000 directory entries per catalogue and never recursively walks game trees.
- Compares private filename sets in memory across: readable physical files, unreadable/rejected directory entries, local `filelist.txt`, global `fileinfo.txt`, and WQW artwork stems. Only counts/statuses leave the audit.
- Per-catalogue statuses are deliberately descriptive: `MATCHED`, `READ_ERRORS_ACCOUNT_FOR_GAP`, `MISMATCH_OBSERVED`, `CATALOGUE_UNAVAILABLE`, or `PARTIAL`. A mismatch is not automatically labelled firmware corruption because some catalogue codes may be virtual/aliased by design.
- Distinguishes a local catalogue entry that is merely unreadable on the filesystem from a catalogue name that is not observed at all. This lets damaged-card evidence explain apparent missing-ROM counts without exposing the underlying ROM names.
- Recognizes `WQW\x03` at offset zero with a missing/invalid WQW central/end structure as `damaged-or-incomplete-wqw` rather than the generic `not-standard-zip`. This is structural evidence only; it does not imply recoverability.
- Clarifies artwork metrics: `raw_artwork_member_count`, `unique_artwork_stem_count`, and `catalogue_records_with_artwork_count` replace the ambiguous older artwork count label.
- Filesystem/content mismatch counts remain excluded from Device Profile structural identity; changing private physical catalogue names does not change the numbered-DAT candidate ID or Device Profile signature.
- Probe schema **v14**; Device Profile candidate schema **v9**; Device Profile signature input **v8**; numbered-DAT profile schema **v4**; consistency-audit schema **v1**.
- Raw restore, DAT regeneration, ROM modification, and every GameStick write path remain disabled.
- Frozen raw-imaging/output safety modules remain unchanged.
- **188/188 automated tests passing** before final packaging audit.

## 0.5.0-alpha3 — WQW catalogue inspector

- Real `root.dat` / `008.dat` evidence confirmed WQW ZIP-derived records (`WQW\x03` local, `WQW\x02` central, `WQW\x01` end) with XOR-`0xE5` member names.
- Added bounded read-only WQW central/local parsing; no source transformation, extraction, or DAT write path.
- Canonical `fileinfo.txt` / `filelist.txt` are selectively inflated only after local-header agreement, with hard size limits and CRC-32 verification.
- Added privacy-safe semicolon record parsing: `filelist` 3-field structure; `fileinfo` 5-field mixed UTF-8/GBK structure; malformed physical lines are counted without repair.
- Added private global↔platform ROM-name correlation and ROM-stem↔artwork correlation with counts-only exported evidence.
- WQW-based `PROBABLE` promotion requires CRC-verified, structurally valid control records rather than control filenames alone.
- Probe schema v13; Device Profile schema v8; Device Profile signature input v7; numbered-DAT profile v3.
- Production raw-imaging/output safety modules remain unchanged.
- **181/181 automated tests passing** before final packaging audit.

Safety-first GameStick SD-card inspector and **verified-transfer** full-card imager.

The original prototype treated a GameStick as a mounted collection of files. This rebuild treats it as a **bootable block device plus firmware-specific filesystems and launcher metadata**. The 0.4.0 line is frozen; 0.5.x now uses real-device evidence to identify and audit the firmware catalogue without enabling any GameStick write path.

## 0.5.0-alpha2.1 — Windows test-harness portability hotfix

This hotfix does **not** change DAT fingerprinting, probing, imaging, reporting, safety, or Device Profile production behavior. It isolates synthetic tests from live Windows physical-disk/Volume-GUID resolution so `test.bat` remains a unit-test run on Windows. Generic file-to-file imaging and evidence-export tests explicitly use the portable host path, while dedicated Windows safety tests continue to exercise Windows logic with injected/fake device resolvers. Symlink-dependent tests skip cleanly when Windows does not permit unprivileged symlink creation.

## 0.5.0-alpha2 — bounded DAT binary fingerprinting

The first real-card 0.5 probe confirmed the numbered-DAT layout but rejected the standard-ZIP hypothesis on every observed `root.dat` / `NNN.dat`. Alpha2 therefore stops guessing at record format and adds a privacy-safe, sample-bounded binary fingerprint layer.

- Keeps the alpha1 exact-path policy: only `root.dat` and exact `NNN/NNN.dat` files derived from the bounded root sample are opened; there is still no recursive DAT search.
- Reads at most **five 64 KiB windows per DAT** (maximum 320 KiB of fingerprint reads per file, plus the existing bounded ZIP-tail/central-directory inspection when applicable). Small files may be fully covered by one bounded sample; there is no sequential full-file fingerprint scan.
- Records only derived binary evidence: prefix/tail SHA-256 commitments, exact header-signature semantics, allowlisted sampled signature hits, allowlisted structural-token hits, entropy, printable/NUL ratios, and bounded sample-window offsets. Raw sampled bytes and arbitrary strings are never exported.
- Detects exact/allowlisted format signatures such as ZIP, 7z, gzip, bzip2, xz, RAR, SquashFS, SQLite, ELF, PNG/JPEG/GIF/BMP, TAR and ISO9660 where their magic is observed in the bounded sample. A sampled signature hit is evidence only, not a claim that the complete DAT is that format.
- Compares numbered catalogues using private in-process prefix comparison buckets (8/16/32/64 bytes) and reports the largest exact common prefix bucket plus whether `root.dat` shares it. The underlying header bytes are never exported.
- Reports common exact header signatures and common sampled signatures across numbered catalogues to help distinguish a shared container family from payload-only coincidences.
- A real-device numbered-DAT layout with enough structural evidence can now outrank incidental generic launcher candidates as `numbered-dat-binary-catalog`, but binary fingerprinting alone is **capped at candidate/medium** and can never produce `probable`.
- Content commitments, entropy, token/signature counts and private payload changes are **excluded from the numbered-DAT structural signature**; changing private catalogue payload does not create a new firmware-family identity.
- Probe schema is **v12**; Device Profile candidate schema is **v7**; Device Profile structural-signature input schema is **v6**; numbered-DAT profile schema is **v2**; binary fingerprint schema is **v1**.
- No DAT extraction, decompression, record parsing, regeneration, ROM modification, raw restore or raw-device write capability is enabled.
- Frozen recovery/imaging modules remain unchanged.

### What alpha2 is trying to answer

Alpha2 is intentionally descriptive, not interpretive: **what binary family do the real DATs resemble, do all numbered DATs share a common header, does `root.dat` use the same family, and which allowlisted structural signatures appear in bounded samples?** It does not infer catalogue rows or game/artwork relationships yet.

## 0.5.0-alpha1 — numbered-DAT real-device catalogue inspection

Real evidence from the target card showed `root.dat` plus numbered top-level catalogue directories such as `000/000.dat` through `014/014.dat`. Alpha1 adds a hardware-specific, still read-only inspection path for that pattern.

- Detects the numbered-DAT family from the **existing bounded root sample**; it performs no recursive search for DAT files.
- Opens only exact structural paths: `root.dat` and at most one `NNN/NNN.dat` per three-digit top-level catalogue directory.
- Treats three-digit catalogue directories as privacy-sensitive: arbitrary game filenames and child-directory names are redacted from snapshots and excluded from generic metadata discovery.
- Inspects DAT containers with a custom **bounded ZIP central-directory reader** rather than extraction. No archive member is written, extracted, or opened as a filesystem path.
- Caps central-directory bytes and member counts before parsing; ZIP64 and multi-disk containers are reported as unsupported rather than guessed.
- Exports only structural archive evidence: bounded member counts, allowlisted member extensions, compression-method counts, and exact canonical control-member names such as `fileinfo.txt` / `filelist.txt`. All other member names remain private.
- Promotes `root.dat` to the Device Profile launcher/index candidate only when internal container evidence corroborates it; a probable numbered-DAT profile requires a readable ZIP central directory, canonical `fileinfo.txt`, and at least one numbered catalogue containing canonical `filelist.txt`.
- Device Profile structural signatures incorporate the numbered-DAT **structural signature only**, not private member names, catalogue sizes, or game counts.
- Probe schema is **v11**; Device Profile candidate schema is **v6**; Device Profile structural-signature input schema is **v5**; numbered-DAT profile schema is **v1**.
- Raw restore, raw-device write, filesystem modification, DAT regeneration, ROM add/remove, and archive extraction remain disabled.
- Frozen 0.4.0/0.3.4 recovery-imaging modules remain unchanged.

### What alpha1 does *not* claim

A valid ZIP central directory proves only that the DAT exposes bounded ZIP catalogue structure. Alpha1 does not yet decompress or parse `fileinfo.txt` / `filelist.txt` records, does not infer game-row semantics from private values, and does not write/rebuild a DAT. Those are later read-only correlation steps after the real card confirms the container/control-member format.

## 0.4.0-alpha7 — privacy-root metadata/extension consistency

- Metadata discovery no longer descends into **any** privacy-library root (`Roms`, `image`, `artwork`, `covers`, `boxart`, `snap`, and aliases); private catalogue filenames therefore cannot become `CandidateArtifact.path`, launcher candidates, or Device Profile signature inputs.
- Metadata truncation diagnostics use the same evidence-safe path formatter as other filesystem warnings.
- Privacy-root extension summaries export only allowlisted structural suffixes (for example `.nes`, `.zip`, `.png`, `.jpg`); arbitrary media-controlled suffix text is collapsed to `<other>`, while suffixless entries use `<none>`.
- Arbitrary privacy-library filenames remain local and cannot influence `launcher_path`, `launcher_candidates`, `candidate_id`, or `profile_signature_sha256`.
- Probe schema is now **v10**; Device Profile candidate schema is **v5**; structural-signature input schema is **v4**.
- Frozen recovery/imaging safety modules remain unchanged from the 0.3.4-alpha3 baseline.

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

This proves that the destination contains exactly the bytes observed during the acquisition pass. Alpha7 can optionally perform a second complete read of the same physical source. If both full-source SHA-256 values match, the manifest records static-media repeatability across those two sequential reads. A mismatch, early EOF, or read error is preserved explicitly as source-instability evidence. This still does **not** claim an atomic snapshot of the card.

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

Current suite: **172/172 passing** before the final packaging audit.

See `docs/SAFETY.md`, `docs/DESIGN.md` and `docs/ROADMAP.md`.
