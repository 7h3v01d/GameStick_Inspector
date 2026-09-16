# Changelog

## 0.5.0-alpha8 — full-image disagreement mapping

- Added streaming read-only comparison for 2+ equal-sized full acquisitions with complete SHA-256 calculation for every image.
- Added 4 MiB chunk classification with 512-byte refinement only inside disagreeing chunks, producing bounded coalesced disagreement ranges.
- Two-image differences remain `SPLIT`; no source is privileged. Three-or-more-image consensus requires a strict >50% byte-identical majority per sector.
- Added `IDENTICAL`, `TWO_IMAGE_DIFFERENCE`, `CONSENSUS_WITH_DISAGREEMENTS`, and `AMBIGUOUS_DISAGREEMENTS` result states plus per-image majority-deviation counts.
- Added privacy/safety-bounded JSON output containing no raw payload bytes and explicitly recording that no consensus image or source write was performed.
- Added `compare.bat`, `src/compare_cli.py`, GUI image-consistency analysis with cancellation/progress, and regression coverage for identical, majority, split, size mismatch, duplicate input, output-source collision, bounded range output and cancellation.
- Marked Phase 3 known-good second-card/full-image baseline comparison complete. Consensus-image materialization remains intentionally absent.
- **219 automated tests passed; 1 Qt smoke test skipped in this packaging environment because PyQt5 is unavailable.**

## 0.5.0-alpha7 — optional second full source reread

- Added an opt-in second complete physical-source reread after the first image has passed destination reread verification.
- Added explicit source-consistency states: `MATCHED`, `MISMATCH`, `SECOND_READ_INCOMPLETE`, `SECOND_READ_ERROR`, and `NOT_REQUESTED`.
- A mismatch or degraded second read no longer destroys a valid first acquisition: the image remains `transfer-verified`, while source instability is recorded separately.
- Manifest schema v3 adds `source_consistency` and `source_static_media_consistency_verified`; `source_snapshot_consistency_verified` intentionally remains false because sequential rereads are not an atomic snapshot guarantee.
- GUI exposes the feature as an optional third read pass; CLI exposes `--second-source-read`. It defaults off to avoid unnecessary extra reads on suspect media.
- No raw restore, DAT regeneration, ROM modification, firmware flashing, or other GameStick write authority is introduced.
- **210 automated tests passed; 1 Qt smoke test skipped in this packaging environment because PyQt5 is unavailable.**

## 0.5.0-alpha6.3 — control-payload stability hardening

- Repeated-read stability now samples the raw compressed byte range of canonical `fileinfo.txt` / `filelist.txt` controls before decompression/CRC validation, so a repeatably corrupt control payload cannot disappear from the stability model.
- Added `READ_STABLE_WITH_CORRUPT_CONTROL` for stable sampled control bytes whose canonical control fails decompression/CRC/structural validation, and `READ_STABLE_PARTIAL` for stable bounded reads from incomplete WQW/container/control structure.
- Added counts-only `control_failure_assessment` evidence (`STABLE_CORRUPTION`, `STABLE_CONTROL_FAILURE`, `CONTROL_FAILURE_NOT_FULLY_SAMPLED`, or no observed failure); sampled bytes and digest values remain private.
- Damaged/incomplete WQW containers can no longer report plain `READ_STABLE` merely because prefix/tail reads are repeatable.
- Longitudinal comparison distinguishes `CURRENT_CONTROL_CORRUPT` and `CURRENT_READ_PARTIAL` from read instability/incompleteness.
- Probe schema v17; numbered-DAT profile v7; read-stability v2; longitudinal-integrity v2. Numbered-DAT structural-signature input remains v5 and Device Profile contracts remain v10/v9 because health diagnostics still do not define firmware identity.
- Frozen imaging/reporting/safety modules and canonical setup/run/test batch files remain unchanged.
- **206 automated tests passed; 1 Qt smoke test skipped in this packaging environment because PyQt5 is unavailable.**

## 0.5.0-alpha6.2 — GUI startup regression hotfix

- Fixes an alpha6.1 startup crash where `BrowserTab` connected `report_invalidated` to a missing `clear_view()` slot.
- Browser invalidation now clears any stale read-only tree after Device Inspector path/baseline changes.
- The signal connection is made only after the browser tree is constructed.
- Adds an offscreen Qt `MainWindow` construction smoke test so missing signal targets/constructor regressions fail the automated suite.
- No probe, WQW, baseline-comparison, imaging, reporting, or safety semantics changed.

## 0.5.0-alpha6.1 — baseline UI stale-report hotfix

- Fixes a GUI state bug where selecting/changing the optional prior-evidence baseline after a probe could leave the previous report active, allowing Profile Evidence and exports to reuse a report that had never received the selected baseline.
- Device-path or baseline edits now invalidate the current report and clear the Profile Evidence view until Probe Read-Only is rerun.
- Exports refuse stale reports whose selected inputs no longer match the inputs used for the probe.
- If a baseline is selected but a completed numbered-DAT probe unexpectedly contains no longitudinal result, the GUI fails loudly and refuses to accept/export that report.
- Adds end-to-end probe integration coverage for baseline evidence ZIPs.
- 199 automated tests passing before final packaging audit.
- Production probing/comparison semantics and the frozen imaging/reporting/safety core are unchanged.

## 0.5.0-alpha6 — longitudinal integrity & alias classification

- Added bounded, read-only prior-evidence baseline loading from inspector JSON or evidence ZIP. Evidence ZIP baselines are never extracted and must pass their manifest SHA-256/size commitment for `gamestick_probe.json`.
- Added longitudinal per-DAT comparison using existing prefix/tail fingerprint commitments plus privacy-safe container/control structure; no new sampled-byte digest commitments or baseline host paths are exported.
- Added current-session-stability precedence so unstable/incomplete live reads cannot be mislabeled as ordinary longitudinal change.
- Added dominant cross-catalogue alias metrics (resolution rate, primary target and primary-target share) and `CROSS_CATALOGUE_ALIAS_WITH_RESIDUAL_GAP` / read-error variant classifications under explicit 95% thresholds.
- Added GUI prior-baseline selector and `probe_cli --baseline`.
- Probe schema v16; numbered-DAT profile v6; consistency audit v3; longitudinal integrity v1. Numbered-DAT structural-signature input remains v5 and Device Profile contracts remain v10/v9 because these diagnostics do not define firmware identity.
- Frozen imaging/reporting/safety modules and canonical setup/run/test batch files remain unchanged.
- 198 automated tests passing before final packaging audit.

## 0.5.0-alpha5 — read stability & catalogue alias auditor

- Added repeated independent bounded DAT reads with canonical `READ_STABLE`, `READ_UNSTABLE`, and `READ_INCOMPLETE` outcomes.
- Stability checks cover prefix/tail plus WQW central-directory and verified control-member regions when structurally available; 64 KiB per region/attempt, 3 attempts, max 65 DAT files.
- Sample bytes and comparison digest values remain private and are never serialized.
- Catalogue consistency schema v2 now performs private cross-directory resolution of missing local filelist names and private cross-reference checks for physical files absent from their own local catalogue.
- Added `CROSS_CATALOGUE_ALIAS` and `READ_ERRORS_AND_ALIAS_ACCOUNT_FOR_GAP` descriptive statuses; alias edges export only numeric catalogue codes and counts.
- Probe schema v15; Device Profile schema v10; Device Profile signature input v9; numbered-DAT profile v5; consistency audit v2; read-stability v1.
- No production raw-imaging/output safety module changes; no GameStick write path enabled.
- 193/193 tests passing before final packaging audit.

## 0.5.0-alpha4 — catalogue consistency auditor

- Added a bounded top-level filesystem audit for numbered catalogue roots (maximum 64 catalogues, 10,000 directory entries each; no recursive traversal).
- Added counts-only comparison of readable physical files, unreadable/rejected entry names, local `filelist.txt`, global `fileinfo.txt`, and artwork relationships. Arbitrary game/media names never enter exported evidence.
- Added descriptive per-code statuses: `MATCHED`, `READ_ERRORS_ACCOUNT_FOR_GAP`, `MISMATCH_OBSERVED`, `CATALOGUE_UNAVAILABLE`, and `PARTIAL`.
- Added explicit counts for local catalogue entries missing only because the corresponding filesystem entry was unreadable/rejected versus names not observed at all.
- Added `damaged-or-incomplete-wqw` classification when a DAT begins with the observed WQW local-record signature but no valid WQW central/end structure can be established.
- Clarified WQW artwork metrics as raw artwork members, unique artwork stems, and catalogue records with artwork matches.
- Kept filesystem/content consistency counts out of numbered-DAT and Device Profile structural signatures.
- Probe schema v14; Device Profile schema v9; Device Profile signature input v8; numbered-DAT profile v4; catalogue consistency audit v1.
- Production raw-imaging/output safety modules remain unchanged.
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

## 0.5.0-alpha2.2

- Windows test-harness portability hotfix only; production imaging/safety logic unchanged.
- Synthetic file-to-file raw-imaging tests now inject a portable ordinary-file source opener, preventing Windows `DeviceIoControl` raw-disk identity checks from being applied to temporary regular files.
- Added a regression that fails if a synthetic imaging test falls through to the host-dependent production source opener.
- Release hygiene test now checks the release-owned `src/` package tree rather than treating a stale top-level `legacy/` directory in a long-lived developer workspace as archive content.


## 0.5.0-alpha2.1 — Windows test-harness portability hotfix

- Fixed Windows-only unit-test contamination where synthetic file-to-file imaging invoked live physical-disk and Volume-GUID destination binding.
- Portable synthetic raw-imaging tests now explicitly run with `host_system="Linux"`; Windows safety behavior remains covered by dedicated resolver-injected tests.
- Privacy/reporting export tests now explicitly use the portable export path so a synthetic card and synthetic output may coexist under one `tmp_path` without triggering the real same-physical-disk refusal.
- Symlink-dependent Windows tests now skip when the host does not permit unprivileged symlink creation.
- No production acquisition, reporting, safety, DAT fingerprint, Device Profile, or privacy logic changed.


## 0.5.0-alpha2 — bounded DAT binary fingerprinting

- Added a read-only binary fingerprint layer for the real-card numbered-DAT family after alpha1 evidence rejected the standard-ZIP hypothesis.
- Fingerprinting is capped at five 64 KiB windows per DAT; it exports no raw sampled bytes or arbitrary media strings.
- Added prefix/tail SHA-256 commitments, exact header-signature detection, bounded sampled signature/token hits, entropy, printable/NUL ratios, and sample coverage metadata.
- Added common private 8/16/32/64-byte prefix-bucket comparison across numbered DATs and root-vs-numbered comparison without exporting header bytes.
- Added common exact-header and sampled-signature aggregation for the numbered catalogue family.
- Non-ZIP numbered-DAT layouts with sufficient real-device structural evidence may become the top `root.dat` launcher candidate, but remain medium/candidate; fingerprint evidence alone cannot produce `probable`.
- Content-dependent binary commitments and private payload changes are excluded from structural profile identity.
- Probe schema v12; Device Profile schema v7; Device Profile signature input v6; numbered-DAT profile v2; binary fingerprint v1.
- Recovery/imaging safety modules remain unchanged.
- **172/172 automated tests passing** before final packaging audit.

## 0.5.0-alpha1 — real-device numbered-DAT catalogue inspection

- Added bounded read-only detection of the real-device `root.dat` + `NNN/NNN.dat` catalogue family from the already-collected root sample.
- Added a custom bounded ZIP central-directory parser; no DAT member extraction, archive writes, or recursive DAT discovery.
- Added exact canonical control-member evidence for `fileinfo.txt` and `filelist.txt` while redacting all arbitrary archive member names.
- Added hard caps for ZIP central-directory bytes and member counts; unsupported ZIP64/multi-disk structures fail closed.
- Three-digit top-level catalogue directories are now privacy roots: snapshots redact game names and generic metadata discovery does not descend into them.
- Device Profile can prefer corroborated `root.dat` evidence over generic `cubegm` metadata candidates.
- Numbered-DAT structural identity excludes content-dependent sizes, counts, and private member names.
- Probe schema bumped to **v11**; Device Profile candidate schema to **v6**; structural-signature input schema to **v5**; numbered-DAT profile schema introduced at **v1**.
- Frozen recovery/imaging safety modules remain unchanged.
- **162/162 automated tests passing** before final packaging audit.

## 0.4.0-alpha7 — privacy-root traversal and extension hardening

- Metadata discovery now refuses recursion into the complete privacy-library root set rather than only ROM-like roots.
- Private artwork/catalogue files such as `image/Secret Game Name.json` cannot become metadata candidates, launcher paths, or structural-signature inputs.
- Metadata truncation diagnostics now pass through the evidence-safe path formatter.
- Privacy-root extension counts now use an explicit structural allowlist; unknown suffixes collapse to `<other>` and suffixless entries to `<none>`.
- Added end-to-end regressions for private artwork metadata candidates, private artwork-folder truncation, arbitrary ROM/artwork suffixes, and Device Profile signature independence from private artwork metadata names.
- Probe schema bumped to **v10**; Device Profile candidate schema bumped to **v5**; structural-signature input schema bumped to **v4**.
- Frozen recovery/imaging safety modules remain unchanged.
- **151/151 automated tests passing** before final packaging audit.

## 0.4.0-alpha6 — snapshot-derived privacy semantics

- Artwork-library filenames are privacy-redacted by default, matching the ROM-library policy.
- Arbitrary first-level child directory names under ROM/artwork roots are no longer exported as structural evidence.
- Added a conservative exact platform canonicalizer; only recognized platform tokens may leave privacy-library snapshots or feed Device Profile `platform_directories`.
- Arbitrary game/artwork folder names therefore cannot influence `profile_signature_sha256`.
- Extended evidence-safe filesystem diagnostic path redaction to artwork-library roots.
- Added end-to-end regressions for `Roms/Secret Game Folder/`, allowlisted `Roms/FC`, `image/Secret Game Name.png`, and private artwork child folders across ProbeReport, Device Profile, `SUMMARY.txt`, and the complete evidence ZIP.
- Probe schema bumped to **v9**; Device Profile candidate schema bumped to **v4**; structural-signature input schema bumped to **v3**.
- Frozen recovery/imaging safety modules remain unchanged.
- **147/147 automated tests passing** before final packaging audit.


## 0.4.0-alpha5 — privacy-safe filesystem diagnostics

- Centralized exported filesystem diagnostic formatting so raw OS/library exception strings do not bypass the privacy boundary.
- Paths beneath ROM-like privacy-redacted roots are serialized as `<root>/<redacted>` rather than exposing ROM filenames.
- Added reparse/`ForensicPathError` and unreadable/`OSError` ROM regressions covering ProbeReport JSON, `SUMMARY.txt`, and the complete evidence bundle.
- Filesystem diagnostics retain useful exception type and safe errno values while discarding media-controlled raw exception text.
- Documented that XML structural corroboration proves a genuine root start-element was observed, not complete XML well-formedness.
- Probe schema bumped to **v8**; Device Profile candidate remains schema v3.
- Frozen recovery/imaging safety modules remain unchanged.
- **142/142 automated tests passing** before final packaging audit.


## 0.4.0-alpha4 — parser-error privacy and XML parser hardening

- Sanitized all evidence-bearing analyzer/parser errors; raw dependency exception strings are never serialized into candidate artifact details.
- SQLite failures export safe error state/type and SQLite code/name only.
- Replaced XML regex root detection with a bounded ElementTree first-start parser.
- Added regressions for malformed SQLite schema-name leakage, XML DOCTYPE false-root evidence, malformed JSON error privacy, and generic error sanitization.
- Probe schema bumped to v7.
- **139/139 automated tests passing** before final packaging audit.

## 0.4.0-alpha3 — Device Profile privacy/corroboration hardening

- Renamed CSV `header_semantics_verified` to `header_semantics_corroborated`; bounded multi-row inspection may corroborate the shape, but CSV structural terms remain heuristic-only and cannot independently elevate a launcher candidate to `probable`.
- Removed arbitrary JSON top-level/nested key strings from default exported evidence; retained bounded key counts and allowlisted derived semantic terms.
- Removed arbitrary INI/CFG section/key strings from default exported evidence; retained sampled counts and allowlisted derived semantic terms.
- Extended the same privacy-bounded name policy to SQLite schema/column names and XML root names.
- Replaced reversible opaque header hex with a bounded header-prefix SHA-256.
- Changed operator-facing heuristic score presentation from percent-like notation to `N/100`.
- Probe schema v6; Device Profile candidate schema v3; structural-signature input schema v2.
- Added end-to-end privacy regressions for headerless/spoofed CSV, JSON game-title/ROM-path keys, config game-title sections/ROM-path keys, SQLite arbitrary schema names, XML arbitrary root names, and evidence-bundle serialization.
- Frozen recovery/imaging safety modules remain unchanged.
- **135/135 automated tests passing** before final packaging audit.

## 0.4.0-alpha2 — Device Profile privacy/determinism hardening

- Removed raw/unverified CSV first-record values from exported structural evidence. CSV analysis now emits only delimiter, field count, a boolean structural-header signal, and exact allowlisted canonical header terms.
- Added end-to-end headerless-CSV regressions proving game titles, ROM paths and artwork paths do not enter serialized probe evidence or falsely promote launcher confidence.
- Added a central total text ordering `(casefold(value), value)` and deterministic score/path ordering for all hash-affecting Device Profile evidence.
- Added multi-`PYTHONHASHSEED` regression coverage for case-colliding platform names (`FC` / `fc`).
- Path/location/format-only launcher candidates are capped below the high/probable threshold; `probable` now requires internal structural corroboration.
- Renamed the structural candidate hash from ambiguous `evidence_sha256` to `profile_signature_sha256`; it identifies structural profile evidence and intentionally ignores catalog row/content changes.
- Bumped ProbeReport schema to **v5** and Device Profile candidate payload schema to **v2** for the serialized contract change.
- SQLite table-column introspection now uses `fetchmany(80)` for a genuine application-level bound.
- Frozen 0.3.4-alpha3 recovery/imaging safety modules remain unchanged.
- **128/128 automated tests passing** before final packaging audit.

## 0.4.0-alpha1 — Device Profile candidate / launcher discovery

- Added deterministic read-only Device Profile v1 candidate synthesis from the existing bounded probe evidence.
- Added ranked launcher/index candidates using filename, location, structured format and schema/header/key-name evidence.
- Added content-root classification for ROM libraries, artwork, launcher-system data, BIOS, saves and configuration.
- Added privacy-preserving observed platform-directory evidence from the existing ROM-root snapshot; ROM filenames remain redacted.
- Added a Device Profile candidate ID and evidence SHA-256 so repeated equivalent probes produce a stable evidence identity.
- Added Profile Evidence UI sections for the Device Profile candidate, launcher/index ranking and content-root roles.
- Device Profile synthesis performs no additional filesystem traversal and does not read launcher data rows.
- Probe JSON schema bumped to 4; existing recovery/imaging/output safety modules remain unchanged.
- Added discovery regressions for high-confidence SQLite launcher evidence, ordinary settings-file rejection, deterministic candidate identity, content-root classification and privacy preservation.
- **124/124 automated tests passing** before final packaging audit.


## 0.3.4-alpha3 — Bounded cross-platform auto-detection

- Replaced Linux recursive `/media` / `/run/media` / `/mnt` auto-detect walking with bounded parsing of actual mount points from `/proc/self/mountinfo`.
- Linux mount-table input is capped at 2,048 lines and Auto-detect profiles at most 512 unique candidate roots.
- Added a no-`/proc` Linux fallback that is shallow, non-recursive, reparse-safe and globally capped at 4,096 directory-enumeration operations.
- Replaced unbounded macOS `/Volumes` iteration with the central bounded scandir primitive.
- Added a global defence-in-depth Auto-detect candidate/profile cap.
- Browser listings now preserve enumeration failures in `BrowserListing.error`; the GUI shows an explicit filesystem-error marker instead of presenting a corrupt/unreadable directory as empty.
- Added hostile 10,000-mount/candidate regressions and Browser corruption truthfulness coverage.
- Frozen 0.3.3-alpha5 raw-imaging/output safety files remain unchanged.
- **118/118 automated tests passing** before final packaging audit.

## 0.3.4-alpha2 — Corrupt-enumeration budget accounting

- Preserves directory-enumeration accounting when `os.scandir()` fails mid-stream.
- `BoundedScandirResult` now carries an optional `OSError` plus the exact bounded iterator-operation count.
- Counts the final failed/end/truncation probe against the enumeration budget, so the configured global cap bounds actual iterator-advance work.
- Metadata discovery charges failed-directory work before deciding whether to continue and discards partial corrupt samples rather than treating them as evidence.
- Root/profile/snapshot/browser callers fail conservatively on incomplete directory samples.
- Added hostile regressions for partial-yield + `OSError`, `OSError` in the truncation-probe slot, and a global-budget attack using repeated corrupt directories.
- Updated README suite status and release metadata to 0.3.4-alpha2 / 0.3.4a2.
- **109/109 automated tests passing** before final packaging audit.

## 0.3.4-alpha1 — Bounded/streaming directory enumeration

First post-freeze hardening branch after the 0.3.3-alpha5 PASS/FREEZE baseline.

### Robustness hardening

- Added central `bounded_scandir_names()` streaming enumeration.
- A limit of `N` retains at most `N` names and consumes at most `N + 1` entries; the extra entry only proves truncation.
- Removed all production `list(os.scandir(...))` / whole-directory-sort patterns from GameStick forensic traversal.
- Browser is bounded to 1,000 entries per directory and 5,000 nodes per loaded tree.
- Directory snapshots consume at most 501 entries for a 500-entry sample.
- Top-level snapshot discovery and root evidence/profile scans are bounded.
- Metadata discovery now has both a per-directory enumeration cap and a global directory-entry enumeration cap, in addition to the existing file/artifact/depth caps.
- Bounded samples are sorted only after capture; truncation is explicitly reported rather than presented as exhaustive ordering.
- Profile scoring reuses one bounded root scan for all candidate profiles during a profile pass.

### Regression coverage

- synthetic 10,000-entry `scandir` with `limit=1` consumes exactly two entries;
- Browser limit bounds enumeration, not merely returned rows;
- directory snapshot limit is enforced before full enumeration;
- top-level snapshot discovery uses a hard root-enumeration cap;
- metadata scan enforces global/per-directory enumeration budgets;
- probe policy exports the active enumeration bounds.

## 0.3.3-alpha5 — Read-side reparse/junction containment

Hardening-only release responding to the external adversarial review of 0.3.3-alpha4. No feature expansion.

### HOLD blocker closed

- **Windows reparse/junction traversal**
  - Added a central `fs_safety.py` boundary that uses non-following `lstat` metadata and the Windows `FILE_ATTRIBUTE_REPARSE_POINT` bit, preserving the Python 3.10/3.11 floor.
  - Symlinks, junctions and all other reparse-point objects are rejected before normal directory/file traversal.
  - Every existing candidate is also canonicalized and required to remain beneath the resolved selected GameStick root before hashing/parsing.
  - Applied to root entries, metadata candidate discovery, directory snapshots, profile markers, and the GUI Browser data source.
  - GameStick profile markers now require real non-reparse directories, closing the name-only `Roms` / `cubegm` / `image` false-high-confidence case.

### Regression coverage

- emulated Python-3.10/3.11 Windows junction semantics via `st_file_attributes`;
- reparse subtree cannot leak config keys, SQLite schema, hashes or candidate paths;
- reparse subtree cannot enter snapshots or Browser entries;
- top-level reparse entries are absent from root evidence;
- selected root itself cannot be a reparse point;
- canonical containment still rejects an escape when the primary link/reparse indicator is deliberately hidden.

### Validation

- **98/98 automated tests passing** before final packaging audit.
- Existing source/destination physical identity, bound-volume staging, transactional image/manifest, and `GENERIC_READ` raw-source controls remain intact.

## 0.3.3-alpha4 — Output identity-lifetime hardening

Hardening-only release responding to the external adversarial review of 0.3.3-alpha3. No feature expansion.

### HOLD blockers closed

- **Unknown source identity now fails closed on Windows**
  - Generated JSON/ZIP/image/manifest output is refused when the source physical disk cannot be proven.
  - UNC/network output rejection is independent of source-identity availability.
- **Fresh source identity before generated writes**
  - JSON/evidence export reuses the raw-imaging source identity comparison machinery.
  - Disk re-enumeration or identity mismatch refuses export and requires a fresh probe before staging begins.
  - Source identity is revalidated again immediately before commit.
- **Staging bound to a stable safe destination volume**
  - Local destination drive resolves to a Windows volume GUID.
  - The volume GUID is independently queried for its physical disk number and must agree with the drive mapping.
  - Unpredictable exclusive staging objects are created directly on that proven-safe volume, not beside a mutable destination pathname.
  - Raw image and manifest staging use the same bound-volume model.
  - A final-path junction/drive swap toward the GameStick cannot move staged bytes across volumes; promotion fails instead.

### Regression coverage

- unknown `source_disk_number`;
- unknown source plus UNC destination;
- source Disk 4 becoming Disk 5 before export;
- destination-directory swap immediately before report staging;
- equivalent destination swap during raw-image staging;
- drive-letter mapping and stable volume-GUID physical identity disagreeing.

### Validation

- **92/92 automated tests passing** before final packaging audit.
- Existing read-only raw source, transactional pair, opened-handle identity, and trusted PowerShell controls remain intact.

## 0.3.3-alpha3 — Generated-output boundary hardening

Hardening-only release responding to the external adversarial review of 0.3.3-alpha2.

### HOLD blocker closed

- **Report/evidence temp symlink write escape**
  - JSON and ZIP exporters no longer open predictable `<destination>.tmp` paths in truncating write mode.
  - Staging files are created with exclusive, unpredictable names in the validated destination directory.
  - The already-open file descriptor/handle is used for all writes; ZIP output is given that open seekable handle directly.
  - Staging content is flushed and fsynced before commit.
  - A pre-existing legacy predictable temp object, including a symlink or dangling symlink, causes refusal and is never overwritten.
  - The destination safety invariant is revalidated immediately before atomic replacement.
  - Regression tests reproduce the alpha2 symlink attack against both JSON and ZIP exporters and verify the protected GameStick-side target remains byte-for-byte unchanged.

### Physical-output alias hardening

- The canonical/resolved output path is now authoritative for Windows drive-to-physical-disk validation.
- A syntactic `C:\alias\...` path that resolves to `F:\...` is validated as `F:` rather than `C:`.
- UNC/network destinations are explicitly refused in this release because their backing physical disk cannot be proven separate from the source.

### Manifest correctness

- Fixed initialization ordering that incorrectly reset `source_identity_revalidated_before_open` to `false` after a successful revalidation.
- Added a regression test that performs successful revalidation and asserts the generated manifest records `true`.

### Validation

- **85/85 automated tests passing** before final packaging audit.
- Existing alpha2 transactional imaging, physical identity binding, handle-level IOCTL validation, and trusted PowerShell controls remain intact.

## 0.3.3-alpha2 — Adversarial raw-imaging hardening

Hardening-only release responding to the external adversarial review of 0.3.3-alpha1.

### HIGH blockers closed

- **Transactional image + manifest replacement**
  - A new image is written and reread-verified under staging names.
  - Its matching manifest is generated and fsynced while any previous pair is still untouched.
  - Existing authoritative image/manifest artifacts are moved to rollback names only at final commit.
  - The old manifest is moved away **before** the old image can be replaced, so a stale VERIFIED manifest can never remain beside a new image.
  - Any promotion failure attempts to restore the previous matching pair.
  - Regression tests force destination-verification failure, manifest-generation failure, and manifest-promotion failure.

- **Physical source identity binding / TOCTOU hardening**
  - Imaging plans now bind to disk number, total byte size, bus, partition style, selected partition number/offset/size, sector sizes, hashed serial/unique ID when available, and a SHA-256 of the full observed partition topology.
  - The physical mapping is independently re-queried immediately before raw acquisition.
  - Any mismatch refuses imaging and requires a fresh probe.
  - On Windows, after `CreateFileW` opens the raw source, `DeviceIoControl` validates the actual handle's disk number and byte length before any imaging read proceeds.

- **Elevated PowerShell PATH hijack removed**
  - Trusted absolute Windows PowerShell locations are preferred.
  - An elevated process **never** executes a PATH-resolved `powershell.exe`/`pwsh.exe` mapping helper.
  - PATH-resolved PowerShell helpers are not used at any privilege level.
  - Regression coverage simulates a poisoned `C:\evil\powershell.exe` at the front of PATH.

### Adjacent hardening

- Output safety now enforces `destination PhysicalDisk != source PhysicalDisk` for local Windows drive-letter destinations, not merely `destination path outside selected volume`.
- This physical-disk invariant applies to raw images, manifests, diagnostic JSON and evidence ZIPs.
- Local destination mapping failures fail closed rather than being guessed safe.
- Recovery manifests now explicitly describe the artifact as **transfer verified**; destination reread verification does not claim that the source media was static for the entire acquisition.
- Manifest schema bumped to 2 and records the bound source identity / partition-layout hashes.
- `pyproject.toml` corrected to PEP 440 version `0.3.3a2`.
- Runtime/dev dependencies are reproducibly pinned.
- Executable legacy destructive prototype code is excluded from the release archive; a documentation-only legacy note remains.
- Leon's canonical `setup.bat`, `run.bat`, and `test.bat` remain unchanged.

### Validation

- **79/79 automated tests passing** before final audit.
- Python sources compile with warnings treated as errors.
- Active raw-device source access remains `GENERIC_READ` only; no `GENERIC_WRITE` path has been added.

## 0.3.3-alpha1 — Raw-imaging elevation UX

- Added explicit Windows process-elevation detection to the Recovery & Images tab.
- Added one-click UAC relaunch using the current venv Python executable.
- Elevated instances require a fresh read-only probe.
- Added optional `run_admin.bat` while keeping the canonical venv batch workflow unchanged.

## 0.3.2-alpha1 — Windows disk mapping hardening

- Added canonical Windows PowerShell path discovery and mapping-backend diagnostics.
- Successful reports record/display the mapping backend used.

## 0.3.1-alpha1 — Corruption-tolerant probing

- Individual corrupt/unreadable filesystem objects no longer abort the probe.
- Reports become `DEGRADED`, record the read issue, and retain valid physical-device evidence.

## 0.3.0-alpha1 — Read-only raw recovery imaging

- Added true sector-for-sector physical-device reads on Windows.
- Added boot/system/external-device gates, exact-byte imaging, SHA-256 transfer verification and manifests.
- Raw restore, firmware flashing, formatting and GameStick filesystem writes remained disabled.
