# Changelog

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
