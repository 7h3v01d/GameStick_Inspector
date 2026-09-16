# Device Profile v1 candidate

0.5.0-alpha6 retains the generic Device Profile as a **candidate** while adding a read-only parser for the observed WQW numbered-DAT catalogue family. The serialized Device Profile payload is schema v10; that schema number is independent of the conceptual "Device Profile v1" format we eventually intend to freeze for a real GameStick family.

## Inputs

The candidate is synthesized only from evidence already produced by the hardened probe:

- filesystem profile match;
- privacy-bounded profile-structure SHA-256;
- bounded metadata candidates and their format/schema names;
- bounded, reparse-contained directory snapshots.

Generic candidate synthesis adds no traversal. The numbered-DAT inspector separately opens only exact `root.dat` / `NNN/NNN.dat` structural paths derived from the already-bounded root sample; it performs no recursive DAT search. No SQLite rows, CSV data rows, JSON values or ROM filenames are exported by this stage.

### CSV privacy boundary

CSV first-record values are untrusted data, not presumed headers. The probe does **not** export those raw values. It may export only:

- delimiter;
- field count;
- exact allowlisted canonical structural terms derived from identifier-like fields (`title`, `rom`, `path`, `image`, `system`, etc.);
- whether multiple exact header aliases were recognized strongly enough to permit structural corroboration.

`csv.Sniffer().has_header()` is not used as a privacy boundary.

## Launcher ranking

Launcher/index candidates are scored from observable structural signals such as:

- known index-style filenames (`games.db`, `gamelist.xml`, `game.csv`, etc.);
- location beneath launcher-style directories such as `cubegm`;
- structured metadata format;
- internal schema/header/key names containing game/ROM/path/title/system/image-style terms.

Filename/location/format evidence may nominate a candidate, but it cannot by itself produce `probable`. Internal structural corroboration is required for the high/probable threshold.

## Structural signature

`profile_signature_sha256` is a deterministic hash of the **derived structural profile evidence**. It is intentionally stable across changes to launcher catalog rows/game content when the observable schema/layout remains the same.

It is **not** a source-evidence/content hash and must not be used to claim two source artifacts are byte-identical. Artifact SHA-256 values remain separate probe evidence where available; a future `evidence_set_sha256` may bind those if a stronger provenance identifier is needed.

All signature-affecting case-insensitive string ordering uses a total secondary key, so case collisions such as `FC` and `fc` remain deterministic across Python hash seeds.

## Freeze rule

A hardware-specific Device Profile v1 should not be frozen until a known-good real-card evidence bundle identifies the authoritative launcher/index and enough structure is understood to write a deterministic read-only parser and consistency model.

## Default privacy-bounded metadata semantics

The default evidence model does not export arbitrary media-supplied strings merely because they occur in a schema-like position. CSV fields, JSON keys, config section/key names, SQLite schema/column names and XML root names are reduced to allowlisted semantic terms plus bounded counts. Unknown names remain local to the analyzer. CSV terms are heuristic-only and cannot independently promote a launcher/index candidate to `probable` until a real device format is frozen.

## XML corroboration semantics

XML evidence is intentionally recovery-oriented. The bounded parser stops at the first legitimate start-element event and derives only allowlisted semantics from that root tag. Observing a genuine root start element can therefore corroborate a damaged/truncated launcher file, but it **does not prove that the full XML document is well-formed or completely parseable**.

## Filesystem diagnostic privacy

Default exported evidence treats diagnostic text as part of the privacy boundary. Paths beneath ROM-like roots are filename-redacted (for example `Roms/<redacted>`), and raw filesystem exception strings are not serialized because OS messages can echo media-controlled filenames. Error type and safe numeric errno values may be retained.

## Snapshot-derived privacy semantics

ROM and artwork library snapshots do not treat arbitrary content names as structural evidence. File names are redacted, and first-level child directory names are exported only when they exactly map to a conservative known-platform alias. Unknown game/artwork folder names contribute no exported identifier and do not enter `platform_directories` or the structural profile signature. This is intentionally stricter than assuming every directory immediately below `Roms` is a platform.
## Privacy-library traversal and extension semantics

Launcher metadata discovery does not recurse into ROM/artwork/catalogue privacy roots. Files beneath roots such as `Roms`, `image`, `artwork`, `covers`, `boxart`, and `snap` are content, not launcher-schema candidates by default, so their filenames cannot become launcher paths or structural-signature inputs.

Privacy-root extension summaries are also structural-only: known ROM/container/artwork suffixes may be counted by canonical extension, suffixless entries are counted as `<none>`, and every unknown media-controlled suffix is collapsed to `<other>`. Arbitrary suffix text is never exported or hashed into Device Profile identity.



## 0.5.0 numbered-DAT real-device profile

The frozen 0.4 generic profile remains a heuristic fallback. Real target-card evidence introduced a separate numbered-DAT candidate identified by `root.dat` and three-digit catalogue roots containing paired `NNN.dat` files. The DAT inspector is read-only and bounded: it consumes the existing root sample, opens exact structural paths only, parses at most a capped ZIP central directory, and never extracts members.

`PROBABLE` requires internal corroboration: `root.dat` must expose a valid bounded ZIP central directory with canonical `fileinfo.txt`, and at least one numbered catalogue must expose canonical `filelist.txt`. Member names other than those exact control identifiers are private and cannot enter evidence or signatures. A central-directory match is **not** yet a claim that the control-file row format is understood.
## 0.5.0-alpha2 binary fingerprint semantics

Real-card evidence showed the numbered-DAT architecture while every observed DAT failed the bounded standard-ZIP check. Alpha2 therefore treats the binary format as **unknown until evidenced**, not as ZIP-by-filename.

Each exact DAT path may be sampled at up to five fixed-position windows of at most 64 KiB each. Evidence can include content commitments (SHA-256), allowlisted binary magic/signature semantics, allowlisted structural-token semantics, entropy and byte-class ratios. Raw sample bytes and arbitrary strings are not exported. Small files can be fully covered by a bounded sample; this is recorded separately from the policy statement that no sequential full-file fingerprint scan is performed.

Prefix/tail sample hashes are comparison commitments only. They and other content-dependent metrics do **not** enter numbered-DAT structural identity. The 8/16/32/64-byte prefix comparison itself is performed only in memory; the per-file short-prefix bytes/hashes are not exported. The numbered profile may report only the largest exact shared prefix bucket and common allowlisted signatures, but those observations do not make the record format understood.

For non-ZIP real-device layouts, `root.dat` may be ranked as `numbered-dat-binary-catalog` once the numbered layout itself reaches the medium structural threshold. This can outrank incidental generic metadata candidates, but it is always capped below `probable`. `PROBABLE` still requires an understood internally corroborated format; binary fingerprinting alone cannot grant that state.


## 0.5.0-alpha3 WQW catalogue semantics

Real `root.dat` / `008.dat` bytes established a WQW ZIP-derived dialect rather than an unidentified binary container. The inspector recognizes `WQW\x03` local records, `WQW\x02` central records and `WQW\x01` end records; filename bytes are decoded privately with XOR `0xE5`. The source DAT is never rewritten or converted on disk.

Only exact root-level `fileinfo.txt` and `filelist.txt` controls are eligible for selective inflation. Their local header must agree with the central record; supported compression is stored/deflate only; compressed and uncompressed sizes are capped; and CRC-32 must verify before parsing. Duplicate or central-only control names do not corroborate the profile.

`filelist.txt` is parsed as three semicolon-separated fields. `fileinfo.txt` is parsed as five fields using UTF-8 first and GBK fallback per field. The parser exports only aggregate encoding/valid/malformed counts, per-catalogue record counts, ROM-stem↔artwork match counts and global↔platform ROM-name correlation counts. It never exports titles, ROM paths, artwork names or search keys. Physical malformed lines are counted as malformed and are not silently repaired.

For the WQW family, `PROBABLE` requires a CRC-verified structurally valid `fileinfo.txt` plus at least one CRC-verified structurally valid numbered `filelist.txt`; WQW signatures or filenames alone are insufficient.


## 0.5.0-alpha4 catalogue consistency semantics

Alpha4 adds a separate read-only **catalogue consistency audit** after WQW parsing. This is not part of Device Profile identity and does not grant write authority. It enumerates only the immediate children of each observed three-digit catalogue directory, with hard caps of 64 catalogues and 10,000 entry names per catalogue; it never recursively walks game content.

Private names are normalized and compared only in memory against the corresponding `filelist.txt` ROM-name set and the `fileinfo.txt` global-name set. Exported evidence contains counts/statuses only. In particular, alpha4 distinguishes:

- a catalogue entry present as a readable physical file;
- a catalogue entry whose directory name was observed but whose filesystem object could not be safely/statistically inspected;
- a catalogue entry not observed in the bounded filesystem pass;
- a readable physical file not represented in the local filelist;
- local/global catalogue disagreements.

The per-code status vocabulary is deliberately descriptive rather than diagnostic: `MATCHED`, `READ_ERRORS_ACCOUNT_FOR_GAP`, `MISMATCH_OBSERVED`, `CATALOGUE_UNAVAILABLE`, or `PARTIAL`. For example, a code with a populated filelist but no physical files is reported as a mismatch observation, not automatically called corruption, because a future real-device profile may establish virtual/aliased catalogue semantics.

Filesystem/content consistency counts are excluded from the numbered-DAT structural signature and from Device Profile identity. Private catalogue changes therefore do not manufacture a new firmware-family identity.

A DAT beginning with the observed `WQW\x03` local-record magic but lacking a valid bounded WQW central/end structure is reported as `damaged-or-incomplete-wqw`. This records evidence of the family while explicitly refusing to claim that the container is complete or parseable.


## 0.5.0-alpha5 read-stability and alias semantics

Alpha5 adds two health/interpretation layers that are deliberately **excluded from firmware identity**. First, each exact DAT is reopened three times and bounded structural regions are compared in memory. The exported status is `READ_STABLE`, `READ_UNSTABLE`, or `READ_INCOMPLETE`; sampled bytes and digest values are not exported. Valid WQW containers contribute central-directory and verified control-member regions in addition to prefix/tail samples.

Second, the catalogue consistency auditor now resolves names privately across numbered directories. If a local filelist name is absent from its own directory but present as a readable file in another numbered directory, the evidence exports only the target catalogue code and count. This can produce `CROSS_CATALOGUE_ALIAS` when all otherwise-missing content is explained by shared/aliased placement. Read errors and alias resolution can combine as `READ_ERRORS_AND_ALIAS_ACCOUNT_FOR_GAP`. Names that remain unresolved, unreferenced physical extras, or local/global catalogue disagreements remain `MISMATCH_OBSERVED`.

Neither read-stability results nor alias/consistency counts enter the numbered-DAT structural signature or Device Profile signature input beyond the numbered-DAT structural identity itself.


## 0.5.0-alpha6 longitudinal integrity and dominant-alias semantics

Alpha6 accepts an optional prior inspector JSON or evidence ZIP as a **read-only baseline**. Evidence ZIPs are never extracted: the loader accepts only the canonical evidence members, applies hard size/member/compression bounds, and requires the manifest SHA-256/size commitment for `gamestick_probe.json` to verify before use. The selected host path is never serialized.

Longitudinal comparison intentionally reuses the binary fingerprint prefix/tail commitments already present in earlier evidence plus privacy-safe WQW/container/control structure. It does not export new DAT sampled-region digest commitments. Current-session stability has precedence: `READ_UNSTABLE` or `READ_INCOMPLETE` cannot be collapsed into an ordinary cross-run change result.

The consistency auditor also exports a resolution rate and dominant target for cross-catalogue aliases. A small residual gap may be classified as `CROSS_CATALOGUE_ALIAS_WITH_RESIDUAL_GAP` only when at least 95% of otherwise-missing local names resolve elsewhere and at least 95% of those resolutions point at one primary catalogue. This remains descriptive evidence, not authority to rewrite the catalogue.

These diagnostics do **not** enter numbered-DAT structural identity. The numbered-DAT structural-signature input remains v5 and the generic Device Profile candidate/signature contracts remain v10/v9.
