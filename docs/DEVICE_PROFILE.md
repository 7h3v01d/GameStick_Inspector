# Device Profile v1 candidate

0.4.0-alpha6 retains a **candidate** profile, not an authoritative hardware/firmware declaration. The serialized candidate payload is schema v4; that schema number is independent of the conceptual "Device Profile v1" format we eventually intend to freeze for a real GameStick family.

## Inputs

The candidate is synthesized only from evidence already produced by the hardened probe:

- filesystem profile match;
- structure SHA-256;
- bounded metadata candidates and their format/schema names;
- bounded, reparse-contained directory snapshots.

No additional filesystem traversal occurs during candidate synthesis. No SQLite rows, CSV data rows, JSON values or ROM filenames are exported by this stage.

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
