# Pace note — alpha10

No further multi-hour full-card acquisitions are required for the current customisation investigation. Prefer surgical catalogue/control reads from the two preserved images. Deep full-image comparison remains optional.

# Pace note — alpha9

The current project path prioritises image-local structural analysis and customisation research. Repeated full-device acquisitions are no longer required by default. Deep whole-image comparison remains optional evidence work.

# Roadmap

## Phase 1 — Evidence & Safety

- [x] quarantine/remove active legacy destructive implementation
- [x] corruption-tolerant read-only volume probe
- [x] Windows physical disk + partition mapping
- [x] evidence-backed profile scoring
- [x] bounded metadata/schema inspection
- [x] genuinely bounded/streaming directory enumeration + cross-platform Auto-detect budgets (0.3.4-alpha3)
- [x] privacy-bounded JSON/evidence ZIP exports
- [x] prevent generated output on any partition of the source physical disk
- [x] fail closed on stale/unknown source identity before generated output
- [x] bind generated-output staging to a stable proven-safe Windows volume
- [x] capture known-good real-card 0.4.0 evidence bundle
- [x] rank launcher/index candidates from bounded schema evidence (0.4.0-alpha1)
- [x] harden Device Profile privacy, determinism and probable-candidate semantics (0.4.0-alpha2)
- [x] extend privacy-bounded structural semantics across CSV/JSON/config/SQLite/XML and cap CSV confidence (0.4.0-alpha3)
- [x] sanitize parser-error evidence and replace regex XML root detection with bounded real parsing (0.4.0-alpha4)
- [x] close privacy-redacted filesystem-warning filename side channels (0.4.0-alpha5)
- [x] close snapshot-derived ROM/artwork name privacy and false-platform channels (0.4.0-alpha6)
- [x] close privacy-root metadata traversal and arbitrary-extension evidence channels (0.4.0-alpha7)
- [x] identify authoritative launcher/index container family from real-card evidence (0.5.0-alpha3 WQW catalogue parser)
- [x] correlate global/per-platform ROM and artwork structure read-only with privacy-safe counts (0.5.0-alpha3)
- [~] freeze hardware-specific Device Profile v1 after adversarial review of WQW parsing/correlation

## Phase 2 — Recovery Imaging

- [x] raw physical-device **read** imaging
- [x] boot/system/external-device fail-closed gates
- [x] exact-byte acquisition and streaming SHA-256
- [x] destination full reread verification
- [x] transactional image+manifest replacement
- [x] acquisition-time physical source identity revalidation
- [x] Windows opened-handle disk-number/length validation
- [x] elevated PowerShell PATH-hijack hardening
- [x] explicit transfer-verification terminology
- [x] second full physical-source read for optional static-media consistency comparison (0.5.0-alpha7)
- [ ] split privileged raw-reader helper from standard-user GUI/parser stack
- [x] adversarial review + freeze read-only recovery-imaging stage (0.3.3-alpha5)

## Phase 3 — Consistency Analysis

- [x] parse WQW launcher/index controls without modification (0.5.0-alpha3)
- [x] correlate global records with per-platform filelists and artwork stems using counts-only exported evidence (0.5.0-alpha3)
- [x] audit filesystem ↔ local filelist ↔ global fileinfo consistency with counts-only evidence (0.5.0-alpha4)
- [x] add bounded repeated-read stability sampling and cross-catalogue alias resolution (0.5.0-alpha5)
- [x] compare current stability/structure against a manifest-verified prior evidence baseline (0.5.0-alpha6)
- [x] compare against a known-good second card or full image baseline (0.5.0-alpha8 full-image disagreement mapper)
- [ ] determine whether firmware integrity/version checks exist

## Phase 4 — Transactional Game Management

- [ ] dry-run change plan
- [ ] add one ROM plus required metadata atomically
- [ ] verify launcher consistency
- [ ] rollback journal
- [ ] remove/rename transaction support
- [ ] collision and file-validation policy

## Phase 5 — Advanced customization

Only after the exact firmware layout is understood: themes, artwork, BIOS/config management and other profile-supported changes.

## Future raw restore

Raw restore remains intentionally absent. Before implementation it requires a separate write-side threat model, target identity binding, lock/dismount strategy, power-loss/cancellation test matrix, write verification and explicit human interlocks.


## ROM customisation milestones

- [x] Prove bounded launcher-only hide operation on real GameStick hardware.
- [x] Fast ROM Manager: reference catalogue browse/search + mounted-card visibility state.
- [x] Selected-entry hide overlay and receipt-bound rollback/unhide.
- [ ] Physical ROM payload removal with catalogue/FAT safety.
- [ ] New ROM payload injection + catalogue/image metadata generation.
- [ ] Batch customisation plan with one bounded hardware commit.
