# Roadmap

## Phase 1 — Evidence & Safety

- [x] quarantine/remove active legacy destructive implementation
- [x] corruption-tolerant read-only volume probe
- [x] Windows physical disk + partition mapping
- [x] evidence-backed profile scoring
- [x] bounded metadata/schema inspection
- [x] genuinely bounded/streaming directory enumeration (0.3.4-alpha1)
- [x] privacy-bounded JSON/evidence ZIP exports
- [x] prevent generated output on any partition of the source physical disk
- [x] fail closed on stale/unknown source identity before generated output
- [x] bind generated-output staging to a stable proven-safe Windows volume
- [ ] capture known-good real-card evidence bundle
- [ ] identify launcher/index format
- [ ] correlate ROM/artwork metadata read-only
- [ ] freeze hardware-specific Device Profile v1

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
- [ ] second full physical-source read for optional static-media consistency comparison
- [ ] split privileged raw-reader helper from standard-user GUI/parser stack
- [x] adversarial review + freeze read-only recovery-imaging stage (0.3.3-alpha5)

## Phase 3 — Consistency Analysis

- [ ] parse launcher/index without modification
- [ ] correlate records with ROMs/artwork
- [ ] identify missing/orphaned/duplicate objects
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
