# Architecture

## Trust layers

### Layer 0 — physical device
Raw SD-card identity, sectors, partition table, boot areas and partitions.

### Layer 1 — mounted filesystems
Host-visible files/directories. Corruption here must not invalidate already established physical-device evidence.

### Layer 2 — evidence-backed GameStick profile
Observed layout markers and launcher/index schemas; no unsupported chipset/firmware inference.

### Layer 3 — consistency model (future)
Read-only correlation between launcher records, ROM paths, artwork, BIOS/configuration and saves.

### Layer 4 — transactional modification (future)
Profile-specific, journalled, verified and rollback-capable writes.

## Active modules

- `fs_safety.py` — non-following reparse/junction detection plus canonical forensic-root containment.
- `browser_model.py` — reparse-safe read-only Browser enumeration shared with the GUI.
- `probe.py` — corruption-tolerant, reparse-contained filesystem evidence plus Windows physical/partition mapping.
- `profiles.py` — evidence-based profile matching.
- `models.py` — probe and acquisition data contracts.
- `safety.py` — destructive lockout plus path and physical-destination invariants.
- `imaging.py` — source identity binding, read-only raw acquisition, transfer verification and transactional image/manifest commit.
- `reporting.py` — privacy-bounded JSON/evidence ZIP export with physical-disk destination separation.
- `windows_privilege.py` — venv-preserving UAC relaunch.
- `ui.py` / `image_cli.py` — user entry points; no GameStick write operations.

## Mounted-filesystem trust boundary

```text
untrusted directory entry
        ↓
non-following lstat
        ↓
symlink / Windows reparse point?
   YES → SKIP; never descend/open
        ↓ NO
check every path component
        ↓
canonical resolve
        ↓
resolved candidate beneath selected root?
   NO → SKIP / REFUSE
        ↓ YES
read-only forensic inspection
```

This policy deliberately rejects every reparse-backed indirection rather than attempting to classify safe versus unsafe junction types.

## Recovery pipeline

```text
fresh read-only probe
        ↓
physical mapping + GameStick profile
        ↓
boot/system/external/partition safety gates
        ↓
destination path + PhysicalDisk safety gates
        ↓
bind destination volume GUID + verify its PhysicalDisk
        ↓
IMAGE DISK N confirmation
        ↓
re-query source physical identity
        ↓
identity match?  NO → REFUSE / RE-PROBE
        ↓ YES
CreateFileW(GENERIC_READ only)
        ↓
IOCTL: opened handle disk number + length match?
        ↓ NO → REFUSE
        ↓ YES
create exclusive staging on bound safe volume
        ↓
stream source → staged image + SHA-256 A
        ↓
flush + fsync
        ↓
reread staged image → SHA-256 B
        ↓
A == B + exact byte count?
        ↓ NO → old authoritative pair untouched
        ↓ YES
build/fsync matching staged manifest on bound volume
        ↓
revalidate source + destination binding
        ↓
rollback-capable same-volume pair promotion
        ↓
TRANSFER-VERIFIED image + matching manifest
```

## Privilege architecture

Current alpha behavior elevates the whole process for raw reads because Windows normally requires administrator rights for `PhysicalDriveN`. The long-term design is deliberately narrower:

```text
standard-user GUI / parsers
        │
        │ narrowly defined acquisition request
        ▼
minimal elevated raw-reader helper
        ├─ revalidate identity
        ├─ GENERIC_READ only
        ├─ stream/hash
        └─ return status/hash
```

This remains roadmap work rather than being mixed into the blocker-fix patch.
