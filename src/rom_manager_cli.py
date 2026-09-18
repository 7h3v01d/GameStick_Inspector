from __future__ import annotations

import argparse

from gamestick.rom_manager import scan_rom_manager


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Browse/search GameStick launcher ROM identities from a healthy image; optionally compare a mounted test card read-only."
    )
    parser.add_argument("reference_image", help="Healthy reference .img/.bin")
    parser.add_argument("--target", help="Optional mounted TEST/CLONE GameStick root")
    parser.add_argument("--search", default="", help="Case-insensitive filename or CODE:filename fragment")
    parser.add_argument("--hidden-only", action="store_true", help="Show only HIDDEN entries")
    parser.add_argument("--limit", type=int, default=200, help="Maximum rows to print (default: 200)")
    args = parser.parse_args()

    snapshot = scan_rom_manager(args.reference_image, args.target, progress=lambda msg: print(msg))
    print()
    if snapshot.target_root:
        print(
            f"Reference={snapshot.reference_entry_count} Visible={snapshot.visible_count} Hidden={snapshot.hidden_count} "
            f"Inconsistent={snapshot.inconsistent_count} TargetOnly={snapshot.target_only_count}"
        )
    else:
        print(f"Reference={snapshot.reference_entry_count} (no target selected)")

    needle = args.search.casefold().strip()
    shown = 0
    matched = 0
    for entry in snapshot.entries:
        if args.hidden_only and entry.state != "HIDDEN":
            continue
        if needle and needle not in entry.identity.casefold():
            continue
        matched += 1
        if shown < max(0, args.limit):
            print(f"{entry.state:12} {entry.catalogue_code}:{entry.filename}")
            shown += 1
    if matched > shown:
        print(f"... {matched - shown} more match(es); refine --search or increase --limit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
