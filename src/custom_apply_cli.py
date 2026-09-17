from __future__ import annotations

import argparse

from gamestick.custom_apply import (
    apply_customization_workspace,
    expected_confirmation,
    rollback_customization,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply or roll back a bounded GameStick .gscustom overlay on a mounted TEST clone."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    apply_p = sub.add_parser("apply", help="Apply a .gscustom overlay to a mounted test clone")
    apply_p.add_argument("source_image", help="Healthy reference .img used to build the workspace")
    apply_p.add_argument("workspace", help="Host-side .gscustom workspace")
    apply_p.add_argument("target_root", help=r"Mounted target GameStick root, e.g. H:\")
    apply_p.add_argument("rollback", help="Host-side .gsrollback output (must not be on target card)")
    apply_p.add_argument("--overwrite-rollback", action="store_true")

    rollback_p = sub.add_parser("rollback", help="Restore original control bytes from .gsrollback")
    rollback_p.add_argument("rollback", help="Host-side .gsrollback archive")
    rollback_p.add_argument("target_root", help=r"Mounted target GameStick root, e.g. H:\")

    args = parser.parse_args()
    if args.command == "apply":
        phrase = expected_confirmation(args.target_root)
        print("WARNING: this is the first bounded write path. Use a TEST/CLONE GameStick card only.")
        print("No ROM payload is deleted; only pre-attested launcher-control byte ranges are overwritten.")
        print(f"Type exactly: {phrase}")
        typed = input("> ")
        result = apply_customization_workspace(
            args.source_image,
            args.workspace,
            args.target_root,
            args.rollback,
            confirmation=typed,
            overwrite_rollback=args.overwrite_rollback,
            progress=lambda message: print(message, flush=True),
        )
        print("\nCUSTOMISATION APPLIED AND VERIFIED")
        print(f"ROM hidden: {result.catalogue_code}:{result.rom}")
        print(f"Target: {result.target_root}")
        print(f"Patched files/ranges: {result.patched_file_count}/{result.patch_range_count}")
        print(f"Patch bytes: {result.patch_payload_bytes}")
        print(f"Rollback: {result.rollback_path}")
        print(f"Receipt: {result.receipt_path}")
        print(f"Verification: {result.verification}")
        return 0

    phrase = f"ROLL BACK {__import__('pathlib').Path(args.target_root).drive.upper() or __import__('pathlib').Path(args.target_root).name}"
    print(f"Type exactly: {phrase}")
    typed = input("> ")
    result = rollback_customization(
        args.rollback,
        args.target_root,
        confirmation=typed,
        progress=lambda message: print(message, flush=True),
    )
    print("\nCUSTOMISATION ROLLED BACK AND VERIFIED")
    print(f"Target: {result.target_root}")
    print(f"Restored files/ranges: {result.restored_file_count}/{result.restored_range_count}")
    print(f"Restored bytes: {result.restored_bytes}")
    print(f"Verification: {result.verification}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
