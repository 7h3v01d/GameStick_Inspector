from __future__ import annotations

import argparse
from pathlib import Path

from gamestick.rom_customization import build_hide_rom_workspace


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a tiny host-side GameStick hide-ROM customisation overlay. Source image is read-only."
    )
    parser.add_argument("image", help="Healthy GameStick .img/.bin reference image")
    parser.add_argument("rom", help="ROM filename/title fragment; use CODE:filename if ambiguous")
    parser.add_argument("output", help="Output .gscustom workspace")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    result = build_hide_rom_workspace(
        args.image,
        args.rom,
        args.output,
        overwrite=args.overwrite,
        progress=lambda message: print(message, flush=True),
    )
    print("\nCUSTOMISATION WORKSPACE CREATED")
    print(f"ROM: {result.catalogue_code}:{result.rom_filename}")
    print(f"Workspace: {result.workspace_path}")
    print(f"Patch payload bytes: {result.patch_payload_bytes}")
    print(f"SHA-256: {result.workspace_sha256}")
    print("Source image modified: NO")
    print("Physical ROM payload removed: NO (launcher hide only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
