from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from gamestick.repair_workspace import RepairWorkspaceError, build_repair_workspace


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a host-side GameStick repair workspace from VERIFIED golden catalogues and damaged base catalogues."
    )
    parser.add_argument("golden_image")
    parser.add_argument("base_image")
    parser.add_argument("--output", required=True, help="Host-side .gsworkspace output path")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    try:
        result = build_repair_workspace(
            args.golden_image,
            args.base_image,
            args.output,
            overwrite=args.overwrite,
            progress=lambda message: print(message, flush=True),
        )
    except RepairWorkspaceError as exc:
        print(f"REPAIR WORKSPACE FAILED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
