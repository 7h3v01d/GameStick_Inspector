from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from gamestick.fast_image_lab import FastImageLabError, compare_fast_structures


def main() -> int:
    parser = argparse.ArgumentParser(description="Fast logical GameStick image comparison (FAT32 metadata + launcher/control files only).")
    parser.add_argument("image_a")
    parser.add_argument("image_b")
    parser.add_argument("--report", required=True, help="Host-side .json report path")
    args = parser.parse_args()
    try:
        result = compare_fast_structures(
            args.image_a,
            args.image_b,
            report_path=args.report,
            progress=lambda message: print(message, flush=True),
        )
    except FastImageLabError as exc:
        print(f"FAST COMPARE FAILED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
