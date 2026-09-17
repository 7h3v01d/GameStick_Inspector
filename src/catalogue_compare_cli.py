from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from gamestick.catalogue_image_lab import CatalogueImageLabError, compare_catalogue_controls
from gamestick.fast_image_lab import FastImageLabError


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Surgical GameStick catalogue comparison: reads only WQW central directories plus filelist.txt/fileinfo.txt."
    )
    parser.add_argument("image_a")
    parser.add_argument("image_b")
    parser.add_argument("--report", required=True, help="Host-side .json report path")
    args = parser.parse_args()
    try:
        result = compare_catalogue_controls(
            args.image_a,
            args.image_b,
            report_path=args.report,
            progress=lambda message: print(message, flush=True),
        )
    except (CatalogueImageLabError, FastImageLabError) as exc:
        print(f"CATALOGUE COMPARE FAILED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
