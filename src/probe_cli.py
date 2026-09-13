from __future__ import annotations

import argparse
import json
from pathlib import Path

from gamestick.probe import find_candidate_volumes, inspect_volume
from gamestick.reporting import write_evidence_bundle, write_probe_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only GameStick forensic volume probe")
    parser.add_argument("path", nargs="?", help="Mounted GameStick volume/root")
    parser.add_argument("--output", "-o", help="Write JSON report outside the inspected device")
    parser.add_argument("--bundle", "-b", help="Write evidence ZIP outside the inspected device")
    parser.add_argument("--detect", action="store_true", help="Auto-detect the highest-confidence candidate")
    args = parser.parse_args()

    path = args.path
    if args.detect:
        candidates = find_candidate_volumes()
        if not candidates:
            parser.error("no GameStick-like candidate volume detected")
        path = str(candidates[0][0])
    if not path:
        parser.error("provide a mounted volume path or use --detect")

    report = inspect_volume(path)
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True, ensure_ascii=False))

    if args.output:
        destination = write_probe_report(report, Path(args.output))
        print(f"\nReport saved: {destination}")
    if args.bundle:
        destination = write_evidence_bundle(report, Path(args.bundle))
        print(f"Evidence bundle saved: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
