from __future__ import annotations

import argparse
from pathlib import Path

from gamestick.image_consistency import compare_full_images


def _fmt_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{amount:.2f} TiB"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only full-image consistency/disagreement analysis for GameStick acquisitions."
    )
    parser.add_argument("images", nargs="+", help="Two or more equal-sized .img/.bin acquisitions")
    parser.add_argument(
        "--report",
        help="Host-side JSON report path (default: gamestick_image_consistency.json beside first image)",
    )
    parser.add_argument("--chunk-mib", type=int, default=4, help="Streaming comparison chunk size in MiB (default 4)")
    parser.add_argument("--sector-size", type=int, default=512, help="Disagreement granularity in bytes (default 512)")
    args = parser.parse_args()

    if len(args.images) < 2:
        parser.error("select at least two images")
    report = args.report or str(Path(args.images[0]).resolve().parent / "gamestick_image_consistency.json")

    last_percent = -1

    def progress(done: int, total: int) -> None:
        nonlocal last_percent
        percent = int((done / total) * 100) if total else 100
        if percent != last_percent:
            print(f"\rcompare {percent:3d}%  {_fmt_bytes(done)} / {_fmt_bytes(total)}", end="", flush=True)
            last_percent = percent

    result = compare_full_images(
        args.images,
        report_path=report,
        chunk_size=args.chunk_mib * 1024 * 1024,
        sector_size=args.sector_size,
        progress=progress,
    )
    print("\n")
    print(f"Status: {result.status}")
    print(f"Images: {result.image_count}")
    print(f"Size: {_fmt_bytes(result.size_bytes)}")
    print(f"Disagreement ranges: {len(result.disagreement_ranges)}" + (" (truncated)" if result.ranges_truncated else ""))
    print(f"Majority sectors: {result.majority_sectors}")
    print(f"Split sectors: {result.split_sectors}")
    if result.consensus_coverage_percent is not None:
        print(f"Consensus coverage: {result.consensus_coverage_percent:.9f}%")
    for image in result.images:
        print(f"{image.name}: {image.sha256}")
    print(f"Report: {result.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
