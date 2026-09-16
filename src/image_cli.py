from __future__ import annotations

import argparse
import sys

from gamestick.imaging import create_raw_image, preflight_physical_image
from gamestick.probe import inspect_volume


def _fmt_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{amount:.2f} TiB"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a verified-transfer GameStick SD image using read-only physical-device access."
    )
    parser.add_argument("path", help="Mounted GameStick volume, e.g. E:\\\\")
    parser.add_argument("output", help="Host-side .img or .bin destination")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacement of an existing host-side image/manifest (never permits GameStick writes)",
    )
    parser.add_argument(
        "--second-source-read",
        action="store_true",
        help=(
            "After the destination transfer verifies, reread the entire physical source read-only and compare SHA-256. "
            "A mismatch is recorded as source instability; it does not invalidate the first transfer-verified image."
        ),
    )
    args = parser.parse_args()

    report = inspect_volume(args.path)
    plan = preflight_physical_image(report, args.output, overwrite=args.overwrite)

    print("VERIFIED RAW IMAGE PREFLIGHT")
    print("============================")
    print(f"Source:      {plan.source_path} (READ ONLY)")
    print(f"Disk:        {plan.disk_number} — {plan.disk_name}")
    print(f"Capacity:    {_fmt_bytes(plan.source_size)}")
    print(f"Bus:         {plan.bus_type or 'Unknown'}")
    print(f"Profile:     {plan.profile_id} (heuristic score {plan.profile_score}/100)")
    print(f"Destination: {plan.destination}")
    print("\nNo raw write access to the GameStick is requested.")
    print(f"Type exactly: {plan.confirmation_phrase}")
    typed = input("> ").strip()
    if typed != plan.confirmation_phrase:
        print("Confirmation mismatch; no image was created.", file=sys.stderr)
        return 2

    last = {"phase": None, "percent": -1}

    def progress(phase: str, done: int, total: int) -> None:
        ratio = done / total if total else 0
        percent = int(ratio * 100)
        if phase != last["phase"] or percent != last["percent"]:
            label = {
                "imaging": "imaging",
                "verifying": "image verify",
                "source-verifying": "source reread",
            }.get(phase, phase)
            print(f"\r{label:10s} {percent:3d}%  {_fmt_bytes(done)} / {_fmt_bytes(total)}", end="", flush=True)
            last["phase"] = phase
            last["percent"] = percent

    result = create_raw_image(plan, progress=progress, second_full_source_read=args.second_source_read)
    print("\n\nVERIFIED")
    print(f"Image:    {result.image_path}")
    print(f"Manifest: {result.manifest_path}")
    print(f"SHA-256:  {result.streaming_sha256}")
    print(f"Source consistency: {result.source_consistency_status}")
    if result.second_source_sha256:
        print(f"Second source SHA-256: {result.second_source_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
