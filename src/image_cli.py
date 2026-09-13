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
    args = parser.parse_args()

    report = inspect_volume(args.path)
    plan = preflight_physical_image(report, args.output, overwrite=args.overwrite)

    print("VERIFIED RAW IMAGE PREFLIGHT")
    print("============================")
    print(f"Source:      {plan.source_path} (READ ONLY)")
    print(f"Disk:        {plan.disk_number} — {plan.disk_name}")
    print(f"Capacity:    {_fmt_bytes(plan.source_size)}")
    print(f"Bus:         {plan.bus_type or 'Unknown'}")
    print(f"Profile:     {plan.profile_id} ({plan.profile_score}%)")
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
            label = "imaging" if phase == "imaging" else "verifying"
            print(f"\r{label:10s} {percent:3d}%  {_fmt_bytes(done)} / {_fmt_bytes(total)}", end="", flush=True)
            last["phase"] = phase
            last["percent"] = percent

    result = create_raw_image(plan, progress=progress)
    print("\n\nVERIFIED")
    print(f"Image:    {result.image_path}")
    print(f"Manifest: {result.manifest_path}")
    print(f"SHA-256:  {result.streaming_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
