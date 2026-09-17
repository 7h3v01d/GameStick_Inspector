from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Callable, Optional

from .models import ImageResult, ImagingPlan, PhysicalMapping, ProbeReport
from .safety import (
    BoundOutputVolume,
    assert_output_outside_source_disk,
    bind_output_volume,
    secure_stage_on_bound_volume,
)

DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024
_FREE_SPACE_RESERVE = 64 * 1024 * 1024
_ALLOWED_IMAGE_SUFFIXES = {".img", ".bin"}
_ALLOWED_EXTERNAL_BUSES = {"usb", "sd", "mmc"}


class ImagingError(RuntimeError):
    """Base class for verified raw-imaging failures."""


class ImagingPreflightError(ImagingError):
    """Raised when a proposed raw image does not satisfy safety gates."""


class ImagingCancelled(ImagingError):
    """Raised when the caller requests cancellation during imaging."""


class VerifiedStagePreserved(ImagingError):
    """A late safety/commit failure occurred after transfer verification.

    The verified staged image is deliberately retained on the already-bound safe
    output volume so a transient metadata failure cannot destroy hours of evidence.
    It is *not* promoted to the canonical destination until all safety gates pass.
    """


class SourceIdentityUnavailable(ImagingError):
    """Fresh physical-source mapping could not be obtained."""


class SourceIdentityChanged(ImagingError):
    """Fresh physical-source mapping disagrees with the probed source."""


def sha256_file(
    path: str | Path,
    *,
    chunk_size: int = 4 * 1024 * 1024,
    progress: Optional[Callable[[int, int], None]] = None,
) -> str:
    image = Path(path)
    if not image.is_file():
        raise ValueError(f"Not a file: {image}")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    total = image.stat().st_size
    done = 0
    digest = hashlib.sha256()
    with image.open("rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
            done += len(block)
            if progress:
                progress(done, total)
    return digest.hexdigest()


def _hash_identifier(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _norm_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text.casefold() if text else None


def physical_drive_path(disk_number: int) -> str:
    if not isinstance(disk_number, int) or isinstance(disk_number, bool) or disk_number < 0:
        raise ValueError("disk_number must be a non-negative integer")
    return rf"\\.\PhysicalDrive{disk_number}"


def _nearest_existing_parent(path: Path) -> Path:
    current = path
    while not current.exists():
        if current.parent == current:
            raise ImagingPreflightError(f"No existing parent filesystem for destination: {path}")
        current = current.parent
    if not current.is_dir():
        current = current.parent
    return current


def _selected_drive_letter(selected_root: str) -> Optional[str]:
    text = str(selected_root).strip()
    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
        return text[0].upper()
    return None


def _partition_layout_sha256(mapping: PhysicalMapping) -> str:
    parts = []
    for part in sorted(
        mapping.partitions,
        key=lambda p: (
            p.partition_number if p.partition_number is not None else 2**31,
            p.offset if p.offset is not None else 2**63,
        ),
    ):
        parts.append(
            {
                "partition_number": part.partition_number,
                "drive_letter": (part.drive_letter or "").upper() or None,
                "offset": part.offset,
                "size": part.size,
                "partition_type": part.partition_type,
                "gpt_type": part.gpt_type,
                "mbr_type": part.mbr_type,
            }
        )
    payload = json.dumps(parts, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _identity_sha256_from_values(
    *,
    disk_number: int,
    disk_size: int,
    bus_type: Optional[str],
    partition_style: Optional[str],
    serial_sha256: Optional[str],
    unique_id_sha256: Optional[str],
    partition_number: Optional[int],
    partition_offset: Optional[int],
    partition_size: Optional[int],
    logical_sector_size: Optional[int],
    physical_sector_size: Optional[int],
    partition_layout_sha256: Optional[str],
) -> str:
    payload = {
        "disk_number": disk_number,
        "disk_size": disk_size,
        "bus_type": _norm_optional(bus_type),
        "partition_style": _norm_optional(partition_style),
        "serial_sha256": serial_sha256,
        "unique_id_sha256": unique_id_sha256,
        "partition_number": partition_number,
        "partition_offset": partition_offset,
        "partition_size": partition_size,
        "logical_sector_size": logical_sector_size,
        "physical_sector_size": physical_sector_size,
        "partition_layout_sha256": partition_layout_sha256,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _default_mapping_resolver(selected_root: str) -> PhysicalMapping:
    # Lazy import avoids probe -> safety -> imaging import coupling at module import time.
    from .probe import _physical_mapping

    return _physical_mapping(Path(selected_root))


def preflight_physical_image(
    report: ProbeReport,
    destination: str | Path,
    *,
    overwrite: bool = False,
    host_system: Optional[str] = None,
    min_profile_score: int = 40,
    available_bytes: Optional[int] = None,
    destination_disk_resolver: Optional[Callable[[str], int]] = None,
) -> ImagingPlan:
    """Build a raw-imaging plan only after conservative read-only safety checks."""

    system = host_system or platform.system()
    if system != "Windows":
        raise ImagingPreflightError("Raw physical-device imaging is currently supported on Windows only.")

    mapping = report.physical_mapping
    if mapping.mapping_error:
        raise ImagingPreflightError(f"Physical disk mapping is not trustworthy: {mapping.mapping_error}")
    if mapping.disk_number is None:
        raise ImagingPreflightError("No physical disk number was resolved for the selected volume.")
    if not isinstance(mapping.disk_number, int) or mapping.disk_number < 0:
        raise ImagingPreflightError("Resolved physical disk number is invalid.")
    if mapping.disk_size is None or mapping.disk_size <= 0:
        raise ImagingPreflightError("Physical disk size is unknown or invalid.")

    # Unknown is not safe enough. These gates deliberately require an explicit False.
    if mapping.is_boot is not False:
        raise ImagingPreflightError("Imaging refused: the disk boot flag is true or could not be proven false.")
    if mapping.is_system is not False:
        raise ImagingPreflightError("Imaging refused: the disk system flag is true or could not be proven false.")
    if mapping.is_offline is True:
        raise ImagingPreflightError("Imaging refused: Windows reports the source disk as offline.")

    if report.profile.score < min_profile_score or report.profile.profile_id == "unknown":
        raise ImagingPreflightError(
            f"Imaging refused: GameStick profile confidence is too low ({report.profile.score}%). "
            "Capture/inspect evidence first."
        )

    bus = (mapping.bus_type or "").strip().casefold()
    drive_type = (mapping.drive_type or "").strip().casefold()
    looks_external = bus in _ALLOWED_EXTERNAL_BUSES or drive_type == "removable"
    if not looks_external:
        raise ImagingPreflightError(
            "Imaging refused: the mapped disk is not positively identified as USB/SD/MMC or a removable volume. "
            f"BusType={mapping.bus_type!r}, DriveType={mapping.drive_type!r}."
        )

    selected_letter = _selected_drive_letter(report.selected_root)
    if selected_letter:
        mapped_letters = {
            (part.drive_letter or "").strip().upper()
            for part in mapping.partitions
            if part.drive_letter
        }
        if selected_letter not in mapped_letters:
            raise ImagingPreflightError(
                f"Imaging refused: selected volume {selected_letter}: is not present in the resolved disk partition map."
            )

    disk_number = int(mapping.disk_number)
    out = assert_output_outside_source_disk(
        destination,
        report.selected_root,
        source_disk_number=disk_number,
        host_system=system,
        destination_disk_resolver=destination_disk_resolver,
    )
    if out.suffix.casefold() not in _ALLOWED_IMAGE_SUFFIXES:
        raise ImagingPreflightError("Raw image destination must use .img or .bin.")
    if out.exists() and out.is_dir():
        raise ImagingPreflightError(f"Destination is a directory: {out}")
    if out.exists() and not overwrite:
        raise ImagingPreflightError(f"Destination already exists: {out}")

    parent = _nearest_existing_parent(out.parent)
    free = available_bytes if available_bytes is not None else shutil.disk_usage(parent).free
    required = int(mapping.disk_size) + _FREE_SPACE_RESERVE
    if free < required:
        raise ImagingPreflightError(
            f"Insufficient destination free space: need at least {required} bytes, have {free} bytes."
        )

    manifest = Path(str(out) + ".manifest.json")
    if manifest.exists() and not overwrite:
        raise ImagingPreflightError(f"Manifest destination already exists: {manifest}")

    layout_sha = _partition_layout_sha256(mapping)
    serial_sha = _hash_identifier(mapping.serial_number)
    unique_sha = _hash_identifier(mapping.disk_unique_id)
    identity_sha = _identity_sha256_from_values(
        disk_number=disk_number,
        disk_size=int(mapping.disk_size),
        bus_type=mapping.bus_type,
        partition_style=mapping.partition_style,
        serial_sha256=serial_sha,
        unique_id_sha256=unique_sha,
        partition_number=mapping.partition_number,
        partition_offset=mapping.partition_offset,
        partition_size=mapping.partition_size,
        logical_sector_size=mapping.logical_sector_size,
        physical_sector_size=mapping.physical_sector_size,
        partition_layout_sha256=layout_sha,
    )

    return ImagingPlan(
        source_path=physical_drive_path(disk_number),
        selected_root=report.selected_root,
        disk_number=disk_number,
        disk_name=mapping.disk_name or f"PhysicalDrive{disk_number}",
        source_size=int(mapping.disk_size),
        destination=str(out),
        manifest_path=str(manifest),
        confirmation_phrase=f"IMAGE DISK {disk_number}",
        profile_id=report.profile.profile_id,
        profile_score=report.profile.score,
        structure_sha256=report.structure_sha256,
        bus_type=mapping.bus_type,
        drive_type=mapping.drive_type,
        partition_style=mapping.partition_style,
        source_serial_sha256=serial_sha,
        source_unique_id_sha256=unique_sha,
        selected_partition_number=mapping.partition_number,
        selected_partition_offset=mapping.partition_offset,
        selected_partition_size=mapping.partition_size,
        logical_sector_size=mapping.logical_sector_size,
        physical_sector_size=mapping.physical_sector_size,
        source_partition_layout_sha256=layout_sha,
        source_identity_sha256=identity_sha,
        overwrite_existing=overwrite,
    )


def _identity_plan_from_report(report: ProbeReport) -> ImagingPlan:
    """Build an identity-only plan from a probe so reporting can reuse acquisition checks."""
    mapping = report.physical_mapping
    if mapping.mapping_error:
        raise ImagingError(f"Source identity revalidation failed: {mapping.mapping_error}")
    if mapping.disk_number is None or mapping.disk_size is None or int(mapping.disk_size) <= 0:
        raise ImagingError(
            "Source physical disk identity is incomplete; generated output is disabled until the device is re-probed."
        )
    disk_number = int(mapping.disk_number)
    disk_size = int(mapping.disk_size)
    layout_sha = _partition_layout_sha256(mapping)
    serial_sha = _hash_identifier(mapping.serial_number)
    unique_sha = _hash_identifier(mapping.disk_unique_id)
    identity_sha = _identity_sha256_from_values(
        disk_number=disk_number,
        disk_size=disk_size,
        bus_type=mapping.bus_type,
        partition_style=mapping.partition_style,
        serial_sha256=serial_sha,
        unique_id_sha256=unique_sha,
        partition_number=mapping.partition_number,
        partition_offset=mapping.partition_offset,
        partition_size=mapping.partition_size,
        logical_sector_size=mapping.logical_sector_size,
        physical_sector_size=mapping.physical_sector_size,
        partition_layout_sha256=layout_sha,
    )
    return ImagingPlan(
        source_path=physical_drive_path(disk_number),
        selected_root=report.selected_root,
        disk_number=disk_number,
        disk_name=mapping.disk_name or f"PhysicalDrive{disk_number}",
        source_size=disk_size,
        destination="",
        manifest_path="",
        confirmation_phrase=f"IMAGE DISK {disk_number}",
        profile_id=report.profile.profile_id,
        profile_score=report.profile.score,
        structure_sha256=report.structure_sha256,
        bus_type=mapping.bus_type,
        drive_type=mapping.drive_type,
        partition_style=mapping.partition_style,
        source_serial_sha256=serial_sha,
        source_unique_id_sha256=unique_sha,
        selected_partition_number=mapping.partition_number,
        selected_partition_offset=mapping.partition_offset,
        selected_partition_size=mapping.partition_size,
        logical_sector_size=mapping.logical_sector_size,
        physical_sector_size=mapping.physical_sector_size,
        source_partition_layout_sha256=layout_sha,
        source_identity_sha256=identity_sha,
    )


def revalidate_probe_source_identity(
    report: ProbeReport,
    *,
    mapping_resolver: Optional[Callable[[str], PhysicalMapping]] = None,
) -> PhysicalMapping:
    """Freshly bind a probe report to the still-present physical source.

    Generated-output code uses the same identity comparison machinery as raw
    imaging. Unknown, stale, re-enumerated, or safety-flag-changed sources fail
    closed and require a fresh probe before any write begins.
    """
    return revalidate_source_identity(
        _identity_plan_from_report(report),
        mapping_resolver=mapping_resolver,
    )


def revalidate_source_identity(
    plan: ImagingPlan,
    *,
    mapping_resolver: Optional[Callable[[str], PhysicalMapping]] = None,
) -> PhysicalMapping:
    """Re-resolve and compare the physical source immediately before acquisition.

    This closes the probe/preflight TOCTOU gap: PhysicalDriveN is not trusted merely
    because it had the expected identity earlier. A mismatch requires a fresh probe.
    """

    resolver = mapping_resolver or _default_mapping_resolver
    current = resolver(plan.selected_root)
    if current.mapping_error:
        raise SourceIdentityUnavailable(f"Source identity revalidation failed: {current.mapping_error}")

    mismatches: list[str] = []

    def compare(label: str, expected, actual) -> None:
        if expected != actual:
            mismatches.append(f"{label}: expected {expected!r}, got {actual!r}")

    compare("disk number", plan.disk_number, current.disk_number)
    compare("disk size", plan.source_size, current.disk_size)

    if plan.bus_type is not None:
        compare("bus type", _norm_optional(plan.bus_type), _norm_optional(current.bus_type))
    if plan.partition_style is not None:
        compare(
            "partition style",
            _norm_optional(plan.partition_style),
            _norm_optional(current.partition_style),
        )
    if plan.selected_partition_number is not None:
        compare("selected partition number", plan.selected_partition_number, current.partition_number)
    if plan.selected_partition_offset is not None:
        compare("selected partition offset", plan.selected_partition_offset, current.partition_offset)
    if plan.selected_partition_size is not None:
        compare("selected partition size", plan.selected_partition_size, current.partition_size)
    if plan.logical_sector_size is not None:
        compare("logical sector size", plan.logical_sector_size, current.logical_sector_size)
    if plan.physical_sector_size is not None:
        compare("physical sector size", plan.physical_sector_size, current.physical_sector_size)

    if plan.source_serial_sha256 is not None:
        compare("serial identity hash", plan.source_serial_sha256, _hash_identifier(current.serial_number))
    if plan.source_unique_id_sha256 is not None:
        compare("unique-id identity hash", plan.source_unique_id_sha256, _hash_identifier(current.disk_unique_id))
    if plan.source_partition_layout_sha256 is not None:
        compare("partition layout hash", plan.source_partition_layout_sha256, _partition_layout_sha256(current))

    # Re-check critical safety flags at the final mapping boundary too.
    if current.is_boot is not False:
        mismatches.append(f"boot flag is not proven false ({current.is_boot!r})")
    if current.is_system is not False:
        mismatches.append(f"system flag is not proven false ({current.is_system!r})")
    if current.is_offline is True:
        mismatches.append("disk is now offline")

    current_identity_sha = _identity_sha256_from_values(
        disk_number=int(current.disk_number) if current.disk_number is not None else -1,
        disk_size=int(current.disk_size) if current.disk_size is not None else -1,
        bus_type=current.bus_type,
        partition_style=current.partition_style,
        serial_sha256=_hash_identifier(current.serial_number),
        unique_id_sha256=_hash_identifier(current.disk_unique_id),
        partition_number=current.partition_number,
        partition_offset=current.partition_offset,
        partition_size=current.partition_size,
        logical_sector_size=current.logical_sector_size,
        physical_sector_size=current.physical_sector_size,
        partition_layout_sha256=_partition_layout_sha256(current),
    )
    if plan.source_identity_sha256 is not None:
        compare("composite source identity", plan.source_identity_sha256, current_identity_sha)

    if mismatches:
        detail = "; ".join(mismatches)
        raise SourceIdentityChanged(
            "Physical source identity changed after the probe/preflight. Raw acquisition refused; "
            f"reinsert/select the intended GameStick and probe again. {detail}"
        )
    return current


def _validate_windows_handle_identity(handle: int, *, expected_disk_number: int, expected_size: int) -> None:
    """Bind the opened Windows handle to the expected disk number and byte length."""
    import ctypes
    from ctypes import wintypes

    IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080
    IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C

    class STORAGE_DEVICE_NUMBER(ctypes.Structure):
        _fields_ = [
            ("DeviceType", wintypes.DWORD),
            ("DeviceNumber", wintypes.DWORD),
            ("PartitionNumber", wintypes.DWORD),
        ]

    class GET_LENGTH_INFORMATION(ctypes.Structure):
        _fields_ = [("Length", ctypes.c_longlong)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    device_io = kernel32.DeviceIoControl
    device_io.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    device_io.restype = wintypes.BOOL

    returned = wintypes.DWORD(0)
    number = STORAGE_DEVICE_NUMBER()
    ok = device_io(
        handle,
        IOCTL_STORAGE_GET_DEVICE_NUMBER,
        None,
        0,
        ctypes.byref(number),
        ctypes.sizeof(number),
        ctypes.byref(returned),
        None,
    )
    if not ok:
        error = ctypes.get_last_error()
        raise OSError(error, "Could not validate raw source device number from the opened handle")
    if int(number.DeviceNumber) != int(expected_disk_number):
        raise ImagingError(
            f"Opened raw handle identifies Disk {int(number.DeviceNumber)}, expected Disk {expected_disk_number}; "
            "acquisition refused."
        )

    returned = wintypes.DWORD(0)
    length = GET_LENGTH_INFORMATION()
    ok = device_io(
        handle,
        IOCTL_DISK_GET_LENGTH_INFO,
        None,
        0,
        ctypes.byref(length),
        ctypes.sizeof(length),
        ctypes.byref(returned),
        None,
    )
    if not ok:
        error = ctypes.get_last_error()
        raise OSError(error, "Could not validate raw source byte length from the opened handle")
    if int(length.Length) != int(expected_size):
        raise ImagingError(
            f"Opened raw handle size is {int(length.Length)} bytes, expected {expected_size}; acquisition refused."
        )


def _default_source_opener(
    path: str,
    *,
    expected_disk_number: Optional[int] = None,
    expected_size: Optional[int] = None,
) -> BinaryIO:
    if platform.system() != "Windows":
        return open(path, "rb", buffering=0)

    # Use CreateFileW explicitly so the physical device is opened with GENERIC_READ
    # only while allowing Windows/filesystems to retain their normal read/write
    # sharing. No write access bit is requested.
    import ctypes
    import msvcrt

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        if error == 5:
            raise PermissionError(
                "Windows refused read access to the physical disk. Relaunch GameStick Inspector as Administrator, "
                "then probe again. No write access was requested."
            )
        raise OSError(error, f"CreateFileW could not open {path} read-only")

    try:
        if expected_disk_number is not None and expected_size is not None:
            _validate_windows_handle_identity(
                handle,
                expected_disk_number=expected_disk_number,
                expected_size=expected_size,
            )
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except Exception:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        raise
    return os.fdopen(fd, "rb", buffering=0)


def _write_staged_manifest(path: Path, payload: dict, *, fd: Optional[int] = None) -> None:
    """Write+fsync a staged manifest, optionally through an already-open exclusive fd."""
    if fd is not None:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return
    if path.exists():
        raise ImagingError(f"Stale staged manifest exists; inspect/remove it manually: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _promote_verified_pair(
    staged_image: Path,
    staged_manifest: Path,
    destination: Path,
    manifest_path: Path,
    *,
    overwrite: bool,
    rollback_image: Optional[Path] = None,
    rollback_manifest: Optional[Path] = None,
) -> None:
    """Promote image+manifest as one rollback-capable artifact set.

    The old manifest is moved away *before* an old image can be replaced, so a stale
    VERIFIED manifest is never left beside a new image. If promotion fails, the old
    pair is restored before the exception escapes.
    """

    if not staged_image.exists() or not staged_manifest.exists():
        raise ImagingError("Verified staging pair is incomplete; promotion refused.")
    if not overwrite and (destination.exists() or manifest_path.exists()):
        raise ImagingError("Final recovery artifact appeared during imaging; existing files will not be overwritten.")

    rollback_image = rollback_image or Path(str(destination) + ".rollback")
    rollback_manifest = rollback_manifest or Path(str(manifest_path) + ".rollback")
    for rollback in (rollback_image, rollback_manifest):
        if rollback.exists():
            raise ImagingError(f"Stale rollback artifact exists; inspect/remove it manually: {rollback}")

    moved_old_image = False
    moved_old_manifest = False
    promoted_new_image = False
    promoted_new_manifest = False

    try:
        if overwrite:
            # Critical ordering: remove the old manifest from the canonical path first.
            if manifest_path.exists():
                os.replace(manifest_path, rollback_manifest)
                moved_old_manifest = True
            if destination.exists():
                os.replace(destination, rollback_image)
                moved_old_image = True

        os.replace(staged_image, destination)
        promoted_new_image = True
        os.replace(staged_manifest, manifest_path)
        promoted_new_manifest = True
    except Exception as exc:
        rollback_errors: list[str] = []

        # Move any partially promoted new pair back out of the canonical names first.
        if promoted_new_manifest and manifest_path.exists():
            try:
                os.replace(manifest_path, staged_manifest)
            except OSError as rollback_exc:
                rollback_errors.append(f"new manifest rollback failed: {rollback_exc}")
        if promoted_new_image and destination.exists():
            try:
                os.replace(destination, staged_image)
            except OSError as rollback_exc:
                rollback_errors.append(f"new image rollback failed: {rollback_exc}")

        # Restore the previous image first and its corresponding manifest last.
        if moved_old_image and rollback_image.exists():
            try:
                os.replace(rollback_image, destination)
            except OSError as rollback_exc:
                rollback_errors.append(f"old image restore failed: {rollback_exc}")
        if moved_old_manifest and rollback_manifest.exists():
            try:
                os.replace(rollback_manifest, manifest_path)
            except OSError as rollback_exc:
                rollback_errors.append(f"old manifest restore failed: {rollback_exc}")

        extra = f" Rollback errors: {'; '.join(rollback_errors)}" if rollback_errors else ""
        raise ImagingError(f"Recovery artifact pair promotion failed; previous pair restored where possible: {exc}.{extra}") from exc

    # Pair is committed. Rollback copies no longer carry authority.
    for rollback in (rollback_image, rollback_manifest):
        if rollback.exists():
            try:
                rollback.unlink()
            except OSError as exc:
                raise ImagingError(
                    f"New verified image/manifest pair was committed, but rollback cleanup failed: {rollback}: {exc}"
                ) from exc


def _second_full_source_read(
    plan: ImagingPlan,
    *,
    chunk_size: int,
    progress: Optional[Callable[[str, int, int], None]],
    cancelled: Optional[Callable[[], bool]],
    source_opener: Optional[Callable[[str], BinaryIO]],
    host_system: str,
) -> tuple[str, Optional[str], int, Optional[str]]:
    """Reread the complete physical source without creating a second image.

    Returns ``(status, sha256, bytes_read, error_category)``. A media/read
    failure is evidence, not a transfer failure, so a successfully verified
    first image can still be committed with an explicit degraded consistency
    status. Cancellation and source-identity failures remain fatal.
    """

    digest = hashlib.sha256()
    read_total = 0
    try:
        if source_opener is None:
            source = _default_source_opener(
                plan.source_path,
                expected_disk_number=plan.disk_number,
                expected_size=plan.source_size,
            )
        else:
            source = source_opener(plan.source_path)

        with source:
            remaining = plan.source_size
            while remaining:
                if cancelled and cancelled():
                    raise ImagingCancelled("Second full source reread cancelled by user.")
                try:
                    block = source.read(min(chunk_size, remaining))
                except OSError:
                    return "SECOND_READ_ERROR", None, read_total, "OS_READ_ERROR"
                if not block:
                    return "SECOND_READ_INCOMPLETE", None, read_total, "EARLY_EOF"
                digest.update(block)
                read_total += len(block)
                remaining -= len(block)
                if progress:
                    progress("source-verifying", read_total, plan.source_size)
    except ImagingCancelled:
        raise
    except ImagingError:
        # Opened-handle identity/size failures are safety failures, not media
        # instability evidence, and must remain fail-closed.
        raise
    except (OSError, PermissionError):
        return "SECOND_READ_ERROR", None, read_total, "SOURCE_OPEN_ERROR"

    return "SECOND_READ_COMPLETE", digest.hexdigest(), read_total, None


def _manifest_payload(
    plan: ImagingPlan,
    result: ImageResult,
    *,
    chunk_size: int,
    source_identity_revalidated: bool,
    handle_identity_checked: bool,
) -> dict:
    return {
        "schema_version": 3,
        "kind": "gamestick-verified-raw-image",
        "status": "transfer-verified" if result.verified else "unverified",
        "verification_scope": (
            "destination matches bytes observed during the acquisition pass; an optional second complete source reread "
            "can establish repeatability across full reads but is not an atomic snapshot guarantee"
        ),
        "source_snapshot_consistency_verified": False,
        "source_static_media_consistency_verified": result.source_consistency_status == "MATCHED",
        "source": {
            "physical_path": plan.source_path,
            "disk_number": plan.disk_number,
            "disk_name": plan.disk_name,
            "disk_size": plan.source_size,
            "bus_type": plan.bus_type,
            "drive_type": plan.drive_type,
            "partition_style": plan.partition_style,
            "profile_id": plan.profile_id,
            "profile_score": plan.profile_score,
            "structure_sha256": plan.structure_sha256,
            "serial_number_sha256": plan.source_serial_sha256,
            "disk_unique_id_sha256": plan.source_unique_id_sha256,
            "partition_layout_sha256": plan.source_partition_layout_sha256,
            "source_identity_sha256": plan.source_identity_sha256,
            "selected_partition_number": plan.selected_partition_number,
            "selected_partition_offset": plan.selected_partition_offset,
            "selected_partition_size": plan.selected_partition_size,
            "logical_sector_size": plan.logical_sector_size,
            "physical_sector_size": plan.physical_sector_size,
        },
        "image": {
            "file_name": Path(result.image_path).name,
            "size": result.bytes_written,
            "streaming_sha256": result.streaming_sha256,
            "reread_sha256": result.reread_sha256,
            "verified": result.verified,
        },
        "source_consistency": {
            "status": result.source_consistency_status,
            "second_full_read_sha256": result.second_source_sha256,
            "second_full_read_bytes": result.second_source_bytes_read,
            "error_category": result.second_source_error_category,
            "meaning": {
                "NOT_REQUESTED": "A second complete source read was not requested.",
                "MATCHED": "Two complete source reads produced the same SHA-256.",
                "MISMATCH": "Two complete source reads produced different SHA-256 values; the source was not static across reads.",
                "SECOND_READ_INCOMPLETE": "The optional second source read ended before the expected device length.",
                "SECOND_READ_ERROR": "The optional second source read encountered a read/open error after the first image had already transfer-verified.",
            }.get(result.source_consistency_status, "Unknown source-consistency state."),
        },
        "method": {
            "source_open_mode": "read-only",
            "source_identity_revalidated_before_open": source_identity_revalidated,
            "opened_handle_disk_number_and_length_checked": handle_identity_checked,
            "exact_source_bytes_requested": plan.source_size,
            "chunk_size": chunk_size,
            "destination_flush_and_fsync": True,
            "destination_reread_verification": True,
            "second_full_source_reread_requested": result.source_consistency_status != "NOT_REQUESTED",
            "second_full_source_reread_performed": result.source_consistency_status in {"MATCHED", "MISMATCH"},
            "second_full_source_reread_completed": result.source_consistency_status in {"MATCHED", "MISMATCH"},
            "raw_device_write_performed": False,
        },
        "timing": {
            "started_at_utc": result.started_at_utc,
            "completed_at_utc": result.completed_at_utc,
        },
        "host": platform.platform(),
    }


def create_raw_image(
    plan: ImagingPlan,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress: Optional[Callable[[str, int, int], None]] = None,
    cancelled: Optional[Callable[[], bool]] = None,
    source_opener: Optional[Callable[[str], BinaryIO]] = None,
    identity_resolver: Optional[Callable[[str], PhysicalMapping]] = None,
    destination_disk_resolver: Optional[Callable[[str], int]] = None,
    volume_root_resolver: Optional[Callable[[str], str]] = None,
    volume_disk_resolver: Optional[Callable[[str], int]] = None,
    host_system: Optional[str] = None,
    second_full_source_read: bool = False,
) -> ImageResult:
    """Create a verified-transfer sector image from a read-only source.

    The new image and its success manifest are fully staged and verified before
    either replaces an existing canonical artifact. Existing pairs are rollback-
    protected during promotion. The source is never opened for write access.
    """

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if plan.source_size <= 0:
        raise ImagingError("source_size must be positive")

    system = host_system or platform.system()
    destination = assert_output_outside_source_disk(
        plan.destination,
        plan.selected_root,
        source_disk_number=plan.disk_number,
        host_system=system,
        destination_disk_resolver=destination_disk_resolver,
    )
    manifest_path = assert_output_outside_source_disk(
        plan.manifest_path,
        plan.selected_root,
        source_disk_number=plan.disk_number,
        host_system=system,
        destination_disk_resolver=destination_disk_resolver,
    )

    # Final source identity binding happens before any staging write.
    is_windows_physical = system == "Windows" and plan.source_path.casefold().startswith(r"\\.\physicaldrive")
    source_identity_revalidated = False
    handle_identity_checked = False
    if identity_resolver is not None or is_windows_physical:
        revalidate_source_identity(plan, mapping_resolver=identity_resolver)
        source_identity_revalidated = True

    image_binding: BoundOutputVolume | None = None
    manifest_binding: BoundOutputVolume | None = None
    if system == "Windows":
        image_binding = bind_output_volume(
            destination,
            plan.selected_root,
            source_disk_number=plan.disk_number,
            host_system=system,
            destination_disk_resolver=destination_disk_resolver,
            volume_root_resolver=volume_root_resolver,
            volume_disk_resolver=volume_disk_resolver,
        )
        manifest_binding = bind_output_volume(
            manifest_path,
            plan.selected_root,
            source_disk_number=plan.disk_number,
            host_system=system,
            destination_disk_resolver=destination_disk_resolver,
            volume_root_resolver=volume_root_resolver,
            volume_disk_resolver=volume_disk_resolver,
        )
        assert image_binding is not None and manifest_binding is not None
        if (
            image_binding.destination_disk_number != manifest_binding.destination_disk_number
            or image_binding.volume_root.casefold() != manifest_binding.volume_root.casefold()
        ):
            raise ImagingError("Image and manifest destinations are not bound to the same safe volume.")
        if not destination.parent.exists() or not destination.parent.is_dir():
            raise ImagingError(
                "Windows image destination parent must already exist; automatic directory creation is disabled "
                "to preserve the zero-write source invariant."
            )
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)

    legacy_partial = Path(str(destination) + ".partial")
    legacy_staged_manifest = Path(str(manifest_path) + ".partial")
    legacy_manifest_temp = Path(str(manifest_path) + ".tmp")
    for stale, label in (
        (legacy_partial, "partial image"),
        (legacy_staged_manifest, "staged manifest"),
        (legacy_manifest_temp, "temporary manifest"),
    ):
        if stale.exists():
            raise ImagingError(f"Stale {label} already exists from an earlier build; inspect/remove it manually: {stale}")
    if destination.exists() and not plan.overwrite_existing:
        raise ImagingError(f"Destination already exists: {destination}")
    if manifest_path.exists() and not plan.overwrite_existing:
        raise ImagingError(f"Manifest already exists: {manifest_path}")

    # Windows staging is created directly on the proven-safe stable volume root,
    # never beside a mutable user pathname. Non-Windows test/portable paths retain
    # the legacy adjacent exclusive staging behavior.
    partial: Path
    image_stage_fd: Optional[int] = None
    staged_manifest: Optional[Path]
    manifest_stage_fd: Optional[int] = None
    if image_binding is not None:
        image_stage_fd, partial = secure_stage_on_bound_volume(image_binding, suffix=".image.partial")
        # Manifest staging is delayed until the image has verified.
        staged_manifest = None
    else:
        partial = legacy_partial
        staged_manifest = legacy_staged_manifest

    started = datetime.now(timezone.utc).isoformat()
    digest = hashlib.sha256()
    written = 0
    transfer_verified = False

    try:
        if source_opener is None:
            source = _default_source_opener(
                plan.source_path,
                expected_disk_number=plan.disk_number,
                expected_size=plan.source_size,
            )
            handle_identity_checked = is_windows_physical
        else:
            source = source_opener(plan.source_path)

        if image_stage_fd is not None:
            output_handle = os.fdopen(image_stage_fd, "w+b")
            image_stage_fd = None
        else:
            output_handle = partial.open("xb")
        with source, output_handle as output:
            remaining = plan.source_size
            while remaining:
                if cancelled and cancelled():
                    raise ImagingCancelled("Raw image creation cancelled by user.")
                block = source.read(min(chunk_size, remaining))
                if not block:
                    raise ImagingError(
                        f"Source ended early after {written} of {plan.source_size} bytes; image is incomplete."
                    )
                output.write(block)
                digest.update(block)
                written += len(block)
                remaining -= len(block)
                if progress:
                    progress("imaging", written, plan.source_size)
            output.flush()
            os.fsync(output.fileno())

        streaming_hash = digest.hexdigest()

        def _verify_progress(done: int, total: int) -> None:
            if cancelled and cancelled():
                raise ImagingCancelled("Image verification cancelled by user.")
            if progress:
                progress("verifying", done, total)

        # Verify the staged image before touching any existing canonical pair.
        reread_hash = sha256_file(partial, chunk_size=chunk_size, progress=_verify_progress)
        verified = reread_hash == streaming_hash and partial.stat().st_size == plan.source_size
        if not verified:
            raise ImagingError(
                "Staged destination reread verification failed. Existing recovery artifacts were not replaced."
            )
        transfer_verified = True

        source_consistency_status = "NOT_REQUESTED"
        second_source_sha256 = None
        second_source_bytes_read = 0
        second_source_error_category = None
        if second_full_source_read:
            # Re-prove source identity before the independent full reread. The
            # first image is already transfer-verified at this point, but a
            # content mismatch/read failure is recorded as evidence rather than
            # being confused with a failed transfer.
            if identity_resolver is not None or is_windows_physical:
                revalidate_source_identity(plan, mapping_resolver=identity_resolver)
            second_status, second_hash, second_bytes, second_error = _second_full_source_read(
                plan,
                chunk_size=chunk_size,
                progress=progress,
                cancelled=cancelled,
                source_opener=source_opener,
                host_system=system,
            )
            second_source_sha256 = second_hash
            second_source_bytes_read = second_bytes
            second_source_error_category = second_error
            if second_status == "SECOND_READ_COMPLETE":
                source_consistency_status = "MATCHED" if second_hash == streaming_hash else "MISMATCH"
            else:
                source_consistency_status = second_status

        completed = datetime.now(timezone.utc).isoformat()
        result = ImageResult(
            image_path=str(destination.resolve()),
            manifest_path=str(manifest_path.resolve()),
            bytes_written=written,
            streaming_sha256=streaming_hash,
            reread_sha256=reread_hash,
            verified=verified,
            started_at_utc=started,
            completed_at_utc=completed,
            source_consistency_status=source_consistency_status,
            second_source_sha256=second_source_sha256,
            second_source_bytes_read=second_source_bytes_read,
            second_source_error_category=second_source_error_category,
        )
        # Build+fsync the matching manifest while the old pair is still untouched.
        if image_binding is not None:
            manifest_stage_fd, staged_manifest = secure_stage_on_bound_volume(
                image_binding, suffix=".manifest.partial"
            )
        assert staged_manifest is not None
        _write_staged_manifest(
            staged_manifest,
            _manifest_payload(
                plan,
                result,
                chunk_size=chunk_size,
                source_identity_revalidated=source_identity_revalidated,
                handle_identity_checked=handle_identity_checked,
            ),
            fd=manifest_stage_fd,
        )
        manifest_stage_fd = None

        # Rebind source identity and destination volume immediately before commit.
        if identity_resolver is not None or is_windows_physical:
            revalidate_source_identity(plan, mapping_resolver=identity_resolver)
        if image_binding is not None:
            current_image_binding = bind_output_volume(
                destination,
                plan.selected_root,
                source_disk_number=plan.disk_number,
                host_system=system,
                destination_disk_resolver=destination_disk_resolver,
                volume_root_resolver=volume_root_resolver,
                volume_disk_resolver=volume_disk_resolver,
            )
            current_manifest_binding = bind_output_volume(
                manifest_path,
                plan.selected_root,
                source_disk_number=plan.disk_number,
                host_system=system,
                destination_disk_resolver=destination_disk_resolver,
                volume_root_resolver=volume_root_resolver,
                volume_disk_resolver=volume_disk_resolver,
            )
            if (
                current_image_binding is None
                or current_manifest_binding is None
                or current_image_binding.destination_disk_number != image_binding.destination_disk_number
                or current_manifest_binding.destination_disk_number != image_binding.destination_disk_number
                or current_image_binding.volume_root.casefold() != image_binding.volume_root.casefold()
                or current_manifest_binding.volume_root.casefold() != image_binding.volume_root.casefold()
                or current_image_binding.final_path != destination
                or current_manifest_binding.final_path != manifest_path
            ):
                raise ImagingError("Destination volume identity changed after staging; promotion refused.")
            rollback_image = partial.with_name(partial.name + ".old-image.rollback")
            rollback_manifest = partial.with_name(partial.name + ".old-manifest.rollback")
        else:
            assert_output_outside_source_disk(
                destination,
                plan.selected_root,
                source_disk_number=plan.disk_number,
                host_system=system,
                destination_disk_resolver=destination_disk_resolver,
            )
            assert_output_outside_source_disk(
                manifest_path,
                plan.selected_root,
                source_disk_number=plan.disk_number,
                host_system=system,
                destination_disk_resolver=destination_disk_resolver,
            )
            rollback_image = None
            rollback_manifest = None

        _promote_verified_pair(
            partial,
            staged_manifest,
            destination,
            manifest_path,
            overwrite=plan.overwrite_existing,
            rollback_image=rollback_image,
            rollback_manifest=rollback_manifest,
        )
        return result
    except Exception as exc:
        for fd in (image_stage_fd, manifest_stage_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

        if transfer_verified and isinstance(exc, (SourceIdentityUnavailable, SourceIdentityChanged)):
            # Once destination reread verification has succeeded, a later *source*
            # identity mapping failure must not destroy hours of verified evidence.
            # Destination-authority/promotion failures retain their existing strict
            # cleanup behavior; only source revalidation failures preserve staging.
            preserved = []
            if partial is not None and partial.exists():
                preserved.append(f"verified staged image: {partial}")
            if staged_manifest is not None and staged_manifest.exists():
                preserved.append(f"staged manifest: {staged_manifest}")
            if preserved:
                detail = "; ".join(preserved)
                raise VerifiedStagePreserved(
                    f"{exc}\n\nTRANSFER-VERIFIED STAGING WAS PRESERVED rather than deleted because the failure "
                    f"occurred after destination reread verification. The canonical image was NOT promoted. "
                    f"Preserved artifact(s): {detail}"
                ) from exc

        # Before transfer verification (or on explicit cancellation), incomplete
        # staging must not masquerade as a completed recovery artifact.
        for staged in (partial, staged_manifest):
            if staged is not None and staged.exists():
                try:
                    staged.unlink()
                except OSError:
                    pass
        raise
