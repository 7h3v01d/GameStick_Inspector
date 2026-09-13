from __future__ import annotations

import platform
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .fs_safety import ForensicPathError, assert_contained_non_reparse, lstat_non_reparse


class UnsafeOperationDisabled(RuntimeError):
    """Raised when a destructive operation is attempted in a read-only build."""


READ_ONLY_BUILD = True


def assert_readable_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    try:
        root = assert_contained_non_reparse(candidate, candidate)
        st = lstat_non_reparse(root)
    except (OSError, ForensicPathError) as exc:
        raise ValueError(f"Selected evidence root is unavailable or unsafe: {candidate}: {exc}") from exc
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"Selected path is not a directory: {root}")
    return root


def refuse_destructive_operation(operation: str) -> None:
    raise UnsafeOperationDisabled(
        f"'{operation}' is intentionally disabled in this read-only safety build. "
        "No operation may modify, format, erase, restore, or flash a GameStick card."
    )


def is_within(candidate: str | Path, protected_root: str | Path) -> bool:
    candidate_path = Path(candidate).expanduser().resolve()
    root_path = Path(protected_root).expanduser().resolve()
    try:
        candidate_path.relative_to(root_path)
        return True
    except ValueError:
        return False


def assert_output_outside_device(candidate: str | Path, device_root: str | Path) -> Path:
    """Path-level guard retained for portability and defence in depth."""
    output = Path(candidate).expanduser().resolve()
    if is_within(output, device_root):
        raise ValueError(
            "Diagnostic output must be saved outside the selected GameStick volume. "
            "This build will not write to the inspected device."
        )
    return output


def _windows_drive_letter(path: str | Path) -> Optional[str]:
    """Return an uppercase drive letter for a Windows local-drive path, if present."""
    text = str(path).strip().replace("/", "\\")
    # Support extended local paths such as \\?\C:\... without treating UNC as local.
    if text.startswith("\\\\?\\"):
        tail = text[4:]
        if tail.upper().startswith("UNC\\"):
            return None
        text = tail
    # Path.resolve() on a non-Windows test host cannot preserve Windows semantics,
    # so recognise raw Windows drive syntax directly.
    if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
        return text[0].upper()
    drive = Path(str(path)).drive
    if len(drive) >= 2 and drive[1] == ":" and drive[0].isalpha():
        return drive[0].upper()
    return None


def _is_windows_unc_path(path: str | Path) -> bool:
    """Return True for UNC/network paths, including extended UNC syntax."""
    text = str(path).strip().replace("/", "\\")
    if text.startswith("\\\\?\\"):
        return text[4:].upper().startswith("UNC\\")
    return text.startswith("\\\\")


def _default_destination_disk_resolver(drive_letter: str) -> int:
    # Lazy import avoids an import cycle: probe imports assert_readable_root from here.
    from .probe import _physical_mapping

    mapping = _physical_mapping(Path(f"{drive_letter}:\\"))
    if mapping.mapping_error:
        raise ValueError(mapping.mapping_error)
    if mapping.disk_number is None:
        raise ValueError(f"Could not resolve physical disk for destination drive {drive_letter}:")
    return int(mapping.disk_number)


def assert_output_outside_source_disk(
    candidate: str | Path,
    device_root: str | Path,
    *,
    source_disk_number: Optional[int],
    host_system: Optional[str] = None,
    destination_disk_resolver: Optional[Callable[[str], int]] = None,
) -> Path:
    """Refuse writes anywhere on the same physical disk as the GameStick source.

    Path canonicalization happens first. On Windows, the *resolved output path* is
    authoritative for physical-disk validation so a junction/symlink alias cannot
    make C: pass validation while the actual destination resolves to F:.

    Safety-first policy for this release also rejects UNC/network output paths:
    their backing physical storage is not proven by the local-disk resolver.
    """

    output = assert_output_outside_device(candidate, device_root)
    system = host_system or platform.system()
    if system != "Windows":
        return output

    # UNC/network paths are refused independently of whether source identity is
    # currently available. We never claim physical separation for storage we
    # cannot map to a local physical disk.
    if _is_windows_unc_path(output) or (
        platform.system() != "Windows" and _is_windows_unc_path(candidate)
    ):
        raise ValueError(
            "UNC/network output paths are not supported in this safety-first build because "
            "their backing physical disk cannot be proven different from the GameStick source."
        )

    # On Windows, unknown source identity is a fail-closed condition. This must
    # never silently degrade to path-only protection.
    if source_disk_number is None:
        raise ValueError(
            "Source physical disk could not be proven; generated output is disabled until the device is re-probed."
        )

    # The canonical/resolved path wins. Only on non-Windows hosts used to exercise
    # Windows logic in unit tests do we fall back to the syntactic candidate when
    # pathlib could not preserve a Windows drive letter at all.
    drive_letter = _windows_drive_letter(output)
    if drive_letter is None and platform.system() != "Windows":
        drive_letter = _windows_drive_letter(candidate)
        # Unit tests exercise Windows policy from non-Windows hosts with native
        # temporary paths. Those paths cannot represent a Windows local disk at all;
        # allow them solely as a portability fixture. This branch is unreachable on
        # actual Windows execution.
        if drive_letter is None:
            return output
    if drive_letter is None:
        raise ValueError(
            "Could not prove the physical disk backing the resolved Windows output path; output refused."
        )

    resolver = destination_disk_resolver or _default_destination_disk_resolver
    try:
        destination_disk = int(resolver(drive_letter))
    except Exception as exc:
        raise ValueError(
            f"Could not prove that destination drive {drive_letter}: is on a different physical disk; "
            f"output refused: {type(exc).__name__}: {exc}"
        ) from exc

    if destination_disk == int(source_disk_number):
        raise ValueError(
            f"Output refused: destination drive {drive_letter}: is on PhysicalDrive{destination_disk}, "
            "the same physical disk as the inspected GameStick. This build will not write anywhere "
            "on the source device, including another partition."
        )
    return output


@dataclass(frozen=True)
class BoundOutputVolume:
    """A generated-output destination bound to a proven-safe Windows volume.

    `volume_root` is a stable volume-GUID root (for example
    ``\\?\\Volume{...}\\``), not a drive-letter or user-controlled directory alias.
    Staging is created directly on this root so directory/junction swaps in the
    requested final pathname cannot redirect staging onto the GameStick.
    """

    final_path: Path
    source_disk_number: int
    destination_disk_number: int
    drive_letter: str
    volume_root: str


def _default_windows_volume_root_resolver(drive_letter: str) -> str:
    """Resolve C: to a stable Windows volume GUID root."""
    if platform.system() != "Windows":
        raise RuntimeError("Windows volume GUID resolution is only available on Windows")

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_volume_name = kernel32.GetVolumeNameForVolumeMountPointW
    get_volume_name.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_volume_name.restype = wintypes.BOOL

    mount = f"{drive_letter.upper()}:\\"
    buf = ctypes.create_unicode_buffer(1024)
    if not get_volume_name(mount, buf, len(buf)):
        error = ctypes.get_last_error()
        raise OSError(error, f"Could not resolve stable volume identity for {mount}")
    value = buf.value
    if not value.startswith("\\\\?\\Volume{") or not value.endswith("\\"):
        raise RuntimeError(f"Unexpected Windows volume GUID path for {mount}: {value!r}")
    return value




def _default_windows_volume_disk_resolver(volume_root: str) -> int:
    """Resolve a stable volume-GUID root to its actual Windows physical disk number."""
    if platform.system() != "Windows":
        raise RuntimeError("Windows volume handle resolution is only available on Windows")

    import ctypes
    from ctypes import wintypes

    IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class STORAGE_DEVICE_NUMBER(ctypes.Structure):
        _fields_ = [
            ("DeviceType", wintypes.DWORD),
            ("DeviceNumber", wintypes.DWORD),
            ("PartitionNumber", wintypes.DWORD),
        ]

    volume_handle_path = volume_root.rstrip("\\")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        volume_handle_path,
        0,  # metadata/IOCTL query only; no read or write data access requested
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise OSError(error, f"Could not open bound destination volume {volume_handle_path}")
    try:
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
            raise OSError(error, f"Could not resolve physical disk for bound volume {volume_root}")
        return int(number.DeviceNumber)
    finally:
        kernel32.CloseHandle(handle)


def bind_output_volume(
    candidate: str | Path,
    device_root: str | Path,
    *,
    source_disk_number: Optional[int],
    host_system: Optional[str] = None,
    destination_disk_resolver: Optional[Callable[[str], int]] = None,
    volume_root_resolver: Optional[Callable[[str], str]] = None,
    volume_disk_resolver: Optional[Callable[[str], int]] = None,
) -> BoundOutputVolume | None:
    """Bind a Windows output to a stable volume before any generated write.

    Non-Windows callers receive ``None`` after the ordinary path-level guard.
    On Windows this function fails closed unless source identity, destination
    physical disk, and a stable volume-GUID root can all be proven.
    """
    system = host_system or platform.system()
    final_path = assert_output_outside_source_disk(
        candidate,
        device_root,
        source_disk_number=source_disk_number,
        host_system=system,
        destination_disk_resolver=destination_disk_resolver,
    )
    if system != "Windows":
        return None
    assert source_disk_number is not None  # enforced above

    drive_letter = _windows_drive_letter(final_path)
    if drive_letter is None and platform.system() != "Windows":
        drive_letter = _windows_drive_letter(candidate)
    if drive_letter is None:
        raise ValueError("Could not bind resolved Windows output to a local drive; output refused.")

    disk_resolver = destination_disk_resolver or _default_destination_disk_resolver
    destination_disk = int(disk_resolver(drive_letter))
    if destination_disk == int(source_disk_number):
        raise ValueError(
            f"Output refused: destination drive {drive_letter}: is on PhysicalDrive{destination_disk}, "
            "the same physical disk as the inspected GameStick."
        )

    volume_resolver = volume_root_resolver or _default_windows_volume_root_resolver
    volume_root = str(volume_resolver(drive_letter))
    if not volume_root:
        raise ValueError("Could not bind destination to a stable Windows volume; output refused.")

    stable_disk_resolver = volume_disk_resolver or _default_windows_volume_disk_resolver
    stable_disk = int(stable_disk_resolver(volume_root))
    if stable_disk != destination_disk:
        raise ValueError(
            f"Destination identity changed while binding: {drive_letter}: resolved to PhysicalDrive{destination_disk}, "
            f"but stable volume {volume_root!r} resolves to PhysicalDrive{stable_disk}. Output refused."
        )
    if stable_disk == int(source_disk_number):
        raise ValueError("Bound destination volume is the GameStick source disk; output refused.")
    return BoundOutputVolume(
        final_path=final_path,
        source_disk_number=int(source_disk_number),
        destination_disk_number=destination_disk,
        drive_letter=drive_letter,
        volume_root=volume_root,
    )


def secure_stage_on_bound_volume(
    binding: BoundOutputVolume,
    *,
    suffix: str = ".tmp",
):
    """Create an unpredictable exclusive staging file directly on the bound volume root.

    The returned descriptor is already open. The caller must write through that
    descriptor rather than reopening the pathname.
    """
    fd, name = tempfile.mkstemp(
        prefix=".gamestick-inspector-",
        suffix=suffix,
        dir=binding.volume_root,
    )
    return fd, Path(name)
