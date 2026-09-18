from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Optional

from .catalogue_image_lab import _FatAccessor, _locate_catalogues
from .fast_image_lab import FatEntry, _parse_geometry, _validate_image
from .fs_safety import bounded_scandir_names
from .rom_customization import RomCustomizationError, _read_control_layout, _rom_names

ProgressCallback = Callable[[str], None]
CancelledCallback = Callable[[], bool]
_MAX_CASEFOLD_ENTRIES = 4096


class RomManagerError(RuntimeError):
    """Raised when the fast ROM-manager inventory cannot be proven trustworthy."""


@dataclass(frozen=True)
class RomManagerEntry:
    catalogue_code: str
    filename: str
    state: str
    catalogue_present: Optional[bool]
    root_present: Optional[bool]

    @property
    def identity(self) -> str:
        return f"{self.catalogue_code}:{self.filename}"


@dataclass(frozen=True)
class RomManagerSnapshot:
    reference_image: str
    target_root: Optional[str]
    entries: tuple[RomManagerEntry, ...]
    reference_entry_count: int
    target_entry_count: Optional[int]
    visible_count: int
    hidden_count: int
    inconsistent_count: int
    target_only_count: int
    unreadable_catalogues: tuple[str, ...]
    root_control_readable: Optional[bool]
    bytes_read_from_reference_controls: int
    bytes_read_from_reference_fat: int


class _DirectAccessor:
    """Minimal read-only adapter for mounted DAT/ROOT files."""

    def __init__(self, handle):
        self.handle = handle
        self.bytes_read = 0

    def chain_for(self, entry: FatEntry):
        return ()

    def read_range(self, entry: FatEntry, offset: int, length: int, chain=None) -> bytes:
        if offset < 0 or length < 0 or offset + length > entry.size_bytes:
            raise RomManagerError(
                f"Requested range {offset}+{length} lies outside {entry.path} ({entry.size_bytes} bytes)."
            )
        self.handle.seek(offset)
        data = self.handle.read(length)
        if len(data) != length:
            raise RomManagerError(
                f"Short read in {entry.path}: expected {length} bytes, got {len(data)}."
            )
        self.bytes_read += len(data)
        return data


def _check_cancelled(cancelled: CancelledCallback | None) -> None:
    if cancelled and cancelled():
        raise RomManagerError("ROM Manager scan cancelled.")


def _unique_names(payload: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in _rom_names(payload):
        folded = name.casefold()
        out.setdefault(folded, name)
    return out


def _root_pairs(payload: bytes) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for line in payload.splitlines():
        if not line:
            continue
        first = line.split(b";", 1)[0]
        text = None
        for encoding in ("utf-8", "gbk"):
            try:
                text = first.decode(encoding, errors="strict")
                break
            except UnicodeDecodeError:
                continue
        if text is None:
            continue
        normalized = text.replace("\\", "/").strip("/")
        parts = normalized.split("/", 1)
        if len(parts) != 2 or len(parts[0]) != 3 or not parts[0].isdigit():
            continue
        filename = PurePosixPath(parts[1]).name
        if filename:
            pairs.add((parts[0], filename.casefold()))
    return pairs


def _require_regular_file(path: Path, label: str) -> Path:
    try:
        st = path.lstat()
    except OSError as exc:
        raise RomManagerError(f"{label} is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RomManagerError(f"{label} must be a regular non-symlink file: {path}")
    return path.resolve(strict=True)


def _resolve_casefold_child(parent: Path, wanted: str, *, must_be_dir: bool = False) -> Path:
    direct = parent / wanted
    if direct.exists():
        candidate = direct
    else:
        result = bounded_scandir_names(parent, _MAX_CASEFOLD_ENTRIES)
        if result.error is not None:
            raise RomManagerError(f"Cannot enumerate {parent}: {result.error}") from result.error
        if result.truncated:
            raise RomManagerError(
                f"Directory enumeration exceeded the {_MAX_CASEFOLD_ENTRIES}-entry safety bound: {parent}"
            )
        matches = [name for name in result.names if name.casefold() == wanted.casefold()]
        if len(matches) != 1:
            raise RomManagerError(f"Expected exactly one {wanted!r} under {parent}; found {len(matches)}.")
        candidate = parent / matches[0]
    try:
        st = candidate.lstat()
    except OSError as exc:
        raise RomManagerError(f"Target path is unavailable: {candidate}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise RomManagerError(f"Target path must not be a symlink: {candidate}")
    if must_be_dir and not stat.S_ISDIR(st.st_mode):
        raise RomManagerError(f"Target path must be a directory: {candidate}")
    if not must_be_dir and not stat.S_ISREG(st.st_mode):
        raise RomManagerError(f"Target path must be a regular file: {candidate}")
    return candidate.resolve(strict=True)


def _read_mounted_control(path: Path, relpath: str, control_name: str) -> bytes:
    path = _require_regular_file(path, relpath)
    entry = FatEntry(path=relpath, size_bytes=path.stat().st_size, start_cluster=2, is_directory=False)
    try:
        with path.open("rb", buffering=0) as handle:
            layout = _read_control_layout(_DirectAccessor(handle), entry, control_name)
    except (OSError, RomCustomizationError, RomManagerError) as exc:
        raise RomManagerError(f"Cannot verify {relpath}:{control_name}: {exc}") from exc
    return layout.payload


def _normalize_target_root(target_root) -> Path:
    root = Path(target_root).expanduser()
    try:
        st = root.lstat()
    except OSError as exc:
        raise RomManagerError(f"Target GameStick volume is unavailable: {root}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RomManagerError("Target GameStick root must be a real directory, not a symlink.")
    root = root.resolve(strict=True)
    for marker in ("ROOT.DAT", "CUBEGM", "Roms"):
        candidate = root / marker
        if not candidate.exists():
            # Windows is case-insensitive; tests/other hosts are not. Resolve safely.
            _resolve_casefold_child(root, marker, must_be_dir=marker != "ROOT.DAT")
    return root


def scan_rom_manager(
    reference_image,
    target_root=None,
    *,
    progress: ProgressCallback | None = None,
    cancelled: CancelledCallback | None = None,
) -> RomManagerSnapshot:
    """Read a healthy reference image and optionally compare it with a mounted test card.

    The reference image is opened read-only. The mounted target is also opened read-only;
    this function has no write path. ROM payload files are never read.
    """

    image = _validate_image(reference_image)
    _check_cancelled(cancelled)
    if progress:
        progress("Reading reference FAT + 15 launcher catalogues...")

    reference_by_code: dict[str, dict[str, str]] = {}
    reference_root_pairs: set[tuple[str, str]] = set()
    reference_control_bytes = 0
    reference_fat_bytes = 0

    with image.open("rb", buffering=0) as handle:
        opened = os.fstat(handle.fileno())
        geometry = _parse_geometry(handle, opened.st_size)
        catalogues, root_entry = _locate_catalogues(handle, geometry, cancelled=cancelled)
        if root_entry is None:
            raise RomManagerError("ROOT.DAT is missing from the healthy reference image.")
        accessor = _FatAccessor(handle, geometry, cancelled=cancelled)
        # _FatAccessor materialises FAT once on construction.
        reference_fat_bytes = int(getattr(accessor, "bytes_read", 0))

        for code in sorted(catalogues):
            _check_cancelled(cancelled)
            try:
                layout = _read_control_layout(accessor, catalogues[code], "filelist.txt")
            except RomCustomizationError as exc:
                raise RomManagerError(f"Reference catalogue {code} is not trustworthy: {exc}") from exc
            reference_by_code[code] = _unique_names(layout.payload)
            reference_control_bytes += len(layout.payload)

        try:
            root_layout = _read_control_layout(accessor, root_entry, "fileinfo.txt")
        except RomCustomizationError as exc:
            raise RomManagerError(f"Reference ROOT.DAT control is not trustworthy: {exc}") from exc
        reference_root_pairs = _root_pairs(root_layout.payload)
        reference_control_bytes += len(root_layout.payload)

        final = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
        ):
            raise RomManagerError("Reference image changed while ROM Manager was scanning it.")

    reference_entries: list[tuple[str, str]] = []
    for code, names in sorted(reference_by_code.items()):
        for _folded, name in sorted(names.items(), key=lambda item: item[1].casefold()):
            reference_entries.append((code, name))

    # A reference-image ROOT mismatch is useful to expose rather than silently hide.
    for code, name in reference_entries:
        if (code, name.casefold()) not in reference_root_pairs:
            # Do not abort the entire manager for known odd factory metadata, but state will
            # become INCONSISTENT if the mounted card mirrors the same one-sided authority.
            pass

    if target_root is None or not str(target_root).strip():
        entries = tuple(
            RomManagerEntry(code, name, "REFERENCE", None, None)
            for code, name in reference_entries
        )
        return RomManagerSnapshot(
            reference_image=str(image),
            target_root=None,
            entries=entries,
            reference_entry_count=len(entries),
            target_entry_count=None,
            visible_count=0,
            hidden_count=0,
            inconsistent_count=0,
            target_only_count=0,
            unreadable_catalogues=(),
            root_control_readable=None,
            bytes_read_from_reference_controls=reference_control_bytes,
            bytes_read_from_reference_fat=reference_fat_bytes,
        )

    root = _normalize_target_root(target_root)
    if progress:
        progress("Comparing mounted TEST/CLONE launcher controls with the reference catalogue...")

    target_by_code: dict[str, dict[str, str]] = {}
    unreadable: list[str] = []
    for code in sorted(reference_by_code):
        _check_cancelled(cancelled)
        try:
            directory = _resolve_casefold_child(root, code, must_be_dir=True)
            dat_path = _resolve_casefold_child(directory, f"{code}.DAT")
            payload = _read_mounted_control(dat_path, f"{code}/{code}.DAT", "filelist.txt")
            target_by_code[code] = _unique_names(payload)
        except RomManagerError:
            unreadable.append(code)
            target_by_code[code] = {}

    root_pairs: set[tuple[str, str]] = set()
    root_readable = True
    try:
        root_dat = _resolve_casefold_child(root, "ROOT.DAT")
        root_pairs = _root_pairs(_read_mounted_control(root_dat, "ROOT.DAT", "fileinfo.txt"))
    except RomManagerError:
        root_readable = False

    entries: list[RomManagerEntry] = []
    reference_keys: set[tuple[str, str]] = set()
    visible = hidden = inconsistent = target_only = 0

    for code, name in reference_entries:
        folded = name.casefold()
        reference_keys.add((code, folded))
        if code in unreadable or not root_readable:
            state = "UNREADABLE"
            cat_present = None if code in unreadable else folded in target_by_code.get(code, {})
            root_present = None if not root_readable else (code, folded) in root_pairs
        else:
            cat_present = folded in target_by_code.get(code, {})
            root_present = (code, folded) in root_pairs
            if cat_present and root_present:
                state = "VISIBLE"
                visible += 1
            elif not cat_present and not root_present:
                state = "HIDDEN"
                hidden += 1
            else:
                state = "INCONSISTENT"
                inconsistent += 1
        entries.append(RomManagerEntry(code, name, state, cat_present, root_present))

    for code, names in sorted(target_by_code.items()):
        if code in unreadable:
            continue
        for folded, name in sorted(names.items(), key=lambda item: item[1].casefold()):
            if (code, folded) in reference_keys:
                continue
            root_present = None if not root_readable else (code, folded) in root_pairs
            entries.append(RomManagerEntry(code, name, "TARGET_ONLY", True, root_present))
            target_only += 1

    entries.sort(key=lambda item: (item.catalogue_code, item.filename.casefold()))
    target_entry_count = sum(len(items) for code, items in target_by_code.items() if code not in unreadable)
    return RomManagerSnapshot(
        reference_image=str(image),
        target_root=str(root),
        entries=tuple(entries),
        reference_entry_count=len(reference_entries),
        target_entry_count=target_entry_count,
        visible_count=visible,
        hidden_count=hidden,
        inconsistent_count=inconsistent,
        target_only_count=target_only,
        unreadable_catalogues=tuple(unreadable),
        root_control_readable=root_readable,
        bytes_read_from_reference_controls=reference_control_bytes,
        bytes_read_from_reference_fat=reference_fat_bytes,
    )
