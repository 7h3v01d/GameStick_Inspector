from __future__ import annotations

import binascii
import hashlib
import json
import os
import stat
import struct
import tempfile
import zlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Optional

from .fast_image_lab import FastImageLabError, Fat32Geometry, FatEntry, _Fat32Reader, _parse_geometry, _validate_image
from .wqw import _bounded_inflate, _decode_name, _parse_fileinfo, _parse_filelist

ProgressCallback = Callable[[str], None]
CancelledCallback = Callable[[], bool]

_LOCAL = b"WQW\x03"
_CENTRAL = b"WQW\x02"
_EOCD = b"WQW\x01"
_LOCAL_FIXED = 30
_CENTRAL_FIXED = 46
_EOCD_FIXED = 22
_MAX_COMMENT = 65_535
_MAX_CENTRAL_BYTES = 16 * 1024 * 1024
_MAX_ENTRIES = 20_000
_MAX_CONTROL_COMPRESSED = 8 * 1024 * 1024
_MAX_CONTROL_UNCOMPRESSED = 8 * 1024 * 1024
_MAX_DIFF_NAMES = 500
_METHODS = {0: "stored", 8: "deflate"}


class CatalogueImageLabError(RuntimeError):
    """Raised when catalogue controls cannot be safely compared from raw images."""


@dataclass(frozen=True)
class CatalogueControl:
    code: str
    path: str
    container_status: str
    control_status: str
    control_sha256: Optional[str]
    file_size_bytes: int
    declared_member_count: Optional[int]
    record_count: Optional[int]
    valid_record_count: Optional[int]
    malformed_record_count: Optional[int]
    unique_rom_name_count: Optional[int]


@dataclass(frozen=True)
class CatalogueDelta:
    code: str
    status: str
    image_a_control_status: str
    image_b_control_status: str
    image_a_unique_rom_count: Optional[int]
    image_b_unique_rom_count: Optional[int]
    only_in_a_count: int
    only_in_b_count: int
    only_in_a_roms: tuple[str, ...]
    only_in_b_roms: tuple[str, ...]
    names_truncated: bool


@dataclass(frozen=True)
class RootControl:
    path: str
    container_status: str
    control_status: str
    control_sha256: Optional[str]
    record_count: Optional[int]
    valid_record_count: Optional[int]
    malformed_record_count: Optional[int]
    code_count: int


@dataclass(frozen=True)
class CatalogueImageSnapshot:
    image_path: str
    image_size_bytes: int
    partition_offset_bytes: int
    catalogue_controls: tuple[CatalogueControl, ...]
    root_control: RootControl
    bytes_read_for_fat: int
    bytes_read_for_controls: int


@dataclass(frozen=True)
class CatalogueComparisonResult:
    status: str
    image_a: CatalogueImageSnapshot
    image_b: CatalogueImageSnapshot
    catalogue_count: int
    identical_catalogue_count: int
    differing_catalogue_count: int
    byte_only_catalogue_count: int
    damaged_or_unreadable_count: int
    differing_catalogue_codes: tuple[str, ...]
    byte_only_catalogue_codes: tuple[str, ...]
    damaged_or_unreadable_codes: tuple[str, ...]
    deltas: tuple[CatalogueDelta, ...]
    root_fileinfo_status: str
    root_fileinfo_codes_changed: tuple[str, ...]
    report_path: Optional[str]
    created_at_utc: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class _FatAccessor:
    def __init__(self, handle, geometry: Fat32Geometry, *, cancelled: CancelledCallback | None = None):
        self.handle = handle
        self.g = geometry
        self.cancelled = cancelled
        fat_size = geometry.fat_size_sectors * geometry.bytes_per_sector
        handle.seek(geometry.fat_offset_bytes)
        self.fat = handle.read(fat_size)
        if len(self.fat) != fat_size:
            raise CatalogueImageLabError("Could not read the complete primary FAT.")
        self.bytes_read = len(self.fat)

    def _cancel(self):
        if self.cancelled and self.cancelled():
            raise CatalogueImageLabError("Catalogue comparison cancelled; no report was written.")

    def next_cluster(self, cluster: int) -> int:
        offset = cluster * 4
        if offset < 0 or offset + 4 > len(self.fat):
            raise CatalogueImageLabError(f"FAT entry {cluster} lies outside the primary FAT.")
        return int.from_bytes(self.fat[offset:offset + 4], "little") & 0x0FFFFFFF

    def chain_for(self, entry: FatEntry) -> tuple[int, ...]:
        if entry.size_bytes == 0:
            return ()
        if entry.start_cluster < 2:
            raise CatalogueImageLabError(f"Non-empty file has invalid start cluster: {entry.path}")
        expected = (entry.size_bytes + self.g.cluster_size_bytes - 1) // self.g.cluster_size_bytes
        out: list[int] = []
        seen: set[int] = set()
        current = entry.start_cluster
        while len(out) < expected:
            self._cancel()
            if current < 2 or current >= 0x0FFFFFF8:
                raise CatalogueImageLabError(
                    f"FAT chain for {entry.path} ended after {len(out)} clusters; expected {expected}."
                )
            if current in seen:
                raise CatalogueImageLabError(f"FAT cluster loop in {entry.path} at cluster {current}.")
            seen.add(current)
            out.append(current)
            current = self.next_cluster(current)
        return tuple(out)

    def read_range(self, entry: FatEntry, offset: int, length: int, chain: tuple[int, ...] | None = None) -> bytes:
        if offset < 0 or length < 0 or offset + length > entry.size_bytes:
            raise CatalogueImageLabError(
                f"Requested range {offset}+{length} lies outside {entry.path} ({entry.size_bytes} bytes)."
            )
        if length == 0:
            return b""
        clusters = chain if chain is not None else self.chain_for(entry)
        cluster_size = self.g.cluster_size_bytes
        first_index = offset // cluster_size
        intra = offset % cluster_size
        remaining = length
        output = bytearray()
        index = first_index
        while remaining:
            self._cancel()
            if index >= len(clusters):
                raise CatalogueImageLabError(f"FAT chain for {entry.path} is shorter than requested range.")
            cluster = clusters[index]
            absolute = self.g.data_offset_bytes + (cluster - 2) * cluster_size + intra
            take = min(remaining, cluster_size - intra)
            self.handle.seek(absolute)
            chunk = self.handle.read(take)
            if len(chunk) != take:
                raise CatalogueImageLabError(f"Short image read while reading {entry.path}.")
            output.extend(chunk)
            self.bytes_read += len(chunk)
            remaining -= take
            index += 1
            intra = 0
        return bytes(output)


def _find_casefold(entries: list[FatEntry], name: str) -> FatEntry | None:
    target = name.casefold()
    for item in entries:
        if item.path.casefold() == target:
            return item
    return None


def _locate_catalogues(handle, geometry: Fat32Geometry, *, cancelled=None) -> tuple[dict[str, FatEntry], FatEntry | None]:
    reader = _Fat32Reader(handle, geometry, cancelled=cancelled)
    root = reader.read_directory(geometry.root_cluster)
    root_dat = _find_casefold(root, "root.dat")
    catalogues: dict[str, FatEntry] = {}
    for code_num in range(15):
        code = f"{code_num:03d}"
        directory = _find_casefold(root, code)
        if directory is None or not directory.is_directory or directory.start_cluster < 2:
            continue
        children = reader.read_directory(directory.start_cluster)
        dat = _find_casefold(children, f"{code}.dat")
        if dat is not None and not dat.is_directory:
            catalogues[code] = FatEntry(
                path=f"{code}/{code}.DAT",
                size_bytes=dat.size_bytes,
                start_cluster=dat.start_cluster,
                is_directory=False,
            )
    return catalogues, root_dat


def _read_wqw_control(
    accessor: _FatAccessor,
    entry: FatEntry,
    control_name: str,
) -> tuple[str, str, Optional[bytes], Optional[int], set[str]]:
    """Return container status, control status, payload, member count, private member names."""
    size = entry.size_bytes
    if size < _EOCD_FIXED:
        return "TOO_SMALL", "CONTROL_UNAVAILABLE", None, None, set()
    try:
        chain = accessor.chain_for(entry)
        tail_size = min(size, _EOCD_FIXED + _MAX_COMMENT)
        tail = accessor.read_range(entry, size - tail_size, tail_size, chain)
        before = len(tail)
        eocd_index = -1
        eocd = b""
        comment_len = 0
        while before > 0:
            candidate = tail.rfind(_EOCD, 0, before)
            if candidate < 0:
                break
            if candidate + _EOCD_FIXED <= len(tail):
                fixed = tail[candidate:candidate + _EOCD_FIXED]
                candidate_comment = struct.unpack("<H", fixed[20:22])[0]
                if candidate + _EOCD_FIXED + candidate_comment == len(tail):
                    eocd_index = candidate
                    eocd = fixed
                    comment_len = candidate_comment
                    break
            before = candidate
        if eocd_index < 0:
            return "WQW_EOCD_NOT_FOUND", "CONTROL_UNAVAILABLE", None, None, set()

        sig, disk, cdisk, entries_disk, total, central_size, central_offset, parsed_comment = struct.unpack(
            "<4s4H2LH", eocd
        )
        if sig != _EOCD or parsed_comment != comment_len:
            return "INVALID_EOCD", "CONTROL_UNAVAILABLE", None, None, set()
        if disk or cdisk or entries_disk != total:
            return "MULTIDISK_UNSUPPORTED", "CONTROL_UNAVAILABLE", None, total, set()
        if total == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
            return "ZIP64_UNSUPPORTED", "CONTROL_UNAVAILABLE", None, total, set()
        if total > _MAX_ENTRIES:
            return "ENTRY_LIMIT_EXCEEDED", "CONTROL_UNAVAILABLE", None, total, set()
        if central_size > _MAX_CENTRAL_BYTES:
            return "CENTRAL_DIRECTORY_LIMIT_EXCEEDED", "CONTROL_UNAVAILABLE", None, total, set()

        eocd_abs = size - tail_size + eocd_index
        actual_central = eocd_abs - central_size
        concat_offset = actual_central - central_offset
        if actual_central < 0 or concat_offset < 0:
            return "INVALID_CENTRAL_OFFSET", "CONTROL_UNAVAILABLE", None, total, set()
        central = accessor.read_range(entry, actual_central, central_size, chain)

        controls = []
        member_names: set[str] = set()
        position = 0
        for _ in range(total):
            if position + _CENTRAL_FIXED > len(central):
                return "TRUNCATED_CENTRAL_DIRECTORY", "CONTROL_UNAVAILABLE", None, total, set()
            fixed = central[position:position + _CENTRAL_FIXED]
            if fixed[:4] != _CENTRAL:
                return "INVALID_CENTRAL_ENTRY", "CONTROL_UNAVAILABLE", None, total, set()
            fields = struct.unpack("<4s6H3L5H2L", fixed)
            flags, method = fields[3], fields[4]
            crc, csize, usize = fields[7], fields[8], fields[9]
            name_len, extra_len, entry_comment_len = fields[10], fields[11], fields[12]
            local_offset = fields[16]
            record_size = _CENTRAL_FIXED + name_len + extra_len + entry_comment_len
            if position + record_size > len(central):
                return "INVALID_CENTRAL_LENGTH", "CONTROL_UNAVAILABLE", None, total, set()
            raw_name = central[position + _CENTRAL_FIXED:position + _CENTRAL_FIXED + name_len]
            try:
                name = _decode_name(raw_name, flags).replace("\\", "/")
            except UnicodeError:
                name = ""
            if name:
                member_names.add(name)
                normalized = name.strip("/").casefold()
                if "/" not in normalized and normalized == control_name.casefold():
                    controls.append((name, flags, method, crc, csize, usize, local_offset))
            position += record_size
        if position != central_size:
            return "CENTRAL_TRAILING_DATA", "CONTROL_UNAVAILABLE", None, total, set()
        if not controls:
            return "VALID_WQW", "CONTROL_NOT_FOUND", None, total, member_names
        if len(controls) != 1:
            return "VALID_WQW", "DUPLICATE_CONTROL", None, total, member_names

        name, flags, method, crc, csize, usize, local_offset = controls[0]
        if flags & 0x0001:
            return "VALID_WQW", "ENCRYPTED_UNSUPPORTED", None, total, member_names
        if method not in (0, 8):
            return "VALID_WQW", "COMPRESSION_UNSUPPORTED", None, total, member_names
        if csize > _MAX_CONTROL_COMPRESSED or usize > _MAX_CONTROL_UNCOMPRESSED:
            return "VALID_WQW", "CONTROL_SIZE_LIMIT", None, total, member_names

        adjusted = int(local_offset) + int(concat_offset)
        if adjusted < 0 or adjusted + _LOCAL_FIXED > size:
            return "VALID_WQW", "INVALID_LOCAL_OFFSET", None, total, member_names
        local = accessor.read_range(entry, adjusted, _LOCAL_FIXED, chain)
        if local[:4] != _LOCAL:
            return "VALID_WQW", "INVALID_LOCAL_HEADER", None, total, member_names
        local_fields = struct.unpack("<4s5H3L2H", local)
        local_flags, local_method = local_fields[2], local_fields[3]
        local_crc, local_csize, local_usize = local_fields[6], local_fields[7], local_fields[8]
        local_name_len, extra_len = local_fields[9], local_fields[10]
        if local_flags != flags or local_method != method or (local_flags & 0x0001):
            return "VALID_WQW", "LOCAL_CENTRAL_MISMATCH", None, total, member_names
        if not (flags & 0x0008) and (local_crc != crc or local_csize != csize or local_usize != usize):
            return "VALID_WQW", "LOCAL_SIZE_CRC_MISMATCH", None, total, member_names
        raw_local_name = accessor.read_range(entry, adjusted + _LOCAL_FIXED, local_name_len, chain)
        try:
            local_name = _decode_name(raw_local_name, local_flags).replace("\\", "/")
        except UnicodeError:
            return "VALID_WQW", "LOCAL_NAME_UNDECODABLE", None, total, member_names
        if local_name.casefold() != name.casefold():
            return "VALID_WQW", "LOCAL_NAME_MISMATCH", None, total, member_names
        data_offset = adjusted + _LOCAL_FIXED + local_name_len + extra_len
        if data_offset + csize > size:
            return "VALID_WQW", "SHORT_MEMBER_RANGE", None, total, member_names
        compressed = accessor.read_range(entry, data_offset, csize, chain)
        try:
            payload = compressed if method == 0 else _bounded_inflate(compressed, usize)
            if method == 0 and len(payload) != usize:
                return "VALID_WQW", "CONTROL_SIZE_MISMATCH", None, total, member_names
        except (ValueError, zlib.error):
            return "VALID_WQW", "DECOMPRESSION_INVALID", None, total, member_names
        if (binascii.crc32(payload) & 0xFFFFFFFF) != crc:
            return "VALID_WQW", "CRC_MISMATCH", None, total, member_names
        return "VALID_WQW", "VERIFIED", payload, total, member_names
    except CatalogueImageLabError:
        raise
    except Exception:
        return "PARSE_ERROR", "CONTROL_UNAVAILABLE", None, None, set()


def _catalogue_control(accessor: _FatAccessor, code: str, entry: FatEntry | None) -> tuple[CatalogueControl, set[str]]:
    if entry is None:
        return CatalogueControl(
            code=code, path=f"{code}/{code}.DAT", container_status="MISSING", control_status="CONTROL_UNAVAILABLE",
            control_sha256=None, file_size_bytes=0, declared_member_count=None, record_count=None,
            valid_record_count=None, malformed_record_count=None, unique_rom_name_count=None,
        ), set()
    container, status, payload, members, member_names = _read_wqw_control(accessor, entry, "filelist.txt")
    parsed = {}
    roms: set[str] = set()
    digest = None
    if payload is not None:
        digest = hashlib.sha256(payload).hexdigest()
        parsed, roms = _parse_filelist(payload, member_names)
    return CatalogueControl(
        code=code,
        path=entry.path,
        container_status=container,
        control_status=status,
        control_sha256=digest,
        file_size_bytes=entry.size_bytes,
        declared_member_count=members,
        record_count=parsed.get("record_count"),
        valid_record_count=parsed.get("valid_record_count"),
        malformed_record_count=parsed.get("malformed_record_count"),
        unique_rom_name_count=parsed.get("unique_rom_name_count"),
    ), roms


def _root_control(accessor: _FatAccessor, entry: FatEntry | None) -> tuple[RootControl, dict[str, set[str]]]:
    if entry is None:
        return RootControl("ROOT.DAT", "MISSING", "CONTROL_UNAVAILABLE", None, None, None, None, 0), {}
    normalized = FatEntry("ROOT.DAT", entry.size_bytes, entry.start_cluster, False)
    container, status, payload, _members, _member_names = _read_wqw_control(accessor, normalized, "fileinfo.txt")
    parsed = {}
    paths: dict[str, set[str]] = {}
    digest = None
    if payload is not None:
        digest = hashlib.sha256(payload).hexdigest()
        parsed, paths = _parse_fileinfo(payload)
    return RootControl(
        path="ROOT.DAT",
        container_status=container,
        control_status=status,
        control_sha256=digest,
        record_count=parsed.get("record_count"),
        valid_record_count=parsed.get("valid_record_count"),
        malformed_record_count=parsed.get("malformed_record_count"),
        code_count=len(paths),
    ), paths


def _snapshot(image_path, *, progress=None, cancelled=None) -> tuple[CatalogueImageSnapshot, dict[str, set[str]], dict[str, set[str]]]:
    path = _validate_image(image_path)
    initial = path.stat()
    with path.open("rb", buffering=0) as handle:
        opened = os.fstat(handle.fileno())
        geometry = _parse_geometry(handle, opened.st_size)
        catalogues, root_entry = _locate_catalogues(handle, geometry, cancelled=cancelled)
        accessor = _FatAccessor(handle, geometry, cancelled=cancelled)
        controls = []
        catalogue_names: dict[str, set[str]] = {}
        if progress:
            progress(f"{path.name}: reading ROOT.DAT control only...")
        root, root_paths = _root_control(accessor, root_entry)
        for code_num in range(15):
            if cancelled and cancelled():
                raise CatalogueImageLabError("Catalogue comparison cancelled; no report was written.")
            code = f"{code_num:03d}"
            if progress:
                progress(f"{path.name}: catalogue {code} — central directory + filelist.txt only...")
            control, names = _catalogue_control(accessor, code, catalogues.get(code))
            controls.append(control)
            catalogue_names[code] = names
        final_handle = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            final_handle.st_dev, final_handle.st_ino, final_handle.st_size, final_handle.st_mtime_ns
        ):
            raise CatalogueImageLabError(f"Input image changed during catalogue inspection: {path.name}")
    final_path = path.stat()
    if initial.st_size != final_path.st_size or initial.st_mtime_ns != final_path.st_mtime_ns:
        raise CatalogueImageLabError(f"Input image pathname changed during catalogue inspection: {path.name}")
    if initial.st_ino and final_path.st_ino and (initial.st_dev, initial.st_ino) != (final_path.st_dev, final_path.st_ino):
        raise CatalogueImageLabError(f"Input image pathname was replaced during catalogue inspection: {path.name}")
    snap = CatalogueImageSnapshot(
        image_path=str(path),
        image_size_bytes=geometry.image_size_bytes,
        partition_offset_bytes=geometry.partition_offset_bytes,
        catalogue_controls=tuple(controls),
        root_control=root,
        bytes_read_for_fat=geometry.fat_size_sectors * geometry.bytes_per_sector,
        bytes_read_for_controls=max(0, accessor.bytes_read - geometry.fat_size_sectors * geometry.bytes_per_sector),
    )
    return snap, root_paths, catalogue_names


def _safe_write_report(path: Path, payload: dict, protected_images: tuple[Path, Path]) -> None:
    target = path.resolve(strict=False)
    protected = {os.path.normcase(str(p.resolve(strict=True))) for p in protected_images}
    if os.path.normcase(str(target)) in protected:
        raise CatalogueImageLabError("Refusing to replace an input image with a catalogue report.")
    if target.suffix.lower() != ".json":
        raise CatalogueImageLabError("Catalogue report destination must end in .json")
    if not target.parent.exists() or not target.parent.is_dir():
        raise CatalogueImageLabError(f"Report destination directory does not exist: {target.parent}")
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def compare_catalogue_controls(
    image_a,
    image_b,
    *,
    report_path=None,
    progress: ProgressCallback | None = None,
    cancelled: CancelledCallback | None = None,
) -> CatalogueComparisonResult:
    a_path = _validate_image(image_a)
    b_path = _validate_image(image_b)
    if os.path.normcase(str(a_path)) == os.path.normcase(str(b_path)):
        raise CatalogueImageLabError("Select two different image files.")
    a, a_root_paths, a_catalogue_names = _snapshot(a_path, progress=progress, cancelled=cancelled)
    b, b_root_paths, b_catalogue_names = _snapshot(b_path, progress=progress, cancelled=cancelled)

    deltas: list[CatalogueDelta] = []
    differing: list[str] = []
    byte_only: list[str] = []
    damaged: list[str] = []
    identical = 0
    for ac, bc in zip(a.catalogue_controls, b.catalogue_controls):
        code = ac.code
        healthy = ac.control_status == "VERIFIED" and bc.control_status == "VERIFIED"
        a_names = a_catalogue_names.get(code, set())
        b_names = b_catalogue_names.get(code, set())
        only_a_all = sorted(a_names - b_names, key=str.casefold)
        only_b_all = sorted(b_names - a_names, key=str.casefold)
        truncated = len(only_a_all) > _MAX_DIFF_NAMES or len(only_b_all) > _MAX_DIFF_NAMES
        if not healthy:
            status = "DAMAGED_OR_UNREADABLE"
            damaged.append(code)
        elif ac.control_sha256 == bc.control_sha256:
            status = "IDENTICAL"
            identical += 1
        elif a_names == b_names:
            status = "CONTROL_BYTES_DIFFER_LIST_SAME"
            byte_only.append(code)
        else:
            status = "CATALOGUE_LIST_DIFFERENT"
            differing.append(code)
        deltas.append(CatalogueDelta(
            code=code,
            status=status,
            image_a_control_status=ac.control_status,
            image_b_control_status=bc.control_status,
            image_a_unique_rom_count=ac.unique_rom_name_count,
            image_b_unique_rom_count=bc.unique_rom_name_count,
            only_in_a_count=len(only_a_all),
            only_in_b_count=len(only_b_all),
            only_in_a_roms=tuple(only_a_all[:_MAX_DIFF_NAMES]),
            only_in_b_roms=tuple(only_b_all[:_MAX_DIFF_NAMES]),
            names_truncated=truncated,
        ))

    root_codes = sorted(set(a_root_paths) | set(b_root_paths), key=str.casefold)
    root_changed = tuple(
        code for code in root_codes if a_root_paths.get(code, set()) != b_root_paths.get(code, set())
    )
    if a.root_control.control_status != "VERIFIED" or b.root_control.control_status != "VERIFIED":
        root_status = "DAMAGED_OR_UNREADABLE"
    elif a.root_control.control_sha256 == b.root_control.control_sha256:
        root_status = "IDENTICAL"
    elif not root_changed:
        root_status = "CONTROL_BYTES_DIFFER_PATHS_SAME"
    else:
        root_status = "GLOBAL_CATALOGUE_DIFFERENT"

    if damaged or root_status == "DAMAGED_OR_UNREADABLE":
        status = "CATALOGUE_DAMAGE_OR_UNREADABLE"
    elif differing or root_status not in {"IDENTICAL", "CONTROL_BYTES_DIFFER_PATHS_SAME"}:
        status = "CATALOGUE_CONTENT_DIFFERENCE"
    elif root_status == "CONTROL_BYTES_DIFFER_PATHS_SAME" or byte_only:
        status = "CATALOGUE_BYTES_DIFFER_LOGIC_MATCHES"
    else:
        status = "CATALOGUES_IDENTICAL"

    result = CatalogueComparisonResult(
        status=status,
        image_a=a,
        image_b=b,
        catalogue_count=15,
        identical_catalogue_count=identical,
        differing_catalogue_count=len(differing),
        byte_only_catalogue_count=len(byte_only),
        damaged_or_unreadable_count=len(damaged),
        differing_catalogue_codes=tuple(differing),
        byte_only_catalogue_codes=tuple(byte_only),
        damaged_or_unreadable_codes=tuple(damaged),
        deltas=tuple(deltas),
        root_fileinfo_status=root_status,
        root_fileinfo_codes_changed=root_changed,
        report_path=str(Path(report_path).resolve(strict=False)) if report_path else None,
        created_at_utc=_utc_now(),
    )
    if report_path:
        payload = asdict(result)
        payload["schema"] = "gamestick-catalogue-image-compare-v1"
        payload["read_policy"] = {
            "full_image_payload_scan_performed": False,
            "rom_payloads_read": False,
            "dat_member_payloads_read": ["filelist.txt", "fileinfo.txt"],
            "input_images_opened_read_only": True,
            "source_writes_performed": False,
            "catalogue_difference_names_bounded_per_side": _MAX_DIFF_NAMES,
        }
        _safe_write_report(Path(report_path), payload, (a_path, b_path))
    return result
