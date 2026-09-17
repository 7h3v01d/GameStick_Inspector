from __future__ import annotations

import binascii
import hashlib
import json
import os
import struct
import tempfile
import zipfile
import zlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Optional

from .catalogue_image_lab import (
    CatalogueImageLabError,
    _FatAccessor,
    _locate_catalogues,
    _read_wqw_control,
)
from .fast_image_lab import FatEntry, _parse_geometry, _validate_image
from .wqw import _bounded_inflate, _decode_name

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
_MAX_QUERY_MATCHES = 50
_SCHEMA = "gamestick-customization-workspace-v1"


class RomCustomizationError(RuntimeError):
    """Raised when a host-side ROM customisation workspace cannot be created safely."""


@dataclass(frozen=True)
class PatchRange:
    offset: int
    length: int
    payload_member: str
    original_sha256: str
    replacement_sha256: str


@dataclass(frozen=True)
class PatchedFile:
    path: str
    file_size_bytes: int
    cluster_count: int
    target_chain_sha256: str
    source_control_sha256: str
    replacement_control_sha256: str
    patches: tuple[PatchRange, ...]


@dataclass(frozen=True)
class HideRomWorkspaceResult:
    workspace_path: str
    workspace_sha256: str
    workspace_size_bytes: int
    catalogue_code: str
    rom_filename: str
    catalogue_records_removed: int
    root_records_removed: int
    patched_file_count: int
    patch_payload_bytes: int
    source_writes_performed: bool
    created_at_utc: str


@dataclass(frozen=True)
class _ControlLayout:
    control_name: str
    entry: FatEntry
    chain: tuple[int, ...]
    flags: int
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int
    local_name: bytes
    local_extra: bytes
    local_fixed: bytes
    central_offset: int
    central_fixed: bytes
    payload: bytes


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _chain_sha256(chain: tuple[int, ...]) -> str:
    h = hashlib.sha256()
    for cluster in chain:
        h.update(int(cluster).to_bytes(4, "little", signed=False))
    return h.hexdigest()


def _compress_raw_deflate(payload: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
    return compressor.compress(payload) + compressor.flush()


def _read_control_layout(accessor: _FatAccessor, entry: FatEntry, control_name: str) -> _ControlLayout:
    size = entry.size_bytes
    if size < _EOCD_FIXED:
        raise RomCustomizationError(f"{entry.path} is too small to be a WQW container.")
    chain = accessor.chain_for(entry)
    tail_size = min(size, _EOCD_FIXED + _MAX_COMMENT)
    tail = accessor.read_range(entry, size - tail_size, tail_size, chain)
    before = len(tail)
    eocd_index = -1
    eocd = None
    while before > 0:
        candidate = tail.rfind(_EOCD, 0, before)
        if candidate < 0:
            break
        if candidate + _EOCD_FIXED <= len(tail):
            fixed = tail[candidate:candidate + _EOCD_FIXED]
            comment_len = struct.unpack("<H", fixed[20:22])[0]
            if candidate + _EOCD_FIXED + comment_len == len(tail):
                eocd_index = candidate
                eocd = fixed
                break
        before = candidate
    if eocd_index < 0 or eocd is None:
        raise RomCustomizationError(f"{entry.path} has no valid WQW end record.")

    sig, disk, cdisk, entries_disk, total, central_size, central_offset, _comment = struct.unpack(
        "<4s4H2LH", eocd
    )
    if sig != _EOCD or disk or cdisk or entries_disk != total:
        raise RomCustomizationError(f"{entry.path} has unsupported WQW archive geometry.")
    if total > _MAX_ENTRIES or central_size > _MAX_CENTRAL_BYTES:
        raise RomCustomizationError(f"{entry.path} exceeds bounded WQW metadata limits.")
    eocd_abs = size - tail_size + eocd_index
    actual_central = eocd_abs - central_size
    concat_offset = actual_central - central_offset
    if actual_central < 0 or concat_offset < 0:
        raise RomCustomizationError(f"{entry.path} has an invalid central-directory offset.")
    central = accessor.read_range(entry, actual_central, central_size, chain)

    matches = []
    position = 0
    for _ in range(total):
        if position + _CENTRAL_FIXED > len(central):
            raise RomCustomizationError(f"{entry.path} central directory is truncated.")
        fixed = central[position:position + _CENTRAL_FIXED]
        if fixed[:4] != _CENTRAL:
            raise RomCustomizationError(f"{entry.path} central directory contains an invalid record.")
        fields = struct.unpack("<4s6H3L5H2L", fixed)
        flags, method = fields[3], fields[4]
        crc, csize, usize = fields[7], fields[8], fields[9]
        name_len, extra_len, comment_len = fields[10], fields[11], fields[12]
        local_offset = fields[16]
        record_size = _CENTRAL_FIXED + name_len + extra_len + comment_len
        if position + record_size > len(central):
            raise RomCustomizationError(f"{entry.path} central record exceeds the directory boundary.")
        raw_name = central[position + _CENTRAL_FIXED:position + _CENTRAL_FIXED + name_len]
        try:
            name = _decode_name(raw_name, flags).replace("\\", "/")
        except UnicodeError as exc:
            raise RomCustomizationError(f"{entry.path} contains an undecodable WQW member name.") from exc
        normalized = name.strip("/").casefold()
        if "/" not in normalized and normalized == control_name.casefold():
            matches.append((
                flags, method, crc, csize, usize, int(local_offset) + int(concat_offset),
                actual_central + position, fixed,
            ))
        position += record_size
    if position != central_size:
        raise RomCustomizationError(f"{entry.path} central directory has trailing structural data.")
    if len(matches) != 1:
        raise RomCustomizationError(
            f"{entry.path} must contain exactly one canonical {control_name}; found {len(matches)}."
        )

    flags, method, crc, csize, usize, local_offset, central_abs, central_fixed = matches[0]
    if flags & 0x0001:
        raise RomCustomizationError(f"{entry.path}:{control_name} is encrypted; customisation is unsupported.")
    if flags & 0x0008:
        raise RomCustomizationError(
            f"{entry.path}:{control_name} uses a data descriptor; fixed-slot patching is intentionally disabled."
        )
    if method not in (0, 8):
        raise RomCustomizationError(f"{entry.path}:{control_name} uses unsupported compression method {method}.")
    if csize > _MAX_CONTROL_COMPRESSED or usize > _MAX_CONTROL_UNCOMPRESSED:
        raise RomCustomizationError(f"{entry.path}:{control_name} exceeds bounded control limits.")
    if local_offset < 0 or local_offset + _LOCAL_FIXED > size:
        raise RomCustomizationError(f"{entry.path}:{control_name} local header offset is invalid.")

    local_fixed = accessor.read_range(entry, local_offset, _LOCAL_FIXED, chain)
    if local_fixed[:4] != _LOCAL:
        raise RomCustomizationError(f"{entry.path}:{control_name} local header is invalid.")
    local_fields = struct.unpack("<4s5H3L2H", local_fixed)
    local_flags, local_method = local_fields[2], local_fields[3]
    local_crc, local_csize, local_usize = local_fields[6], local_fields[7], local_fields[8]
    name_len, extra_len = local_fields[9], local_fields[10]
    if (local_flags, local_method, local_crc, local_csize, local_usize) != (flags, method, crc, csize, usize):
        raise RomCustomizationError(f"{entry.path}:{control_name} local/central metadata does not match.")
    raw_local_name = accessor.read_range(entry, local_offset + _LOCAL_FIXED, name_len, chain)
    try:
        local_name_text = _decode_name(raw_local_name, flags).replace("\\", "/")
    except UnicodeError as exc:
        raise RomCustomizationError(f"{entry.path}:{control_name} local name is undecodable.") from exc
    if local_name_text.strip("/").casefold() != control_name.casefold():
        raise RomCustomizationError(f"{entry.path}:{control_name} local member name does not match central metadata.")
    local_extra = accessor.read_range(entry, local_offset + _LOCAL_FIXED + name_len, extra_len, chain)
    compressed = accessor.read_range(
        entry, local_offset + _LOCAL_FIXED + name_len + extra_len, csize, chain
    )
    try:
        payload = compressed if method == 0 else _bounded_inflate(compressed, usize)
    except (ValueError, zlib.error) as exc:
        raise RomCustomizationError(f"{entry.path}:{control_name} cannot be decompressed safely.") from exc
    if len(payload) != usize or (binascii.crc32(payload) & 0xFFFFFFFF) != crc:
        raise RomCustomizationError(f"{entry.path}:{control_name} failed CRC/size verification.")

    return _ControlLayout(
        control_name=control_name,
        entry=entry,
        chain=chain,
        flags=flags,
        method=method,
        crc32=crc,
        compressed_size=csize,
        uncompressed_size=usize,
        local_offset=local_offset,
        local_name=raw_local_name,
        local_extra=local_extra,
        local_fixed=local_fixed,
        central_offset=central_abs,
        central_fixed=central_fixed,
        payload=payload,
    )


def _build_same_slot_patches(layout: _ControlLayout, replacement_payload: bytes) -> tuple[tuple[int, bytes], ...]:
    new_crc = binascii.crc32(replacement_payload) & 0xFFFFFFFF
    if layout.method == 0:
        new_compressed = replacement_payload
    else:
        new_compressed = _compress_raw_deflate(replacement_payload)

    old_capacity = len(layout.local_extra) + layout.compressed_size
    if len(new_compressed) > old_capacity:
        raise RomCustomizationError(
            f"Updated {layout.entry.path}:{layout.control_name} needs {len(new_compressed):,} compressed bytes but "
            f"the fixed slot has {old_capacity:,}. This operation is not safe for same-slot patching."
        )
    new_extra_len = old_capacity - len(new_compressed)
    if new_extra_len > 0xFFFF:
        raise RomCustomizationError(
            f"Updated {layout.entry.path}:{layout.control_name} would require an oversized local extra field."
        )

    local_fields = list(struct.unpack("<4s5H3L2H", layout.local_fixed))
    local_fields[6] = new_crc
    local_fields[7] = len(new_compressed)
    local_fields[8] = len(replacement_payload)
    local_fields[10] = new_extra_len
    new_local_fixed = struct.pack("<4s5H3L2H", *local_fields)
    preserved_extra = layout.local_extra[:new_extra_len]
    if len(preserved_extra) < new_extra_len:
        preserved_extra += b"\x00" * (new_extra_len - len(preserved_extra))
    new_local_region = new_local_fixed + layout.local_name + preserved_extra + new_compressed

    old_local_region_len = _LOCAL_FIXED + len(layout.local_name) + old_capacity
    if len(new_local_region) != old_local_region_len:
        raise RomCustomizationError("Internal fixed-slot accounting failed for local WQW record.")

    central_fields = list(struct.unpack("<4s6H3L5H2L", layout.central_fixed))
    central_fields[7] = new_crc
    central_fields[8] = len(new_compressed)
    central_fields[9] = len(replacement_payload)
    new_central_fixed = struct.pack("<4s6H3L5H2L", *central_fields)
    return (
        (layout.local_offset, new_local_region),
        (layout.central_offset, new_central_fixed),
    )


class _OverlayAccessor:
    def __init__(self, base: _FatAccessor, patches: tuple[tuple[int, bytes], ...]):
        self.base = base
        self.patches = patches
        self.bytes_read = 0

    def chain_for(self, entry: FatEntry):
        return self.base.chain_for(entry)

    def read_range(self, entry: FatEntry, offset: int, length: int, chain=None):
        raw = bytearray(self.base.read_range(entry, offset, length, chain))
        self.bytes_read += length
        end = offset + length
        for patch_offset, patch_data in self.patches:
            patch_end = patch_offset + len(patch_data)
            overlap_start = max(offset, patch_offset)
            overlap_end = min(end, patch_end)
            if overlap_start >= overlap_end:
                continue
            raw_start = overlap_start - offset
            patch_start = overlap_start - patch_offset
            raw[raw_start:raw_start + (overlap_end - overlap_start)] = patch_data[
                patch_start:patch_start + (overlap_end - overlap_start)
            ]
        return bytes(raw)


def _filter_filelist(payload: bytes, rom_filename: str) -> tuple[bytes, int]:
    target = PurePosixPath(rom_filename.replace("\\", "/")).name.casefold()
    out: list[bytes] = []
    removed = 0
    for line in payload.splitlines(keepends=True):
        body = line.rstrip(b"\r\n")
        first = body.split(b";", 1)[0]
        try:
            name = PurePosixPath(first.decode("utf-8", errors="strict").replace("\\", "/")).name.casefold()
        except UnicodeDecodeError:
            name = ""
        if name == target:
            removed += 1
            continue
        out.append(line)
    return b"".join(out), removed


def _filter_fileinfo(payload: bytes, code: str, rom_filename: str) -> tuple[bytes, int]:
    target = PurePosixPath(rom_filename.replace("\\", "/")).name.casefold()
    out: list[bytes] = []
    removed = 0
    for line in payload.splitlines(keepends=True):
        body = line.rstrip(b"\r\n")
        first = body.split(b";", 1)[0]
        text = None
        for encoding in ("utf-8", "gbk"):
            try:
                text = first.decode(encoding, errors="strict")
                break
            except UnicodeDecodeError:
                continue
        if text is not None:
            normalized = text.replace("\\", "/").strip("/")
            parts = normalized.split("/", 1)
            if len(parts) == 2 and parts[0] == code and PurePosixPath(parts[1]).name.casefold() == target:
                removed += 1
                continue
        out.append(line)
    return b"".join(out), removed


def _rom_names(payload: bytes) -> list[str]:
    names: list[str] = []
    for line in payload.splitlines():
        if not line:
            continue
        first = line.split(b";", 1)[0]
        try:
            name = PurePosixPath(first.decode("utf-8", errors="strict").replace("\\", "/")).name
        except UnicodeDecodeError:
            continue
        if name:
            names.append(name)
    return names


def _resolve_rom(accessor: _FatAccessor, catalogues: dict[str, FatEntry], query: str) -> tuple[str, str, _ControlLayout]:
    text = query.strip()
    if not text:
        raise RomCustomizationError("Enter a ROM filename or distinctive title fragment.")
    explicit_code: Optional[str] = None
    if len(text) > 4 and text[:3].isdigit() and text[3] == ":":
        explicit_code = text[:3]
        text = text[4:].strip()
    needle = PurePosixPath(text.replace("\\", "/")).name.casefold()
    exact: list[tuple[str, str, _ControlLayout]] = []
    partial: list[tuple[str, str, _ControlLayout]] = []
    for code in sorted(catalogues):
        if explicit_code is not None and code != explicit_code:
            continue
        entry = catalogues[code]
        layout = _read_control_layout(accessor, entry, "filelist.txt")
        for name in _rom_names(layout.payload):
            folded = name.casefold()
            if folded == needle:
                exact.append((code, name, layout))
            elif needle and needle in folded:
                partial.append((code, name, layout))
    matches = exact if exact else partial
    # Collapse exact duplicate records inside a single catalogue to one candidate.
    unique: dict[tuple[str, str], tuple[str, str, _ControlLayout]] = {}
    for item in matches:
        unique[(item[0], item[1].casefold())] = item
    matches = list(unique.values())
    if not matches:
        raise RomCustomizationError(f"No catalogue ROM matched {query!r}.")
    if len(matches) != 1:
        preview = ", ".join(f"{code}:{name}" for code, name, _ in matches[:_MAX_QUERY_MATCHES])
        suffix = " ..." if len(matches) > _MAX_QUERY_MATCHES else ""
        raise RomCustomizationError(
            f"ROM query is ambiguous ({len(matches)} matches). Use CODE:filename, for example 003:Solitaire.zip. "
            f"Matches: {preview}{suffix}"
        )
    return matches[0]


def _make_patch_records(
    path: str,
    entry: FatEntry,
    chain: tuple[int, ...],
    source_control: bytes,
    replacement_control: bytes,
    raw_patches: tuple[tuple[int, bytes], ...],
    accessor: _FatAccessor,
    member_prefix: str,
) -> tuple[PatchedFile, dict[str, bytes]]:
    payloads: dict[str, bytes] = {}
    records: list[PatchRange] = []
    for index, (offset, replacement) in enumerate(raw_patches):
        original = accessor.read_range(entry, offset, len(replacement), chain)
        member = f"patches/{member_prefix}/{index:02d}.bin"
        payloads[member] = replacement
        records.append(PatchRange(
            offset=offset,
            length=len(replacement),
            payload_member=member,
            original_sha256=_sha256(original),
            replacement_sha256=_sha256(replacement),
        ))
    return PatchedFile(
        path=path,
        file_size_bytes=entry.size_bytes,
        cluster_count=len(chain),
        target_chain_sha256=_chain_sha256(chain),
        source_control_sha256=_sha256(source_control),
        replacement_control_sha256=_sha256(replacement_control),
        patches=tuple(records),
    ), payloads


def _safe_output_path(output_path, source_image: Path, *, overwrite: bool) -> Path:
    target = Path(output_path).expanduser().resolve(strict=False)
    if os.path.normcase(str(target)) == os.path.normcase(str(source_image.resolve(strict=True))):
        raise RomCustomizationError("Refusing to replace the source image with a customisation workspace.")
    if target.suffix.casefold() != ".gscustom":
        raise RomCustomizationError("Customisation workspace destination must end in .gscustom")
    parent = target.parent.resolve(strict=True)
    if not parent.is_dir():
        raise RomCustomizationError(f"Customisation destination directory is not a directory: {parent}")
    if target.exists():
        if target.is_dir() or target.is_symlink():
            raise RomCustomizationError("Refusing to replace a directory or symlink as customisation output.")
        if not overwrite:
            raise RomCustomizationError(f"Customisation workspace already exists: {target}")
    return target


def _archive_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def build_hide_rom_workspace(
    source_image,
    rom_query: str,
    output_path,
    *,
    overwrite: bool = False,
    progress: ProgressCallback | None = None,
    cancelled: CancelledCallback | None = None,
) -> HideRomWorkspaceResult:
    image = _validate_image(source_image)
    target = _safe_output_path(output_path, image, overwrite=overwrite)
    initial = image.stat()
    created = _utc_now()

    with image.open("rb", buffering=0) as handle:
        opened = os.fstat(handle.fileno())
        geometry = _parse_geometry(handle, opened.st_size)
        catalogues, root_entry = _locate_catalogues(handle, geometry, cancelled=cancelled)
        if root_entry is None:
            raise RomCustomizationError("ROOT.DAT is missing from the source image.")
        accessor = _FatAccessor(handle, geometry, cancelled=cancelled)
        if progress:
            progress("Searching verified catalogue controls for the requested ROM...")
        code, rom_name, catalogue_layout = _resolve_rom(accessor, catalogues, rom_query)
        if cancelled and cancelled():
            raise RomCustomizationError("Customisation cancelled; no workspace was written.")

        if progress:
            progress(f"{code}:{rom_name} found. Building fixed-slot catalogue + ROOT control patches...")
        new_filelist, catalogue_removed = _filter_filelist(catalogue_layout.payload, rom_name)
        if catalogue_removed < 1:
            raise RomCustomizationError("Resolved ROM was not removable from its catalogue control.")
        catalogue_raw_patches = _build_same_slot_patches(catalogue_layout, new_filelist)
        catalogue_overlay = _OverlayAccessor(accessor, catalogue_raw_patches)
        container, status, verified_filelist, _total, _members = _read_wqw_control(
            catalogue_overlay, catalogue_layout.entry, "filelist.txt"
        )
        if container != "VALID_WQW" or status != "VERIFIED" or verified_filelist != new_filelist:
            raise RomCustomizationError("Virtual verification of the patched catalogue failed.")
        remaining_names = {name.casefold() for name in _rom_names(verified_filelist)}
        if rom_name.casefold() in remaining_names:
            raise RomCustomizationError("Patched catalogue still contains the selected ROM.")

        root_layout = _read_control_layout(accessor, root_entry, "fileinfo.txt")
        new_fileinfo, root_removed = _filter_fileinfo(root_layout.payload, code, rom_name)
        if root_removed < 1:
            raise RomCustomizationError(
                f"ROOT.DAT contains no {code}/{rom_name} record. Refusing to create a half-synchronised customisation."
            )
        root_raw_patches = _build_same_slot_patches(root_layout, new_fileinfo)
        root_overlay = _OverlayAccessor(accessor, root_raw_patches)
        container, status, verified_fileinfo, _total, _members = _read_wqw_control(
            root_overlay, root_layout.entry, "fileinfo.txt"
        )
        if container != "VALID_WQW" or status != "VERIFIED" or verified_fileinfo != new_fileinfo:
            raise RomCustomizationError("Virtual verification of patched ROOT.DAT failed.")
        _, root_after = _filter_fileinfo(verified_fileinfo, code, rom_name)
        if root_after:
            raise RomCustomizationError("Patched ROOT.DAT still contains the selected ROM.")

        catalogue_file, catalogue_payloads = _make_patch_records(
            catalogue_layout.entry.path,
            catalogue_layout.entry,
            catalogue_layout.chain,
            catalogue_layout.payload,
            new_filelist,
            catalogue_raw_patches,
            accessor,
            f"{code}_catalogue",
        )
        root_file, root_payloads = _make_patch_records(
            "ROOT.DAT",
            root_layout.entry,
            root_layout.chain,
            root_layout.payload,
            new_fileinfo,
            root_raw_patches,
            accessor,
            "root",
        )
        final_handle = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            final_handle.st_dev, final_handle.st_ino, final_handle.st_size, final_handle.st_mtime_ns
        ):
            raise RomCustomizationError("Source image changed while customisation workspace was being built.")

    final = image.stat()
    if initial.st_size != final.st_size or initial.st_mtime_ns != final.st_mtime_ns:
        raise RomCustomizationError("Source image pathname changed while customisation workspace was being built.")

    payloads = {**catalogue_payloads, **root_payloads}
    patched_files = (catalogue_file, root_file)
    manifest = {
        "schema": _SCHEMA,
        "created_at_utc": created,
        "action": "HIDE_ROM_FROM_LAUNCHER",
        "source_image": {
            "name": image.name,
            "size_bytes": initial.st_size,
            "partition_offset_bytes": geometry.partition_offset_bytes,
        },
        "rom": {
            "catalogue_code": code,
            "filename": rom_name,
            "catalogue_records_removed": catalogue_removed,
            "root_records_removed": root_removed,
            "physical_rom_file_removed": False,
        },
        "patched_files": [
            {
                **{k: v for k, v in asdict(item).items() if k != "patches"},
                "patches": [asdict(patch) for patch in item.patches],
            }
            for item in patched_files
        ],
        "safety": {
            "source_image_opened_read_only": True,
            "source_writes_performed": False,
            "game_stick_write_performed": False,
            "physical_rom_payload_removed": False,
            "workspace_contains_only_control_metadata_patches": True,
            "future_apply_must_revalidate_control_hashes_chain_hashes_and_original_patch_bytes": True,
        },
    }

    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        if progress:
            progress(f"Writing tiny host-side customisation workspace ({sum(len(v) for v in payloads.values()):,} patch bytes)...")
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            for member, data in sorted(payloads.items()):
                archive.writestr(member, data)
        with zipfile.ZipFile(temp, "r") as archive:
            loaded = json.loads(archive.read("manifest.json").decode("utf-8"))
            if loaded.get("schema") != _SCHEMA:
                raise RomCustomizationError("Created customisation workspace manifest verification failed.")
            for item in patched_files:
                for patch in item.patches:
                    data = archive.read(patch.payload_member)
                    if len(data) != patch.length or _sha256(data) != patch.replacement_sha256:
                        raise RomCustomizationError(f"Created patch payload verification failed: {patch.payload_member}")
        os.replace(temp, target)
    except Exception:
        temp.unlink(missing_ok=True)
        raise

    return HideRomWorkspaceResult(
        workspace_path=str(target),
        workspace_sha256=_archive_sha256(target),
        workspace_size_bytes=target.stat().st_size,
        catalogue_code=code,
        rom_filename=rom_name,
        catalogue_records_removed=catalogue_removed,
        root_records_removed=root_removed,
        patched_file_count=len(patched_files),
        patch_payload_bytes=sum(len(v) for v in payloads.values()),
        source_writes_performed=False,
        created_at_utc=created,
    )
