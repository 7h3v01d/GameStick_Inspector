from __future__ import annotations

import binascii
import os
import stat
import struct
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Set, Tuple

from .fs_safety import ForensicPathError, lstat_non_reparse
from .models import DatContainerEvidence

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
_MAX_CONTROL_RECORDS = 100_000
_MAX_CONTROL_LINE_BYTES = 32 * 1024
_NAME_XOR = 0xE5
_CONTROL_NAMES = {"fileinfo.txt", "filelist.txt"}
_SAFE_EXTS = frozenset({".txt", ".raw", ".dat", ".cfg", ".ini", ".xml", ".json", ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"})
_METHODS = {0: "stored", 8: "deflate"}


def wqw_limits() -> Dict[str, int]:
    return {
        "max_central_directory_bytes": _MAX_CENTRAL_BYTES,
        "max_central_entries": _MAX_ENTRIES,
        "max_control_compressed_bytes": _MAX_CONTROL_COMPRESSED,
        "max_control_uncompressed_bytes": _MAX_CONTROL_UNCOMPRESSED,
        "max_control_records": _MAX_CONTROL_RECORDS,
        "max_control_line_bytes": _MAX_CONTROL_LINE_BYTES,
    }


@dataclass(frozen=True)
class _Entry:
    name: str
    flags: int
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int


@dataclass
class WqwPrivateEvidence:
    entries: List[_Entry] = field(default_factory=list)
    filelist_rom_names: Set[str] = field(default_factory=set)
    fileinfo_paths_by_code: Dict[str, Set[str]] = field(default_factory=dict)
    # Internal-only byte ranges used by the read-stability auditor. These
    # offsets/lengths and their sampled bytes are never serialized into probe
    # evidence; only aggregate stability results leave the process.
    stability_regions: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    # Canonical control-member validation outcomes used only to qualify the
    # repeated-read stability result. Names are fixed allowlisted semantics.
    control_read_statuses: Dict[str, str] = field(default_factory=dict)


def _decode_name(raw: bytes, flags: int) -> str:
    decoded = bytes(value ^ _NAME_XOR for value in raw)
    encoding = "utf-8" if (flags & 0x0800) else "cp437"
    return decoded.decode(encoding, errors="strict")


def _safe_ext(name: str) -> str:
    suffix = PurePosixPath(PurePosixPath(name.replace("\\", "/")).name).suffix.casefold()
    if not suffix:
        return "<none>"
    return suffix if suffix in _SAFE_EXTS else "<other>"


def _sanitized_error(exc: BaseException) -> Dict[str, object]:
    result: Dict[str, object] = {"wqw_error_type": type(exc).__name__}
    if isinstance(exc, OSError) and isinstance(exc.errno, int):
        result["wqw_error_errno"] = exc.errno
    return result


def _bounded_inflate(raw: bytes, expected_size: int) -> bytes:
    if expected_size > _MAX_CONTROL_UNCOMPRESSED:
        raise ValueError("control-output-limit")
    inflater = zlib.decompressobj(-15)
    output = bytearray()
    pending = raw
    while pending:
        remaining = _MAX_CONTROL_UNCOMPRESSED - len(output)
        if remaining < 0:
            raise ValueError("control-output-limit")
        before = len(pending)
        chunk = inflater.decompress(pending, remaining + 1)
        output.extend(chunk)
        if len(output) > _MAX_CONTROL_UNCOMPRESSED:
            raise ValueError("control-output-limit")
        pending = inflater.unconsumed_tail
        if pending and len(pending) >= before and not chunk:
            raise ValueError("control-deflate-stalled")
        if not pending:
            break
    # Drain any output buffered because max_length was reached, still under the cap.
    while not inflater.eof:
        remaining = _MAX_CONTROL_UNCOMPRESSED - len(output)
        if remaining < 0:
            raise ValueError("control-output-limit")
        chunk = inflater.decompress(b"", remaining + 1)
        if not chunk:
            break
        output.extend(chunk)
        if len(output) > _MAX_CONTROL_UNCOMPRESSED:
            raise ValueError("control-output-limit")
    if not inflater.eof:
        raise ValueError("control-deflate-incomplete")
    if inflater.unused_data:
        raise ValueError("control-deflate-trailing-data")
    if len(output) != expected_size:
        raise ValueError("control-size-mismatch")
    return bytes(output)



def _read_member(path: Path, entry: _Entry, *, concat_offset: int, size: int) -> Tuple[Optional[bytes], Dict[str, object]]:
    summary: Dict[str, object] = {
        "compression_method": _METHODS.get(entry.method, f"method-{entry.method}"),
        "compressed_size": entry.compressed_size,
        "uncompressed_size": entry.uncompressed_size,
        "crc32_verified": False,
    }
    if entry.flags & 0x0001:
        summary["read_status"] = "encrypted-unsupported"
        return None, summary
    if entry.method not in {0, 8}:
        summary["read_status"] = "compression-unsupported"
        return None, summary
    if entry.compressed_size > _MAX_CONTROL_COMPRESSED or entry.uncompressed_size > _MAX_CONTROL_UNCOMPRESSED:
        summary["read_status"] = "control-size-limit"
        return None, summary
    local_offset = entry.local_offset + concat_offset
    try:
        with path.open("rb") as handle:
            if local_offset < 0 or local_offset + _LOCAL_FIXED > size:
                summary["read_status"] = "invalid-local-offset"
                return None, summary
            handle.seek(local_offset)
            fixed = handle.read(_LOCAL_FIXED)
            if len(fixed) != _LOCAL_FIXED or fixed[:4] != _LOCAL:
                summary["read_status"] = "invalid-local-header"
                return None, summary
            fields = struct.unpack("<4s5H3L2H", fixed)
            flags = fields[2]
            method = fields[3]
            local_crc = fields[6]
            local_compressed_size = fields[7]
            local_uncompressed_size = fields[8]
            name_len = fields[9]
            extra_len = fields[10]
            if method != entry.method or flags != entry.flags or (flags & 0x0001):
                summary["read_status"] = "local-central-mismatch"
                return None, summary
            if not (flags & 0x0008) and (
                local_crc != entry.crc32
                or local_compressed_size != entry.compressed_size
                or local_uncompressed_size != entry.uncompressed_size
            ):
                summary["read_status"] = "local-central-size-crc-mismatch"
                return None, summary
            raw_name = handle.read(name_len)
            local_name = _decode_name(raw_name, flags).replace("\\", "/")
            if local_name.casefold() != entry.name.casefold():
                summary["read_status"] = "local-name-mismatch"
                return None, summary
            if extra_len:
                handle.seek(extra_len, os.SEEK_CUR)
            compressed = handle.read(entry.compressed_size)
            if len(compressed) != entry.compressed_size:
                summary["read_status"] = "short-member-read"
                return None, summary
    except (OSError, UnicodeError, ForensicPathError) as exc:
        summary.update(_sanitized_error(exc))
        summary["read_status"] = "unreadable"
        return None, summary

    try:
        if entry.method == 0:
            payload = compressed
            if len(payload) != entry.uncompressed_size:
                raise ValueError("control-size-mismatch")
        else:
            payload = _bounded_inflate(compressed, entry.uncompressed_size)
    except (zlib.error, ValueError):
        summary["read_status"] = "decompression-invalid"
        return None, summary
    crc_ok = (binascii.crc32(payload) & 0xFFFFFFFF) == entry.crc32
    summary["crc32_verified"] = crc_ok
    summary["read_status"] = "verified" if crc_ok else "crc-mismatch"
    return (payload if crc_ok else None), summary



def _control_data_region(path: Path, entry: _Entry, *, concat_offset: int, size: int) -> Optional[Tuple[int, int]]:
    """Return the compressed control payload region after local-header validation.

    This deliberately does *not* decompress or CRC-check the member body.  The
    stability auditor must be able to reread raw compressed control bytes even
    when those bytes are repeatably corrupt.  We still require the local record
    to corroborate the canonical central-directory entry before calling the
    range a control payload.  Offsets/lengths never leave private process state.
    """
    local_offset = entry.local_offset + concat_offset
    try:
        if local_offset < 0 or local_offset + _LOCAL_FIXED > size:
            return None
        with path.open("rb") as handle:
            handle.seek(local_offset)
            fixed = handle.read(_LOCAL_FIXED)
            if len(fixed) != _LOCAL_FIXED or fixed[:4] != _LOCAL:
                return None
            fields = struct.unpack("<4s5H3L2H", fixed)
            flags = fields[2]
            method = fields[3]
            local_crc = fields[6]
            local_compressed_size = fields[7]
            local_uncompressed_size = fields[8]
            name_len = fields[9]
            extra_len = fields[10]
            if flags != entry.flags or method != entry.method or (flags & 0x0001):
                return None
            if not (flags & 0x0008) and (
                local_crc != entry.crc32
                or local_compressed_size != entry.compressed_size
                or local_uncompressed_size != entry.uncompressed_size
            ):
                return None
            raw_name = handle.read(name_len)
            local_name = _decode_name(raw_name, flags).replace("\\", "/")
            if local_name.casefold() != entry.name.casefold():
                return None
            data_offset = local_offset + _LOCAL_FIXED + name_len + extra_len
            if data_offset < 0 or data_offset + entry.compressed_size > size:
                return None
            return int(data_offset), int(entry.compressed_size)
    except (OSError, UnicodeError, ForensicPathError):
        return None

def _parse_filelist(payload: bytes, member_names: Set[str]) -> Tuple[Dict[str, object], Set[str]]:
    valid = 0
    malformed = 0
    record_count = 0
    records_truncated = False
    roms: Set[str] = set()
    raw_artwork_members = [
        name
        for name in member_names
        if "/" not in name.replace("\\", "/") and name.casefold().endswith("_000.raw")
    ]
    artwork_stems = {PurePosixPath(name).name[:-8].casefold() for name in raw_artwork_members}
    matched_artwork = 0
    start = 0
    while start < len(payload):
        if record_count >= _MAX_CONTROL_RECORDS:
            records_truncated = True
            break
        end = payload.find(b"\n", start)
        if end < 0:
            end = len(payload)
            next_start = len(payload)
        else:
            next_start = end + 1
        row = payload[start:end]
        if row.endswith(b"\r"):
            row = row[:-1]
        start = next_start
        if not row:
            continue
        record_count += 1
        if len(row) > _MAX_CONTROL_LINE_BYTES or row.count(b";") != 2:
            malformed += 1
            continue
        fields = row.split(b";", 2)
        try:
            decoded = [field.decode("utf-8", errors="strict") for field in fields]
        except UnicodeDecodeError:
            malformed += 1
            continue
        rom_name = PurePosixPath(decoded[0].replace("\\", "/")).name
        if not rom_name:
            malformed += 1
            continue
        valid += 1
        roms.add(rom_name.casefold())
        if PurePosixPath(rom_name).stem.casefold() in artwork_stems:
            matched_artwork += 1
    return {
        "parse_schema": "filelist-semicolon-3-v1",
        "record_count": record_count,
        "valid_record_count": valid,
        "malformed_record_count": malformed,
        "expected_field_count": 3,
        "record_limit": _MAX_CONTROL_RECORDS,
        "records_truncated": records_truncated,
        "max_line_bytes": _MAX_CONTROL_LINE_BYTES,
        "unique_rom_name_count": len(roms),
        "raw_artwork_member_count": len(raw_artwork_members),
        "unique_artwork_stem_count": len(artwork_stems),
        "catalogue_records_with_artwork_count": matched_artwork,
        "arbitrary_values_exported": False,
    }, roms


def _parse_fileinfo(payload: bytes) -> Tuple[Dict[str, object], Dict[str, Set[str]]]:
    valid = 0
    malformed = 0
    record_count = 0
    records_truncated = False
    field_utf8 = [0, 0, 0, 0, 0]
    field_gbk = [0, 0, 0, 0, 0]
    field_undecodable = [0, 0, 0, 0, 0]
    paths: Dict[str, Set[str]] = {}
    code_record_counts: Counter[str] = Counter()
    start = 0
    while start < len(payload):
        if record_count >= _MAX_CONTROL_RECORDS:
            records_truncated = True
            break
        end = payload.find(b"\n", start)
        if end < 0:
            end = len(payload)
            next_start = len(payload)
        else:
            next_start = end + 1
        row = payload[start:end]
        if row.endswith(b"\r"):
            row = row[:-1]
        start = next_start
        if not row:
            continue
        record_count += 1
        if len(row) > _MAX_CONTROL_LINE_BYTES or row.count(b";") != 4:
            malformed += 1
            continue
        fields = row.split(b";", 4)
        decoded: List[str] = []
        row_ok = True
        for index, field in enumerate(fields):
            try:
                decoded.append(field.decode("utf-8", errors="strict"))
                field_utf8[index] += 1
            except UnicodeDecodeError:
                try:
                    decoded.append(field.decode("gbk", errors="strict"))
                    field_gbk[index] += 1
                except UnicodeDecodeError:
                    field_undecodable[index] += 1
                    row_ok = False
                    break
        if not row_ok:
            malformed += 1
            continue
        normalized = decoded[0].replace("\\", "/").strip("/")
        parts = normalized.split("/", 1)
        if len(parts) != 2 or len(parts[0]) != 3 or not parts[0].isdigit() or not parts[1]:
            malformed += 1
            continue
        valid += 1
        code_record_counts[parts[0]] += 1
        paths.setdefault(parts[0], set()).add(PurePosixPath(parts[1]).name.casefold())
    return {
        "parse_schema": "fileinfo-semicolon-5-mixed-v1",
        "record_count": record_count,
        "valid_record_count": valid,
        "malformed_record_count": malformed,
        "expected_field_count": 5,
        "record_limit": _MAX_CONTROL_RECORDS,
        "records_truncated": records_truncated,
        "max_line_bytes": _MAX_CONTROL_LINE_BYTES,
        "field_utf8_counts": field_utf8,
        "field_gbk_fallback_counts": field_gbk,
        "field_undecodable_counts": field_undecodable,
        "catalogue_code_record_counts": dict(sorted(code_record_counts.items())),
        "arbitrary_values_exported": False,
    }, paths


def inspect_wqw(path: Path, *, relative_path: str, role: str) -> Optional[Tuple[DatContainerEvidence, WqwPrivateEvidence]]:
    """Inspect a WQW-obfuscated ZIP container without exporting private member names."""
    try:
        st = lstat_non_reparse(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        size = int(st.st_size)
        if size < _EOCD_FIXED:
            return None
        tail_size = min(size, _EOCD_FIXED + _MAX_COMMENT)
        with path.open("rb") as handle:
            handle.seek(size - tail_size)
            tail = handle.read(tail_size)
        search_before = len(tail)
        eocd_index = -1
        eocd = b""
        comment_len = 0
        while search_before > 0:
            candidate_index = tail.rfind(_EOCD, 0, search_before)
            if candidate_index < 0:
                break
            if candidate_index + _EOCD_FIXED <= len(tail):
                candidate = tail[candidate_index:candidate_index + _EOCD_FIXED]
                candidate_comment = struct.unpack("<H", candidate[20:22])[0]
                if candidate_index + _EOCD_FIXED + candidate_comment == len(tail):
                    eocd_index = candidate_index
                    eocd = candidate
                    comment_len = candidate_comment
                    break
            search_before = candidate_index
        if eocd_index < 0:
            return None
        sig, disk, cdisk, entries_disk, total, central_size, central_offset, parsed_comment = struct.unpack("<4s4H2LH", eocd)
        if sig != _EOCD or parsed_comment != comment_len:
            return None
        if disk or cdisk or entries_disk != total:
            return None
        if total == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
            return None
        if total > _MAX_ENTRIES or central_size > _MAX_CENTRAL_BYTES:
            state = "wqw-entry-limit-exceeded" if total > _MAX_ENTRIES else "wqw-central-directory-limit-exceeded"
            evidence = DatContainerEvidence(path=relative_path, role=role, size=size, container_format=state, central_directory_valid=False, declared_member_count=total, central_directory_size=central_size, member_names_redacted=True, details={"archive_dialect": "wqw-xor-e5"})
            return evidence, WqwPrivateEvidence()
        eocd_abs = size - tail_size + eocd_index
        actual_central = eocd_abs - central_size
        concat_offset = actual_central - central_offset
        if actual_central < 0 or concat_offset < 0:
            return None
        with path.open("rb") as handle:
            handle.seek(actual_central)
            central = handle.read(central_size)
        if len(central) != central_size:
            return None

        entries: List[_Entry] = []
        position = 0
        files = directories = encrypted = undecodable = 0
        ext_counts: Counter[str] = Counter()
        methods: Counter[str] = Counter()
        controls: Dict[str, _Entry] = {}
        duplicate_controls: Set[str] = set()
        private_member_names: Set[str] = set()
        for _ in range(total):
            if position + _CENTRAL_FIXED > len(central):
                return None
            fixed = central[position:position + _CENTRAL_FIXED]
            if fixed[:4] != _CENTRAL:
                return None
            fields = struct.unpack("<4s6H3L5H2L", fixed)
            flags, method = fields[3], fields[4]
            crc, csize, usize = fields[7], fields[8], fields[9]
            name_len, extra_len, entry_comment_len = fields[10], fields[11], fields[12]
            local_offset = fields[16]
            record_size = _CENTRAL_FIXED + name_len + extra_len + entry_comment_len
            if position + record_size > len(central):
                return None
            raw_name = central[position + _CENTRAL_FIXED:position + _CENTRAL_FIXED + name_len]
            try:
                name = _decode_name(raw_name, flags).replace("\\", "/")
            except UnicodeError:
                undecodable += 1
                name = ""
            entry = _Entry(name=name, flags=flags, method=method, crc32=crc, compressed_size=csize, uncompressed_size=usize, local_offset=local_offset)
            entries.append(entry)
            if flags & 0x0001:
                encrypted += 1
            methods[_METHODS.get(method, f"method-{method}")] += 1
            if name.endswith("/"):
                directories += 1
            else:
                files += 1
                if name:
                    private_member_names.add(name)
                    ext_counts[_safe_ext(name)] += 1
                    normalized = name.strip("/").casefold()
                    if "/" not in normalized and normalized in _CONTROL_NAMES:
                        if normalized in controls:
                            duplicate_controls.add(normalized)
                        else:
                            controls[normalized] = entry
            position += record_size
        if position != central_size:
            return None

        summaries: Dict[str, object] = {}
        verified_controls: List[str] = []
        private = WqwPrivateEvidence(
            entries=entries,
            stability_regions={"central-directory": (int(actual_central), int(central_size))},
        )
        expected_control = "fileinfo.txt" if role == "global-catalog" else "filelist.txt" if role == "platform-catalog" else None
        for control_name in sorted(controls):
            region_key = f"control-{control_name}"
            if control_name in duplicate_controls:
                summaries[control_name] = {
                    "read_status": "duplicate-control-name",
                    "crc32_verified": False,
                }
                private.control_read_statuses[region_key] = "duplicate-control-name"
                continue
            control_entry = controls[control_name]
            # Locate the raw compressed member range *before* attempting
            # decompression/CRC validation.  This is what lets the repeated-read
            # auditor distinguish stable corruption from unstable media reads.
            region = _control_data_region(path, control_entry, concat_offset=concat_offset, size=size)
            if region is not None:
                private.stability_regions[region_key] = region
            payload, base_summary = _read_member(path, control_entry, concat_offset=concat_offset, size=size)
            summary = dict(base_summary)
            private.control_read_statuses[region_key] = str(summary.get("read_status", "unknown"))
            if payload is not None:
                verified_controls.append(control_name)
                if control_name == "filelist.txt":
                    parsed, roms = _parse_filelist(payload, private_member_names)
                    summary.update(parsed)
                    private.filelist_rom_names = roms
                elif control_name == "fileinfo.txt":
                    parsed, paths = _parse_fileinfo(payload)
                    summary.update(parsed)
                    private.fileinfo_paths_by_code = paths
            summaries[control_name] = summary
        if expected_control is not None and expected_control not in controls:
            private.control_read_statuses[f"control-{expected_control}"] = "control-not-found"

        evidence = DatContainerEvidence(
            path=relative_path,
            role=role,
            size=size,
            container_format="wqw-obfuscated-zip",
            central_directory_valid=True,
            declared_member_count=total,
            file_member_count=files,
            directory_member_count=directories,
            central_directory_size=central_size,
            zip_comment_length=comment_len,
            control_members=verified_controls,
            member_extension_counts=dict(sorted(ext_counts.items())),
            compression_method_counts=dict(sorted(methods.items())),
            encrypted_member_count=encrypted,
            undecodable_member_name_count=undecodable,
            member_names_redacted=True,
            details={
                "archive_dialect": "wqw-xor-e5",
                "filename_xor": "0xe5",
                "prepended_bytes": concat_offset,
                "control_summaries": summaries,
                "duplicate_control_name_count": len(duplicate_controls),
                "arbitrary_member_names_exported": False,
            },
        )
        return evidence, private
    except (OSError, ForensicPathError) as exc:
        evidence = DatContainerEvidence(path=relative_path, role=role, size=0, container_format="unreadable", central_directory_valid=False, member_names_redacted=True, details=_sanitized_error(exc))
        return evidence, WqwPrivateEvidence()


def relationship_summary(root_private: WqwPrivateEvidence, platform_private: Dict[str, WqwPrivateEvidence]) -> Dict[str, object]:
    by_code: Dict[str, Dict[str, int]] = {}
    total_filelist = total_global = total_matches = 0
    for code, private in sorted(platform_private.items()):
        local = private.filelist_rom_names
        global_names = root_private.fileinfo_paths_by_code.get(code, set())
        matches = len(local & global_names)
        by_code[code] = {
            "filelist_unique_rom_name_count": len(local),
            "global_unique_rom_name_count": len(global_names),
            "global_filelist_unique_match_count": matches,
            "filelist_unique_missing_from_global_count": len(local - global_names),
            "global_unique_missing_from_filelist_count": len(global_names - local),
        }
        total_filelist += len(local)
        total_global += len(global_names)
        total_matches += matches
    return {
        "schema": "global-platform-rom-correlation-v1",
        "catalogue_count": len(platform_private),
        "filelist_unique_rom_name_count": total_filelist,
        "global_unique_rom_name_count_for_inspected_catalogues": total_global,
        "global_filelist_unique_match_count": total_matches,
        "by_catalogue_code": by_code,
        "arbitrary_values_exported": False,
    }
