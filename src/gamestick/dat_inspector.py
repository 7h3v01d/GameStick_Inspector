from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
from dataclasses import replace
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .catalogue_audit import audit_numbered_catalogues
from .binary_fingerprint import (
    common_header_signatures,
    common_sampled_signatures,
    inspect_binary_fingerprint,
    largest_common_prefix_bucket,
    read_prefix_for_comparison,
)
from .fs_safety import ForensicPathError, assert_contained_non_reparse, lstat_non_reparse
from .models import DatContainerEvidence, NumberedDatProfileCandidate
from .ordering import stable_text_key
from .read_stability import inspect_read_stability, summarize_read_stability
from .wqw import WqwPrivateEvidence, inspect_wqw, relationship_summary

# This module deliberately does not use zipfile.ZipFile.  Python's zipfile reader
# materializes the complete central directory before callers can impose an
# application-level member cap.  GameStick media is untrusted/recovery-oriented,
# so alpha1 uses a small bounded central-directory parser instead.  It never
# extracts or writes any archive member.
_EOCD_SIGNATURE = b"PK\x05\x06"
_CENTRAL_SIGNATURE = b"PK\x01\x02"
_EOCD_FIXED_SIZE = 22
_CENTRAL_FIXED_SIZE = 46
_LOCAL_FIXED_SIZE = 30
_LOCAL_SIGNATURE = b"PK\x03\x04"
_MAX_ZIP_COMMENT = 65_535
_MAX_CENTRAL_DIRECTORY_BYTES = 16 * 1024 * 1024
_MAX_CENTRAL_ENTRIES = 20_000
_MAX_NUMBERED_CATALOGS = 64
_NUMBERED_CATALOG_RE = re.compile(r"^[0-9]{3}$")

_CONTROL_MEMBER_BASENAMES = {
    "fileinfo.txt": "fileinfo.txt",
    "filelist.txt": "filelist.txt",
}

# Member suffixes are structural evidence only when explicitly allowlisted.
# Arbitrary suffix text is private catalogue data and collapses to <other>.
_MEMBER_STRUCTURAL_EXTENSIONS = frozenset({
    ".txt", ".raw", ".dat", ".cfg", ".ini", ".xml", ".json",
    ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp",
})

_COMPRESSION_NAMES = {
    0: "stored",
    8: "deflate",
    12: "bzip2",
    14: "lzma",
    93: "zstd",
}


def is_numbered_catalog_name(value: object) -> bool:
    return bool(_NUMBERED_CATALOG_RE.fullmatch(str(value).strip()))


def _safe_member_extension(name: str) -> str:
    basename = PurePosixPath(name.replace("\\", "/")).name
    suffix = PurePosixPath(basename).suffix.casefold()
    if not suffix:
        return "<none>"
    if suffix in _MEMBER_STRUCTURAL_EXTENSIONS:
        return suffix
    return "<other>"


def _decode_member_name(raw: bytes, flags: int) -> str:
    encoding = "utf-8" if (flags & 0x0800) else "cp437"
    return raw.decode(encoding, errors="replace")


def _error_fields(exc: BaseException) -> Dict[str, object]:
    fields: Dict[str, object] = {"error_type": type(exc).__name__}
    if isinstance(exc, OSError) and isinstance(exc.errno, int):
        fields["error_errno"] = exc.errno
    return fields


def _not_zip_evidence(path: str, role: str, size: int, state: str, *, error: Optional[BaseException] = None) -> DatContainerEvidence:
    details: Dict[str, object] = {}
    if error is not None:
        details.update(_error_fields(error))
    return DatContainerEvidence(
        path=path,
        role=role,
        size=size,
        container_format=state,
        central_directory_valid=False,
        member_names_redacted=True,
        details=details,
    )


def _inspect_zip_container(path: Path, *, relative_path: str, role: str) -> DatContainerEvidence:
    """Inspect a DAT as a bounded ZIP central directory without extracting data.

    Only canonical control-member names are exported.  All other member names stay
    local and contribute only bounded counts / allowlisted extension semantics.
    """
    try:
        st = lstat_non_reparse(path)
        if not stat.S_ISREG(st.st_mode):
            return _not_zip_evidence(relative_path, role, int(getattr(st, "st_size", 0)), "not-regular-file")
        size = int(st.st_size)
        if size < _EOCD_FIXED_SIZE:
            return _not_zip_evidence(relative_path, role, size, "not-standard-zip")

        tail_size = min(size, _EOCD_FIXED_SIZE + _MAX_ZIP_COMMENT)
        with path.open("rb") as handle:
            handle.seek(size - tail_size)
            tail = handle.read(tail_size)
        if len(tail) != tail_size:
            return _not_zip_evidence(relative_path, role, size, "short-read")

        # A ZIP comment can itself contain the EOCD signature bytes. Search
        # backwards until a candidate whose declared comment reaches EOF is found.
        search_before = len(tail)
        eocd_index = -1
        eocd = b""
        comment_length = 0
        while search_before > 0:
            candidate_index = tail.rfind(_EOCD_SIGNATURE, 0, search_before)
            if candidate_index < 0:
                break
            if candidate_index + _EOCD_FIXED_SIZE <= len(tail):
                candidate = tail[candidate_index:candidate_index + _EOCD_FIXED_SIZE]
                candidate_comment_length = struct.unpack("<H", candidate[20:22])[0]
                if candidate_index + _EOCD_FIXED_SIZE + candidate_comment_length == len(tail):
                    eocd_index = candidate_index
                    eocd = candidate
                    comment_length = candidate_comment_length
                    break
            search_before = candidate_index
        if eocd_index < 0:
            return _not_zip_evidence(relative_path, role, size, "not-standard-zip")

        (
            signature,
            disk_number,
            central_disk,
            entries_on_disk,
            total_entries,
            central_size,
            central_offset,
            parsed_comment_length,
        ) = struct.unpack("<4s4H2LH", eocd)
        if signature != _EOCD_SIGNATURE or parsed_comment_length != comment_length:
            return _not_zip_evidence(relative_path, role, size, "invalid-zip-eocd")

        eocd_absolute = (size - tail_size) + eocd_index
        if disk_number != 0 or central_disk != 0 or entries_on_disk != total_entries:
            return _not_zip_evidence(relative_path, role, size, "multi-disk-zip-unsupported")
        if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
            return _not_zip_evidence(relative_path, role, size, "zip64-unsupported")
        if total_entries > _MAX_CENTRAL_ENTRIES:
            return DatContainerEvidence(
                path=relative_path,
                role=role,
                size=size,
                container_format="zip-entry-limit-exceeded",
                central_directory_valid=False,
                declared_member_count=total_entries,
                central_directory_size=central_size,
                member_names_redacted=True,
                details={"member_limit": _MAX_CENTRAL_ENTRIES},
            )
        if central_size > _MAX_CENTRAL_DIRECTORY_BYTES:
            return DatContainerEvidence(
                path=relative_path,
                role=role,
                size=size,
                container_format="zip-central-directory-limit-exceeded",
                central_directory_valid=False,
                declared_member_count=total_entries,
                central_directory_size=central_size,
                member_names_redacted=True,
                details={"central_directory_byte_limit": _MAX_CENTRAL_DIRECTORY_BYTES},
            )

        # The central directory must end immediately before EOCD.  Deriving the
        # actual start this way also supports ZIPs with a prepended wrapper/SFX.
        actual_central_start = eocd_absolute - central_size
        if actual_central_start < 0 or actual_central_start > size:
            return _not_zip_evidence(relative_path, role, size, "invalid-central-directory-offset")
        concat_offset = actual_central_start - central_offset
        if concat_offset < 0:
            return _not_zip_evidence(relative_path, role, size, "invalid-central-directory-offset")

        with path.open("rb") as handle:
            handle.seek(actual_central_start)
            central = handle.read(central_size)
        if len(central) != central_size:
            return _not_zip_evidence(relative_path, role, size, "short-central-directory-read")

        position = 0
        files = 0
        directories = 0
        encrypted = 0
        undecodable = 0
        controls: set[str] = set()
        control_candidates: List[Tuple[str, int, int, int]] = []
        extensions: Counter[str] = Counter()
        methods: Counter[str] = Counter()

        for _ in range(total_entries):
            if position + _CENTRAL_FIXED_SIZE > len(central):
                return _not_zip_evidence(relative_path, role, size, "truncated-central-directory")
            fixed = central[position:position + _CENTRAL_FIXED_SIZE]
            if fixed[:4] != _CENTRAL_SIGNATURE:
                return _not_zip_evidence(relative_path, role, size, "invalid-central-directory-entry")
            fields = struct.unpack("<4s6H3L5H2L", fixed)
            flags = fields[3]
            method = fields[4]
            compressed_size = fields[8]
            uncompressed_size = fields[9]
            name_length = fields[10]
            extra_length = fields[11]
            entry_comment_length = fields[12]
            local_header_offset = fields[16]
            record_size = _CENTRAL_FIXED_SIZE + name_length + extra_length + entry_comment_length
            if record_size < _CENTRAL_FIXED_SIZE or position + record_size > len(central):
                return _not_zip_evidence(relative_path, role, size, "invalid-central-directory-length")

            raw_name = central[position + _CENTRAL_FIXED_SIZE:position + _CENTRAL_FIXED_SIZE + name_length]
            try:
                member_name = _decode_member_name(raw_name, flags)
            except Exception:
                member_name = ""
                undecodable += 1

            # Ensure local offsets are at least plausible, while never opening members.
            adjusted_local_offset = int(local_header_offset) + int(concat_offset)
            if adjusted_local_offset < 0 or adjusted_local_offset >= size:
                return _not_zip_evidence(relative_path, role, size, "invalid-local-header-offset")

            normalized = member_name.replace("\\", "/")
            is_directory = normalized.endswith("/")
            if is_directory:
                directories += 1
            else:
                files += 1
                canonical_member = normalized.casefold()
                control = _CONTROL_MEMBER_BASENAMES.get(canonical_member)
                if control is not None:
                    control_candidates.append((control, adjusted_local_offset, flags, method))
                extensions[_safe_member_extension(normalized)] += 1

            if flags & 0x0001:
                encrypted += 1
            methods[_COMPRESSION_NAMES.get(method, f"method-{method}")] += 1

            # Touch numeric size fields only to force bounded integer conversion;
            # private member names are deliberately not retained.
            int(compressed_size)
            int(uncompressed_size)
            position += record_size

        # A central-directory digital signature may follow entries; reject other
        # unexplained bytes rather than guessing at structure.
        trailing = len(central) - position
        if trailing:
            if trailing < 6 or central[position:position + 4] != b"PK\x05\x05":
                return _not_zip_evidence(relative_path, role, size, "unexpected-central-directory-trailing-data")
            signature_size = struct.unpack("<H", central[position + 4:position + 6])[0]
            if trailing != 6 + signature_size:
                return _not_zip_evidence(relative_path, role, size, "invalid-central-directory-signature")

        # Canonical control names only corroborate the firmware profile when the
        # corresponding local header exists, repeats the same exact root-level
        # control name, is not encrypted, and uses a compression method that a
        # later bounded reader can support (stored/deflate). No member data is read.
        if control_candidates:
            with path.open("rb") as handle:
                for control, local_offset, flags, method in control_candidates:
                    if flags & 0x0001 or method not in {0, 8}:
                        continue
                    if local_offset < 0 or local_offset + _LOCAL_FIXED_SIZE > size:
                        continue
                    handle.seek(local_offset)
                    local_fixed = handle.read(_LOCAL_FIXED_SIZE)
                    if len(local_fixed) != _LOCAL_FIXED_SIZE or local_fixed[:4] != _LOCAL_SIGNATURE:
                        continue
                    local_fields = struct.unpack("<4s5H3L2H", local_fixed)
                    local_flags = local_fields[2]
                    local_method = local_fields[3]
                    local_name_length = local_fields[9]
                    local_extra_length = local_fields[10]
                    if local_flags & 0x0001 or local_method != method:
                        continue
                    if local_offset + _LOCAL_FIXED_SIZE + local_name_length + local_extra_length > size:
                        continue
                    raw_local_name = handle.read(local_name_length)
                    local_name = _decode_member_name(raw_local_name, local_flags).replace("\\", "/").casefold()
                    if _CONTROL_MEMBER_BASENAMES.get(local_name) == control:
                        controls.add(control)

        return DatContainerEvidence(
            path=relative_path,
            role=role,
            size=size,
            container_format="zip-central-directory",
            central_directory_valid=True,
            declared_member_count=total_entries,
            file_member_count=files,
            directory_member_count=directories,
            central_directory_size=central_size,
            zip_comment_length=comment_length,
            control_members=sorted(controls, key=stable_text_key),
            member_extension_counts=dict(sorted(extensions.items(), key=lambda item: stable_text_key(item[0]))),
            compression_method_counts=dict(sorted(methods.items(), key=lambda item: stable_text_key(item[0]))),
            encrypted_member_count=encrypted,
            undecodable_member_name_count=undecodable,
            member_names_redacted=True,
            details={"prepended_bytes": int(concat_offset)},
        )
    except (OSError, ForensicPathError) as exc:
        size = 0
        try:
            size = int(os.lstat(path).st_size)
        except OSError:
            pass
        return _not_zip_evidence(relative_path, role, size, "unreadable", error=exc)


def _starts_with_wqw_local_header(path: Path) -> bool:
    """Return True only when the file begins with the observed WQW local-record magic."""
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"WQW\x03"
    except OSError:
        return False


def _inspect_dat_container_internal(
    path: Path, *, relative_path: str, role: str
) -> Tuple[DatContainerEvidence, Optional[WqwPrivateEvidence]]:
    """Inspect standard ZIP first, then the observed WQW dialect, read-only."""
    private: Optional[WqwPrivateEvidence] = None
    evidence = _inspect_zip_container(path, relative_path=relative_path, role=role)
    if not evidence.central_directory_valid and evidence.container_format != "unreadable":
        wqw_result = inspect_wqw(path, relative_path=relative_path, role=role)
        if wqw_result is not None:
            evidence, private = wqw_result
        elif _starts_with_wqw_local_header(path):
            details = dict(evidence.details)
            details.update({
                "wqw_local_header_observed": True,
                "wqw_container_complete": False,
            })
            evidence = replace(
                evidence,
                container_format="damaged-or-incomplete-wqw",
                central_directory_valid=False,
                details=details,
            )
    if evidence.container_format == "unreadable":
        return evidence, private
    try:
        fingerprint = inspect_binary_fingerprint(path, size=evidence.size)
    except (OSError, ForensicPathError) as exc:
        details = dict(evidence.details)
        details["binary_fingerprint_error_type"] = type(exc).__name__
        if isinstance(exc, OSError) and isinstance(exc.errno, int):
            details["binary_fingerprint_error_errno"] = exc.errno
        return replace(evidence, details=details), private
    return replace(evidence, binary_fingerprint=fingerprint), private


def inspect_dat_container(path: Path, *, relative_path: str, role: str) -> DatContainerEvidence:
    """Inspect a DAT using bounded standard-ZIP/WQW structure plus fingerprinting."""
    evidence, _private = _inspect_dat_container_internal(path, relative_path=relative_path, role=role)
    return evidence


def _structural_container_identity(container: DatContainerEvidence) -> Dict[str, object]:
    """Return only catalogue-layout identity; omit content-dependent counts/sizes."""
    return {
        "path": container.path.replace("\\", "/"),
        "role": container.role,
        "container_format": container.container_format,
        "central_directory_valid": container.central_directory_valid,
        "control_members": list(container.control_members),
    }


def inspect_numbered_dat_profile(
    root: Path,
    root_entries: Sequence[Dict[str, object]],
) -> Optional[NumberedDatProfileCandidate]:
    """Identify/inspect the numbered-DAT catalogue family from an existing root sample.

    This performs no recursive search.  It uses already-collected root-entry names,
    then opens at most one exact ``NNN/NNN.dat`` per numeric root plus ``root.dat``.
    """
    safe_root = assert_contained_non_reparse(root, root)
    root_types = {
        str(entry.get("name", "")): str(entry.get("type", ""))
        for entry in root_entries
        if isinstance(entry, dict)
    }
    numbered_names = sorted(
        [name for name, kind in root_types.items() if kind == "directory" and is_numbered_catalog_name(name)],
        key=stable_text_key,
    )[:_MAX_NUMBERED_CATALOGS]
    root_dat_actual = next(
        (name for name, kind in root_types.items() if kind == "file" and name.casefold() == "root.dat"),
        None,
    )
    root_dat_present = root_dat_actual is not None

    # Do not manufacture a device-family candidate from an isolated numeric
    # directory.  The real evidence showed a root.dat + many numbered roots.
    if not root_dat_present and len(numbered_names) < 2:
        return None

    containers: List[DatContainerEvidence] = []
    platform_prefix_samples: List[bytes] = []
    root_container: Optional[DatContainerEvidence] = None
    root_private: Optional[WqwPrivateEvidence] = None
    platform_private: Dict[str, WqwPrivateEvidence] = {}
    root_prefix_sample = b""
    stability_rows: Dict[str, Dict[str, object]] = {}
    if root_dat_present and root_dat_actual is not None:
        root_path = assert_contained_non_reparse(root, safe_root / root_dat_actual)
        root_container, root_private = _inspect_dat_container_internal(
            root_path, relative_path="root.dat", role="global-catalog"
        )
        stability_rows["root.dat"] = inspect_read_stability(
            root_path,
            relative_path="root.dat",
            structural_regions=(root_private.stability_regions if root_private is not None else None),
            control_read_statuses=(root_private.control_read_statuses if root_private is not None else None),
            container_format=root_container.container_format,
        )
        try:
            root_prefix_sample = read_prefix_for_comparison(root_path)
        except OSError:
            root_prefix_sample = b""

    matched_pairs = 0
    for name in numbered_names:
        safe_candidate = None
        for filename in (f"{name}.dat", f"{name}.DAT"):
            candidate = safe_root / name / filename
            try:
                possible = assert_contained_non_reparse(root, candidate)
                st = lstat_non_reparse(possible)
                if stat.S_ISREG(st.st_mode):
                    safe_candidate = possible
                    break
            except (OSError, ForensicPathError):
                continue
        if safe_candidate is None:
            continue
        matched_pairs += 1
        inspected, private = _inspect_dat_container_internal(
            safe_candidate,
            relative_path=f"{name}/{name}.dat",
            role="platform-catalog",
        )
        containers.append(inspected)
        if private is not None:
            platform_private[name] = private
        stability_rows[f"{name}/{name}.dat"] = inspect_read_stability(
            safe_candidate,
            relative_path=f"{name}/{name}.dat",
            structural_regions=(private.stability_regions if private is not None else None),
            control_read_statuses=(private.control_read_statuses if private is not None else None),
            container_format=inspected.container_format,
        )
        try:
            platform_prefix_samples.append(read_prefix_for_comparison(safe_candidate))
        except OSError:
            pass

    if not root_dat_present and matched_pairs < 2:
        return None

    zip_platforms = sum(1 for item in containers if item.central_directory_valid)
    wqw_platforms = sum(1 for item in containers if item.container_format == "wqw-obfuscated-zip")
    damaged_wqw_platforms = sum(1 for item in containers if item.container_format == "damaged-or-incomplete-wqw")

    def _verified_control_schema(item: DatContainerEvidence, control: str, expected_schema: str) -> bool:
        if control not in item.control_members:
            return False
        if item.container_format != "wqw-obfuscated-zip":
            return True
        summaries = item.details.get("control_summaries")
        if not isinstance(summaries, dict):
            return False
        summary = summaries.get(control)
        return bool(
            isinstance(summary, dict)
            and summary.get("crc32_verified") is True
            and summary.get("parse_schema") == expected_schema
            and int(summary.get("valid_record_count") or 0) > 0
        )

    filelist_count = sum(
        1 for item in containers
        if _verified_control_schema(item, "filelist.txt", "filelist-semicolon-3-v1")
    )
    root_zip = bool(root_container and root_container.central_directory_valid)
    root_fileinfo = bool(
        root_container
        and _verified_control_schema(root_container, "fileinfo.txt", "fileinfo-semicolon-5-mixed-v1")
    )

    score = 0
    if root_dat_present:
        score += 20
    score += min(35, matched_pairs * 3)
    if root_zip:
        score += 10
    if root_fileinfo:
        score += 15
    if zip_platforms:
        score += min(10, zip_platforms)
    if filelist_count:
        score += min(10, filelist_count)
    score = min(100, score)

    # 'PROBABLE' needs internal container corroboration, not merely filenames.
    probable = root_zip and root_fileinfo and filelist_count >= 1
    if probable:
        score = max(90, score)
        confidence = "high"
        status = "PROBABLE"
    elif score >= 75:
        confidence = "high"
        status = "CANDIDATE"
    elif score >= 50:
        confidence = "medium"
        status = "CANDIDATE"
    else:
        confidence = "low"
        status = "CANDIDATE"

    platform_fingerprints = [
        item.binary_fingerprint
        for item in containers
        if item.binary_fingerprint is not None
    ]
    all_rows = ([root_container] if root_container is not None else []) + list(containers)
    fingerprint_count = sum(1 for item in all_rows if item.binary_fingerprint is not None)
    common_prefix_bytes = (
        largest_common_prefix_bucket(platform_prefix_samples)
        if len(platform_prefix_samples) == len(containers)
        else 0
    )
    root_matches_prefix_bytes = (
        largest_common_prefix_bucket([root_prefix_sample, *platform_prefix_samples])
        if root_prefix_sample and len(platform_prefix_samples) == len(containers) and containers
        else 0
    )
    common_headers = common_header_signatures(platform_fingerprints)
    common_signatures = common_sampled_signatures(platform_fingerprints)

    inspected_platforms = [item for item in containers if item.container_format != "unreadable"]
    if inspected_platforms and all(item.container_format == "wqw-obfuscated-zip" for item in inspected_platforms):
        binary_family = "wqw-obfuscated-zip"
    elif (
        inspected_platforms
        and any(item.container_format == "wqw-obfuscated-zip" for item in inspected_platforms)
        and all(
            item.container_format in {"wqw-obfuscated-zip", "damaged-or-incomplete-wqw"}
            for item in inspected_platforms
        )
    ):
        binary_family = "wqw-with-damaged-containers"
    elif inspected_platforms and all(item.container_format == "zip-central-directory" for item in inspected_platforms):
        binary_family = "standard-zip"
    elif inspected_platforms and all(not item.central_directory_valid for item in inspected_platforms):
        if common_headers:
            binary_family = "known-header:" + ",".join(common_headers)
        elif len(platform_fingerprints) == len(inspected_platforms):
            binary_family = "unidentified-binary"
        else:
            binary_family = "nonzip-partial-fingerprint"
    elif inspected_platforms:
        binary_family = "mixed-or-partial"
    else:
        binary_family = "unknown"

    correlation = (
        relationship_summary(root_private, platform_private)
        if root_private is not None and platform_private
        else None
    )
    consistency = audit_numbered_catalogues(
        root,
        numbered_names,
        platform_private,
        root_private,
    )
    read_stability = summarize_read_stability(stability_rows)

    structural_payload = {
        "schema_version": 5,
        "profile_family": "numbered-dat-catalog",
        "root_catalog": _structural_container_identity(root_container) if root_container else None,
        "platform_catalogs": [_structural_container_identity(item) for item in containers],
        "binary_family_assessment": binary_family,
        "control_schema_family": (
            "wqw-fileinfo-filelist-v1"
            if binary_family in {"wqw-obfuscated-zip", "wqw-with-damaged-containers"} and root_fileinfo and filelist_count
            else None
        ),
    }
    canonical = json.dumps(structural_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signature = hashlib.sha256(canonical).hexdigest()

    notes = [
        "Read-only numbered-DAT inspection uses exact root.dat / NNN/NNN.dat paths only; no archive extraction is performed.",
        "Archive member names are privacy-redacted; only exact allowlisted control-member semantics and bounded counts are exported.",
        "Binary fingerprinting reads at most five bounded windows per DAT; no full-file binary scan is performed.",
        "Binary prefix/tail digests are content commitments for comparison only and are excluded from structural profile identity.",
    ]
    if binary_family in {"wqw-obfuscated-zip", "wqw-with-damaged-containers"}:
        notes.append("Observed DAT containers use the WQW ZIP-derived dialect with XOR-0xE5 member names.")
        notes.append("Only bounded control members are inflated; CRC-32 must verify before catalogue parsing.")
    if root_fileinfo:
        notes.append("Global catalogue contains canonical control member fileinfo.txt.")
    if filelist_count:
        notes.append(f"Canonical filelist.txt control member observed in {filelist_count} numbered catalogue container(s).")
    if containers and zip_platforms != len(containers):
        notes.append(
            f"Only {zip_platforms} of {len(containers)} inspected numbered DAT containers exposed a bounded ZIP/WQW central directory."
        )

    if correlation is not None:
        notes.append(
            "Global/per-platform ROM-name correlation is computed privately and exported as counts only."
        )
    notes.append(
        "Top-level numbered-directory filesystem consistency is audited with a hard per-directory enumeration cap; private names remain in memory only."
    )
    notes.append(
        "DAT read stability reopens each exact DAT three times and compares bounded structural-region samples; canonical compressed control ranges remain sampled even when control decompression/CRC validation fails; sampled bytes and digest values are never exported."
    )
    notes.append(
        "Cross-catalogue alias resolution compares private names only in memory and exports catalogue-code/count relationships, not filenames; dominant aliases may be classified with a bounded residual gap."
    )

    return NumberedDatProfileCandidate(
        schema_version=7,
        candidate_id=f"ndpv7-{signature[:16]}",
        status=status,
        confidence=confidence,
        heuristic_score=score,
        profile_family="numbered-dat-catalog",
        root_dat_present=root_dat_present,
        numbered_directory_count=len(numbered_names),
        matched_numbered_dat_count=matched_pairs,
        zip_numbered_dat_count=zip_platforms,
        wqw_numbered_dat_count=wqw_platforms,
        damaged_wqw_numbered_dat_count=damaged_wqw_platforms,
        filelist_control_count=filelist_count,
        structural_signature_sha256=signature,
        binary_fingerprint_count=fingerprint_count,
        binary_family_assessment=binary_family,
        numbered_catalog_common_prefix_bytes=common_prefix_bytes,
        root_matches_numbered_prefix_bytes=root_matches_prefix_bytes,
        common_header_signatures=common_headers,
        common_sampled_signatures=common_signatures,
        root_catalog=root_container,
        numbered_catalogs=containers,
        catalogue_codes=[item.path.split("/", 1)[0] for item in containers],
        member_names_redacted=True,
        catalogue_relationships=correlation or {},
        catalogue_consistency=consistency,
        read_stability=read_stability,
        notes=notes,
    )
