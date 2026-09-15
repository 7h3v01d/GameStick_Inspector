from __future__ import annotations

import csv
import io
import hashlib
import json
import ntpath
import os
import platform
import re
import shutil
import sqlite3
import stat
import string
import subprocess
import xml.etree.ElementTree as ET
from collections import Counter
from itertools import islice
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote

from .discovery import build_device_profile_candidate
from .fs_safety import (
    ForensicPathError,
    assert_contained_non_reparse,
    bounded_scandir_names,
    lstat_non_reparse,
)
from .ordering import stable_text_key
from .privacy import (
    ARTWORK_LIBRARY_ROOT_NAMES,
    PRIVACY_LIBRARY_ROOT_NAMES,
    ROM_LIBRARY_ROOT_NAMES,
    canonical_platform_name,
)
from .models import (
    CandidateArtifact,
    DirectorySnapshot,
    DiskPartitionInfo,
    PhysicalMapping,
    ProbeReport,
)
from .profiles import best_profile, best_profile_from_matches, profile_matches
from .safety import assert_readable_root

_ARTIFACT_SUFFIXES = {
    ".db", ".sqlite", ".sqlite3", ".csv", ".dat", ".ini", ".cfg", ".conf", ".json", ".xml"
}
_ARTIFACT_NAMES = {
    "games.db", "game.db", "game.csv", "games.csv", "gamelist.xml",
    "retroarch.cfg", "config.ini", "settings.ini", "emulators.cfg",
}
_MAX_HASH_BYTES = 16 * 1024 * 1024
_MAX_SCAN_FILES = 20_000
_MAX_SCAN_ENUMERATED_ENTRIES = 20_000
_MAX_SCAN_ENTRIES_PER_DIRECTORY = 4_096
_MAX_SCAN_DEPTH = 4
_MAX_ARTIFACTS = 500
_MAX_ROOT_ENTRIES = 4_096
_MAX_SNAPSHOT_DIRS = 32
_MAX_TOP_LEVEL_SNAPSHOT_ENUM_ENTRIES = 2_048
_MAX_SNAPSHOT_ENTRIES = 500
_MAX_ANALYSIS_BYTES = 2 * 1024 * 1024

# Auto-detection is user reachable and must obey the same hostile-media
# robustness model as an already-selected GameStick. Linux primarily consumes
# the kernel mount table rather than recursively walking arbitrary mount trees.
_MAX_AUTO_DETECT_CANDIDATES = 512
_MAX_LINUX_MOUNTINFO_LINES = 2_048
_MAX_LINUX_FALLBACK_ENUMERATED_ENTRIES = 4_096
_MAX_LINUX_FALLBACK_ENTRIES_PER_DIRECTORY = 256
_MAX_MACOS_VOLUME_ENTRIES = 512
_LINUX_MOUNT_BASES = (Path("/media"), Path("/run/media"), Path("/mnt"))
_MACOS_VOLUMES_ROOT = Path("/Volumes")

_ROM_LIKE_DIRS = set(ROM_LIBRARY_ROOT_NAMES)
_ARTWORK_LIKE_DIRS = set(ARTWORK_LIBRARY_ROOT_NAMES)
_PRIVACY_LIBRARY_DIRS = set(PRIVACY_LIBRARY_ROOT_NAMES)
_TEXT_CONFIG_SUFFIXES = {".ini", ".cfg", ".conf"}

# Names found inside media-supplied metadata are untrusted data until a real
# device format is frozen. Default exported evidence never includes arbitrary
# source names from CSV/JSON/config/XML/SQLite schema positions; only derived
# allowlisted semantic terms and bounded counts are emitted.
_STRUCTURAL_NAME_ALIASES = {
    "id": ("id",),
    "game": ("game",),
    "games": ("game",),
    "game_id": ("game", "id"),
    "gameid": ("game", "id"),
    "game_name": ("game", "title"),
    "gamename": ("game", "title"),
    "name": ("title",),
    "title": ("title",),
    "rom": ("rom",),
    "roms": ("rom",),
    "rom_file": ("rom", "file"),
    "romfile": ("rom", "file"),
    "rom_filename": ("rom", "filename"),
    "romfilename": ("rom", "filename"),
    "rom_path": ("rom", "path"),
    "rompath": ("rom", "path"),
    "path": ("path",),
    "file": ("file",),
    "filename": ("filename",),
    "image": ("image",),
    "images": ("image",),
    "image_path": ("image", "path"),
    "imagepath": ("image", "path"),
    "cover": ("cover",),
    "covers": ("cover",),
    "cover_path": ("cover", "path"),
    "coverpath": ("cover", "path"),
    "boxart": ("boxart",),
    "artwork": ("artwork",),
    "preview": ("preview",),
    "snap": ("snap",),
    "system": ("system",),
    "systems": ("system",),
    "platform": ("platform",),
    "platforms": ("platform",),
    "console": ("platform",),
    "emulator": ("emulator",),
    "emulators": ("emulator",),
    "launcher": ("launcher",),
    "menu": ("launcher",),
    "frontend": ("launcher",),
    "index": ("index",),
    "catalog": ("catalog",),
    "library": ("library",),
    "gamelist": ("gamelist",),
}


def _semantic_terms_for_name(value: object) -> tuple[str, ...]:
    text = str(value).strip().casefold()
    normalized = re.sub(r"[\s-]+", "_", text)
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,63}", normalized):
        return ()
    return _STRUCTURAL_NAME_ALIASES.get(normalized, ())


def _derived_semantics(values: Iterable[object], limit: int) -> tuple[List[str], int]:
    terms: set[str] = set()
    recognized = 0
    for value in islice(values, limit):
        mapped = _semantic_terms_for_name(value)
        if mapped:
            recognized += 1
            terms.update(mapped)
    return sorted(terms, key=stable_text_key), recognized


def _sanitized_error_fields(prefix: str, exc: BaseException) -> Dict[str, Any]:
    """Return privacy-bounded parser error evidence.

    Dependency/library exception strings can contain media-controlled identifiers.
    Evidence therefore records only the exception class plus bounded numeric/symbolic
    codes that are not derived from source strings. Raw ``str(exc)`` stays local.
    """
    details: Dict[str, Any] = {
        prefix: True,
        f"{prefix}_type": type(exc).__name__,
    }
    if isinstance(exc, sqlite3.Error):
        code = getattr(exc, "sqlite_errorcode", None)
        name = getattr(exc, "sqlite_errorname", None)
        if isinstance(code, int):
            details[f"{prefix}_code"] = code
        if isinstance(name, str) and re.fullmatch(r"SQLITE_[A-Z0-9_]+", name):
            details[f"{prefix}_code_name"] = name
    elif isinstance(exc, OSError):
        if isinstance(exc.errno, int):
            details[f"{prefix}_errno"] = exc.errno
    elif isinstance(exc, json.JSONDecodeError):
        details[f"{prefix}_line"] = int(exc.lineno)
        details[f"{prefix}_column"] = int(exc.colno)
    elif isinstance(exc, ET.ParseError):
        position = getattr(exc, "position", None)
        if isinstance(position, tuple) and len(position) == 2:
            details[f"{prefix}_line"] = int(position[0])
            details[f"{prefix}_column"] = int(position[1])
        code = getattr(exc, "code", None)
        if isinstance(code, int):
            details[f"{prefix}_code"] = code
    return details


def _sanitized_exception_summary(exc: BaseException) -> str:
    """Return an evidence-safe exception summary with no raw dependency text."""
    summary = type(exc).__name__
    if isinstance(exc, OSError) and isinstance(exc.errno, int):
        summary += f" (errno={exc.errno})"
    return summary


def _evidence_safe_path(root: Path, path: Path) -> tuple[str, bool]:
    """Return a root-relative path safe for privacy-bounded evidence.

    Any entry beneath a ROM- or artwork-like top-level privacy directory is
    represented only as ``<root>/<redacted>``. This function is lexical on purpose: a rejected
    reparse entry must not be resolved merely to format a diagnostic.
    """
    root_resolved = root.resolve(strict=True)
    candidate = Path(path)
    try:
        relative = candidate.relative_to(root_resolved)
    except ValueError:
        return "<outside-root>", False

    parts = relative.parts
    if not parts:
        return ".", False
    if parts[0].casefold() in _PRIVACY_LIBRARY_DIRS and len(parts) > 1:
        return f"{parts[0]}/<redacted>", True
    return relative.as_posix(), False


def _filesystem_warning(action: str, root: Path, path: Path, exc: BaseException) -> str:
    """Format an exported filesystem diagnostic without privacy side channels.

    Paths below ROM-like roots are filename-redacted. Raw exception text is never
    serialized because OS/library messages commonly repeat media-controlled paths.
    """
    safe_path, _ = _evidence_safe_path(root, path)
    return f"{action} {safe_path}: {_sanitized_exception_summary(exc)}"


class _XMLRootFound(Exception):
    def __init__(self, tag: object):
        super().__init__("XML root found")
        self.tag = tag


class _FirstXMLStartTarget:
    """ElementTree target that stops at the first real start-element event."""

    def start(self, tag: object, attrs: Dict[str, object]) -> None:
        del attrs
        raise _XMLRootFound(tag)

    def end(self, tag: object) -> None:
        del tag

    def data(self, data: str) -> None:
        del data

    def close(self) -> None:
        return None


def _xml_local_name(tag: object) -> str:
    text = str(tag)
    if "}" in text:
        text = text.rsplit("}", 1)[-1]
    if ":" in text:
        text = text.rsplit(":", 1)[-1]
    return text


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _root_entries(root: Path) -> tuple[List[Dict[str, object]], List[str]]:
    """Enumerate a bounded root sample without following reparse points."""
    entries: List[Dict[str, object]] = []
    warnings: List[str] = []
    try:
        safe_root = assert_contained_non_reparse(root, root)
        sampled = bounded_scandir_names(safe_root, _MAX_ROOT_ENTRIES)
        if sampled.error is not None:
            return [], [
                f"Could not enumerate volume root after "
                f"{sampled.enumerated:,} enumeration operations: "
                f"{_sanitized_exception_summary(sampled.error)}"
            ]
        names = sorted(sampled.names, key=stable_text_key)
    except ForensicPathError as exc:
        return [], [f"Could not enumerate volume root: {_sanitized_exception_summary(exc)}"]

    if sampled.truncated:
        warnings.append(
            f"Root entry sample truncated after {_MAX_ROOT_ENTRIES:,} entries "
            f"(enumerated at most {_MAX_ROOT_ENTRIES + 1:,})."
        )

    for name in names:
        item = safe_root / name
        try:
            resolved = assert_contained_non_reparse(root, item)
            st = lstat_non_reparse(resolved)
            if stat.S_ISDIR(st.st_mode):
                entry_type = "directory"
                size = None
            elif stat.S_ISREG(st.st_mode):
                entry_type = "file"
                size = st.st_size
            else:
                entry_type = "other"
                size = None
            entries.append({"name": item.name, "type": entry_type, "size": size})
        except ForensicPathError as exc:
            warnings.append(_filesystem_warning("Skipped reparse/out-of-root entry", root, item, exc))
        except OSError as exc:
            message = _filesystem_warning("Could not inspect root entry", root, item, exc)
            warnings.append(message)
            entries.append({"name": item.name, "type": "unreadable", "error": _sanitized_exception_summary(exc)})
    return entries, warnings

def _structure_hash(entries: List[Dict[str, object]]) -> str:
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _safe_text_prefix(path: Path, limit: int = 64 * 1024) -> str:
    with path.open("rb") as handle:
        raw = handle.read(limit)
    return raw.decode("utf-8-sig", errors="replace")


def _sqlite_uri(path: Path) -> str:
    # SQLite URI syntax accepts forward slashes on Windows. mode=ro prevents
    # database writes; immutable=1 prevents journal/WAL coordination writes.
    normalized = str(path.resolve()).replace("\\", "/")
    return "file:" + quote(normalized, safe="/:~") + "?mode=ro&immutable=1"


def _analyze_sqlite(path: Path) -> Dict[str, Any]:
    details: Dict[str, Any] = {}
    try:
        connection = sqlite3.connect(_sqlite_uri(path), uri=True, timeout=1.0)
        try:
            rows = connection.execute(
                "SELECT type, name FROM sqlite_master "
                "WHERE type IN ('table','view','index','trigger') "
                "AND name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT 200"
            ).fetchall()
            object_counts = Counter(str(object_type) for object_type, _ in rows)
            schema_terms, recognized_schema_names = _derived_semantics(
                (name for _, name in rows), 200
            )
            details["schema_object_counts"] = dict(sorted(object_counts.items(), key=lambda item: stable_text_key(item[0])))
            details["schema_object_count"] = len(rows)
            details["recognized_schema_terms"] = schema_terms
            details["recognized_schema_name_count"] = recognized_schema_names

            # Table names are needed locally to query PRAGMA metadata, but arbitrary
            # names are never exported. Only derived allowlisted column semantics and
            # bounded counts leave this analyzer.
            table_names = [str(name) for object_type, name in rows if str(object_type) == "table"][:50]
            column_terms: set[str] = set()
            columns_inspected = 0
            recognized_column_names = 0
            tables_inspected = 0
            for table_name in table_names:
                escaped = table_name.replace('"', '""')
                cursor = connection.execute(f'PRAGMA table_info("{escaped}")')
                column_rows = cursor.fetchmany(80)
                tables_inspected += 1
                for row in column_rows:
                    if len(row) <= 1:
                        continue
                    columns_inspected += 1
                    mapped = _semantic_terms_for_name(row[1])
                    if mapped:
                        recognized_column_names += 1
                        column_terms.update(mapped)
            details["tables_inspected"] = tables_inspected
            details["columns_inspected"] = columns_inspected
            details["recognized_column_terms"] = sorted(column_terms, key=stable_text_key)
            details["recognized_column_name_count"] = recognized_column_names
        finally:
            connection.close()
    except sqlite3.Error as exc:
        details.update(_sanitized_error_fields("schema_read_error", exc))
    return details

def _analyze_csv(path: Path) -> Dict[str, Any]:
    details: Dict[str, Any] = {}
    try:
        text = _safe_text_prefix(path)
        if not text.strip():
            return {"empty": True}
        sample = text[:32768]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            delimiter = dialect.delimiter
        except csv.Error:
            delimiter = ","

        reader = csv.reader(io.StringIO(sample), delimiter=delimiter)
        rows = list(islice(reader, 3))
        if not rows:
            return {"empty": True}
        first_fields = rows[0][:80]
        recognized_terms, recognized_fields = _derived_semantics(first_fields, 80)

        # Multi-row corroboration is intentionally heuristic, not verification.
        # Even a corroborated CSV is not allowed to independently elevate a launcher
        # to probable until a real GameStick CSV layout has been observed/frozen.
        comparable_rows = 0
        data_like_rows = 0
        for row in rows[1:]:
            if len(row) != len(rows[0]):
                continue
            comparable_rows += 1
            _, row_recognized = _derived_semantics(row, 80)
            # A later row is data-like when most of its fields are not exact
            # structural aliases. Raw row values never leave this function.
            threshold = max(1, len(row) // 2)
            if row_recognized < threshold:
                data_like_rows += 1

        corroborated = (
            recognized_fields >= 2
            and comparable_rows >= 1
            and data_like_rows == comparable_rows
        )
        details["delimiter"] = "\\t" if delimiter == "\t" else delimiter
        details["field_count"] = len(rows[0])
        details["recognized_header_terms"] = recognized_terms
        details["recognized_header_field_count"] = recognized_fields
        details["header_semantics_corroborated"] = corroborated
        details["rows_sampled"] = len(rows)
        details["corroborating_data_rows"] = data_like_rows
    except (OSError, UnicodeError, csv.Error) as exc:
        details.update(_sanitized_error_fields("analysis_error", exc))
    return details

def _analyze_json(path: Path, size: int) -> Dict[str, Any]:
    if size > _MAX_ANALYSIS_BYTES:
        return {"analysis_skipped": f"JSON larger than {_MAX_ANALYSIS_BYTES} bytes"}
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            payload = json.load(handle)
        if isinstance(payload, dict):
            recognized_terms: set[str] = set()
            keys_inspected = 0
            containers_inspected = 0
            stack: List[tuple[object, int]] = [(payload, 0)]
            max_keys = 200
            max_depth = 3
            while stack and keys_inspected < max_keys:
                current, depth = stack.pop()
                if isinstance(current, dict):
                    containers_inspected += 1
                    for key, value in current.items():
                        if keys_inspected >= max_keys:
                            break
                        keys_inspected += 1
                        recognized_terms.update(_semantic_terms_for_name(key))
                        if depth < max_depth and isinstance(value, (dict, list)):
                            stack.append((value, depth + 1))
                elif isinstance(current, list) and depth <= max_depth:
                    containers_inspected += 1
                    # Bound fan-out from arrays; values are inspected only for nested
                    # object keys and are never serialized into evidence.
                    for value in current[:32]:
                        if isinstance(value, (dict, list)):
                            stack.append((value, depth + 1))
            return {
                "top_level_type": "object",
                "top_level_key_count": len(payload),
                "recognized_key_terms": sorted(recognized_terms, key=stable_text_key),
                "keys_inspected": keys_inspected,
                "containers_inspected": containers_inspected,
                "key_scan_truncated": bool(stack) or keys_inspected >= max_keys,
            }
        if isinstance(payload, list):
            return {"top_level_type": "array", "top_level_length": len(payload)}
        return {"top_level_type": type(payload).__name__}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _sanitized_error_fields("analysis_error", exc)

def _analyze_xml(path: Path) -> Dict[str, Any]:
    """Inspect only the first legitimate XML start element from a bounded prefix.

    Regex matching is intentionally forbidden here: DOCTYPE/entity text can contain
    element-like strings that are not document structure. ElementTree drives a real
    XML parser and the custom target aborts immediately when the actual root start
    event occurs. External resources are not resolved by ElementTree.
    """
    max_bytes = 32 * 1024
    try:
        parser = ET.XMLParser(target=_FirstXMLStartTarget())
        with path.open("rb") as handle:
            remaining = max_bytes
            while remaining > 0:
                chunk = handle.read(min(4096, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                try:
                    parser.feed(chunk)
                except _XMLRootFound as found:
                    local_name = _xml_local_name(found.tag)
                    terms = sorted(set(_semantic_terms_for_name(local_name)), key=stable_text_key)
                    return {
                        "root_element_present": True,
                        "recognized_root_terms": terms,
                        "xml_root_parser": "elementtree-first-start",
                    }
            try:
                parser.close()
            except _XMLRootFound as found:
                local_name = _xml_local_name(found.tag)
                terms = sorted(set(_semantic_terms_for_name(local_name)), key=stable_text_key)
                return {
                    "root_element_present": True,
                    "recognized_root_terms": terms,
                    "xml_root_parser": "elementtree-first-start",
                }
        return {
            "root_element_present": False,
            "recognized_root_terms": [],
            "xml_root_parser": "elementtree-first-start",
            "xml_prefix_limit_reached": remaining == 0,
        }
    except (OSError, ET.ParseError) as exc:
        details = {
            "root_element_present": False,
            "recognized_root_terms": [],
            "xml_root_parser": "elementtree-first-start",
        }
        details.update(_sanitized_error_fields("analysis_error", exc))
        return details

def _analyze_text_config(path: Path) -> Dict[str, Any]:
    try:
        text = _safe_text_prefix(path)
        section_terms: set[str] = set()
        key_terms: set[str] = set()
        section_count = 0
        key_count = 0
        entries_sampled = 0
        max_entries = 200
        truncated = False
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            if entries_sampled >= max_entries:
                truncated = True
                break
            if stripped.startswith("[") and "]" in stripped:
                section_count += 1
                entries_sampled += 1
                section_terms.update(_semantic_terms_for_name(stripped[1:stripped.index("]")][:100]))
                continue
            match = re.match(r"([^=:#]{1,100})\s*[=:#]", stripped)
            if match:
                key_count += 1
                entries_sampled += 1
                key_terms.update(_semantic_terms_for_name(match.group(1).strip()))
        return {
            "sampled_section_count": section_count,
            "sampled_key_count": key_count,
            "recognized_section_terms": sorted(section_terms, key=stable_text_key),
            "recognized_key_terms": sorted(key_terms, key=stable_text_key),
            "entries_sampled": entries_sampled,
            "analysis_truncated": truncated,
        }
    except OSError as exc:
        return _sanitized_error_fields("analysis_error", exc)

def _artifact_format_and_details(path: Path, size: int) -> tuple[str, Dict[str, Any]]:
    try:
        with path.open("rb") as handle:
            header = handle.read(64)
    except OSError as exc:
        return "unreadable", _sanitized_error_fields("analysis_error", exc)

    if header.startswith(b"SQLite format 3\x00"):
        return "sqlite3", _analyze_sqlite(path)

    suffix = path.suffix.casefold()
    if suffix == ".csv":
        return "csv", _analyze_csv(path)
    if suffix == ".json":
        return "json", _analyze_json(path, size)
    if suffix == ".xml":
        return "xml", _analyze_xml(path)
    if suffix in _TEXT_CONFIG_SUFFIXES:
        return "text-config", _analyze_text_config(path)
    if suffix in {".db", ".sqlite", ".sqlite3"}:
        return "database-extension/non-sqlite", {"header_prefix_sha256": hashlib.sha256(header).hexdigest(), "header_bytes_sampled": len(header)}
    if suffix == ".dat":
        # DAT is intentionally treated as opaque until the real device tells us more.
        return "opaque-dat", {"header_prefix_sha256": hashlib.sha256(header).hexdigest(), "header_bytes_sampled": len(header)}
    return "unknown", {"header_prefix_sha256": hashlib.sha256(header).hexdigest(), "header_bytes_sampled": len(header)}


def _candidate_artifacts(root: Path) -> tuple[List[CandidateArtifact], List[str]]:
    """Discover metadata candidates with hard global/per-directory enumeration caps."""
    results: List[CandidateArtifact] = []
    warnings: List[str] = []
    scanned_files = 0
    enumerated_entries = 0
    stack: List[tuple[Path, int]] = [(root, 0)]

    while stack:
        current_path, depth = stack.pop()
        remaining = _MAX_SCAN_ENUMERATED_ENTRIES - enumerated_entries
        if remaining <= 1:
            warnings.append(
                f"Metadata scan enumeration stopped after {_MAX_SCAN_ENUMERATED_ENTRIES:,} directory entries."
            )
            break

        try:
            safe_current = assert_contained_non_reparse(root, current_path)
            # Reserve one enumeration slot for the truncation probe so the
            # global hard bound is never exceeded.
            retained_limit = min(_MAX_SCAN_ENTRIES_PER_DIRECTORY, remaining - 1)
            sampled = bounded_scandir_names(safe_current, retained_limit)
            enumerated_entries += sampled.enumerated
            if sampled.error is not None:
                warnings.append(
                    f"Could not enumerate {_evidence_safe_path(root, safe_current)[0]} after "
                    f"{sampled.enumerated:,} enumeration operations: "
                    f"{_sanitized_exception_summary(sampled.error)}"
                )
                if enumerated_entries >= _MAX_SCAN_ENUMERATED_ENTRIES:
                    warnings.append(
                        f"Metadata scan enumeration stopped after "
                        f"{_MAX_SCAN_ENUMERATED_ENTRIES:,} directory-entry operations."
                    )
                    break
                # A corrupt partial directory sample is not trusted for evidence
                # or traversal, but its consumed work remains charged above.
                continue
            names = sorted(sampled.names, key=stable_text_key)
        except ForensicPathError as exc:
            warnings.append(_filesystem_warning("Skipped reparse/out-of-root directory", root, current_path, exc))
            continue

        if sampled.truncated:
            warnings.append(
                f"Metadata directory enumeration truncated at {safe_current} after "
                f"{retained_limit:,} sampled entries."
            )

        child_dirs: List[Path] = []
        for name in names:
            path = safe_current / name
            try:
                safe_path = assert_contained_non_reparse(root, path)
                st = lstat_non_reparse(safe_path)
            except ForensicPathError as exc:
                warnings.append(_filesystem_warning("Skipped reparse/out-of-root entry", root, path, exc))
                continue
            except OSError as exc:
                warnings.append(_filesystem_warning("Could not inspect directory entry", root, path, exc))
                continue

            if stat.S_ISDIR(st.st_mode):
                if depth < _MAX_SCAN_DEPTH and name.casefold() not in _ROM_LIKE_DIRS:
                    child_dirs.append(safe_path)
                continue
            if not stat.S_ISREG(st.st_mode):
                continue

            scanned_files += 1
            if scanned_files > _MAX_SCAN_FILES:
                warnings.append(f"Metadata scan stopped after {_MAX_SCAN_FILES:,} files.")
                results.sort(key=lambda x: stable_text_key(x.path))
                return results, warnings

            suffix = safe_path.suffix.casefold()
            folded_name = name.casefold()
            if folded_name not in _ARTIFACT_NAMES and suffix not in _ARTIFACT_SUFFIXES:
                continue

            try:
                # Re-check every component immediately before opening/hash/parsing.
                safe_path = assert_contained_non_reparse(root, safe_path)
                st = lstat_non_reparse(safe_path)
                if not stat.S_ISREG(st.st_mode):
                    continue
                size = st.st_size
                digest = _sha256(safe_path) if size <= _MAX_HASH_BYTES else None
                safe_path = assert_contained_non_reparse(root, safe_path)
                format_name, details = _artifact_format_and_details(safe_path, size)
                results.append(CandidateArtifact(
                    path=str(safe_path.relative_to(root.resolve(strict=True))),
                    kind="launcher/database/config candidate",
                    size=size,
                    sha256=digest,
                    format_name=format_name,
                    details=details,
                ))
                if len(results) >= _MAX_ARTIFACTS:
                    warnings.append(f"Metadata candidate list stopped after {_MAX_ARTIFACTS:,} artifacts.")
                    results.sort(key=lambda x: stable_text_key(x.path))
                    return results, warnings
            except ForensicPathError as exc:
                warnings.append(_filesystem_warning("Metadata candidate escaped forensic root and was skipped", root, safe_path, exc))
            except OSError as exc:
                warnings.append(_filesystem_warning("Could not inspect", root, safe_path, exc))
            except Exception as exc:
                warnings.append(_filesystem_warning("Metadata analysis skipped for", root, safe_path, exc))

        # Reverse push preserves the sorted order of the bounded sample with a LIFO stack.
        for child in reversed(child_dirs):
            stack.append((child, depth + 1))

    results.sort(key=lambda x: stable_text_key(x.path))
    return results, warnings

def _snapshot_directory(root: Path, directory: Path) -> tuple[DirectorySnapshot, List[str]]:
    safe_directory = assert_contained_non_reparse(root, directory)
    resolved_root = root.resolve(strict=True)
    relative = str(safe_directory.relative_to(resolved_root))
    privacy_root = safe_directory.name.casefold() in _PRIVACY_LIBRARY_DIRS
    redact_filenames = privacy_root
    directory_names: List[str] = []
    file_names: List[str] = []
    extensions: Counter[str] = Counter()
    sampled_count = 0
    truncated = False
    warnings: List[str] = []

    try:
        sampled = bounded_scandir_names(safe_directory, _MAX_SNAPSHOT_ENTRIES)
        if sampled.error is not None:
            warnings.append(
                f"Could not enumerate directory {_evidence_safe_path(root, safe_directory)[0]} after "
                f"{sampled.enumerated:,} enumeration operations: "
                f"{_sanitized_exception_summary(sampled.error)}"
            )
            names = []
            truncated = False
        else:
            truncated = sampled.truncated
            names = sorted(sampled.names, key=stable_text_key)
        for name in names:
            path = safe_directory / name
            try:
                safe_path = assert_contained_non_reparse(root, path)
                st = lstat_non_reparse(safe_path)
            except ForensicPathError as exc:
                warnings.append(_filesystem_warning("Skipped reparse/out-of-root snapshot entry", root, path, exc))
                continue
            except OSError as exc:
                warnings.append(_filesystem_warning("Could not inspect directory entry", root, path, exc))
                continue

            sampled_count += 1
            if stat.S_ISDIR(st.st_mode):
                if privacy_root:
                    platform = canonical_platform_name(name)
                    if platform is not None and platform not in directory_names and len(directory_names) < 150:
                        directory_names.append(platform)
                elif len(directory_names) < 150:
                    directory_names.append(name)
            elif stat.S_ISREG(st.st_mode):
                suffix = Path(name).suffix.casefold() or "<none>"
                extensions[suffix] += 1
                if not redact_filenames and len(file_names) < 150:
                    file_names.append(name)
        if truncated:
            warnings.append(
                f"Directory snapshot sample truncated at {safe_directory} after "
                f"{_MAX_SNAPSHOT_ENTRIES:,} entries."
            )
    except OSError as exc:
        warnings.append(_filesystem_warning("Could not enumerate directory", root, safe_directory, exc))

    return DirectorySnapshot(
        path=relative,
        directory_names=sorted(directory_names, key=stable_text_key),
        file_names=sorted(file_names, key=stable_text_key),
        file_extension_counts=dict(sorted(extensions.items())),
        entries_sampled=sampled_count,
        truncated=truncated,
        file_names_redacted=redact_filenames,
    ), warnings

def _directory_snapshots(root: Path) -> tuple[List[DirectorySnapshot], List[str]]:
    warnings: List[str] = []
    snapshots: List[DirectorySnapshot] = []
    top_dirs: List[Path] = []
    try:
        safe_root = assert_contained_non_reparse(root, root)
        sampled = bounded_scandir_names(safe_root, _MAX_TOP_LEVEL_SNAPSHOT_ENUM_ENTRIES)
        if sampled.error is not None:
            return [], [
                f"Could not enumerate top-level directories after "
                f"{sampled.enumerated:,} enumeration operations: "
                f"{_sanitized_exception_summary(sampled.error)}"
            ]
        names = sorted(sampled.names, key=stable_text_key)
    except ForensicPathError as exc:
        return [], [f"Could not enumerate top-level directories: {_sanitized_exception_summary(exc)}"]

    if sampled.truncated:
        warnings.append(
            f"Top-level snapshot discovery truncated after "
            f"{_MAX_TOP_LEVEL_SNAPSHOT_ENUM_ENTRIES:,} root entries."
        )

    for name in names:
        path = safe_root / name
        try:
            safe_path = assert_contained_non_reparse(root, path)
            st = lstat_non_reparse(safe_path)
            if stat.S_ISDIR(st.st_mode):
                top_dirs.append(safe_path)
                # One extra directory proves that the advertised snapshot count
                # is truncated without scanning the remainder of the root.
                if len(top_dirs) > _MAX_SNAPSHOT_DIRS:
                    break
        except ForensicPathError as exc:
            warnings.append(_filesystem_warning("Skipped reparse/out-of-root top-level entry", root, path, exc))
        except OSError as exc:
            warnings.append(_filesystem_warning("Could not inspect top-level entry", root, path, exc))

    top_dirs.sort(key=lambda p: stable_text_key(p.name))
    if len(top_dirs) > _MAX_SNAPSHOT_DIRS:
        warnings.append(
            f"Directory snapshots limited to {_MAX_SNAPSHOT_DIRS} top-level directories."
        )

    for directory in top_dirs[:_MAX_SNAPSHOT_DIRS]:
        try:
            snapshot, snapshot_warnings = _snapshot_directory(root, directory)
            snapshots.append(snapshot)
            warnings.extend(snapshot_warnings)
        except ForensicPathError as exc:
            warnings.append(_filesystem_warning("Directory snapshot skipped for", root, directory, exc))
        except Exception as exc:
            warnings.append(_filesystem_warning("Directory snapshot skipped for", root, directory, exc))
    return snapshots, warnings

def _as_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _partition_from_dict(data: Dict[str, Any]) -> DiskPartitionInfo:
    return DiskPartitionInfo(
        partition_number=data.get("PartitionNumber"),
        drive_letter=_as_optional_str(data.get("DriveLetter")),
        offset=data.get("Offset"),
        size=data.get("Size"),
        partition_type=_as_optional_str(data.get("Type")),
        gpt_type=_as_optional_str(data.get("GptType")),
        mbr_type=_as_optional_str(data.get("MbrType")),
        is_active=data.get("IsActive"),
        is_boot=data.get("IsBoot"),
        is_system=data.get("IsSystem"),
        filesystem=_as_optional_str(data.get("FileSystem")),
        filesystem_label=_as_optional_str(data.get("FileSystemLabel")),
    )


def _mapping_from_windows_payload(data: Dict[str, Any]) -> PhysicalMapping:
    raw_parts = data.get("Partitions") or []
    if isinstance(raw_parts, dict):
        raw_parts = [raw_parts]
    partitions = [_partition_from_dict(p) for p in raw_parts if isinstance(p, dict)]
    return PhysicalMapping(
        disk_number=data.get("DiskNumber"),
        partition_number=data.get("PartitionNumber"),
        disk_name=_as_optional_str(data.get("DiskName")),
        bus_type=_as_optional_str(data.get("BusType")),
        partition_style=_as_optional_str(data.get("PartitionStyle")),
        disk_size=data.get("DiskSize"),
        partition_size=data.get("PartitionSize"),
        partition_offset=data.get("PartitionOffset"),
        is_boot=data.get("IsBoot"),
        is_system=data.get("IsSystem"),
        serial_number=_as_optional_str(data.get("SerialNumber")),
        disk_unique_id=_as_optional_str(data.get("DiskUniqueId")),
        logical_sector_size=data.get("LogicalSectorSize"),
        physical_sector_size=data.get("PhysicalSectorSize"),
        is_read_only=data.get("IsReadOnly"),
        is_offline=data.get("IsOffline"),
        disk_health=_as_optional_str(data.get("DiskHealth")),
        disk_operational_status=_as_optional_str(data.get("DiskOperationalStatus")),
        filesystem=_as_optional_str(data.get("FileSystem")),
        filesystem_label=_as_optional_str(data.get("FileSystemLabel")),
        drive_type=_as_optional_str(data.get("DriveType")),
        volume_health=_as_optional_str(data.get("VolumeHealth")),
        partitions=partitions,
        mapping_backend=_as_optional_str(data.get("MappingBackend")),
    )


def _standard_windows_powershell_paths(system_root: str) -> List[str]:
    """Return canonical Windows PowerShell locations using Windows path semantics."""
    return [
        ntpath.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        # Sysnative bypasses WOW64 redirection for a 32-bit Python on 64-bit Windows.
        ntpath.join(system_root, "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
    ]


def _trusted_windows_directory() -> Optional[str]:
    """Resolve the Windows directory from kernel32, not inherited environment variables."""
    if platform.system() != "Windows":
        # Test/non-Windows fallback only; production Windows mapping uses GetWindowsDirectoryW.
        return os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
        if not length or length >= len(buffer):
            return None
        return buffer.value
    except Exception:
        return None


def _windows_powershell_candidates(
    *,
    elevated: Optional[bool] = None,
    windows_directory: Optional[str] = None,
) -> List[str]:
    """Return only trusted absolute Windows PowerShell executables.

    PATH lookup is intentionally not used in either standard-user or elevated mode.
    The ``elevated`` parameter is retained for API/test compatibility; trust policy is
    identical at both privilege levels.
    """
    del elevated
    candidates: List[str] = []
    seen = set()

    system_root = windows_directory or _trusted_windows_directory()
    if not system_root:
        return candidates

    for value in _standard_windows_powershell_paths(system_root):
        key = os.path.normcase(value)
        if key in seen or not os.path.isfile(value):
            continue
        seen.add(key)
        candidates.append(value)
    return candidates


def _run_windows_mapping_script(ps: str) -> tuple[Dict[str, Any], str]:
    candidates = _windows_powershell_candidates()
    if not candidates:
        system_root = _trusted_windows_directory() or "<unresolved Windows directory>"
        checked = ", ".join(_standard_windows_powershell_paths(system_root))
        raise FileNotFoundError(
            "No trusted canonical Windows PowerShell executable was found; PATH lookup is intentionally disabled. "
            f"Checked: {checked}"
        )

    failures: List[str] = []
    for executable in candidates:
        try:
            completed = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=12,
                check=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            payload_text = completed.stdout.strip()
            if not payload_text:
                raise ValueError("PowerShell returned no mapping JSON")
            data = json.loads(payload_text)
            if not isinstance(data, dict):
                raise ValueError("PowerShell returned an unexpected mapping payload")
            return data, executable
        except FileNotFoundError as exc:
            failures.append(f"{executable}: not found ({exc})")
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip().replace("\r", " ").replace("\n", " ")
            stdout = (exc.stdout or "").strip().replace("\r", " ").replace("\n", " ")
            detail = stderr or stdout or f"exit code {exc.returncode}"
            failures.append(f"{executable}: {detail[:500]}")
        except Exception as exc:
            failures.append(f"{executable}: {type(exc).__name__}: {exc}")

    raise RuntimeError("All PowerShell mapping backends failed: " + " | ".join(failures))


def _windows_physical_mapping(root: Path) -> PhysicalMapping:
    drive = root.drive.rstrip(":\\/")
    if len(drive) != 1 or drive.upper() not in string.ascii_uppercase:
        return PhysicalMapping(mapping_error="Selected path is not a Windows drive-letter volume.")

    ps = rf"""
$ErrorActionPreference = 'Stop'
$p = Get-Partition -DriveLetter '{drive.upper()}' | Select-Object -First 1
$d = Get-Disk -Number $p.DiskNumber
$v = Get-Volume -DriveLetter '{drive.upper()}' | Select-Object -First 1
$parts = @(
  Get-Partition -DiskNumber $p.DiskNumber | Sort-Object PartitionNumber | ForEach-Object {{
    $pv = $null
    try {{ $pv = $_ | Get-Volume -ErrorAction Stop }} catch {{}}
    [pscustomobject]@{{
      PartitionNumber=$_.PartitionNumber
      DriveLetter=[string]$_.DriveLetter
      Offset=$_.Offset
      Size=$_.Size
      Type=[string]$_.Type
      GptType=[string]$_.GptType
      MbrType=[string]$_.MbrType
      IsActive=$_.IsActive
      IsBoot=$_.IsBoot
      IsSystem=$_.IsSystem
      FileSystem=if ($pv) {{ [string]$pv.FileSystem }} else {{ $null }}
      FileSystemLabel=if ($pv) {{ [string]$pv.FileSystemLabel }} else {{ $null }}
    }}
  }}
)
[pscustomobject]@{{
  DiskNumber=$p.DiskNumber
  PartitionNumber=$p.PartitionNumber
  PartitionSize=$p.Size
  PartitionOffset=$p.Offset
  DiskName=$d.FriendlyName
  BusType=[string]$d.BusType
  PartitionStyle=[string]$d.PartitionStyle
  DiskSize=$d.Size
  IsBoot=$d.IsBoot
  IsSystem=$d.IsSystem
  SerialNumber=$d.SerialNumber
  DiskUniqueId=$d.UniqueId
  LogicalSectorSize=$d.LogicalSectorSize
  PhysicalSectorSize=$d.PhysicalSectorSize
  IsReadOnly=$d.IsReadOnly
  IsOffline=$d.IsOffline
  DiskHealth=[string]$d.HealthStatus
  DiskOperationalStatus=([string[]]$d.OperationalStatus -join ',')
  FileSystem=[string]$v.FileSystem
  FileSystemLabel=[string]$v.FileSystemLabel
  DriveType=[string]$v.DriveType
  VolumeHealth=[string]$v.HealthStatus
  Partitions=$parts
}} | ConvertTo-Json -Compress -Depth 6
"""
    try:
        data, backend = _run_windows_mapping_script(ps)
        data["MappingBackend"] = backend
        return _mapping_from_windows_payload(data)
    except Exception as exc:
        return PhysicalMapping(mapping_error=f"Physical disk mapping unavailable: {type(exc).__name__}: {exc}")


def _physical_mapping(root: Path) -> PhysicalMapping:
    if platform.system() == "Windows":
        return _windows_physical_mapping(root)
    return PhysicalMapping(mapping_error="Physical disk mapping is currently implemented for Windows only.")


def _read_issue_messages(messages: Iterable[str]) -> List[str]:
    """Select warnings that represent actual filesystem/read failures."""
    markers = (
        "Could not ",
        " skipped:",
        "unreadable",
        "corrupt",
    )
    return [message for message in messages if any(marker.casefold() in message.casefold() for marker in markers)]


def inspect_volume(path: str | Path) -> ProbeReport:
    """Probe a mounted GameStick volume without allowing corrupt files to abort progress.

    Safety-critical identity/mapping is collected independently from forensic
    enrichment. Filesystem corruption encountered during enrichment is recorded
    as warnings/read errors and yields a DEGRADED report rather than an exception.
    """
    root = assert_readable_root(path)
    warnings: List[str] = []
    read_errors: List[str] = []

    try:
        usage = shutil.disk_usage(root)
        total, used, free = usage.total, usage.used, usage.free
    except OSError as exc:
        total = used = free = None
        message = f"Could not read filesystem usage: {_sanitized_exception_summary(exc)}"
        warnings.append(message)
        read_errors.append(message)

    # Safety-critical identity is deliberately obtained before deep filesystem
    # enrichment so a corrupt metadata file cannot invalidate disk mapping.
    try:
        candidates = profile_matches(root)
        profile = best_profile_from_matches(candidates)
    except Exception as exc:
        candidates = []
        from .models import ProfileMatch
        profile = ProfileMatch(
            profile_id="unknown",
            display_name="Unknown / unsupported layout",
            score=0,
            confidence="none",
            matched_markers=[],
            missing_markers=[],
        )
        warnings.append(f"Profile scoring degraded: {_sanitized_exception_summary(exc)}")

    try:
        mapping = _physical_mapping(root)
    except Exception as exc:
        mapping = PhysicalMapping(mapping_error=f"Physical disk mapping unavailable: {type(exc).__name__}: {exc}")

    try:
        entries, root_warnings = _root_entries(root)
        warnings.extend(root_warnings)
        read_errors.extend(_read_issue_messages(root_warnings))
    except Exception as exc:
        entries = []
        message = f"Root structure scan skipped: {_sanitized_exception_summary(exc)}"
        warnings.append(message)
        read_errors.append(message)

    try:
        snapshots, snapshot_warnings = _directory_snapshots(root)
        warnings.extend(snapshot_warnings)
        read_errors.extend(_read_issue_messages(snapshot_warnings))
    except Exception as exc:
        snapshots = []
        message = f"Directory snapshot enrichment skipped: {_sanitized_exception_summary(exc)}"
        warnings.append(message)
        read_errors.append(message)

    try:
        artifacts, artifact_warnings = _candidate_artifacts(root)
        warnings.extend(artifact_warnings)
        read_errors.extend(_read_issue_messages(artifact_warnings))
    except Exception as exc:
        artifacts = []
        message = f"Metadata enrichment skipped: {_sanitized_exception_summary(exc)}"
        warnings.append(message)
        read_errors.append(message)

    try:
        device_profile_candidate = build_device_profile_candidate(
            profile=profile,
            structure_sha256=_structure_hash(entries),
            artifacts=artifacts,
            snapshots=snapshots,
        )
    except Exception as exc:
        device_profile_candidate = None
        warnings.append(
            f"Device Profile candidate synthesis skipped: {_sanitized_exception_summary(exc)}"
        )

    if profile.profile_id == "unknown":
        warnings.append("No supported filesystem profile matched with useful confidence. Read-only inspection only.")
    if mapping.is_boot is True or mapping.is_system is True:
        warnings.append("DANGER: selected volume maps to a boot/system disk. Destructive operations must never target it.")
    if mapping.is_read_only is False:
        warnings.append(
            "Host reports the physical disk as writable. This application still performs read-only probing only."
        )

    # Avoid duplicates while retaining the first occurrence/order.
    read_errors = list(dict.fromkeys(read_errors))
    probe_status = "DEGRADED" if read_errors else "COMPLETE"

    return ProbeReport(
        schema_version=9,
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        platform=platform.platform(),
        selected_root=str(root),
        volume_total=total,
        volume_used=used,
        volume_free=free,
        root_entries=entries,
        directory_snapshots=snapshots,
        profile=profile,
        profile_candidates=candidates,
        physical_mapping=mapping,
        candidate_artifacts=artifacts,
        warnings=warnings,
        structure_sha256=_structure_hash(entries),
        probe_status=probe_status,
        read_errors=read_errors,
        probe_policy={
            "device_write_paths_enabled": False,
            "raw_device_access_used": False,
            "rom_tree_recursive_scan": False,
            "rom_filenames_exported_from_rom_root": False,
            "artwork_filenames_exported_from_artwork_root": False,
            "privacy_library_child_names_exported_arbitrarily": False,
            "platform_directory_evidence_allowlisted": True,
            "privacy_redacted_filesystem_diagnostics": True,
            "forensic_enrichment_best_effort": True,
            "device_profile_candidate_read_only": True,
            "device_profile_candidate_additional_filesystem_traversal": False,
            "default_metadata_evidence_exports_arbitrary_names": False,
            "csv_semantics_can_independently_elevate_probable": False,
            "corrupt_entries_are_nonfatal": True,
            "max_metadata_scan_files": _MAX_SCAN_FILES,
            "max_metadata_enumerated_entries": _MAX_SCAN_ENUMERATED_ENTRIES,
            "max_metadata_entries_per_directory": _MAX_SCAN_ENTRIES_PER_DIRECTORY,
            "max_metadata_scan_depth": _MAX_SCAN_DEPTH,
            "max_root_entries": _MAX_ROOT_ENTRIES,
            "max_snapshot_directories": _MAX_SNAPSHOT_DIRS,
            "max_top_level_snapshot_enumeration": _MAX_TOP_LEVEL_SNAPSHOT_ENUM_ENTRIES,
            "max_snapshot_entries_per_directory": _MAX_SNAPSHOT_ENTRIES,
            "directory_enumeration_is_bounded": True,
            "max_auto_detect_candidates": _MAX_AUTO_DETECT_CANDIDATES,
            "max_linux_mountinfo_lines": _MAX_LINUX_MOUNTINFO_LINES,
            "max_linux_fallback_enumerated_entries": _MAX_LINUX_FALLBACK_ENUMERATED_ENTRIES,
            "max_macos_volume_entries": _MAX_MACOS_VOLUME_ENTRIES,
            "max_hashed_artifact_bytes": _MAX_HASH_BYTES,
        },
        device_profile_candidate=device_profile_candidate,
    )


def _decode_linux_mountinfo_path(value: str) -> str:
    """Decode the octal escapes used in /proc/*/mountinfo path fields."""
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _linux_mountinfo_lines() -> Iterable[str]:
    """Yield a bounded number of mountinfo lines from the current mount namespace."""
    with Path("/proc/self/mountinfo").open("r", encoding="utf-8", errors="replace") as handle:
        yield from islice(handle, _MAX_LINUX_MOUNTINFO_LINES)


def _linux_mount_is_candidate(path: Path) -> bool:
    """Preserve the old /media,/run/media,/mnt discovery scope without walking it."""
    lexical = Path(os.path.abspath(os.fspath(path)))
    for base in _LINUX_MOUNT_BASES:
        base_abs = Path(os.path.abspath(os.fspath(base)))
        try:
            relative = lexical.relative_to(base_abs)
        except ValueError:
            continue
        # The old walker yielded levels one and two below each mount base.
        depth = len(relative.parts)
        if 1 <= depth <= 2:
            return True
    return False


def _iter_linux_mountinfo_roots() -> Iterable[Path]:
    yielded = 0
    seen: set[str] = set()
    for line in _linux_mountinfo_lines():
        fields = line.rstrip("\n").split()
        if len(fields) < 6:
            continue
        mount_point = Path(_decode_linux_mountinfo_path(fields[4]))
        if not _linux_mount_is_candidate(mount_point):
            continue
        key = os.path.normcase(os.path.abspath(os.fspath(mount_point)))
        if key in seen:
            continue
        seen.add(key)
        yield mount_point
        yielded += 1
        if yielded >= _MAX_AUTO_DETECT_CANDIDATES:
            break


def _iter_linux_fallback_roots() -> Iterable[Path]:
    """Bounded fallback for Linux environments without /proc/self/mountinfo.

    No recursive os.walk() is used. Enumeration work across all three historical
    mount bases shares one hard global iterator-operation budget.
    """
    remaining_ops = _MAX_LINUX_FALLBACK_ENUMERATED_ENTRIES
    yielded = 0
    seen: set[str] = set()

    for base in _LINUX_MOUNT_BASES:
        if remaining_ops <= 1 or yielded >= _MAX_AUTO_DETECT_CANDIDATES:
            break
        try:
            safe_base = assert_contained_non_reparse(base, base)
        except (OSError, ForensicPathError):
            continue

        first_limit = min(_MAX_LINUX_FALLBACK_ENTRIES_PER_DIRECTORY, remaining_ops - 1)
        first = bounded_scandir_names(safe_base, first_limit)
        remaining_ops -= first.enumerated
        if first.error is not None:
            continue

        for first_name in first.names:
            if yielded >= _MAX_AUTO_DETECT_CANDIDATES or remaining_ops <= 1:
                break
            first_path = safe_base / first_name
            try:
                safe_first = assert_contained_non_reparse(safe_base, first_path)
                first_st = lstat_non_reparse(safe_first)
            except (OSError, ForensicPathError):
                continue
            if not stat.S_ISDIR(first_st.st_mode):
                continue

            key = os.path.normcase(os.path.abspath(os.fspath(safe_first)))
            if key not in seen:
                seen.add(key)
                yield safe_first
                yielded += 1
                if yielded >= _MAX_AUTO_DETECT_CANDIDATES:
                    break

            second_limit = min(_MAX_LINUX_FALLBACK_ENTRIES_PER_DIRECTORY, remaining_ops - 1)
            if second_limit < 0:
                break
            second = bounded_scandir_names(safe_first, second_limit)
            remaining_ops -= second.enumerated
            if second.error is not None:
                continue
            for second_name in second.names:
                if yielded >= _MAX_AUTO_DETECT_CANDIDATES:
                    break
                second_path = safe_first / second_name
                try:
                    safe_second = assert_contained_non_reparse(safe_base, second_path)
                    second_st = lstat_non_reparse(safe_second)
                except (OSError, ForensicPathError):
                    continue
                if not stat.S_ISDIR(second_st.st_mode):
                    continue
                key = os.path.normcase(os.path.abspath(os.fspath(safe_second)))
                if key in seen:
                    continue
                seen.add(key)
                yield safe_second
                yielded += 1


def _iter_macos_volume_roots() -> Iterable[Path]:
    base = _MACOS_VOLUMES_ROOT
    try:
        safe_base = assert_contained_non_reparse(base, base)
        sampled = bounded_scandir_names(
            safe_base,
            min(_MAX_MACOS_VOLUME_ENTRIES, _MAX_AUTO_DETECT_CANDIDATES),
        )
    except (OSError, ForensicPathError):
        return
    if sampled.error is not None:
        return

    yielded = 0
    for name in sampled.names:
        if yielded >= _MAX_AUTO_DETECT_CANDIDATES:
            break
        child = safe_base / name
        try:
            safe_child = assert_contained_non_reparse(safe_base, child)
            st = lstat_non_reparse(safe_child)
        except (OSError, ForensicPathError):
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue
        yield safe_child
        yielded += 1


def iter_mount_roots() -> Iterable[Path]:
    """Yield bounded candidate mount roots without recursive hostile-tree walking."""
    system = platform.system()
    if system == "Windows":
        # Windows drive-letter discovery is intrinsically bounded to 26 letters.
        try:
            mask = __import__("ctypes").windll.kernel32.GetLogicalDrives()
            for index, letter in enumerate(string.ascii_uppercase):
                if mask & (1 << index):
                    yield Path(f"{letter}:\\")
        except Exception:
            for letter in string.ascii_uppercase:
                root = Path(f"{letter}:\\")
                if root.exists():
                    yield root
    elif system == "Darwin":
        yield from _iter_macos_volume_roots()
    else:
        try:
            yield from _iter_linux_mountinfo_roots()
        except OSError:
            # Some minimal/non-proc environments still need discovery, but the
            # fallback is explicitly shallow and globally budgeted.
            yield from _iter_linux_fallback_roots()


def find_candidate_volumes(min_score: int = 40) -> List[tuple[Path, object]]:
    """Profile at most the configured number of unique auto-detect candidates."""
    candidates = []
    seen = set()
    profile_probes = 0
    for root in islice(iter_mount_roots(), _MAX_AUTO_DETECT_CANDIDATES):
        # Dedupe lexically; do not canonicalize an untrusted auto-detect root
        # before the profile layer applies its non-reparse containment policy.
        key = os.path.normcase(os.path.abspath(os.fspath(root)))
        if key in seen:
            continue
        seen.add(key)
        profile_probes += 1
        try:
            match = best_profile(root)
            if match.score >= min_score:
                mapping = _physical_mapping(root)
                if mapping.is_boot is True or mapping.is_system is True:
                    continue
                candidates.append((root, match))
        except (OSError, PermissionError, ForensicPathError):
            continue
    candidates.sort(key=lambda pair: pair[1].score, reverse=True)
    return candidates
