from __future__ import annotations

import csv
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
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote

from .fs_safety import (
    ForensicPathError,
    assert_contained_non_reparse,
    bounded_scandir_names,
    lstat_non_reparse,
)
from .models import (
    CandidateArtifact,
    DirectorySnapshot,
    DiskPartitionInfo,
    PhysicalMapping,
    ProbeReport,
)
from .profiles import best_profile_from_matches, profile_matches
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
_ROM_LIKE_DIRS = {"rom", "roms", "games"}
_TEXT_CONFIG_SUFFIXES = {".ini", ".cfg", ".conf"}


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
                f"Could not enumerate volume root {root} after "
                f"{sampled.enumerated:,} enumeration operations: {sampled.error}"
            ]
        names = sorted(sampled.names, key=str.casefold)
    except ForensicPathError as exc:
        return [], [f"Could not enumerate volume root {root}: {exc}"]

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
            warnings.append(f"Skipped reparse/out-of-root entry {item}: {exc}")
        except OSError as exc:
            message = f"Could not inspect root entry {item}: {exc}"
            warnings.append(message)
            entries.append({"name": item.name, "type": "unreadable", "error": str(exc)})
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
            by_type: Dict[str, List[str]] = {}
            for object_type, name in rows:
                by_type.setdefault(str(object_type), []).append(str(name))
            details["schema_objects"] = by_type
            details["schema_object_count"] = len(rows)
        finally:
            connection.close()
    except sqlite3.Error as exc:
        details["schema_read_error"] = str(exc)
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
        first_line = sample.splitlines()[0] if sample.splitlines() else ""
        fields = next(csv.reader([first_line], delimiter=delimiter), [])
        details["delimiter"] = "\\t" if delimiter == "\t" else delimiter
        details["header_fields"] = [field.strip()[:80] for field in fields[:80]]
        details["header_field_count"] = len(fields)
    except (OSError, UnicodeError, csv.Error) as exc:
        details["analysis_error"] = str(exc)
    return details


def _analyze_json(path: Path, size: int) -> Dict[str, Any]:
    if size > _MAX_ANALYSIS_BYTES:
        return {"analysis_skipped": f"JSON larger than {_MAX_ANALYSIS_BYTES} bytes"}
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            payload = json.load(handle)
        if isinstance(payload, dict):
            return {"top_level_type": "object", "top_level_keys": [str(k) for k in list(payload)[:100]]}
        if isinstance(payload, list):
            return {"top_level_type": "array", "top_level_length": len(payload)}
        return {"top_level_type": type(payload).__name__}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {"analysis_error": str(exc)}


def _analyze_xml(path: Path) -> Dict[str, Any]:
    try:
        text = _safe_text_prefix(path, 32 * 1024)
        # Skip XML declarations/comments and capture only the first element name.
        match = re.search(r"<(?!\?|!)([A-Za-z_][\w:.-]*)\b", text)
        return {"root_element": match.group(1) if match else None}
    except OSError as exc:
        return {"analysis_error": str(exc)}


def _analyze_text_config(path: Path) -> Dict[str, Any]:
    try:
        text = _safe_text_prefix(path)
        sections: List[str] = []
        keys: List[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            if stripped.startswith("[") and "]" in stripped:
                sections.append(stripped[1:stripped.index("]")][:100])
                continue
            match = re.match(r"([^=:#]{1,100})\s*[=:#]", stripped)
            if match:
                keys.append(match.group(1).strip())
            if len(sections) >= 100 and len(keys) >= 100:
                break
        return {
            "sections": sections[:100],
            "key_names": keys[:100],
        }
    except OSError as exc:
        return {"analysis_error": str(exc)}


def _artifact_format_and_details(path: Path, size: int) -> tuple[str, Dict[str, Any]]:
    try:
        with path.open("rb") as handle:
            header = handle.read(64)
    except OSError as exc:
        return "unreadable", {"analysis_error": str(exc)}

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
        return "database-extension/non-sqlite", {"header_hex": header[:16].hex()}
    if suffix == ".dat":
        # DAT is intentionally treated as opaque until the real device tells us more.
        return "opaque-dat", {"header_hex": header[:16].hex()}
    return "unknown", {"header_hex": header[:16].hex()}


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
                    f"Could not enumerate {safe_current} after "
                    f"{sampled.enumerated:,} enumeration operations: {sampled.error}"
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
            names = sorted(sampled.names, key=str.casefold)
        except ForensicPathError as exc:
            warnings.append(f"Skipped reparse/out-of-root directory {current_path}: {exc}")
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
                warnings.append(f"Skipped reparse/out-of-root entry {path}: {exc}")
                continue
            except OSError as exc:
                warnings.append(f"Could not inspect directory entry {path}: {exc}")
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
                results.sort(key=lambda x: x.path.casefold())
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
                    results.sort(key=lambda x: x.path.casefold())
                    return results, warnings
            except ForensicPathError as exc:
                warnings.append(f"Metadata candidate escaped forensic root and was skipped {safe_path}: {exc}")
            except OSError as exc:
                warnings.append(f"Could not inspect {safe_path}: {exc}")
            except Exception as exc:
                warnings.append(
                    f"Metadata analysis skipped for {safe_path}: {type(exc).__name__}: {exc}"
                )

        # Reverse push preserves the sorted order of the bounded sample with a LIFO stack.
        for child in reversed(child_dirs):
            stack.append((child, depth + 1))

    results.sort(key=lambda x: x.path.casefold())
    return results, warnings

def _snapshot_directory(root: Path, directory: Path) -> tuple[DirectorySnapshot, List[str]]:
    safe_directory = assert_contained_non_reparse(root, directory)
    resolved_root = root.resolve(strict=True)
    relative = str(safe_directory.relative_to(resolved_root))
    redact_filenames = safe_directory.name.casefold() in _ROM_LIKE_DIRS
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
                f"Could not enumerate directory {safe_directory} after "
                f"{sampled.enumerated:,} enumeration operations: {sampled.error}"
            )
            names = []
            truncated = False
        else:
            truncated = sampled.truncated
            names = sorted(sampled.names, key=str.casefold)
        for name in names:
            path = safe_directory / name
            try:
                safe_path = assert_contained_non_reparse(root, path)
                st = lstat_non_reparse(safe_path)
            except ForensicPathError as exc:
                warnings.append(f"Skipped reparse/out-of-root snapshot entry {path}: {exc}")
                continue
            except OSError as exc:
                warnings.append(f"Could not inspect directory entry {path}: {exc}")
                continue

            sampled_count += 1
            if stat.S_ISDIR(st.st_mode):
                if len(directory_names) < 150:
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
        warnings.append(f"Could not enumerate directory {safe_directory}: {exc}")

    return DirectorySnapshot(
        path=relative,
        directory_names=sorted(directory_names, key=str.casefold),
        file_names=sorted(file_names, key=str.casefold),
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
                f"{sampled.enumerated:,} enumeration operations: {sampled.error}"
            ]
        names = sorted(sampled.names, key=str.casefold)
    except ForensicPathError as exc:
        return [], [f"Could not enumerate top-level directories: {exc}"]

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
            warnings.append(f"Skipped reparse/out-of-root top-level entry {path}: {exc}")
        except OSError as exc:
            warnings.append(f"Could not inspect top-level entry {path}: {exc}")

    top_dirs.sort(key=lambda p: p.name.casefold())
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
            warnings.append(f"Directory snapshot skipped for {directory}: {exc}")
        except Exception as exc:
            warnings.append(f"Directory snapshot skipped for {directory}: {type(exc).__name__}: {exc}")
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
        message = f"Could not read filesystem usage: {exc}"
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
        warnings.append(f"Profile scoring degraded: {type(exc).__name__}: {exc}")

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
        message = f"Root structure scan skipped: {type(exc).__name__}: {exc}"
        warnings.append(message)
        read_errors.append(message)

    try:
        snapshots, snapshot_warnings = _directory_snapshots(root)
        warnings.extend(snapshot_warnings)
        read_errors.extend(_read_issue_messages(snapshot_warnings))
    except Exception as exc:
        snapshots = []
        message = f"Directory snapshot enrichment skipped: {type(exc).__name__}: {exc}"
        warnings.append(message)
        read_errors.append(message)

    try:
        artifacts, artifact_warnings = _candidate_artifacts(root)
        warnings.extend(artifact_warnings)
        read_errors.extend(_read_issue_messages(artifact_warnings))
    except Exception as exc:
        artifacts = []
        message = f"Metadata enrichment skipped: {type(exc).__name__}: {exc}"
        warnings.append(message)
        read_errors.append(message)

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
        schema_version=3,
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
            "forensic_enrichment_best_effort": True,
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
            "max_hashed_artifact_bytes": _MAX_HASH_BYTES,
        },
    )


def iter_mount_roots() -> Iterable[Path]:
    system = platform.system()
    if system == "Windows":
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
        base = Path("/Volumes")
        if base.exists():
            yield from (p for p in base.iterdir() if p.is_dir())
    else:
        for base in (Path("/media"), Path("/run/media"), Path("/mnt")):
            if not base.exists():
                continue
            for current, dirs, _ in os.walk(base):
                current_path = Path(current)
                depth = len(current_path.relative_to(base).parts)
                if depth > 2:
                    dirs[:] = []
                    continue
                if current_path != base:
                    yield current_path


def find_candidate_volumes(min_score: int = 40) -> List[tuple[Path, object]]:
    candidates = []
    seen = set()
    for root in iter_mount_roots():
        try:
            resolved = str(root.resolve())
        except OSError:
            resolved = str(root)
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            match = best_profile(root)
            if match.score >= min_score:
                mapping = _physical_mapping(root)
                if mapping.is_boot is True or mapping.is_system is True:
                    continue
                candidates.append((root, match))
        except (OSError, PermissionError):
            continue
    candidates.sort(key=lambda pair: pair[1].score, reverse=True)
    return candidates
