from __future__ import annotations

import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Mapping, Set

from .fs_safety import ForensicPathError, assert_contained_non_reparse, bounded_scandir_names, lstat_non_reparse
from .ordering import stable_text_key
from .wqw import WqwPrivateEvidence

_MAX_AUDIT_CATALOGUES = 64
_MAX_AUDIT_ENTRIES_PER_DIRECTORY = 10_000
_ALIAS_RESOLUTION_THRESHOLD_PPM = 950_000
_ALIAS_PRIMARY_TARGET_THRESHOLD_PPM = 950_000


def catalogue_audit_limits() -> Dict[str, int]:
    return {
        "max_catalogues": _MAX_AUDIT_CATALOGUES,
        "max_entries_per_directory": _MAX_AUDIT_ENTRIES_PER_DIRECTORY,
        "alias_resolution_threshold_ppm": _ALIAS_RESOLUTION_THRESHOLD_PPM,
        "alias_primary_target_threshold_ppm": _ALIAS_PRIMARY_TARGET_THRESHOLD_PPM,
    }


def _error_fields(exc: BaseException) -> Dict[str, object]:
    result: Dict[str, object] = {"error_type": type(exc).__name__}
    if isinstance(exc, OSError) and isinstance(exc.errno, int):
        result["error_errno"] = exc.errno
    return result


def _normalize_name(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].casefold()


@dataclass
class _FsObservation:
    row: Dict[str, object]
    readable_names: Set[str] = field(default_factory=set)
    unreadable_names: Set[str] = field(default_factory=set)
    rejected_names: Set[str] = field(default_factory=set)


def _observe_one_directory(root: Path, code: str) -> _FsObservation:
    row: Dict[str, object] = {
        "catalogue_code": code,
        "filesystem_enumeration_complete": False,
        "filesystem_enumeration_truncated": False,
        "filesystem_enumeration_operations": 0,
        "readable_content_file_count": 0,
        "readable_content_unique_name_count": 0,
        "unreadable_entry_count": 0,
        "rejected_entry_count": 0,
        "subdirectory_count": 0,
        "other_entry_count": 0,
        "arbitrary_names_exported": False,
    }
    observation = _FsObservation(row=row)
    try:
        safe_root = assert_contained_non_reparse(root, root)
        directory = assert_contained_non_reparse(root, safe_root / code)
        st = lstat_non_reparse(directory)
        if not stat.S_ISDIR(st.st_mode):
            row["directory_observation_status"] = "CATALOGUE_DIRECTORY_UNAVAILABLE"
            return observation
        sampled = bounded_scandir_names(directory, _MAX_AUDIT_ENTRIES_PER_DIRECTORY)
    except (OSError, ForensicPathError) as exc:
        row["directory_observation_status"] = "CATALOGUE_DIRECTORY_UNAVAILABLE"
        row.update(_error_fields(exc))
        return observation

    row["filesystem_enumeration_operations"] = sampled.enumerated
    row["filesystem_enumeration_truncated"] = sampled.truncated
    row["filesystem_enumeration_complete"] = sampled.error is None and not sampled.truncated
    row["directory_observation_status"] = "PARTIAL" if sampled.error is not None or sampled.truncated else "COMPLETE"
    if sampled.error is not None:
        row.update(_error_fields(sampled.error))

    dat_name = f"{code}.dat".casefold()
    subdirectories = 0
    other_entries = 0
    for name in sorted(sampled.names, key=stable_text_key):
        normalized_name = _normalize_name(name)
        if normalized_name == dat_name:
            continue
        candidate = directory / name
        try:
            safe_candidate = assert_contained_non_reparse(root, candidate)
            entry_stat = lstat_non_reparse(safe_candidate)
        except ForensicPathError:
            observation.rejected_names.add(normalized_name)
            continue
        except OSError:
            observation.unreadable_names.add(normalized_name)
            continue

        if stat.S_ISREG(entry_stat.st_mode):
            observation.readable_names.add(normalized_name)
        elif stat.S_ISDIR(entry_stat.st_mode):
            subdirectories += 1
        else:
            other_entries += 1

    row["readable_content_file_count"] = len(observation.readable_names)
    row["readable_content_unique_name_count"] = len(observation.readable_names)
    row["unreadable_entry_count"] = len(observation.unreadable_names)
    row["rejected_entry_count"] = len(observation.rejected_names)
    row["subdirectory_count"] = subdirectories
    row["other_entry_count"] = other_entries
    return observation


def _populate_catalogue_counts(
    observation: _FsObservation,
    local_names: Set[str] | None,
    global_names: Set[str] | None,
) -> None:
    row = observation.row
    local = set(local_names or ())
    global_set = set(global_names or ())
    readable = observation.readable_names
    unreadable = observation.unreadable_names
    rejected = observation.rejected_names

    row.update({
        "local_catalogue_available": local_names is not None,
        "global_catalogue_available": global_names is not None,
        "filelist_unique_rom_name_count": len(local),
        "global_unique_rom_name_count": len(global_set),
        "readable_filelist_unique_match_count": 0,
        "readable_global_unique_match_count": 0,
        "present_local_global_unique_match_count": 0,
        "readable_not_filelist_count": 0,
        "filelist_missing_from_readable_count": 0,
        "filelist_missing_but_seen_unreadable_count": 0,
        "filelist_missing_from_filesystem_observation_count": 0,
        "filelist_unique_missing_from_global_count": 0,
        "global_unique_missing_from_filelist_count": 0,
        "unreadable_entry_name_matches_filelist_count": 0,
        "rejected_entry_name_matches_filelist_count": 0,
        "cross_catalogue_resolved_unique_name_count": 0,
        "cross_catalogue_unresolved_unique_name_count": 0,
        "cross_catalogue_ambiguous_unique_name_count": 0,
        "cross_catalogue_resolution_counts": {},
        "cross_catalogue_missing_unique_name_count": 0,
        "cross_catalogue_resolution_rate_ppm": 0,
        "cross_catalogue_primary_target_code": None,
        "cross_catalogue_primary_target_match_count": 0,
        "cross_catalogue_primary_target_resolution_rate_ppm": 0,
        "readable_not_local_but_referenced_elsewhere_count": 0,
        "readable_unreferenced_by_any_local_catalogue_count": 0,
    })

    if local_names is not None:
        row["readable_filelist_unique_match_count"] = len(readable & local)
        row["readable_not_filelist_count"] = len(readable - local)
        missing_readable = local - readable
        row["filelist_missing_from_readable_count"] = len(missing_readable)
        row["filelist_missing_but_seen_unreadable_count"] = len(missing_readable & unreadable)
        row["filelist_missing_from_filesystem_observation_count"] = len(missing_readable - unreadable - rejected)
        row["unreadable_entry_name_matches_filelist_count"] = len(unreadable & local)
        row["rejected_entry_name_matches_filelist_count"] = len(rejected & local)
    if global_names is not None:
        row["readable_global_unique_match_count"] = len(readable & global_set)
    if local_names is not None and global_names is not None:
        row["present_local_global_unique_match_count"] = len(readable & local & global_set)
        row["filelist_unique_missing_from_global_count"] = len(local - global_set)
        row["global_unique_missing_from_filelist_count"] = len(global_set - local)


def _apply_cross_catalogue_aliases(
    code: str,
    observation: _FsObservation,
    observations: Mapping[str, _FsObservation],
    local_sets: Mapping[str, Set[str] | None],
) -> None:
    row = observation.row
    local = local_sets.get(code)
    if local is None:
        return

    own_seen = observation.readable_names | observation.unreadable_names | observation.rejected_names
    missing_from_own_observation = set(local) - own_seen
    resolution_counts: Dict[str, int] = {}
    resolved = 0
    ambiguous = 0
    for name in missing_from_own_observation:
        targets = [
            other_code
            for other_code, other_observation in observations.items()
            if other_code != code and name in other_observation.readable_names
        ]
        if targets:
            resolved += 1
            if len(targets) > 1:
                ambiguous += 1
            for target in targets:
                resolution_counts[target] = resolution_counts.get(target, 0) + 1

    other_local_union: Set[str] = set()
    for other_code, other_local in local_sets.items():
        if other_code != code and other_local is not None:
            other_local_union.update(other_local)
    extras = observation.readable_names - set(local)
    referenced_extras = extras & other_local_union

    missing_count = len(missing_from_own_observation)
    unresolved = missing_count - resolved
    primary_target = None
    primary_count = 0
    if resolution_counts:
        primary_target, primary_count = sorted(
            resolution_counts.items(),
            key=lambda item: (-item[1], stable_text_key(item[0])),
        )[0]
    row["cross_catalogue_resolved_unique_name_count"] = resolved
    row["cross_catalogue_unresolved_unique_name_count"] = unresolved
    row["cross_catalogue_ambiguous_unique_name_count"] = ambiguous
    row["cross_catalogue_resolution_counts"] = dict(
        sorted(resolution_counts.items(), key=lambda item: stable_text_key(item[0]))
    )
    row["cross_catalogue_missing_unique_name_count"] = missing_count
    row["cross_catalogue_resolution_rate_ppm"] = (resolved * 1_000_000 // missing_count) if missing_count else 0
    row["cross_catalogue_primary_target_code"] = primary_target
    row["cross_catalogue_primary_target_match_count"] = primary_count
    row["cross_catalogue_primary_target_resolution_rate_ppm"] = (primary_count * 1_000_000 // resolved) if resolved else 0
    row["readable_not_local_but_referenced_elsewhere_count"] = len(referenced_extras)
    row["readable_unreferenced_by_any_local_catalogue_count"] = len(extras - referenced_extras)


def _classify(observation: _FsObservation) -> str:
    row = observation.row
    if row.get("directory_observation_status") == "CATALOGUE_DIRECTORY_UNAVAILABLE":
        return "CATALOGUE_DIRECTORY_UNAVAILABLE"
    if row.get("directory_observation_status") == "PARTIAL":
        return "PARTIAL"
    if not row.get("local_catalogue_available"):
        return "CATALOGUE_UNAVAILABLE"

    unresolved_local = int(row.get("cross_catalogue_unresolved_unique_name_count", 0))
    unreferenced_extra = int(row.get("readable_unreferenced_by_any_local_catalogue_count", 0))
    local_not_global = int(row.get("filelist_unique_missing_from_global_count", 0))
    global_not_local = int(row.get("global_unique_missing_from_filelist_count", 0))
    read_errors_matching = (
        int(row.get("filelist_missing_but_seen_unreadable_count", 0))
        + int(row.get("rejected_entry_name_matches_filelist_count", 0))
    )
    aliases = int(row.get("cross_catalogue_resolved_unique_name_count", 0))
    shared_extras = int(row.get("readable_not_local_but_referenced_elsewhere_count", 0))

    alias_resolution_rate = int(row.get("cross_catalogue_resolution_rate_ppm", 0))
    primary_resolution_rate = int(row.get("cross_catalogue_primary_target_resolution_rate_ppm", 0))
    dominant_alias_with_residual = bool(
        aliases
        and unresolved_local
        and alias_resolution_rate >= _ALIAS_RESOLUTION_THRESHOLD_PPM
        and primary_resolution_rate >= _ALIAS_PRIMARY_TARGET_THRESHOLD_PPM
        and not any((unreferenced_extra, local_not_global, global_not_local))
    )
    if dominant_alias_with_residual:
        if read_errors_matching:
            return "READ_ERRORS_AND_ALIAS_WITH_RESIDUAL_GAP"
        return "CROSS_CATALOGUE_ALIAS_WITH_RESIDUAL_GAP"
    if any((unresolved_local, unreferenced_extra, local_not_global, global_not_local)):
        return "MISMATCH_OBSERVED"
    if aliases and read_errors_matching:
        return "READ_ERRORS_AND_ALIAS_ACCOUNT_FOR_GAP"
    if aliases or shared_extras:
        return "CROSS_CATALOGUE_ALIAS"
    if read_errors_matching:
        return "READ_ERRORS_ACCOUNT_FOR_GAP"
    return "MATCHED"


def audit_numbered_catalogues(
    root: Path,
    catalogue_codes: Iterable[str],
    platform_private: Mapping[str, WqwPrivateEvidence],
    root_private: WqwPrivateEvidence | None,
) -> Dict[str, object]:
    codes = sorted({str(code) for code in catalogue_codes}, key=stable_text_key)[:_MAX_AUDIT_CATALOGUES]
    observations: Dict[str, _FsObservation] = {code: _observe_one_directory(root, code) for code in codes}
    local_sets: Dict[str, Set[str] | None] = {
        code: (set(platform_private[code].filelist_rom_names) if code in platform_private else None)
        for code in codes
    }
    global_sets: Dict[str, Set[str] | None] = {
        code: (set(root_private.fileinfo_paths_by_code.get(code, set())) if root_private is not None else None)
        for code in codes
    }

    for code in codes:
        _populate_catalogue_counts(observations[code], local_sets[code], global_sets[code])
    for code in codes:
        _apply_cross_catalogue_aliases(code, observations[code], observations, local_sets)

    by_code: Dict[str, Dict[str, object]] = {}
    status_counts: Dict[str, int] = {}
    alias_edges: Dict[str, Dict[str, int]] = {}
    for code in codes:
        row = observations[code].row
        status = _classify(observations[code])
        row["audit_status"] = status
        by_code[code] = row
        status_counts[status] = status_counts.get(status, 0) + 1
        resolutions = row.get("cross_catalogue_resolution_counts", {})
        if isinstance(resolutions, dict) and resolutions:
            alias_edges[code] = dict(resolutions)

    return {
        "schema": "catalogue-filesystem-consistency-v3",
        "catalogue_count": len(codes),
        "max_catalogues": _MAX_AUDIT_CATALOGUES,
        "max_entries_per_directory": _MAX_AUDIT_ENTRIES_PER_DIRECTORY,
        "alias_resolution_threshold_ppm": _ALIAS_RESOLUTION_THRESHOLD_PPM,
        "alias_primary_target_threshold_ppm": _ALIAS_PRIMARY_TARGET_THRESHOLD_PPM,
        "status_counts": dict(sorted(status_counts.items(), key=lambda item: stable_text_key(item[0]))),
        "total_readable_content_file_count": sum(int(row["readable_content_file_count"]) for row in by_code.values()),
        "total_unreadable_entry_count": sum(int(row["unreadable_entry_count"]) for row in by_code.values()),
        "total_rejected_entry_count": sum(int(row["rejected_entry_count"]) for row in by_code.values()),
        "total_cross_catalogue_resolved_unique_name_count": sum(int(row["cross_catalogue_resolved_unique_name_count"]) for row in by_code.values()),
        "total_cross_catalogue_unresolved_unique_name_count": sum(int(row["cross_catalogue_unresolved_unique_name_count"]) for row in by_code.values()),
        "alias_resolution_edges": alias_edges,
        "by_catalogue_code": by_code,
        "arbitrary_names_exported": False,
        "recursive_traversal_performed": False,
    }
