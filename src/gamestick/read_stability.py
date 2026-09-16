from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Dict, Mapping, Tuple

from .fs_safety import ForensicPathError, lstat_non_reparse
from .ordering import stable_text_key

_READ_ATTEMPTS = 3
_REGION_SAMPLE_BYTES = 64 * 1024
_MAX_STABILITY_FILES = 65  # root.dat + up to 64 numbered catalogues
_CONTROL_REGION_NAMES = frozenset({"control-fileinfo.txt", "control-filelist.txt"})
_CORRUPT_CONTROL_STATUSES = frozenset({
    "decompression-invalid",
    "crc-mismatch",
    "invalid-local-header",
    "local-central-mismatch",
    "local-central-size-crc-mismatch",
    "local-name-mismatch",
})
_PARTIAL_CONTAINER_FORMATS = frozenset({
    "damaged-or-incomplete-wqw",
    "wqw-entry-limit-exceeded",
    "wqw-central-directory-limit-exceeded",
})


def read_stability_limits() -> Dict[str, int]:
    return {
        "read_attempts": _READ_ATTEMPTS,
        "region_sample_bytes": _REGION_SAMPLE_BYTES,
        "max_files": _MAX_STABILITY_FILES,
    }


def _open_readonly(path: Path):
    return path.open("rb")


def _safe_error(exc: BaseException) -> Dict[str, object]:
    result: Dict[str, object] = {"error_type": type(exc).__name__}
    if isinstance(exc, OSError) and isinstance(exc.errno, int):
        result["error_errno"] = exc.errno
    return result


def _region_sample(handle, offset: int, length: int) -> Tuple[bytes, int]:
    """Read a deterministic bounded sample from one structural byte region."""
    if offset < 0 or length < 0:
        raise ValueError("invalid-region")
    if length <= _REGION_SAMPLE_BYTES:
        handle.seek(offset)
        data = handle.read(length)
        return data, length

    # Sample both ends of larger structural regions so an unstable tail inside
    # a central directory/control payload is not hidden by a stable prefix.
    first_len = _REGION_SAMPLE_BYTES // 2
    last_len = _REGION_SAMPLE_BYTES - first_len
    handle.seek(offset)
    first = handle.read(first_len)
    handle.seek(offset + length - last_len)
    last = handle.read(last_len)
    return first + last, _REGION_SAMPLE_BYTES


def inspect_read_stability(
    path: Path,
    *,
    relative_path: str,
    structural_regions: Mapping[str, Tuple[int, int]] | None = None,
    control_read_statuses: Mapping[str, str] | None = None,
    container_format: str | None = None,
) -> Dict[str, object]:
    """Reopen a DAT repeatedly and compare bounded structural reads in memory.

    No sampled bytes or digest values are serialized. The exported result is
    limited to status/count metadata for canonical regions.  Canonical WQW
    control payload ranges are reread independently even when decompression or
    CRC validation has failed, allowing stable corruption to be distinguished
    from unstable media reads.
    """
    result: Dict[str, object] = {
        "schema": "dat-read-stability-v2",
        "path": relative_path.replace("\\", "/"),
        "attempt_count": _READ_ATTEMPTS,
        "region_sample_bytes": _REGION_SAMPLE_BYTES,
        "status": "READ_INCOMPLETE",
        "size_stable": False,
        "region_count": 0,
        "stable_region_count": 0,
        "unstable_region_count": 0,
        "incomplete_region_count": 0,
        "control_failure_count": 0,
        "stable_failed_control_count": 0,
        "control_failure_assessment": "NO_CONTROL_FAILURE_OBSERVED",
        "regions": {},
        "arbitrary_bytes_exported": False,
        "digest_values_exported": False,
    }

    try:
        st = lstat_non_reparse(path)
        if not stat.S_ISREG(st.st_mode):
            result["error_type"] = "NotRegularFile"
            return result
        baseline_size = int(st.st_size)
    except (OSError, ForensicPathError) as exc:
        result.update(_safe_error(exc))
        return result

    regions: Dict[str, Tuple[int, int]] = {}
    prefix_len = min(baseline_size, _REGION_SAMPLE_BYTES)
    regions["prefix"] = (0, prefix_len)
    tail_len = min(baseline_size, _REGION_SAMPLE_BYTES)
    regions["tail"] = (max(0, baseline_size - tail_len), tail_len)
    for name, raw_region in (structural_regions or {}).items():
        if name not in {"central-directory", *_CONTROL_REGION_NAMES}:
            continue
        try:
            offset, length = int(raw_region[0]), int(raw_region[1])
        except (TypeError, ValueError, IndexError):
            continue
        if offset < 0 or length < 0 or offset + length > baseline_size:
            continue
        regions[name] = (offset, length)

    canonical_control_statuses: Dict[str, str] = {}
    for name, raw_status in (control_read_statuses or {}).items():
        if name in _CONTROL_REGION_NAMES:
            canonical_control_statuses[name] = str(raw_status)

    observations: Dict[str, Dict[str, object]] = {
        name: {
            "sample_bytes_expected": min(length, _REGION_SAMPLE_BYTES),
            "successful_attempt_count": 0,
            "short_read_count": 0,
            "read_error_count": 0,
            "digests": [],  # internal only; removed before return
        }
        for name, (_offset, length) in regions.items()
    }
    sizes = []

    for _attempt in range(_READ_ATTEMPTS):
        try:
            with _open_readonly(path) as handle:
                try:
                    sizes.append(int(os.fstat(handle.fileno()).st_size))
                except (OSError, AttributeError):
                    sizes.append(baseline_size)
                for name in sorted(regions, key=stable_text_key):
                    offset, length = regions[name]
                    row = observations[name]
                    try:
                        data, expected = _region_sample(handle, offset, length)
                    except (OSError, ValueError):
                        row["read_error_count"] = int(row["read_error_count"]) + 1
                        continue
                    if len(data) != expected:
                        row["short_read_count"] = int(row["short_read_count"]) + 1
                        continue
                    row["successful_attempt_count"] = int(row["successful_attempt_count"]) + 1
                    row["digests"].append(hashlib.sha256(data).digest())
        except (OSError, ForensicPathError) as exc:
            result.update(_safe_error(exc))
            # This attempt could not open the file, so every canonical region
            # lacks an independent observation for this pass.
            for row in observations.values():
                row["read_error_count"] = int(row["read_error_count"]) + 1

    size_stable = len(sizes) == _READ_ATTEMPTS and len(set(sizes)) == 1 and sizes[0] == baseline_size
    result["size_stable"] = size_stable

    exported_regions: Dict[str, Dict[str, object]] = {}
    unstable = 0
    incomplete = 0
    stable = 0
    for name in sorted(observations, key=stable_text_key):
        row = observations[name]
        digests = list(row.pop("digests"))
        successful = int(row["successful_attempt_count"])
        short_reads = int(row["short_read_count"])
        read_errors = int(row["read_error_count"])
        region_unstable = len(set(digests)) > 1
        region_complete = successful == _READ_ATTEMPTS and short_reads == 0 and read_errors == 0
        if region_unstable:
            state = "UNSTABLE"
            unstable += 1
        elif region_complete:
            state = "STABLE"
            stable += 1
        else:
            state = "INCOMPLETE"
            incomplete += 1
        exported_regions[name] = {
            **row,
            "state": state,
        }

    failed_controls = {
        name: status
        for name, status in canonical_control_statuses.items()
        if status != "verified"
    }
    stable_failed_controls = {
        name: status
        for name, status in failed_controls.items()
        if exported_regions.get(name, {}).get("state") == "STABLE"
    }
    corrupt_controls = {
        name: status
        for name, status in failed_controls.items()
        if status in _CORRUPT_CONTROL_STATUSES
    }

    if failed_controls:
        if (
            len(corrupt_controls) == len(failed_controls)
            and len(stable_failed_controls) == len(failed_controls)
        ):
            control_failure_assessment = "STABLE_CORRUPTION"
        elif len(stable_failed_controls) == len(failed_controls):
            control_failure_assessment = "STABLE_CONTROL_FAILURE"
        else:
            control_failure_assessment = "CONTROL_FAILURE_NOT_FULLY_SAMPLED"
    else:
        control_failure_assessment = "NO_CONTROL_FAILURE_OBSERVED"

    if not size_stable and len(set(sizes)) > 1:
        status = "READ_UNSTABLE"
    elif unstable:
        status = "READ_UNSTABLE"
    elif incomplete or not size_stable:
        status = "READ_INCOMPLETE"
    elif control_failure_assessment == "STABLE_CORRUPTION":
        status = "READ_STABLE_WITH_CORRUPT_CONTROL"
    elif failed_controls or (container_format or "") in _PARTIAL_CONTAINER_FORMATS:
        status = "READ_STABLE_PARTIAL"
    else:
        status = "READ_STABLE"

    result.update({
        "status": status,
        "region_count": len(exported_regions),
        "stable_region_count": stable,
        "unstable_region_count": unstable,
        "incomplete_region_count": incomplete,
        "control_failure_count": len(failed_controls),
        "stable_failed_control_count": len(stable_failed_controls),
        "control_failure_assessment": control_failure_assessment,
        "regions": exported_regions,
    })
    return result


def summarize_read_stability(rows: Mapping[str, Dict[str, object]]) -> Dict[str, object]:
    limited_items = list(sorted(rows.items(), key=lambda item: stable_text_key(item[0])))[:_MAX_STABILITY_FILES]
    status_counts: Dict[str, int] = {}
    control_assessment_counts: Dict[str, int] = {}
    by_path: Dict[str, Dict[str, object]] = {}
    for path, row in limited_items:
        by_path[path] = row
        status = str(row.get("status", "READ_INCOMPLETE"))
        status_counts[status] = status_counts.get(status, 0) + 1
        assessment = str(row.get("control_failure_assessment", "NO_CONTROL_FAILURE_OBSERVED"))
        control_assessment_counts[assessment] = control_assessment_counts.get(assessment, 0) + 1
    return {
        "schema": "numbered-dat-read-stability-v2",
        "file_count": len(by_path),
        "attempt_count": _READ_ATTEMPTS,
        "region_sample_bytes": _REGION_SAMPLE_BYTES,
        "status_counts": dict(sorted(status_counts.items(), key=lambda item: stable_text_key(item[0]))),
        "control_failure_assessment_counts": dict(sorted(control_assessment_counts.items(), key=lambda item: stable_text_key(item[0]))),
        "by_path": by_path,
        "arbitrary_bytes_exported": False,
        "digest_values_exported": False,
    }
