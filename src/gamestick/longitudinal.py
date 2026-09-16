from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

from .fs_safety import ForensicPathError, lstat_non_reparse
from .models import DatContainerEvidence, NumberedDatProfileCandidate
from .ordering import stable_text_key

_MAX_BASELINE_JSON_BYTES = 16 * 1024 * 1024
_MAX_BASELINE_MANIFEST_BYTES = 256 * 1024
_MAX_BASELINE_ZIP_MEMBERS = 32
_MAX_BASELINE_COMPRESSION_RATIO = 250
_MIN_BASELINE_PROBE_SCHEMA = 12


class BaselineEvidenceError(ValueError):
    pass


def longitudinal_limits() -> Dict[str, int]:
    return {
        "max_baseline_json_bytes": _MAX_BASELINE_JSON_BYTES,
        "max_baseline_manifest_bytes": _MAX_BASELINE_MANIFEST_BYTES,
        "max_baseline_zip_members": _MAX_BASELINE_ZIP_MEMBERS,
        "max_baseline_compression_ratio": _MAX_BASELINE_COMPRESSION_RATIO,
        "min_baseline_probe_schema": _MIN_BASELINE_PROBE_SCHEMA,
    }


def _bounded_file_bytes(path: Path, limit: int) -> bytes:
    try:
        st = lstat_non_reparse(path)
    except (OSError, ForensicPathError) as exc:
        raise BaselineEvidenceError(f"baseline-unreadable:{type(exc).__name__}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise BaselineEvidenceError("baseline-not-regular-file")
    if int(st.st_size) > limit:
        raise BaselineEvidenceError("baseline-size-limit")
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise BaselineEvidenceError(f"baseline-unreadable:{type(exc).__name__}") from exc
    if len(data) > limit:
        raise BaselineEvidenceError("baseline-size-limit")
    return data


def _zip_member_bytes(archive: zipfile.ZipFile, name: str, limit: int) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as exc:
        raise BaselineEvidenceError(f"baseline-zip-missing:{name}") from exc
    if info.is_dir():
        raise BaselineEvidenceError(f"baseline-zip-invalid-member:{name}")
    if info.flag_bits & 0x0001:
        raise BaselineEvidenceError(f"baseline-zip-encrypted:{name}")
    if info.file_size > limit:
        raise BaselineEvidenceError(f"baseline-zip-member-size-limit:{name}")
    if info.compress_size == 0 and info.file_size:
        raise BaselineEvidenceError(f"baseline-zip-invalid-compression:{name}")
    if info.compress_size and info.file_size > info.compress_size * _MAX_BASELINE_COMPRESSION_RATIO:
        raise BaselineEvidenceError(f"baseline-zip-compression-ratio-limit:{name}")
    try:
        with archive.open(info, "r") as handle:
            data = handle.read(limit + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise BaselineEvidenceError(f"baseline-zip-read-error:{name}:{type(exc).__name__}") from exc
    if len(data) > limit or len(data) != info.file_size:
        raise BaselineEvidenceError(f"baseline-zip-member-length-invalid:{name}")
    return data


def _parse_json_bytes(data: bytes, *, label: str) -> Dict[str, Any]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineEvidenceError(f"{label}-json-invalid:{type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise BaselineEvidenceError(f"{label}-json-not-object")
    return payload


def load_baseline_probe(path: str | Path) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Load a prior inspector JSON/evidence ZIP without extracting it.

    Returns ``(probe_dict, source_metadata)``. Host paths and arbitrary archive
    member names are never included in source_metadata.
    """
    baseline = Path(path)
    suffix = baseline.suffix.casefold()
    if suffix == ".zip":
        try:
            st = lstat_non_reparse(baseline)
            if not stat.S_ISREG(st.st_mode):
                raise BaselineEvidenceError("baseline-not-regular-file")
            with zipfile.ZipFile(baseline, "r") as archive:
                infos = archive.infolist()
                if len(infos) > _MAX_BASELINE_ZIP_MEMBERS:
                    raise BaselineEvidenceError("baseline-zip-member-count-limit")
                allowed = {"gamestick_probe.json", "SUMMARY.txt", "MANIFEST.json"}
                for info in infos:
                    normalized = info.filename.replace("\\", "/")
                    if normalized.startswith("/") or ".." in normalized.split("/"):
                        raise BaselineEvidenceError("baseline-zip-unsafe-member-path")
                    if normalized not in allowed:
                        raise BaselineEvidenceError("baseline-zip-unexpected-member")
                probe_bytes = _zip_member_bytes(archive, "gamestick_probe.json", _MAX_BASELINE_JSON_BYTES)
                manifest_bytes = _zip_member_bytes(archive, "MANIFEST.json", _MAX_BASELINE_MANIFEST_BYTES)
        except (OSError, zipfile.BadZipFile) as exc:
            raise BaselineEvidenceError(f"baseline-zip-invalid:{type(exc).__name__}") from exc

        manifest = _parse_json_bytes(manifest_bytes, label="baseline-manifest")
        files = manifest.get("files")
        if not isinstance(files, dict):
            raise BaselineEvidenceError("baseline-manifest-files-missing")
        probe_meta = files.get("gamestick_probe.json")
        if not isinstance(probe_meta, dict):
            raise BaselineEvidenceError("baseline-manifest-probe-entry-missing")
        expected_sha = probe_meta.get("sha256")
        expected_size = probe_meta.get("size")
        actual_sha = hashlib.sha256(probe_bytes).hexdigest()
        if not isinstance(expected_sha, str) or expected_sha.casefold() != actual_sha:
            raise BaselineEvidenceError("baseline-manifest-probe-sha256-mismatch")
        if not isinstance(expected_size, int) or expected_size != len(probe_bytes):
            raise BaselineEvidenceError("baseline-manifest-probe-size-mismatch")
        probe = _parse_json_bytes(probe_bytes, label="baseline-probe")
        source = {
            "source_type": "evidence-zip",
            "manifest_verified": True,
            "probe_sha256": actual_sha,
        }
    else:
        probe_bytes = _bounded_file_bytes(baseline, _MAX_BASELINE_JSON_BYTES)
        probe = _parse_json_bytes(probe_bytes, label="baseline-probe")
        source = {
            "source_type": "probe-json",
            "manifest_verified": False,
            "probe_sha256": hashlib.sha256(probe_bytes).hexdigest(),
        }

    schema = probe.get("schema_version")
    if not isinstance(schema, int) or schema < _MIN_BASELINE_PROBE_SCHEMA:
        raise BaselineEvidenceError("baseline-probe-schema-unsupported")
    numbered = probe.get("numbered_dat_profile")
    if not isinstance(numbered, dict):
        raise BaselineEvidenceError("baseline-numbered-dat-profile-missing")
    source.update({
        "probe_schema_version": schema,
        "generated_at_utc": probe.get("generated_at_utc") if isinstance(probe.get("generated_at_utc"), str) else None,
        "numbered_profile_schema_version": numbered.get("schema_version") if isinstance(numbered.get("schema_version"), int) else None,
    })
    return probe, source


def _current_container_map(profile: NumberedDatProfileCandidate) -> Dict[str, DatContainerEvidence]:
    result: Dict[str, DatContainerEvidence] = {}
    if profile.root_catalog is not None:
        result[profile.root_catalog.path.replace("\\", "/")] = profile.root_catalog
    for row in profile.numbered_catalogs:
        result[row.path.replace("\\", "/")] = row
    return result


def _baseline_container_map(numbered: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    result: Dict[str, Mapping[str, Any]] = {}
    root = numbered.get("root_catalog")
    if isinstance(root, dict) and isinstance(root.get("path"), str):
        result[root["path"].replace("\\", "/")] = root
    rows = numbered.get("numbered_catalogs")
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("path"), str):
                result[row["path"].replace("\\", "/")] = row
    return result


def _safe_control_shape(details: Any) -> Dict[str, Dict[str, Any]]:
    if not isinstance(details, dict):
        return {}
    summaries = details.get("control_summaries")
    if not isinstance(summaries, dict):
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    allowed = {
        "compression_method", "compressed_size", "uncompressed_size", "crc32_verified",
        "read_status", "parse_schema", "record_count", "valid_record_count",
        "malformed_record_count", "records_truncated", "raw_artwork_member_count",
        "unique_artwork_stem_count", "catalogue_records_with_artwork_count",
    }
    for name in ("fileinfo.txt", "filelist.txt"):
        row = summaries.get(name)
        if not isinstance(row, dict):
            continue
        result[name] = {key: row.get(key) for key in sorted(allowed) if key in row}
    return result


def _current_structure_shape(row: DatContainerEvidence) -> Dict[str, Any]:
    return {
        "container_format": row.container_format,
        "central_directory_valid": row.central_directory_valid,
        "declared_member_count": row.declared_member_count,
        "central_directory_size": row.central_directory_size,
        "control_members": list(row.control_members),
        "control_summaries": _safe_control_shape(row.details),
    }


def _baseline_structure_shape(row: Mapping[str, Any]) -> Dict[str, Any]:
    controls = row.get("control_members") if isinstance(row.get("control_members"), list) else []
    return {
        "container_format": row.get("container_format"),
        "central_directory_valid": row.get("central_directory_valid"),
        "declared_member_count": row.get("declared_member_count"),
        "central_directory_size": row.get("central_directory_size"),
        "control_members": list(controls),
        "control_summaries": _safe_control_shape(row.get("details")),
    }


def _fingerprint_hashes_current(row: DatContainerEvidence) -> Tuple[str | None, str | None]:
    fingerprint = row.binary_fingerprint
    if fingerprint is None:
        return None, None
    return fingerprint.prefix_sha256, fingerprint.tail_sha256


def _fingerprint_hashes_baseline(row: Mapping[str, Any]) -> Tuple[str | None, str | None]:
    fingerprint = row.get("binary_fingerprint")
    if not isinstance(fingerprint, dict):
        return None, None
    prefix = fingerprint.get("prefix_sha256")
    tail = fingerprint.get("tail_sha256")
    return (prefix if isinstance(prefix, str) else None, tail if isinstance(tail, str) else None)


def _comparison_state(current: str | None, baseline: str | None) -> str:
    if current is None or baseline is None:
        return "NOT_COMPARABLE"
    return "UNCHANGED" if current == baseline else "CHANGED"


def compare_to_baseline(
    current: NumberedDatProfileCandidate,
    baseline_probe: Mapping[str, Any],
    *,
    source_metadata: Mapping[str, Any],
) -> Dict[str, Any]:
    numbered = baseline_probe.get("numbered_dat_profile")
    if not isinstance(numbered, dict):
        raise BaselineEvidenceError("baseline-numbered-dat-profile-missing")

    current_map = _current_container_map(current)
    baseline_map = _baseline_container_map(numbered)
    current_stability = current.read_stability.get("by_path", {}) if isinstance(current.read_stability, dict) else {}
    if not isinstance(current_stability, dict):
        current_stability = {}

    by_path: Dict[str, Dict[str, Any]] = {}
    status_counts: Dict[str, int] = {}
    for path in sorted(set(current_map) | set(baseline_map), key=stable_text_key):
        crow = current_map.get(path)
        brow = baseline_map.get(path)
        if crow is None:
            status = "MISSING_FROM_CURRENT_PROBE"
            row = {
                "status": status,
                "current_read_status": "UNAVAILABLE",
                "prefix_comparison": "NOT_COMPARABLE",
                "tail_comparison": "NOT_COMPARABLE",
                "structure_comparison": "NOT_COMPARABLE",
            }
        elif brow is None:
            stability = current_stability.get(path, {})
            read_status = stability.get("status", "READ_INCOMPLETE") if isinstance(stability, dict) else "READ_INCOMPLETE"
            status = "ADDED_SINCE_BASELINE"
            row = {
                "status": status,
                "current_read_status": read_status,
                "prefix_comparison": "NOT_COMPARABLE",
                "tail_comparison": "NOT_COMPARABLE",
                "structure_comparison": "NOT_COMPARABLE",
            }
        else:
            stability = current_stability.get(path, {})
            read_status = stability.get("status", "READ_INCOMPLETE") if isinstance(stability, dict) else "READ_INCOMPLETE"
            current_prefix, current_tail = _fingerprint_hashes_current(crow)
            baseline_prefix, baseline_tail = _fingerprint_hashes_baseline(brow)
            prefix_state = _comparison_state(current_prefix, baseline_prefix)
            tail_state = _comparison_state(current_tail, baseline_tail)
            structure_state = (
                "UNCHANGED"
                if _current_structure_shape(crow) == _baseline_structure_shape(brow)
                else "CHANGED"
            )
            if read_status == "READ_UNSTABLE":
                status = "CURRENT_READ_UNSTABLE"
            elif read_status == "READ_INCOMPLETE":
                status = "CURRENT_READ_INCOMPLETE"
            elif read_status == "READ_STABLE_WITH_CORRUPT_CONTROL":
                status = "CURRENT_CONTROL_CORRUPT"
            elif read_status == "READ_STABLE_PARTIAL":
                status = "CURRENT_READ_PARTIAL"
            elif read_status != "READ_STABLE":
                status = "CURRENT_READ_INCOMPLETE"
            elif structure_state == "CHANGED":
                status = "STRUCTURE_OR_CATALOGUE_CHANGED_SINCE_BASELINE"
            elif prefix_state == "CHANGED" or tail_state == "CHANGED":
                status = "CONTENT_REGION_CHANGED_SINCE_BASELINE"
            elif prefix_state == "UNCHANGED" and tail_state == "UNCHANGED":
                status = "UNCHANGED_SINCE_BASELINE"
            else:
                status = "STRUCTURE_UNCHANGED_CONTENT_NOT_COMPARABLE"
            row = {
                "status": status,
                "current_read_status": read_status,
                "prefix_comparison": prefix_state,
                "tail_comparison": tail_state,
                "structure_comparison": structure_state,
            }
        by_path[path] = row
        status_counts[status] = status_counts.get(status, 0) + 1

    baseline_signature = numbered.get("structural_signature_sha256")
    return {
        "schema": "numbered-dat-longitudinal-integrity-v2",
        "baseline_status": "BASELINE_VERIFIED",
        "baseline_source": dict(source_metadata),
        "baseline_structural_signature_matches": bool(
            isinstance(baseline_signature, str)
            and baseline_signature == current.structural_signature_sha256
        ),
        "current_session_read_stability_status_counts": dict(current.read_stability.get("status_counts", {})) if isinstance(current.read_stability, dict) else {},
        "compared_path_count": len(by_path),
        "status_counts": dict(sorted(status_counts.items(), key=lambda item: stable_text_key(item[0]))),
        "by_path": by_path,
        "arbitrary_media_names_exported": False,
        "baseline_host_path_exported": False,
        "new_sampled_region_digest_values_exported": False,
        "comparison_uses_existing_binary_fingerprint_commitments": True,
    }
