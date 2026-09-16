from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
import zipfile

import pytest

from gamestick.longitudinal import BaselineEvidenceError, compare_to_baseline, load_baseline_probe
from gamestick.models import BinaryFingerprintEvidence, DatContainerEvidence, NumberedDatProfileCandidate


def _fingerprint(prefix: str, tail: str) -> BinaryFingerprintEvidence:
    return BinaryFingerprintEvidence(
        schema_version=1,
        sample_strategy="synthetic",
        sample_window_bytes=65536,
        sampled_window_count=2,
        sampled_bytes_total=2,
        unique_sampled_bytes=2,
        sample_covers_entire_file=False,
        prefix_sha256=prefix,
        tail_sha256=tail,
    )


def _profile(prefix: str = "a" * 64, tail: str = "b" * 64, *, read_status: str = "READ_STABLE") -> NumberedDatProfileCandidate:
    root = DatContainerEvidence(
        path="root.dat",
        role="global-catalog",
        size=1000,
        container_format="wqw-obfuscated-zip",
        central_directory_valid=True,
        declared_member_count=16,
        file_member_count=16,
        central_directory_size=853,
        control_members=["fileinfo.txt"],
        member_names_redacted=True,
        binary_fingerprint=_fingerprint(prefix, tail),
        details={
            "control_summaries": {
                "fileinfo.txt": {
                    "read_status": "verified",
                    "crc32_verified": True,
                    "parse_schema": "fileinfo-semicolon-5-mixed-v1",
                    "valid_record_count": 10,
                    "malformed_record_count": 0,
                    "compressed_size": 100,
                    "uncompressed_size": 500,
                }
            }
        },
    )
    return NumberedDatProfileCandidate(
        schema_version=6,
        candidate_id="ndpv6-deadbeefdeadbeef",
        status="PROBABLE",
        confidence="high",
        heuristic_score=100,
        profile_family="numbered-dat-catalog",
        root_dat_present=True,
        numbered_directory_count=0,
        matched_numbered_dat_count=0,
        zip_numbered_dat_count=0,
        wqw_numbered_dat_count=0,
        damaged_wqw_numbered_dat_count=0,
        filelist_control_count=0,
        structural_signature_sha256="s" * 64,
        root_catalog=root,
        read_stability={
            "status_counts": {read_status: 1},
            "by_path": {"root.dat": {"status": read_status}},
        },
    )


def _baseline_probe(profile: NumberedDatProfileCandidate) -> dict:
    return {
        "schema_version": 15,
        "generated_at_utc": "2026-09-16T00:00:00+00:00",
        "numbered_dat_profile": asdict(profile),
    }


def test_longitudinal_comparison_reports_stable_now_but_tail_changed_since_baseline():
    baseline_profile = _profile(tail="1" * 64)
    current = _profile(tail="2" * 64)
    result = compare_to_baseline(
        current,
        _baseline_probe(baseline_profile),
        source_metadata={"source_type": "evidence-zip", "manifest_verified": True, "probe_sha256": "f" * 64},
    )
    row = result["by_path"]["root.dat"]
    assert row["current_read_status"] == "READ_STABLE"
    assert row["prefix_comparison"] == "UNCHANGED"
    assert row["tail_comparison"] == "CHANGED"
    assert row["structure_comparison"] == "UNCHANGED"
    assert row["status"] == "CONTENT_REGION_CHANGED_SINCE_BASELINE"
    assert result["new_sampled_region_digest_values_exported"] is False


def test_longitudinal_current_read_instability_takes_precedence():
    baseline = _profile()
    current = _profile(read_status="READ_UNSTABLE")
    result = compare_to_baseline(
        current,
        _baseline_probe(baseline),
        source_metadata={"source_type": "probe-json", "manifest_verified": False, "probe_sha256": "e" * 64},
    )
    assert result["by_path"]["root.dat"]["status"] == "CURRENT_READ_UNSTABLE"


def test_baseline_evidence_zip_manifest_is_verified_without_exporting_host_path(tmp_path):
    profile = _profile()
    probe_bytes = (json.dumps(_baseline_probe(profile), sort_keys=True) + "\n").encode("utf-8")
    manifest = {
        "bundle_schema_version": 1,
        "source_probe_schema_version": 15,
        "files": {
            "gamestick_probe.json": {
                "sha256": hashlib.sha256(probe_bytes).hexdigest(),
                "size": len(probe_bytes),
            }
        },
    }
    path = tmp_path / "private-host-folder" / "prior-evidence.zip"
    path.parent.mkdir()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("gamestick_probe.json", probe_bytes)
        archive.writestr("SUMMARY.txt", b"summary\n")
        archive.writestr("MANIFEST.json", json.dumps(manifest).encode("utf-8"))

    probe, source = load_baseline_probe(path)
    assert probe["schema_version"] == 15
    assert source["manifest_verified"] is True
    assert source["source_type"] == "evidence-zip"
    assert str(path) not in json.dumps(source, sort_keys=True)


def test_baseline_evidence_zip_rejects_manifest_mismatch(tmp_path):
    profile = _profile()
    probe_bytes = json.dumps(_baseline_probe(profile)).encode("utf-8")
    manifest = {
        "files": {
            "gamestick_probe.json": {
                "sha256": "0" * 64,
                "size": len(probe_bytes),
            }
        }
    }
    path = tmp_path / "bad.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("gamestick_probe.json", probe_bytes)
        archive.writestr("SUMMARY.txt", b"summary")
        archive.writestr("MANIFEST.json", json.dumps(manifest).encode("utf-8"))

    with pytest.raises(BaselineEvidenceError, match="sha256-mismatch"):
        load_baseline_probe(path)


def test_longitudinal_reports_stable_corrupt_control_distinct_from_incomplete_read():
    baseline = _profile()
    current = _profile(read_status="READ_STABLE_WITH_CORRUPT_CONTROL")
    result = compare_to_baseline(
        current,
        _baseline_probe(baseline),
        source_metadata={"source_type": "probe-json", "manifest_verified": False, "probe_sha256": "d" * 64},
    )
    assert result["schema"] == "numbered-dat-longitudinal-integrity-v2"
    assert result["by_path"]["root.dat"]["status"] == "CURRENT_CONTROL_CORRUPT"


def test_longitudinal_reports_stable_partial_container_distinct_from_incomplete_read():
    baseline = _profile()
    current = _profile(read_status="READ_STABLE_PARTIAL")
    result = compare_to_baseline(
        current,
        _baseline_probe(baseline),
        source_metadata={"source_type": "probe-json", "manifest_verified": False, "probe_sha256": "c" * 64},
    )
    assert result["by_path"]["root.dat"]["status"] == "CURRENT_READ_PARTIAL"
