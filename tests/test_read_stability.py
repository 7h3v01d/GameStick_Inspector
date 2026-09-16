from pathlib import Path

import gamestick.read_stability as stability
from gamestick.read_stability import inspect_read_stability


def test_read_stability_reopens_and_reports_only_derived_status(tmp_path):
    path = tmp_path / "catalog.dat"
    path.write_bytes((b"0123456789abcdef" * 20_000) + b"tail")
    result = inspect_read_stability(
        path,
        relative_path="008/008.dat",
        structural_regions={
            "central-directory": (32_000, 90_000),
            "control-filelist.txt": (140_000, 80_000),
        },
    )
    assert result["status"] == "READ_STABLE"
    assert result["attempt_count"] == 3
    assert result["region_count"] == 4
    assert result["stable_region_count"] == 4
    assert result["unstable_region_count"] == 0
    assert result["incomplete_region_count"] == 0
    assert result["digest_values_exported"] is False
    assert result["arbitrary_bytes_exported"] is False
    rendered = repr(result)
    assert "0123456789abcdef" not in rendered
    assert "sha256" not in rendered.casefold()


def test_read_stability_detects_same_size_byte_change_between_independent_opens(tmp_path, monkeypatch):
    path = tmp_path / "catalog.dat"
    path.write_bytes(b"A" * (128 * 1024))
    real_open = Path.open
    calls = {"count": 0}

    def mutating_open(target):
        calls["count"] += 1
        if calls["count"] == 2:
            with real_open(target, "r+b") as handle:
                handle.seek(0)
                handle.write(b"B")
                handle.flush()
        return real_open(target, "rb")

    monkeypatch.setattr(stability, "_open_readonly", mutating_open)
    result = inspect_read_stability(path, relative_path="000/000.dat")
    assert calls["count"] == 3
    assert result["status"] == "READ_UNSTABLE"
    assert result["unstable_region_count"] >= 1
    assert result["digest_values_exported"] is False


def test_read_stability_marks_incomplete_when_an_independent_open_fails(tmp_path, monkeypatch):
    path = tmp_path / "catalog.dat"
    path.write_bytes(b"A" * 4096)
    real_open = Path.open
    calls = {"count": 0}

    def intermittent_open(target):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError(5, "synthetic read failure")
        return real_open(target, "rb")

    monkeypatch.setattr(stability, "_open_readonly", intermittent_open)
    result = inspect_read_stability(path, relative_path="003/003.dat")
    assert result["status"] == "READ_INCOMPLETE"
    assert result["incomplete_region_count"] == 2
    assert result["error_errno"] == 5


def test_read_stability_distinguishes_repeatably_corrupt_control_from_unstable_reads(tmp_path):
    path = tmp_path / "root.dat"
    path.write_bytes(b"A" * 8192)
    result = inspect_read_stability(
        path,
        relative_path="root.dat",
        structural_regions={"control-fileinfo.txt": (1024, 2048)},
        control_read_statuses={"control-fileinfo.txt": "decompression-invalid"},
        container_format="wqw-obfuscated-zip",
    )
    assert result["schema"] == "dat-read-stability-v2"
    assert result["status"] == "READ_STABLE_WITH_CORRUPT_CONTROL"
    assert result["control_failure_count"] == 1
    assert result["stable_failed_control_count"] == 1
    assert result["control_failure_assessment"] == "STABLE_CORRUPTION"
    assert result["regions"]["control-fileinfo.txt"]["state"] == "STABLE"
    assert result["digest_values_exported"] is False


def test_read_stability_marks_damaged_wqw_as_stable_partial_not_plain_stable(tmp_path):
    path = tmp_path / "003.dat"
    path.write_bytes(b"WQW\x03" + b"A" * 4092)
    result = inspect_read_stability(
        path,
        relative_path="003/003.dat",
        container_format="damaged-or-incomplete-wqw",
    )
    assert result["status"] == "READ_STABLE_PARTIAL"
    assert result["control_failure_assessment"] == "NO_CONTROL_FAILURE_OBSERVED"
