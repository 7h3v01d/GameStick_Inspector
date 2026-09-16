from pathlib import Path

import gamestick.probe as probe


def _make_card(root: Path) -> None:
    (root / "Roms").mkdir()
    (root / "cubegm").mkdir()
    (root / "image").mkdir()
    (root / "cubegm" / "00.dat").write_bytes(b"candidate data")


def test_corrupt_metadata_file_does_not_abort_probe(tmp_path, monkeypatch):
    _make_card(tmp_path)
    original_sha256 = probe._sha256

    def flaky_sha256(path: Path):
        if path.name == "00.dat":
            error = OSError(1392, "The file or directory is corrupted and unreadable")
            error.filename = str(path)
            raise error
        return original_sha256(path)

    monkeypatch.setattr(probe, "_sha256", flaky_sha256)

    report = probe.inspect_volume(tmp_path)

    assert report.probe_status == "DEGRADED"
    assert report.profile.profile_id == "observed_cubegm_layout"
    assert report.profile.score >= 90
    assert any("00.dat" in message for message in report.read_errors)
    assert any("OSError (errno=1392)" in message for message in report.read_errors)
    assert all("corrupted and unreadable" not in message for message in report.read_errors)
    # The critical contract: a usable report exists despite the bad file.
    assert report.structure_sha256
    assert report.probe_policy["corrupt_entries_are_nonfatal"] is True


def test_scan_limit_warning_is_not_mislabeled_as_corruption(tmp_path, monkeypatch):
    _make_card(tmp_path)
    monkeypatch.setattr(probe, "_MAX_SCAN_FILES", 0)

    report = probe.inspect_volume(tmp_path)

    assert any("Metadata scan stopped" in message for message in report.warnings)
    assert not any("Metadata scan stopped" in message for message in report.read_errors)
