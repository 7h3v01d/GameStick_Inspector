import json
import zipfile
from pathlib import Path

from gamestick import probe
from gamestick.fs_safety import ForensicPathError
from gamestick.probe import inspect_volume
from gamestick.reporting import render_text_summary, write_evidence_bundle


SECRET_NAME = "Secret Game Name.nes"


def _make_layout(root: Path) -> None:
    for name in ("Roms", "cubegm", "image"):
        (root / name).mkdir()
    (root / "Roms" / SECRET_NAME).write_bytes(b"rom")


def _assert_secret_absent_from_export_surfaces(tmp_path: Path, report) -> None:
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    summary = render_text_summary(report)
    assert SECRET_NAME not in rendered
    assert SECRET_NAME not in summary

    destination = tmp_path / "out" / "evidence.zip"
    saved = write_evidence_bundle(report, destination, host_system="Linux")
    assert SECRET_NAME.encode("utf-8") not in saved.read_bytes()

    with zipfile.ZipFile(saved) as archive:
        contents = b"\n".join(archive.read(name) for name in archive.namelist())
        assert SECRET_NAME.encode("utf-8") not in contents
        assert SECRET_NAME not in archive.read("gamestick_probe.json").decode("utf-8")
        assert SECRET_NAME not in archive.read("SUMMARY.txt").decode("utf-8")


def test_rom_forensic_path_error_warning_redacts_filename_everywhere(tmp_path, monkeypatch):
    card = tmp_path / "card"
    card.mkdir()
    _make_layout(card)

    real_assert = probe.assert_contained_non_reparse

    def reject_secret(root, candidate):
        candidate = Path(candidate)
        if candidate.name == SECRET_NAME and "Roms" in candidate.parts:
            raise ForensicPathError(f"reparse-backed secret path: {candidate}")
        return real_assert(root, candidate)

    monkeypatch.setattr(probe, "assert_contained_non_reparse", reject_secret)
    report = inspect_volume(card)

    snapshot = next(s for s in report.directory_snapshots if s.path.casefold() == "roms")
    assert snapshot.file_names_redacted is True
    assert snapshot.file_names == []
    assert any("Roms/<redacted>" in warning for warning in report.warnings)
    assert any("ForensicPathError" in warning for warning in report.warnings)
    _assert_secret_absent_from_export_surfaces(tmp_path, report)


def test_rom_oserror_warning_redacts_filename_and_degrades_probe(tmp_path, monkeypatch):
    card = tmp_path / "card"
    card.mkdir()
    _make_layout(card)

    real_lstat = probe.lstat_non_reparse

    def unreadable_secret(candidate):
        candidate = Path(candidate)
        if candidate.name == SECRET_NAME and "Roms" in candidate.parts:
            raise PermissionError(13, f"denied {candidate}", str(candidate))
        return real_lstat(candidate)

    monkeypatch.setattr(probe, "lstat_non_reparse", unreadable_secret)
    report = inspect_volume(card)

    snapshot = next(s for s in report.directory_snapshots if s.path.casefold() == "roms")
    assert snapshot.file_names_redacted is True
    assert snapshot.file_names == []
    assert report.probe_status == "DEGRADED"
    assert any("Roms/<redacted>" in warning for warning in report.warnings)
    assert any("PermissionError (errno=13)" in warning for warning in report.warnings)
    assert any("Roms/<redacted>" in error for error in report.read_errors)
    _assert_secret_absent_from_export_surfaces(tmp_path, report)


def test_filesystem_warning_never_serializes_raw_exception_text_for_rom_entry(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    _make_layout(card)
    secret = card / "Roms" / SECRET_NAME
    exc = PermissionError(13, f"PRIVATE ERROR TEXT {secret}", str(secret))

    warning = probe._filesystem_warning("Could not inspect directory entry", card, secret, exc)

    assert warning == "Could not inspect directory entry Roms/<redacted>: PermissionError (errno=13)"
    assert SECRET_NAME not in warning
    assert "PRIVATE ERROR TEXT" not in warning


def _assert_text_absent_from_export_surfaces(tmp_path: Path, report, secret: str) -> None:
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    summary = render_text_summary(report)
    assert secret not in rendered
    assert secret not in summary

    destination = tmp_path / f"out-{abs(hash(secret))}" / "evidence.zip"
    saved = write_evidence_bundle(report, destination, host_system="Linux")
    assert secret.encode("utf-8") not in saved.read_bytes()
    with zipfile.ZipFile(saved) as archive:
        contents = b"\n".join(archive.read(name) for name in archive.namelist())
        assert secret.encode("utf-8") not in contents
        assert secret not in archive.read("gamestick_probe.json").decode("utf-8")
        assert secret not in archive.read("SUMMARY.txt").decode("utf-8")


def test_rom_child_game_folder_name_is_private_and_not_platform_evidence(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir()
    secret_folder = "Secret Game Folder"
    game_dir = card / "Roms" / secret_folder
    game_dir.mkdir()
    (game_dir / "game.nes").write_bytes(b"rom")

    report = inspect_volume(card)
    snapshot = next(s for s in report.directory_snapshots if s.path.casefold() == "roms")
    assert snapshot.file_names_redacted is True
    assert snapshot.directory_names == []
    assert report.device_profile_candidate is not None
    assert report.device_profile_candidate.platform_directories == []
    _assert_text_absent_from_export_surfaces(tmp_path, report, secret_folder)


def test_rom_platform_allowlist_exports_only_canonical_semantics(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir()
    (card / "Roms" / "FC").mkdir()
    (card / "Roms" / "Secret Game Folder").mkdir()

    report = inspect_volume(card)
    snapshot = next(s for s in report.directory_snapshots if s.path.casefold() == "roms")
    assert snapshot.directory_names == ["FC"]
    assert report.device_profile_candidate is not None
    assert report.device_profile_candidate.platform_directories == ["FC"]
    _assert_text_absent_from_export_surfaces(tmp_path, report, "Secret Game Folder")


def test_artwork_filename_is_private_in_default_evidence(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir()
    secret_art = "Secret Game Name.png"
    (card / "image" / secret_art).write_bytes(b"png")

    report = inspect_volume(card)
    snapshot = next(s for s in report.directory_snapshots if s.path.casefold() == "image")
    assert snapshot.file_names_redacted is True
    assert snapshot.file_names == []
    assert snapshot.file_extension_counts[".png"] == 1
    _assert_text_absent_from_export_surfaces(tmp_path, report, secret_art)


def test_artwork_child_folder_name_is_private_by_default(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir()
    secret_folder = "Secret Artwork Folder"
    folder = card / "image" / secret_folder
    folder.mkdir()
    (folder / "cover.png").write_bytes(b"png")

    report = inspect_volume(card)
    snapshot = next(s for s in report.directory_snapshots if s.path.casefold() == "image")
    assert snapshot.file_names_redacted is True
    assert snapshot.directory_names == []
    _assert_text_absent_from_export_surfaces(tmp_path, report, secret_folder)


def test_artwork_metadata_candidate_is_not_discovered_or_profiled(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir()
    secret = "Secret Game Name.json"
    (card / "image" / secret).write_text('{"title":"private"}', encoding="utf-8")

    report = inspect_volume(card)
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert all("image/" not in artifact.path.replace("\\", "/").casefold() for artifact in report.candidate_artifacts)
    assert report.device_profile_candidate is not None
    assert report.device_profile_candidate.launcher_path is None
    assert secret not in rendered
    assert "Secret Game Name" not in rendered
    _assert_text_absent_from_export_surfaces(tmp_path, report, secret)


def test_artwork_private_folder_does_not_leak_through_metadata_truncation(tmp_path, monkeypatch):
    card = tmp_path / "card"
    card.mkdir()
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir()
    secret_folder = "Secret Artwork Folder"
    folder = card / "image" / secret_folder
    folder.mkdir()
    for index in range(12):
        (folder / f"{index}.json").write_text("{}", encoding="utf-8")

    # A tiny metadata-directory limit would trigger truncation immediately if
    # metadata discovery incorrectly entered the privacy library.
    monkeypatch.setattr(probe, "_MAX_SCAN_ENTRIES_PER_DIRECTORY", 2)
    report = inspect_volume(card)

    assert all(secret_folder not in warning for warning in report.warnings)
    assert all("image/" not in artifact.path.replace("\\", "/").casefold() for artifact in report.candidate_artifacts)
    _assert_text_absent_from_export_surfaces(tmp_path, report, secret_folder)


def test_privacy_root_arbitrary_suffixes_are_bucketed_as_other(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir()
    rom_secret = "MyPrivateGameTitle"
    art_secret = "AnotherPrivateArtworkTitle"
    (card / "Roms" / f"x.{rom_secret}").write_bytes(b"rom")
    (card / "image" / f"y.{art_secret}").write_bytes(b"art")

    report = inspect_volume(card)
    roms = next(s for s in report.directory_snapshots if s.path.casefold() == "roms")
    image = next(s for s in report.directory_snapshots if s.path.casefold() == "image")
    assert roms.file_extension_counts == {"<other>": 1}
    assert image.file_extension_counts == {"<other>": 1}
    _assert_text_absent_from_export_surfaces(tmp_path, report, rom_secret)
    _assert_text_absent_from_export_surfaces(tmp_path, report, art_secret)


def test_private_artwork_metadata_names_do_not_affect_device_profile_signature(tmp_path):
    def build(card: Path, private_name: str):
        card.mkdir()
        for name in ("Roms", "cubegm", "image"):
            (card / name).mkdir()
        (card / "image" / private_name).write_text('{"launcher":"private"}', encoding="utf-8")
        return inspect_volume(card)

    first = build(tmp_path / "first", "Secret Game Name.json")
    second = build(tmp_path / "second", "Another Private Title.json")
    assert first.device_profile_candidate is not None
    assert second.device_profile_candidate is not None
    assert first.device_profile_candidate.launcher_path is None
    assert second.device_profile_candidate.launcher_path is None
    assert first.device_profile_candidate.profile_signature_sha256 == second.device_profile_candidate.profile_signature_sha256
    assert first.device_profile_candidate.candidate_id == second.device_profile_candidate.candidate_id
