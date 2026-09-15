import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from gamestick.probe import inspect_volume
from gamestick.reporting import write_evidence_bundle, write_probe_report


def _report(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir()
    return card, inspect_volume(card)


def test_report_writer_rejects_device_destination(tmp_path):
    card, report = _report(tmp_path)
    with pytest.raises(ValueError):
        write_probe_report(report, card / "probe.json")


def test_evidence_bundle_rejects_device_destination(tmp_path):
    card, report = _report(tmp_path)
    with pytest.raises(ValueError):
        write_evidence_bundle(report, card / "evidence.zip")


def test_evidence_bundle_contains_only_generated_evidence(tmp_path):
    card, report = _report(tmp_path)
    destination = tmp_path / "out" / "evidence.zip"
    saved = write_evidence_bundle(report, destination)
    assert saved == destination.resolve()

    with zipfile.ZipFile(saved) as archive:
        names = sorted(archive.namelist())
        assert names == ["MANIFEST.json", "SUMMARY.txt", "gamestick_probe.json"]
        manifest = json.loads(archive.read("MANIFEST.json"))
        for name in ("SUMMARY.txt", "gamestick_probe.json"):
            data = archive.read(name)
            assert manifest["files"][name]["size"] == len(data)
            assert manifest["files"][name]["sha256"] == hashlib.sha256(data).hexdigest()
        payload = json.loads(archive.read("gamestick_probe.json"))
        assert payload["schema_version"] == 9




def test_headerless_csv_private_values_absent_from_evidence_bundle(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir()
    (card / "cubegm" / "game.csv").write_text(
        "1,Secret Game Name,Roms/FC/secret.nes,image/secret.png\n"
        "2,Other Game,Roms/FC/other.nes,image/other.png\n",
        encoding="utf-8",
    )
    report = inspect_volume(card)
    destination = tmp_path / "out" / "evidence.zip"
    saved = write_evidence_bundle(report, destination)

    with zipfile.ZipFile(saved) as archive:
        payload = archive.read("gamestick_probe.json").decode("utf-8")
    assert "Secret Game Name" not in payload
    assert "Roms/FC/secret.nes" not in payload
    assert "image/secret.png" not in payload
    assert "header_fields" not in payload

def test_probe_report_written_atomically(tmp_path):
    _, report = _report(tmp_path)
    destination = tmp_path / "reports" / "probe.json"
    saved = write_probe_report(report, destination)
    assert saved.exists()
    assert not destination.with_suffix(".json.tmp").exists()
    assert json.loads(saved.read_text(encoding="utf-8"))["schema_version"] == 9


def test_probe_report_refuses_preexisting_predictable_temp_symlink(tmp_path):
    card, report = _report(tmp_path)
    important = card / "important.cfg"
    important.write_bytes(b"ORIGINAL")
    host = tmp_path / "host"
    host.mkdir()
    destination = host / "probe.json"
    legacy_temp = destination.with_suffix(".json.tmp")
    legacy_temp.symlink_to(important)

    with pytest.raises(ValueError, match="legacy predictable temporary object"):
        write_probe_report(report, destination)

    assert important.read_bytes() == b"ORIGINAL"
    assert legacy_temp.is_symlink()
    assert not destination.exists()


def test_evidence_bundle_refuses_preexisting_predictable_temp_symlink(tmp_path):
    card, report = _report(tmp_path)
    important = card / "important.cfg"
    important.write_bytes(b"ORIGINAL")
    host = tmp_path / "host"
    host.mkdir()
    destination = host / "evidence.zip"
    legacy_temp = destination.with_suffix(".zip.tmp")
    legacy_temp.symlink_to(important)

    with pytest.raises(ValueError, match="legacy predictable temporary object"):
        write_evidence_bundle(report, destination)

    assert important.read_bytes() == b"ORIGINAL"
    assert legacy_temp.is_symlink()
    assert not destination.exists()


def test_report_export_uses_unpredictable_secure_stage_not_legacy_tmp(tmp_path, monkeypatch):
    card, report = _report(tmp_path)
    destination = tmp_path / "host" / "probe.json"
    seen = {}

    import gamestick.reporting as reporting

    real_secure = reporting._secure_temp_file

    def capture(path):
        fd, temp = real_secure(path)
        seen["temp"] = temp
        return fd, temp

    monkeypatch.setattr(reporting, "_secure_temp_file", capture)
    write_probe_report(report, destination)

    assert seen["temp"] != destination.with_suffix(".json.tmp")
    assert not seen["temp"].exists()
    assert destination.exists()


def _windows_report(tmp_path):
    from gamestick.models import DiskPartitionInfo, PhysicalMapping, ProbeReport, ProfileMatch

    card = tmp_path / "card"
    card.mkdir(exist_ok=True)
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir(exist_ok=True)
    mapping = PhysicalMapping(
        disk_number=4,
        partition_number=1,
        disk_name="USB Card",
        bus_type="USB",
        partition_style="MBR",
        disk_size=64 * 1024 * 1024,
        partition_size=63 * 1024 * 1024,
        partition_offset=1024 * 1024,
        is_boot=False,
        is_system=False,
        serial_number="SERIAL-A",
        disk_unique_id="UNIQUE-A",
        logical_sector_size=512,
        physical_sector_size=512,
        is_offline=False,
        drive_type="Removable",
        partitions=[
            DiskPartitionInfo(
                partition_number=1,
                drive_letter="E",
                offset=1024 * 1024,
                size=63 * 1024 * 1024,
            )
        ],
    )
    profile = ProfileMatch(
        profile_id="observed_cubegm_layout",
        display_name="Observed GameStick layout",
        score=100,
        confidence="high",
        matched_markers=["Roms", "cubegm", "image"],
        missing_markers=[],
    )
    report = ProbeReport(
        schema_version=3,
        generated_at_utc="2026-09-13T00:00:00+00:00",
        platform="Windows-10",
        selected_root=str(card),
        volume_total=63 * 1024 * 1024,
        volume_used=0,
        volume_free=63 * 1024 * 1024,
        root_entries=[],
        directory_snapshots=[],
        profile=profile,
        profile_candidates=[profile],
        physical_mapping=mapping,
        candidate_artifacts=[],
        warnings=[],
        structure_sha256="a" * 64,
        probe_policy={},
    )
    return card, report


def test_export_revalidates_source_before_any_staging(tmp_path, monkeypatch):
    import gamestick.reporting as reporting
    from dataclasses import replace

    _, report = _windows_report(tmp_path)
    destination = tmp_path / "host" / "probe.json"
    destination.parent.mkdir()
    stage_called = {"value": False}

    def stage_should_not_run(*args, **kwargs):
        stage_called["value"] = True
        raise AssertionError("staging must not begin after source identity failure")

    monkeypatch.setattr(reporting, "_make_stage", stage_should_not_run)
    changed = replace(report.physical_mapping, disk_number=5)

    with pytest.raises(Exception, match="identity changed"):
        reporting.write_probe_report(
            report,
            destination,
            host_system="Windows",
            mapping_resolver=lambda root: changed,
            destination_disk_resolver=lambda drive: 2,
            volume_root_resolver=lambda drive: str(tmp_path / "safe-stage"),
            volume_disk_resolver=lambda volume: 2,
        )
    assert stage_called["value"] is False
    assert not destination.exists()


def test_destination_junction_swap_before_staging_writes_only_to_bound_safe_volume(tmp_path, monkeypatch):
    import gamestick.reporting as reporting
    from gamestick.safety import BoundOutputVolume

    card, report = _windows_report(tmp_path)
    host = tmp_path / "host"
    host.mkdir()
    safe_stage = tmp_path / "safe-stage"
    safe_stage.mkdir()
    destination = host / "probe.json"

    bind_calls = {"n": 0}

    def fake_bind(candidate, device_root, **kwargs):
        bind_calls["n"] += 1
        current = Path(candidate).resolve()
        if bind_calls["n"] == 1:
            return BoundOutputVolume(current, 4, 2, "C", str(safe_stage))
        # By commit time the syntactic destination resolves into the card.
        return BoundOutputVolume(current, 4, 4, "E", str(card))

    monkeypatch.setattr(reporting, "bind_output_volume", fake_bind)
    real_make_stage = reporting._make_stage

    def swap_then_stage(path, binding):
        old = tmp_path / "host-old"
        host.rename(old)
        host.symlink_to(card, target_is_directory=True)
        return real_make_stage(path, binding)

    monkeypatch.setattr(reporting, "_make_stage", swap_then_stage)

    with pytest.raises(ValueError, match="destination identity changed"):
        reporting.write_probe_report(
            report,
            destination,
            host_system="Windows",
            mapping_resolver=lambda root: report.physical_mapping,
        )

    # The protected source receives no staging file and no final report.
    assert not (card / "probe.json").exists()
    assert [p for p in card.iterdir() if p.name.startswith(".gamestick-inspector-")] == []
    assert [p for p in safe_stage.iterdir() if p.name.startswith(".gamestick-inspector-")] == []


def test_source_revalidation_failure_reaches_no_temp_creation_primitive(tmp_path, monkeypatch):
    import gamestick.reporting as reporting
    from dataclasses import replace

    _, report = _windows_report(tmp_path)
    destination = tmp_path / "host2" / "probe.json"
    destination.parent.mkdir()
    calls = {"portable": 0, "bound": 0}

    def no_portable(*args, **kwargs):
        calls["portable"] += 1
        raise AssertionError("portable temp creation must not be reached")

    def no_bound(*args, **kwargs):
        calls["bound"] += 1
        raise AssertionError("bound temp creation must not be reached")

    monkeypatch.setattr(reporting, "_secure_temp_file", no_portable)
    monkeypatch.setattr(reporting, "secure_stage_on_bound_volume", no_bound)
    changed = replace(report.physical_mapping, disk_number=5)

    with pytest.raises(Exception, match="identity changed"):
        reporting.write_probe_report(
            report,
            destination,
            host_system="Windows",
            mapping_resolver=lambda root: changed,
            destination_disk_resolver=lambda drive: 2,
            volume_root_resolver=lambda drive: str(tmp_path / "safe-stage2"),
            volume_disk_resolver=lambda volume: 2,
        )

    assert calls == {"portable": 0, "bound": 0}


def test_json_and_config_private_names_absent_from_evidence_bundle(tmp_path):
    card = tmp_path / "card-private-structured"
    card.mkdir()
    for name in ("Roms", "cubegm", "image"):
        (card / name).mkdir()
    (card / "cubegm" / "games.json").write_text(
        json.dumps({
            "Secret Game Name": {"rom": "Roms/FC/secret.nes"},
            "Roms/FC/private.nes": {"title": "Private Game"},
        }),
        encoding="utf-8",
    )
    (card / "cubegm" / "games.cfg").write_text(
        "[Secret Config Game]\nRoms/FC/private.nes=value\n[launcher]\nrom_path=hidden\n",
        encoding="utf-8",
    )
    report = inspect_volume(card)
    saved = write_evidence_bundle(report, tmp_path / "out-private" / "evidence.zip")
    with zipfile.ZipFile(saved) as archive:
        payload = archive.read("gamestick_probe.json").decode("utf-8")
    for forbidden in (
        "Secret Game Name",
        "Roms/FC/secret.nes",
        "Roms/FC/private.nes",
        "Private Game",
        "Secret Config Game",
        '"top_level_keys"',
        '"sections"',
        '"key_names"',
    ):
        assert forbidden not in payload
