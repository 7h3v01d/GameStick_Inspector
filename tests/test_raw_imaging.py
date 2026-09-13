import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from gamestick.imaging import (
    ImagingCancelled,
    ImagingError,
    ImagingPreflightError,
    create_raw_image,
    physical_drive_path,
    preflight_physical_image,
    revalidate_source_identity,
)
from gamestick.models import (
    DiskPartitionInfo,
    ImagingPlan,
    PhysicalMapping,
    ProbeReport,
    ProfileMatch,
)


def _report(tmp_path, **mapping_overrides):
    mapping = PhysicalMapping(
        disk_number=4,
        partition_number=1,
        disk_name="USB Card Reader",
        bus_type="USB",
        partition_style="MBR",
        disk_size=32 * 1024 * 1024,
        partition_size=31 * 1024 * 1024,
        partition_offset=1024 * 1024,
        is_boot=False,
        is_system=False,
        serial_number="SERIAL-123",
        disk_unique_id="UNIQUE-456",
        logical_sector_size=512,
        physical_sector_size=512,
        is_read_only=False,
        is_offline=False,
        disk_health="Healthy",
        drive_type="Removable",
        partitions=[
            DiskPartitionInfo(
                partition_number=1,
                drive_letter="E",
                offset=1024 * 1024,
                size=31 * 1024 * 1024,
                filesystem="FAT32",
            )
        ],
    )
    mapping = replace(mapping, **mapping_overrides)
    profile = ProfileMatch(
        profile_id="observed_cubegm_layout",
        display_name="Observed GameStick layout",
        score=100,
        confidence="high",
        matched_markers=["Roms", "cubegm", "image"],
        missing_markers=[],
    )
    return ProbeReport(
        schema_version=2,
        generated_at_utc="2026-09-12T00:00:00+00:00",
        platform="Windows-10",
        selected_root="E:\\",
        volume_total=31 * 1024 * 1024,
        volume_used=0,
        volume_free=31 * 1024 * 1024,
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


def _plan(source: Path, destination: Path, *, source_size=None, overwrite=False):
    size = source.stat().st_size if source_size is None else source_size
    return ImagingPlan(
        source_path=str(source),
        selected_root=str(source.parent / "synthetic-card-root"),
        disk_number=4,
        disk_name="Synthetic source",
        source_size=size,
        destination=str(destination),
        manifest_path=str(destination) + ".manifest.json",
        confirmation_phrase="IMAGE DISK 4",
        profile_id="test-profile",
        profile_score=100,
        structure_sha256="b" * 64,
        bus_type="USB",
        drive_type="Removable",
        partition_style="MBR",
        source_serial_sha256="c" * 64,
        source_unique_id_sha256="d" * 64,
        overwrite_existing=overwrite,
    )


def test_physical_drive_path():
    assert physical_drive_path(4) == r"\\.\PhysicalDrive4"
    with pytest.raises(ValueError):
        physical_drive_path(-1)
    with pytest.raises(ValueError):
        physical_drive_path(True)


def test_preflight_accepts_known_external_non_system_gamestick(tmp_path):
    report = _report(tmp_path)
    plan = preflight_physical_image(
        report,
        tmp_path / "factory.img",
        host_system="Windows",
        available_bytes=200 * 1024 * 1024,
    )
    assert plan.disk_number == 4
    assert plan.source_path == r"\\.\PhysicalDrive4"
    assert plan.confirmation_phrase == "IMAGE DISK 4"
    assert plan.source_size == report.physical_mapping.disk_size
    assert plan.source_serial_sha256 != report.physical_mapping.serial_number
    assert plan.source_unique_id_sha256 != report.physical_mapping.disk_unique_id


@pytest.mark.parametrize(
    "field,value,needle",
    [
        ("is_boot", True, "boot flag"),
        ("is_boot", None, "boot flag"),
        ("is_system", True, "system flag"),
        ("is_system", None, "system flag"),
        ("is_offline", True, "offline"),
        ("disk_size", None, "size"),
        ("disk_size", 0, "size"),
    ],
)
def test_preflight_rejects_unsafe_mapping_flags(tmp_path, field, value, needle):
    report = _report(tmp_path, **{field: value})
    with pytest.raises(ImagingPreflightError, match=needle):
        preflight_physical_image(
            report,
            tmp_path / "factory.img",
            host_system="Windows",
            available_bytes=200 * 1024 * 1024,
        )


def test_preflight_rejects_mapping_error(tmp_path):
    report = _report(tmp_path, mapping_error="mapping failed")
    with pytest.raises(ImagingPreflightError, match="not trustworthy"):
        preflight_physical_image(
            report, tmp_path / "factory.img", host_system="Windows", available_bytes=200 * 1024 * 1024
        )


def test_preflight_rejects_internal_bus(tmp_path):
    report = _report(tmp_path, bus_type="NVMe", drive_type="Fixed")
    with pytest.raises(ImagingPreflightError, match="not positively identified"):
        preflight_physical_image(
            report, tmp_path / "factory.img", host_system="Windows", available_bytes=200 * 1024 * 1024
        )


def test_preflight_allows_removable_drive_even_if_bus_is_unknown(tmp_path):
    report = _report(tmp_path, bus_type="Unknown", drive_type="Removable")
    plan = preflight_physical_image(
        report, tmp_path / "factory.img", host_system="Windows", available_bytes=200 * 1024 * 1024
    )
    assert plan.disk_number == 4


def test_preflight_rejects_low_profile_confidence(tmp_path):
    report = _report(tmp_path)
    report.profile = replace(report.profile, profile_id="unknown", score=20, confidence="none")
    with pytest.raises(ImagingPreflightError, match="profile confidence"):
        preflight_physical_image(
            report, tmp_path / "factory.img", host_system="Windows", available_bytes=200 * 1024 * 1024
        )


def test_preflight_rejects_wrong_host(tmp_path):
    with pytest.raises(ImagingPreflightError, match="Windows only"):
        preflight_physical_image(
            _report(tmp_path), tmp_path / "factory.img", host_system="Linux", available_bytes=200 * 1024 * 1024
        )


def test_preflight_rejects_selected_drive_not_in_partition_map(tmp_path):
    report = _report(
        tmp_path,
        partitions=[DiskPartitionInfo(partition_number=1, drive_letter="F", size=1234)],
    )
    with pytest.raises(ImagingPreflightError, match="not present"):
        preflight_physical_image(
            report, tmp_path / "factory.img", host_system="Windows", available_bytes=200 * 1024 * 1024
        )


def test_preflight_rejects_insufficient_space(tmp_path):
    with pytest.raises(ImagingPreflightError, match="Insufficient"):
        preflight_physical_image(
            _report(tmp_path), tmp_path / "factory.img", host_system="Windows", available_bytes=1
        )


def test_preflight_rejects_wrong_suffix(tmp_path):
    with pytest.raises(ImagingPreflightError, match=".img or .bin"):
        preflight_physical_image(
            _report(tmp_path), tmp_path / "factory.zip", host_system="Windows", available_bytes=200 * 1024 * 1024
        )


def test_preflight_refuses_existing_destination_without_overwrite(tmp_path):
    destination = tmp_path / "factory.img"
    destination.write_bytes(b"existing")
    with pytest.raises(ImagingPreflightError, match="already exists"):
        preflight_physical_image(
            _report(tmp_path), destination, host_system="Windows", available_bytes=200 * 1024 * 1024
        )


def test_create_raw_image_is_exact_and_verified(tmp_path):
    data = (b"GAMESTICK-SECTOR-DATA\x00\xff" * 10000) + b"tail"
    source = tmp_path / "source.bin"
    source.write_bytes(data)
    destination = tmp_path / "factory.img"
    progress = []

    result = create_raw_image(
        _plan(source, destination),
        chunk_size=4096,
        progress=lambda phase, done, total: progress.append((phase, done, total)),
    )

    expected = hashlib.sha256(data).hexdigest()
    assert destination.read_bytes() == data
    assert result.verified is True
    assert result.streaming_sha256 == expected
    assert result.reread_sha256 == expected
    assert result.bytes_written == len(data)
    assert not Path(str(destination) + ".partial").exists()
    assert {item[0] for item in progress} == {"imaging", "verifying"}

    manifest_path = Path(str(destination) + ".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["kind"] == "gamestick-verified-raw-image"
    assert manifest["status"] == "transfer-verified"
    assert manifest["image"]["streaming_sha256"] == expected
    assert manifest["image"]["reread_sha256"] == expected
    assert manifest["method"]["raw_device_write_performed"] is False
    assert manifest["method"]["source_open_mode"] == "read-only"


def test_create_raw_image_rejects_short_source_and_removes_partial(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"12345678")
    destination = tmp_path / "factory.img"
    plan = _plan(source, destination, source_size=100)

    with pytest.raises(ImagingError, match="ended early"):
        create_raw_image(plan, chunk_size=4)

    assert not destination.exists()
    assert not Path(str(destination) + ".partial").exists()
    assert not Path(str(destination) + ".manifest.json").exists()


def test_create_raw_image_cancellation_removes_partial(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"x" * 10000)
    destination = tmp_path / "factory.img"

    with pytest.raises(ImagingCancelled):
        create_raw_image(_plan(source, destination), chunk_size=1024, cancelled=lambda: True)

    assert not destination.exists()
    assert not Path(str(destination) + ".partial").exists()


def test_create_raw_image_refuses_stale_partial(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"abc")
    destination = tmp_path / "factory.img"
    Path(str(destination) + ".partial").write_bytes(b"stale")

    with pytest.raises(ImagingError, match="partial image already exists"):
        create_raw_image(_plan(source, destination))


def test_create_raw_image_does_not_overwrite_existing_without_permission(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"new")
    destination = tmp_path / "factory.img"
    destination.write_bytes(b"old")

    with pytest.raises(ImagingError, match="already exists"):
        create_raw_image(_plan(source, destination))
    assert destination.read_bytes() == b"old"


def test_create_raw_image_can_replace_host_side_artifact_when_preflight_allowed(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"new-data")
    destination = tmp_path / "factory.img"
    destination.write_bytes(b"old-data")
    manifest = Path(str(destination) + ".manifest.json")
    manifest.write_text("old", encoding="utf-8")

    result = create_raw_image(_plan(source, destination, overwrite=True), chunk_size=3)
    assert result.verified
    assert destination.read_bytes() == b"new-data"
    assert json.loads(manifest.read_text(encoding="utf-8"))["status"] == "transfer-verified"


def test_create_raw_image_refuses_legacy_stale_manifest_temp_before_acquisition(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"recoverable")
    destination = tmp_path / "factory.img"
    temp_manifest = Path(str(destination) + ".manifest.json.tmp")
    temp_manifest.write_text("stale", encoding="utf-8")

    with pytest.raises(ImagingError, match="Stale temporary manifest"):
        create_raw_image(_plan(source, destination))

    assert not destination.exists()
    assert temp_manifest.exists()


def test_execution_reasserts_destination_is_outside_selected_card(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    source = tmp_path / "source.bin"
    source.write_bytes(b"safe-source")
    destination = card / "should-not-write.img"
    plan = replace(_plan(source, destination), selected_root=str(card))

    with pytest.raises(ValueError, match="outside the selected GameStick"):
        create_raw_image(plan)
    assert not destination.exists()


def test_windows_raw_opener_source_requests_no_generic_write():
    import inspect
    import gamestick.imaging as imaging

    source = inspect.getsource(imaging._default_source_opener)
    assert "GENERIC_READ" in source
    assert "GENERIC_WRITE" not in source
    assert 'open(path, "rb"' in source


def test_preflight_allows_degraded_filesystem_probe_when_device_safety_is_proven(tmp_path):
    report = _report(tmp_path)
    report.probe_status = "DEGRADED"
    report.read_errors = [r"Could not inspect E:\\004\\00.dat: [WinError 1392] corrupted and unreadable"]

    plan = preflight_physical_image(
        report,
        tmp_path / "degraded-card.img",
        host_system="Windows",
        available_bytes=200 * 1024 * 1024,
    )

    assert plan.disk_number == 4
    assert plan.source_path == r"\\.\PhysicalDrive4"



def test_overwrite_verification_failure_preserves_old_authoritative_pair(tmp_path, monkeypatch):
    import gamestick.imaging as imaging

    source = tmp_path / "source.bin"
    source.write_bytes(b"new-image-bytes")
    destination = tmp_path / "factory.img"
    manifest = Path(str(destination) + ".manifest.json")
    destination.write_bytes(b"OLD-IMAGE")
    manifest.write_text('{"status":"old-verified"}\n', encoding="utf-8")

    monkeypatch.setattr(imaging, "sha256_file", lambda *args, **kwargs: "0" * 64)
    with pytest.raises(ImagingError, match="verification failed"):
        create_raw_image(_plan(source, destination, overwrite=True), chunk_size=4)

    assert destination.read_bytes() == b"OLD-IMAGE"
    assert manifest.read_text(encoding="utf-8") == '{"status":"old-verified"}\n'
    assert not Path(str(destination) + ".partial").exists()
    assert not Path(str(manifest) + ".partial").exists()


def test_overwrite_manifest_staging_failure_preserves_old_authoritative_pair(tmp_path, monkeypatch):
    import gamestick.imaging as imaging

    source = tmp_path / "source.bin"
    source.write_bytes(b"new-image-bytes")
    destination = tmp_path / "factory.img"
    manifest = Path(str(destination) + ".manifest.json")
    destination.write_bytes(b"OLD-IMAGE")
    manifest.write_text('{"status":"old-verified"}\n', encoding="utf-8")

    def fail_manifest(*args, **kwargs):
        raise ImagingError("forced manifest emission failure")

    monkeypatch.setattr(imaging, "_write_staged_manifest", fail_manifest)
    with pytest.raises(ImagingError, match="forced manifest emission failure"):
        create_raw_image(_plan(source, destination, overwrite=True), chunk_size=4)

    assert destination.read_bytes() == b"OLD-IMAGE"
    assert manifest.read_text(encoding="utf-8") == '{"status":"old-verified"}\n'


def test_pair_promotion_failure_restores_old_image_and_matching_manifest(tmp_path, monkeypatch):
    import gamestick.imaging as imaging

    source = tmp_path / "source.bin"
    source.write_bytes(b"new-image-bytes")
    destination = tmp_path / "factory.img"
    manifest = Path(str(destination) + ".manifest.json")
    destination.write_bytes(b"OLD-IMAGE")
    manifest.write_text('{"status":"old-verified"}\n', encoding="utf-8")

    real_replace = imaging.os.replace

    def fail_new_manifest_promotion(src, dst):
        src_p, dst_p = Path(src), Path(dst)
        if src_p == Path(str(manifest) + ".partial") and dst_p == manifest:
            raise OSError("forced manifest promotion failure")
        return real_replace(src, dst)

    monkeypatch.setattr(imaging.os, "replace", fail_new_manifest_promotion)
    with pytest.raises(ImagingError, match="pair promotion failed"):
        create_raw_image(_plan(source, destination, overwrite=True), chunk_size=4)

    assert destination.read_bytes() == b"OLD-IMAGE"
    assert manifest.read_text(encoding="utf-8") == '{"status":"old-verified"}\n'
    assert not Path(str(destination) + ".rollback").exists()
    assert not Path(str(manifest) + ".rollback").exists()


def test_source_identity_revalidation_accepts_same_device(tmp_path):
    report = _report(tmp_path)
    plan = preflight_physical_image(
        report,
        tmp_path / "factory.img",
        host_system="Windows",
        available_bytes=200 * 1024 * 1024,
    )
    current = revalidate_source_identity(plan, mapping_resolver=lambda root: report.physical_mapping)
    assert current.disk_number == 4


def test_source_identity_revalidation_refuses_physicaldrive_reuse(tmp_path):
    report = _report(tmp_path)
    plan = preflight_physical_image(
        report,
        tmp_path / "factory.img",
        host_system="Windows",
        available_bytes=200 * 1024 * 1024,
    )
    replacement = replace(
        report.physical_mapping,
        disk_name="Different USB device",
        disk_size=64 * 1024 * 1024,
        serial_number="OTHER-SERIAL",
        disk_unique_id="OTHER-ID",
    )
    with pytest.raises(ImagingError, match="identity changed"):
        revalidate_source_identity(plan, mapping_resolver=lambda root: replacement)


def test_source_identity_revalidation_refuses_partition_topology_change(tmp_path):
    report = _report(tmp_path)
    plan = preflight_physical_image(
        report,
        tmp_path / "factory.img",
        host_system="Windows",
        available_bytes=200 * 1024 * 1024,
    )
    changed = replace(
        report.physical_mapping,
        partitions=[
            DiskPartitionInfo(
                partition_number=1,
                drive_letter="E",
                offset=2 * 1024 * 1024,
                size=30 * 1024 * 1024,
                filesystem="FAT32",
            )
        ],
    )
    with pytest.raises(ImagingError, match="partition layout hash"):
        revalidate_source_identity(plan, mapping_resolver=lambda root: changed)


def test_create_raw_image_revalidates_identity_before_source_open(tmp_path):
    report = _report(tmp_path)
    destination = tmp_path / "factory.img"
    plan = preflight_physical_image(
        report,
        destination,
        host_system="Windows",
        available_bytes=200 * 1024 * 1024,
    )
    replacement = replace(report.physical_mapping, disk_size=64 * 1024 * 1024)
    opened = {"value": False}

    def opener(_path):
        opened["value"] = True
        raise AssertionError("source must not be opened after identity mismatch")

    with pytest.raises(ImagingError, match="identity changed"):
        create_raw_image(
            plan,
            source_opener=opener,
            identity_resolver=lambda root: replacement,
        )
    assert opened["value"] is False


def test_preflight_rejects_destination_on_another_partition_of_source_disk(tmp_path):
    with pytest.raises(ValueError, match="same physical disk"):
        preflight_physical_image(
            _report(tmp_path),
            r"F:\\factory.img",
            host_system="Windows",
            available_bytes=200 * 1024 * 1024,
            destination_disk_resolver=lambda drive: 4,
        )


def test_windows_raw_opener_performs_handle_identity_ioctls():
    import inspect
    import gamestick.imaging as imaging

    source = inspect.getsource(imaging._default_source_opener)
    validator = inspect.getsource(imaging._validate_windows_handle_identity)
    assert "_validate_windows_handle_identity" in source
    assert "IOCTL_STORAGE_GET_DEVICE_NUMBER" in validator
    assert "IOCTL_DISK_GET_LENGTH_INFO" in validator
    assert "DeviceIoControl" in validator


def test_manifest_records_successful_source_identity_revalidation(tmp_path):
    import io

    data = b"A" * 8192
    part = DiskPartitionInfo(
        partition_number=1,
        drive_letter="E",
        offset=0,
        size=len(data),
        filesystem="FAT32",
    )
    report = _report(
        tmp_path,
        disk_size=len(data),
        partition_size=len(data),
        partition_offset=0,
        partitions=[part],
    )
    destination = tmp_path / "factory.img"
    plan = preflight_physical_image(
        report,
        destination,
        host_system="Windows",
        available_bytes=200 * 1024 * 1024,
    )

    result = create_raw_image(
        plan,
        source_opener=lambda _path: io.BytesIO(data),
        identity_resolver=lambda _root: report.physical_mapping,
        chunk_size=1024,
    )
    assert result.verified is True
    manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
    assert manifest["method"]["source_identity_revalidated_before_open"] is True


def test_windows_raw_staging_survives_destination_junction_swap_without_source_write(tmp_path, monkeypatch):
    import gamestick.imaging as imaging
    from gamestick.safety import BoundOutputVolume

    data = b"sector-data" * 512
    source = tmp_path / "source.bin"
    source.write_bytes(data)

    report = _report(
        tmp_path,
        disk_size=len(data),
        partition_size=len(data),
        partition_offset=0,
        partitions=[
            DiskPartitionInfo(
                partition_number=1,
                drive_letter="E",
                offset=0,
                size=len(data),
                filesystem="FAT32",
            )
        ],
    )
    host = tmp_path / "host"
    host.mkdir()
    card = tmp_path / "card"
    card.mkdir()
    safe_stage = tmp_path / "safe-stage"
    safe_stage.mkdir()
    destination = host / "factory.img"
    plan = preflight_physical_image(
        report,
        destination,
        host_system="Windows",
        available_bytes=200 * 1024 * 1024,
    )

    bind_calls = {"n": 0}

    def fake_bind(candidate, device_root, **kwargs):
        bind_calls["n"] += 1
        current = Path(candidate).resolve()
        if bind_calls["n"] <= 2:
            return BoundOutputVolume(current, 4, 2, "C", str(safe_stage))
        return BoundOutputVolume(current, 4, 4, "E", str(card))

    monkeypatch.setattr(imaging, "bind_output_volume", fake_bind)
    real_stage = imaging.secure_stage_on_bound_volume
    stage_calls = {"n": 0}

    def swap_then_stage(binding, *, suffix=".tmp"):
        stage_calls["n"] += 1
        if stage_calls["n"] == 1:
            old = tmp_path / "host-old"
            host.rename(old)
            host.symlink_to(card, target_is_directory=True)
        return real_stage(binding, suffix=suffix)

    monkeypatch.setattr(imaging, "secure_stage_on_bound_volume", swap_then_stage)

    with pytest.raises(ImagingError, match="Destination volume identity changed"):
        create_raw_image(
            plan,
            chunk_size=1024,
            source_opener=lambda path: source.open("rb"),
            identity_resolver=lambda root: report.physical_mapping,
            host_system="Windows",
        )

    assert not (card / "factory.img").exists()
    assert not (card / "factory.img.manifest.json").exists()
    assert [p for p in card.iterdir() if p.name.startswith(".gamestick-inspector-")] == []
    assert [p for p in safe_stage.iterdir() if p.name.startswith(".gamestick-inspector-")] == []
