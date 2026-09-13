import pytest

from gamestick.safety import UnsafeOperationDisabled, refuse_destructive_operation


@pytest.mark.parametrize("operation", ["restore", "flash", "format", "delete all"])
def test_destructive_operations_are_unconditionally_blocked(operation):
    with pytest.raises(UnsafeOperationDisabled):
        refuse_destructive_operation(operation)


def test_output_cannot_be_written_inside_device(tmp_path):
    from gamestick.safety import assert_output_outside_device
    device = tmp_path / "card"
    device.mkdir()
    with pytest.raises(ValueError):
        assert_output_outside_device(device / "probe.json", device)


def test_output_can_be_written_elsewhere(tmp_path):
    from gamestick.safety import assert_output_outside_device
    device = tmp_path / "card"
    destination = tmp_path / "reports" / "probe.json"
    device.mkdir()
    assert assert_output_outside_device(destination, device) == destination.resolve()


def test_output_rejects_other_partition_on_same_physical_disk():
    from gamestick.safety import assert_output_outside_source_disk

    with pytest.raises(ValueError, match="same physical disk"):
        assert_output_outside_source_disk(
            r"F:\\evidence.zip",
            r"E:\\",
            source_disk_number=4,
            host_system="Windows",
            destination_disk_resolver=lambda drive: 4,
        )


def test_output_allows_different_physical_disk():
    from gamestick.safety import assert_output_outside_source_disk

    out = assert_output_outside_source_disk(
        r"G:\\evidence.zip",
        r"E:\\",
        source_disk_number=4,
        host_system="Windows",
        destination_disk_resolver=lambda drive: 2,
    )
    assert out.name == "G:\\\\evidence.zip" or str(out).endswith("evidence.zip")


def test_output_fails_closed_when_destination_local_disk_cannot_be_resolved():
    from gamestick.safety import assert_output_outside_source_disk

    def fail(_drive):
        raise RuntimeError("mapping unavailable")

    with pytest.raises(ValueError, match="Could not prove"):
        assert_output_outside_source_disk(
            r"G:\\evidence.zip",
            r"E:\\",
            source_disk_number=4,
            host_system="Windows",
            destination_disk_resolver=fail,
        )


def test_output_physical_validation_uses_resolved_drive_not_syntactic_alias(monkeypatch):
    import gamestick.safety as safety

    # Simulate C:\\host-link\\ resolving through a junction to F:\\ on the source disk.
    monkeypatch.setattr(
        safety,
        "assert_output_outside_device",
        lambda candidate, device_root: safety.Path(r"F:\\evidence.zip"),
    )
    seen = []

    def resolve_disk(drive):
        seen.append(drive)
        return 4

    with pytest.raises(ValueError, match="same physical disk"):
        safety.assert_output_outside_source_disk(
            r"C:\\host-link\\evidence.zip",
            r"E:\\",
            source_disk_number=4,
            host_system="Windows",
            destination_disk_resolver=resolve_disk,
        )
    assert seen == ["F"]


def test_output_rejects_unc_destination_before_disk_resolution():
    from gamestick.safety import assert_output_outside_source_disk

    called = {"value": False}

    def resolver(_drive):
        called["value"] = True
        return 2

    with pytest.raises(ValueError, match="UNC/network"):
        assert_output_outside_source_disk(
            r"\\server\share\evidence.zip",
            r"E:\\",
            source_disk_number=4,
            host_system="Windows",
            destination_disk_resolver=resolver,
        )
    assert called["value"] is False


def test_windows_output_fails_closed_when_source_disk_unknown():
    from gamestick.safety import assert_output_outside_source_disk

    called = {"value": False}

    def resolver(_drive):
        called["value"] = True
        return 2

    with pytest.raises(ValueError, match="Source physical disk could not be proven"):
        assert_output_outside_source_disk(
            r"F:\\evidence.zip",
            r"E:\\",
            source_disk_number=None,
            host_system="Windows",
            destination_disk_resolver=resolver,
        )
    assert called["value"] is False


def test_windows_unknown_source_does_not_bypass_unc_rejection():
    from gamestick.safety import assert_output_outside_source_disk

    with pytest.raises(ValueError, match="UNC/network"):
        assert_output_outside_source_disk(
            r"\\server\share\evidence.zip",
            r"E:\\",
            source_disk_number=None,
            host_system="Windows",
        )


def test_bound_volume_rejects_drive_to_volume_identity_change(monkeypatch):
    import gamestick.safety as safety

    monkeypatch.setattr(
        safety,
        "assert_output_outside_device",
        lambda candidate, device_root: safety.Path(r"F:\\evidence.zip"),
    )
    with pytest.raises(ValueError, match="changed while binding"):
        safety.bind_output_volume(
            r"F:\\evidence.zip",
            r"E:\\",
            source_disk_number=4,
            host_system="Windows",
            destination_disk_resolver=lambda drive: 2,
            volume_root_resolver=lambda drive: r"\\?\Volume{SAFE}\\",
            volume_disk_resolver=lambda volume: 3,
        )
