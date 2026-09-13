from gamestick.probe import _mapping_from_windows_payload


def test_windows_mapping_payload_handles_partition_list():
    mapping = _mapping_from_windows_payload({
        "DiskNumber": 4,
        "PartitionNumber": 2,
        "DiskName": "USB Reader",
        "BusType": "USB",
        "PartitionStyle": "MBR",
        "DiskSize": 64000000000,
        "PartitionSize": 63000000000,
        "PartitionOffset": 1048576,
        "IsBoot": False,
        "IsSystem": False,
        "IsReadOnly": False,
        "LogicalSectorSize": 512,
        "PhysicalSectorSize": 512,
        "FileSystem": "FAT32",
        "FileSystemLabel": "GAME",
        "Partitions": [
            {"PartitionNumber": 1, "Offset": 1048576, "Size": 1000000, "FileSystem": None},
            {"PartitionNumber": 2, "DriveLetter": "E", "Offset": 2048576, "Size": 63000000000, "FileSystem": "FAT32"},
        ],
    })
    assert mapping.disk_number == 4
    assert mapping.filesystem == "FAT32"
    assert mapping.logical_sector_size == 512
    assert len(mapping.partitions) == 2
    assert mapping.partitions[1].drive_letter == "E"


def test_windows_mapping_payload_normalizes_single_partition_object():
    mapping = _mapping_from_windows_payload({
        "Partitions": {"PartitionNumber": 1, "DriveLetter": "E", "Size": 1234}
    })
    assert len(mapping.partitions) == 1
    assert mapping.partitions[0].partition_number == 1
