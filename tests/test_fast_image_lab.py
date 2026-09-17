import json
from pathlib import Path

import pytest

from gamestick.fast_image_lab import FastImageLabError, compare_fast_structures, inspect_image_structure


def _short_entry(base, ext="", *, attr=0x20, cluster=0, size=0):
    entry = bytearray(32)
    entry[0:8] = base.upper().encode("ascii").ljust(8, b" ")[:8]
    entry[8:11] = ext.upper().encode("ascii").ljust(3, b" ")[:3]
    entry[11] = attr
    entry[20:22] = ((cluster >> 16) & 0xFFFF).to_bytes(2, "little")
    entry[26:28] = (cluster & 0xFFFF).to_bytes(2, "little")
    entry[28:32] = int(size).to_bytes(4, "little")
    return bytes(entry)


def _make_image(path: Path, *, root_payload=b"ROOT", extra_rom=False, cluster_shift=0):
    bps = 512
    start_lba = 2048
    partition_sectors = 4096
    image_size = (start_lba + partition_sectors) * bps
    blob = bytearray(image_size)

    # MBR: active FAT32 LBA partition.
    pe = 446
    blob[pe] = 0x80
    blob[pe + 4] = 0x0C
    blob[pe + 8:pe + 12] = start_lba.to_bytes(4, "little")
    blob[pe + 12:pe + 16] = partition_sectors.to_bytes(4, "little")
    blob[510:512] = b"\x55\xaa"

    part = start_lba * bps
    boot = bytearray(512)
    boot[11:13] = (512).to_bytes(2, "little")
    boot[13] = 1
    boot[14:16] = (32).to_bytes(2, "little")
    boot[16] = 1
    boot[36:40] = (8).to_bytes(4, "little")
    boot[44:48] = (2 + cluster_shift).to_bytes(4, "little")
    boot[510:512] = b"\x55\xaa"
    blob[part:part + 512] = boot

    fat_off = part + 32 * bps
    data_off = part + (32 + 8) * bps

    def fat_set(cluster, value=0x0FFFFFFF):
        off = fat_off + cluster * 4
        blob[off:off + 4] = value.to_bytes(4, "little")

    # Reserve FAT entries plus our used clusters.
    fat_set(0, 0x0FFFFFF8)
    fat_set(1, 0x0FFFFFFF)
    for c in range(2 + cluster_shift, 10 + cluster_shift):
        fat_set(c)

    def cluster_off(cluster):
        return data_off + (cluster - 2) * bps

    root_c = 2 + cluster_shift
    root_file_c = 3 + cluster_shift
    d000_c = 4 + cluster_shift
    dat000_c = 5 + cluster_shift
    cubegm_c = 6 + cluster_shift
    config_c = 7 + cluster_shift
    roms_c = 8 + cluster_shift
    rom_c = 9 + cluster_shift

    root_entries = [
        _short_entry("ROOT", "DAT", cluster=root_file_c, size=len(root_payload)),
        _short_entry("000", attr=0x10, cluster=d000_c),
        _short_entry("CUBEGM", attr=0x10, cluster=cubegm_c),
        _short_entry("ROMS", attr=0x10, cluster=roms_c),
    ]
    root_dir = b"".join(root_entries) + b"\x00" * 32
    blob[cluster_off(root_c):cluster_off(root_c) + len(root_dir)] = root_dir
    blob[cluster_off(root_file_c):cluster_off(root_file_c) + len(root_payload)] = root_payload

    dat_payload = b"CATALOGUE000"
    dir000 = _short_entry("000", "DAT", cluster=dat000_c, size=len(dat_payload)) + b"\x00" * 32
    blob[cluster_off(d000_c):cluster_off(d000_c) + len(dir000)] = dir000
    blob[cluster_off(dat000_c):cluster_off(dat000_c) + len(dat_payload)] = dat_payload

    config_payload = b"mode=game\n"
    cubegm = _short_entry("CONFIG", "INI", cluster=config_c, size=len(config_payload)) + b"\x00" * 32
    blob[cluster_off(cubegm_c):cluster_off(cubegm_c) + len(cubegm)] = cubegm
    blob[cluster_off(config_c):cluster_off(config_c) + len(config_payload)] = config_payload

    rom_payload = b"ROMDATA"
    rom_entries = [_short_entry("GAME", "ROM", cluster=rom_c, size=len(rom_payload))]
    blob[cluster_off(rom_c):cluster_off(rom_c) + len(rom_payload)] = rom_payload
    if extra_rom:
        extra_c = 10 + cluster_shift
        fat_set(extra_c)
        extra_payload = b"SECOND"
        rom_entries.append(_short_entry("EXTRA", "ROM", cluster=extra_c, size=len(extra_payload)))
        blob[cluster_off(extra_c):cluster_off(extra_c) + len(extra_payload)] = extra_payload
    rom_dir = b"".join(rom_entries) + b"\x00" * 32
    blob[cluster_off(roms_c):cluster_off(roms_c) + len(rom_dir)] = rom_dir

    path.write_bytes(blob)
    return path


def test_inspect_reads_structure_without_full_image_hash(tmp_path):
    image = _make_image(tmp_path / "a.img")
    result, entries = inspect_image_structure(image)
    assert result.geometry.partition_lba_start == 2048
    assert result.file_count == 4
    assert "root.dat" in {x.path.lower() for x in result.critical_files}
    assert "000/000.dat" in {x.path.lower() for x in result.critical_files}
    assert "cubegm/config.ini" in {x.path.lower() for x in result.critical_files}
    assert result.bytes_hashed_for_controls < 1024
    assert "ROMS/GAME.ROM" in entries


def test_identical_logical_images_can_use_different_clusters(tmp_path):
    a = _make_image(tmp_path / "a.img", cluster_shift=0)
    b = _make_image(tmp_path / "b.img", cluster_shift=20)
    result = compare_fast_structures(a, b)
    assert result.status == "LOGICALLY_IDENTICAL"
    assert result.structure_identical is True
    assert result.critical_files_identical is True


def test_rom_only_difference_does_not_become_control_difference(tmp_path):
    a = _make_image(tmp_path / "a.img")
    b = _make_image(tmp_path / "b.img", extra_rom=True)
    result = compare_fast_structures(a, b)
    assert result.status == "CONTENT_LAYOUT_DIFFERS_CONTROLS_MATCH"
    assert result.critical_files_identical is True
    assert result.only_in_b_count == 1


def test_control_change_is_reported(tmp_path):
    a = _make_image(tmp_path / "a.img", root_payload=b"ROOT-A")
    b = _make_image(tmp_path / "b.img", root_payload=b"ROOT-B")
    result = compare_fast_structures(a, b)
    assert result.status == "LAUNCHER_OR_CONTROL_DIFFERENCE"
    assert result.critical_files_identical is False
    assert any(name.lower() == "root.dat" for name in result.critical_hash_changed)


def test_report_is_host_side_json_and_never_replaces_source(tmp_path):
    a = _make_image(tmp_path / "a.img")
    b = _make_image(tmp_path / "b.img", extra_rom=True)
    report = tmp_path / "fast.json"
    result = compare_fast_structures(a, b, report_path=report)
    data = json.loads(report.read_text("utf-8"))
    assert result.report_path == str(report.resolve())
    assert data["schema"] == "gamestick-fast-image-structure-v1"
    assert data["read_policy"]["full_image_payload_scan_performed"] is False
    assert data["read_policy"]["source_writes_performed"] is False
    with pytest.raises(FastImageLabError, match="replace an input image"):
        compare_fast_structures(a, b, report_path=a)
