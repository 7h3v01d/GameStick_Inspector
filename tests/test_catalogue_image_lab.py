import io
import json
import struct
import zipfile
from pathlib import Path

import pytest

from gamestick.catalogue_image_lab import CatalogueImageLabError, compare_catalogue_controls
from gamestick.repair_workspace import RepairWorkspaceError, build_repair_workspace


def _wqw_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    raw = bytearray(buffer.getvalue())
    eocd = raw.rfind(b"PK\x05\x06")
    assert eocd >= 0
    _, _, _, _, total, central_size, central_offset, comment_len = struct.unpack(
        "<4s4H2LH", raw[eocd:eocd + 22]
    )
    assert comment_len == 0
    position = central_offset
    local_offsets = []
    for _ in range(total):
        fixed = bytes(raw[position:position + 46])
        fields = struct.unpack("<4s6H3L5H2L", fixed)
        name_len, extra_len, entry_comment_len = fields[10], fields[11], fields[12]
        local_offset = fields[16]
        name_start = position + 46
        raw[position:position + 4] = b"WQW\x02"
        raw[name_start:name_start + name_len] = bytes(v ^ 0xE5 for v in raw[name_start:name_start + name_len])
        local_offsets.append(local_offset)
        position += 46 + name_len + extra_len + entry_comment_len
    assert position == central_offset + central_size
    for local_offset in local_offsets:
        fixed = bytes(raw[local_offset:local_offset + 30])
        fields = struct.unpack("<4s5H3L2H", fixed)
        name_len = fields[9]
        name_start = local_offset + 30
        raw[local_offset:local_offset + 4] = b"WQW\x03"
        raw[name_start:name_start + name_len] = bytes(v ^ 0xE5 for v in raw[name_start:name_start + name_len])
    raw[eocd:eocd + 4] = b"WQW\x01"
    return bytes(raw)


def _short_entry(base, ext="", *, attr=0x20, cluster=0, size=0):
    entry = bytearray(32)
    entry[0:8] = base.upper().encode("ascii").ljust(8, b" ")[:8]
    entry[8:11] = ext.upper().encode("ascii").ljust(3, b" ")[:3]
    entry[11] = attr
    entry[20:22] = ((cluster >> 16) & 0xFFFF).to_bytes(2, "little")
    entry[26:28] = (cluster & 0xFFFF).to_bytes(2, "little")
    entry[28:32] = int(size).to_bytes(4, "little")
    return bytes(entry)


def _make_image(path: Path, *, code0_roms=("game-a.zip", "game-b.zip"), code0_title="Title", damage_code1=False):
    bps = 512
    spc = 8
    cluster_size = bps * spc
    start_lba = 2048
    partition_sectors = 16384
    image_size = (start_lba + partition_sectors) * bps
    blob = bytearray(image_size)

    pe = 446
    blob[pe] = 0x80
    blob[pe + 4] = 0x0C
    blob[pe + 8:pe + 12] = start_lba.to_bytes(4, "little")
    blob[pe + 12:pe + 16] = partition_sectors.to_bytes(4, "little")
    blob[510:512] = b"\x55\xaa"

    part = start_lba * bps
    boot = bytearray(512)
    boot[11:13] = bps.to_bytes(2, "little")
    boot[13] = spc
    boot[14:16] = (32).to_bytes(2, "little")
    boot[16] = 1
    boot[36:40] = (16).to_bytes(4, "little")
    boot[44:48] = (2).to_bytes(4, "little")
    boot[510:512] = b"\x55\xaa"
    blob[part:part + 512] = boot

    fat_off = part + 32 * bps
    data_off = part + (32 + 16) * bps

    def fat_set(cluster, value=0x0FFFFFFF):
        off = fat_off + cluster * 4
        blob[off:off + 4] = value.to_bytes(4, "little")

    fat_set(0, 0x0FFFFFF8)
    fat_set(1, 0x0FFFFFFF)

    next_cluster = 2
    def alloc(payload: bytes) -> int:
        nonlocal next_cluster
        count = max(1, (len(payload) + cluster_size - 1) // cluster_size)
        start = next_cluster
        for i in range(count):
            c = next_cluster
            next_cluster += 1
            fat_set(c, (c + 1) if i + 1 < count else 0x0FFFFFFF)
            off = data_off + (c - 2) * cluster_size
            piece = payload[i * cluster_size:(i + 1) * cluster_size]
            blob[off:off + len(piece)] = piece
        return start

    # Reserve root first; fill after child allocation.
    root_cluster = alloc(b"\x00" * cluster_size)

    root_fileinfo = (
        "000/game-a.zip;Game A;GAME A;A;X\r\n"
        "000/game-b.zip;Game B;GAME B;B;X\r\n"
        "001/one.zip;One;ONE;One;X\r\n"
    ).encode()
    root_dat = _wqw_bytes({"fileinfo.txt": root_fileinfo, "000.raw": b"x"})
    root_dat_cluster = alloc(root_dat)

    dir_entries = []
    for code_num in range(15):
        code = f"{code_num:03d}"
        if code_num == 0:
            filelist = "".join(f"{name};{code0_title};{code0_title}\r\n" for name in code0_roms).encode()
        elif code_num == 1:
            filelist = b"one.zip;One;One\r\n"
        else:
            filelist = f"{code}.zip;{code};{code}\r\n".encode()
        dat = _wqw_bytes({"filelist.txt": filelist, f"{code}_000.raw": b"preview"})
        if damage_code1 and code_num == 1:
            damaged = bytearray(dat)
            central = damaged.find(b"WQW\x02")
            assert central >= 0
            damaged[central:central + 4] = b"BAD!"
            dat = bytes(damaged)
        dat_cluster = alloc(dat)
        directory_payload = _short_entry(code, "DAT", cluster=dat_cluster, size=len(dat)) + b"\x00" * 32
        dir_cluster = alloc(directory_payload)
        dir_entries.append(_short_entry(code, attr=0x10, cluster=dir_cluster))

    root_entries = [_short_entry("ROOT", "DAT", cluster=root_dat_cluster, size=len(root_dat)), *dir_entries]
    root_payload = b"".join(root_entries) + b"\x00" * 32
    root_off = data_off + (root_cluster - 2) * cluster_size
    blob[root_off:root_off + len(root_payload)] = root_payload
    path.write_bytes(blob)
    return path


def test_catalogue_compare_reads_only_controls_and_reports_list_delta(tmp_path):
    a = _make_image(tmp_path / "a.img")
    b = _make_image(tmp_path / "b.img", code0_roms=("game-a.zip", "game-c.zip"))
    report = tmp_path / "catalogues.json"
    result = compare_catalogue_controls(a, b, report_path=report)
    assert result.status == "CATALOGUE_CONTENT_DIFFERENCE"
    assert result.differing_catalogue_codes == ("000",)
    delta = result.deltas[0]
    assert delta.status == "CATALOGUE_LIST_DIFFERENT"
    assert delta.only_in_a_roms == ("game-b.zip",)
    assert delta.only_in_b_roms == ("game-c.zip",)
    payload = json.loads(report.read_text("utf-8"))
    assert payload["read_policy"]["full_image_payload_scan_performed"] is False
    assert payload["read_policy"]["rom_payloads_read"] is False
    assert payload["read_policy"]["source_writes_performed"] is False
    assert '"rom_names":' not in report.read_text("utf-8")
    assert result.image_a.bytes_read_for_controls < 2 * 1024 * 1024



def test_byte_only_filelist_change_is_not_misclassified_as_rom_list_change(tmp_path):
    a = _make_image(tmp_path / "a.img", code0_title="Title A")
    b = _make_image(tmp_path / "b.img", code0_title="Title B")
    result = compare_catalogue_controls(a, b)
    assert result.status == "CATALOGUE_BYTES_DIFFER_LOGIC_MATCHES"
    assert result.differing_catalogue_count == 0
    assert result.byte_only_catalogue_codes == ("000",)
    assert result.deltas[0].status == "CONTROL_BYTES_DIFFER_LIST_SAME"


def test_catalogue_compare_reports_damaged_container_without_guessing(tmp_path):
    a = _make_image(tmp_path / "a.img")
    b = _make_image(tmp_path / "b.img", damage_code1=True)
    result = compare_catalogue_controls(a, b)
    assert result.status == "CATALOGUE_DAMAGE_OR_UNREADABLE"
    assert "001" in result.damaged_or_unreadable_codes
    assert result.deltas[1].status == "DAMAGED_OR_UNREADABLE"
    assert result.deltas[1].image_b_control_status == "CONTROL_UNAVAILABLE"


def test_catalogue_report_cannot_replace_source_image(tmp_path):
    a = _make_image(tmp_path / "a.img")
    b = _make_image(tmp_path / "b.img")
    with pytest.raises(CatalogueImageLabError, match="replace an input image"):
        compare_catalogue_controls(a, b, report_path=a)



def test_repair_workspace_builds_same_slot_replacement_without_touching_sources(tmp_path):
    golden = _make_image(tmp_path / "golden.img")
    base = _make_image(tmp_path / "base.img", damage_code1=True)
    golden_before = golden.read_bytes()
    base_before = base.read_bytes()
    output = tmp_path / "repair.gsworkspace"

    result = build_repair_workspace(golden, base, output)

    assert result.repair_count == 1
    assert result.repaired_codes == ("001",)
    assert result.archive_verified is True
    assert result.source_writes_performed is False
    assert golden.read_bytes() == golden_before
    assert base.read_bytes() == base_before
    assert output.is_file()

    with zipfile.ZipFile(output, "r") as archive:
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        repair = manifest["repairs"][0]
        assert repair["code"] == "001"
        assert repair["file_size_bytes"] > 0
        assert repair["base_file_sha256"] != repair["replacement_file_sha256"]
        assert repair["replacement_unique_rom_name_count"] == 1
        payload = archive.read(repair["payload_member"])
        assert len(payload) == repair["file_size_bytes"]
        assert manifest["safety"]["source_writes_performed"] is False
        assert manifest["safety"]["full_image_copy_performed"] is False


def test_repair_workspace_refuses_when_there_is_no_damaged_target_catalogue(tmp_path):
    golden = _make_image(tmp_path / "golden.img")
    base = _make_image(tmp_path / "base.img")
    with pytest.raises(RepairWorkspaceError, match="No safe repair candidate"):
        build_repair_workspace(golden, base, tmp_path / "repair.gsworkspace")


def test_repair_workspace_cannot_replace_source_image(tmp_path):
    golden = _make_image(tmp_path / "golden.img")
    base = _make_image(tmp_path / "base.img", damage_code1=True)
    with pytest.raises(RepairWorkspaceError, match="replace an input image"):
        build_repair_workspace(golden, base, golden)
