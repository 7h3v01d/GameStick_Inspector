import io
import os
import json
import struct
import zipfile
from pathlib import Path

import pytest

from gamestick.catalogue_image_lab import _FatAccessor, _locate_catalogues
from gamestick.custom_apply import (
    CustomizationApplyError,
    _DirectAccessor,
    apply_customization_workspace,
    expected_confirmation,
    rollback_customization,
)
from gamestick.fast_image_lab import FatEntry, _parse_geometry
from gamestick.rom_customization import _read_control_layout, build_hide_rom_workspace


def _wqw_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    raw = bytearray(buffer.getvalue())
    eocd = raw.rfind(b"PK\x05\x06")
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


def _make_source_image(path: Path):
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

    root_cluster = alloc(b"\x00" * cluster_size)
    root_fileinfo = (
        "000/game-a.zip;Game A;GAME A;A;X\r\n"
        "000/game-b.zip;Game B;GAME B;B;X\r\n"
    ).encode()
    root_dat = _wqw_bytes({"fileinfo.txt": root_fileinfo, "000.raw": b"x"})
    root_dat_cluster = alloc(root_dat)

    dir_entries = []
    for code_num in range(15):
        code = f"{code_num:03d}"
        if code_num == 0:
            filelist = b"game-a.zip;Game A;Game A\r\ngame-b.zip;Game B;Game B\r\n"
        else:
            filelist = f"{code}.zip;{code};{code}\r\n".encode()
        dat = _wqw_bytes({"filelist.txt": filelist, f"{code}_000.raw": b"preview"})
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


def _materialize_target_from_image(image: Path, root: Path):
    root.mkdir()
    (root / "CUBEGM").mkdir()
    (root / "Roms").mkdir()
    with image.open("rb", buffering=0) as handle:
        geometry = _parse_geometry(handle, image.stat().st_size)
        catalogues, root_entry = _locate_catalogues(handle, geometry)
        accessor = _FatAccessor(handle, geometry)
        assert root_entry is not None
        (root / "ROOT.DAT").write_bytes(accessor.read_range(root_entry, 0, root_entry.size_bytes))
        for code, entry in catalogues.items():
            directory = root / code
            directory.mkdir()
            (directory / f"{code}.DAT").write_bytes(accessor.read_range(entry, 0, entry.size_bytes))
    return root


def _control_payload(path: Path, rel: str, control: str) -> bytes:
    entry = FatEntry(path=rel, size_bytes=path.stat().st_size, start_cluster=2, is_directory=False)
    with path.open("rb", buffering=0) as handle:
        layout = _read_control_layout(_DirectAccessor(handle), entry, control)
    return layout.payload


def test_apply_and_rollback_tiny_workspace_against_mounted_clone(tmp_path):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    before_dat = (target / "000" / "000.DAT").read_bytes()
    before_root = (target / "ROOT.DAT").read_bytes()
    rollback = tmp_path / "hide.gsrollback"

    result = apply_customization_workspace(
        source,
        workspace,
        target,
        rollback,
        confirmation=expected_confirmation(target),
        host_system="Linux",
    )
    assert result.verification == "REREAD_REPLACEMENT_CONTROL_AND_PATCH_BYTES_MATCHED"
    assert rollback.is_file()
    assert b"game-a.zip" not in _control_payload(target / "000" / "000.DAT", "000/000.DAT", "filelist.txt")
    assert b"000/game-a.zip" not in _control_payload(target / "ROOT.DAT", "ROOT.DAT", "fileinfo.txt")
    assert (target / "000" / "000.DAT").stat().st_size == len(before_dat)
    assert (target / "ROOT.DAT").stat().st_size == len(before_root)

    rollback_result = rollback_customization(
        rollback,
        target,
        confirmation=f"ROLL BACK {target.name}",
        host_system="Linux",
    )
    assert rollback_result.verification == "REREAD_SOURCE_CONTROL_AND_ORIGINAL_PATCH_BYTES_MATCHED"
    assert (target / "000" / "000.DAT").read_bytes() == before_dat
    assert (target / "ROOT.DAT").read_bytes() == before_root



def test_apply_uses_writable_descriptor_for_rollback_fsync(tmp_path, monkeypatch):
    """Emulate Windows `_commit`: fsync must not be called on a read-only descriptor."""
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    rollback = tmp_path / "hide.gsrollback"

    real_fsync = os.fsync

    def windows_like_fsync(fd):
        # A zero-byte write is harmless but fails with EBADF on a read-only fd,
        # matching Windows CRT `_commit`/os.fsync behaviour that exposed alpha13.
        os.write(fd, b"")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", windows_like_fsync)

    result = apply_customization_workspace(
        source,
        workspace,
        target,
        rollback,
        confirmation=expected_confirmation(target),
        host_system="Linux",
    )
    assert result.verification == "REREAD_REPLACEMENT_CONTROL_AND_PATCH_BYTES_MATCHED"
    assert rollback.is_file()

def test_apply_rejects_wrong_confirmation_before_write(tmp_path):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    before = (target / "000" / "000.DAT").read_bytes()
    with pytest.raises(CustomizationApplyError, match="Typed confirmation"):
        apply_customization_workspace(
            source, workspace, target, tmp_path / "hide.gsrollback",
            confirmation="NO", host_system="Linux",
        )
    assert (target / "000" / "000.DAT").read_bytes() == before


def test_apply_rejects_target_byte_drift_before_write(tmp_path):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    dat = target / "000" / "000.DAT"
    raw = bytearray(dat.read_bytes())
    raw[-1] ^= 0x01
    dat.write_bytes(raw)
    with pytest.raises(CustomizationApplyError):
        apply_customization_workspace(
            source, workspace, target, tmp_path / "hide.gsrollback",
            confirmation=expected_confirmation(target), host_system="Linux",
        )


def test_apply_revalidates_source_chain_fingerprint(tmp_path):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    # Tamper only with the workspace manifest chain fingerprint, preserving archive structure.
    tampered = tmp_path / "tampered.gscustom"
    with zipfile.ZipFile(workspace, "r") as zin, zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_STORED) as zout:
        manifest = json.loads(zin.read("manifest.json"))
        manifest["patched_files"][0]["target_chain_sha256"] = "0" * 64
        zout.writestr("manifest.json", json.dumps(manifest))
        for name in zin.namelist():
            if name != "manifest.json":
                zout.writestr(name, zin.read(name))
    with pytest.raises(CustomizationApplyError, match="FAT-chain fingerprint"):
        apply_customization_workspace(
            source, tampered, target, tmp_path / "hide.gsrollback",
            confirmation=expected_confirmation(target), host_system="Linux",
        )


def test_workspace_with_unreferenced_payload_fails_closed(tmp_path):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "game-a.zip", workspace)
    bad = tmp_path / "bad.gscustom"
    with zipfile.ZipFile(workspace, "r") as zin, zipfile.ZipFile(bad, "w", compression=zipfile.ZIP_STORED) as zout:
        for name in zin.namelist():
            zout.writestr(name, zin.read(name))
        zout.writestr("patches/extra.bin", b"surprise")
    target = _materialize_target_from_image(source, tmp_path / "target")
    with pytest.raises(CustomizationApplyError, match="unreferenced"):
        apply_customization_workspace(
            source, bad, target, tmp_path / "hide.gsrollback",
            confirmation=expected_confirmation(target), host_system="Linux",
        )
