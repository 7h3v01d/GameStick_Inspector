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
        host_system="Linux", _test_allow_non_windows=True,
    )
    assert result.verification == "REREAD_REPLACEMENT_CONTROL_AND_PATCH_BYTES_MATCHED_AND_RECEIPT_COMMITTED"
    assert rollback.is_file()
    assert b"game-a.zip" not in _control_payload(target / "000" / "000.DAT", "000/000.DAT", "filelist.txt")
    assert b"000/game-a.zip" not in _control_payload(target / "ROOT.DAT", "ROOT.DAT", "fileinfo.txt")
    assert (target / "000" / "000.DAT").stat().st_size == len(before_dat)
    assert (target / "ROOT.DAT").stat().st_size == len(before_root)

    rollback_result = rollback_customization(
        rollback,
        target,
        confirmation=f"ROLL BACK {target.name}",
        host_system="Linux", _test_allow_non_windows=True,
    )
    assert rollback_result.verification == "REREAD_SOURCE_CONTROL_AND_ORIGINAL_PATCH_BYTES_MATCHED_TRANSACTIONALLY"
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
        host_system="Linux", _test_allow_non_windows=True,
    )
    assert result.verification == "REREAD_REPLACEMENT_CONTROL_AND_PATCH_BYTES_MATCHED_AND_RECEIPT_COMMITTED"
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
            confirmation="NO", host_system="Linux", _test_allow_non_windows=True,
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
            confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
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
    with pytest.raises(CustomizationApplyError, match="patch authority"):
        apply_customization_workspace(
            source, tampered, target, tmp_path / "hide.gsrollback",
            confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
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
            confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
        )


def test_rom_manager_marks_exact_hidden_entry_and_rollback_restores_visibility(tmp_path):
    from gamestick.rom_manager import scan_rom_manager

    source = _make_source_image(tmp_path / "golden.img")
    target = _materialize_target_from_image(source, tmp_path / "target")

    before = scan_rom_manager(source, target)
    entry_before = next(item for item in before.entries if item.identity == "000:game-a.zip")
    assert entry_before.state == "VISIBLE"
    assert before.hidden_count == 0

    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    rollback = tmp_path / "hide.gsrollback"
    apply_customization_workspace(
        source,
        workspace,
        target,
        rollback,
        confirmation=expected_confirmation(target),
        host_system="Linux", _test_allow_non_windows=True,
    )

    hidden = scan_rom_manager(source, target)
    entry_hidden = next(item for item in hidden.entries if item.identity == "000:game-a.zip")
    other = next(item for item in hidden.entries if item.identity == "000:game-b.zip")
    assert entry_hidden.state == "HIDDEN"
    assert entry_hidden.catalogue_present is False
    assert entry_hidden.root_present is False
    assert other.state == "VISIBLE"
    assert hidden.hidden_count == 1

    rollback_customization(
        rollback,
        target,
        confirmation=f"ROLL BACK {target.name}",
        host_system="Linux", _test_allow_non_windows=True,
    )
    restored = scan_rom_manager(source, target)
    entry_restored = next(item for item in restored.entries if item.identity == "000:game-a.zip")
    assert entry_restored.state == "VISIBLE"
    assert restored.hidden_count == 0


def test_rom_manager_reference_only_uses_exact_code_plus_filename_identity(tmp_path):
    from gamestick.rom_manager import scan_rom_manager

    source = _make_source_image(tmp_path / "golden.img")
    snapshot = scan_rom_manager(source)
    identities = {item.identity for item in snapshot.entries}
    assert "000:game-a.zip" in identities
    assert "000:game-b.zip" in identities
    assert snapshot.target_root is None
    assert all(item.state == "REFERENCE" for item in snapshot.entries)


def _rewrite_workspace(workspace: Path, output: Path, mutator):
    with zipfile.ZipFile(workspace, "r") as zin, zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as zout:
        manifest = json.loads(zin.read("manifest.json"))
        extra_members = mutator(manifest, zin) or {}
        zout.writestr("manifest.json", json.dumps(manifest))
        for name in zin.namelist():
            if name != "manifest.json":
                zout.writestr(name, zin.read(name))
        for name, payload in extra_members.items():
            zout.writestr(name, payload)


def test_alpha15_rejects_workspace_with_extra_authorized_looking_byte_patch(tmp_path):
    import hashlib

    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    dat_bytes = (target / "000" / "000.DAT").read_bytes()
    bad = tmp_path / "enlarged.gscustom"

    def mutate(manifest, _zin):
        item = manifest["patched_files"][0]
        occupied = [(p["offset"], p["offset"] + p["length"]) for p in item["patches"]]
        offset = len(dat_bytes) - 1
        while any(start <= offset < end for start, end in occupied):
            offset -= 1
        original = dat_bytes[offset:offset + 1]
        replacement = bytes([original[0] ^ 0x01])
        member = "patches/000_catalogue/99.bin"
        item["patches"].append({
            "offset": offset,
            "length": 1,
            "payload_member": member,
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "replacement_sha256": hashlib.sha256(replacement).hexdigest(),
        })
        return {member: replacement}

    _rewrite_workspace(workspace, bad, mutate)
    before = (target / "000" / "000.DAT").read_bytes()
    with pytest.raises(CustomizationApplyError, match="canonical"):
        apply_customization_workspace(
            source, bad, target, tmp_path / "hide.gsrollback",
            confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
        )
    assert (target / "000" / "000.DAT").read_bytes() == before


def test_alpha15_rejects_forged_rom_identity_with_old_patch_bytes(tmp_path):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide-a.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    forged = tmp_path / "forged-name.gscustom"

    def mutate(manifest, _zin):
        manifest["rom"]["filename"] = "game-b.zip"
        return {}

    _rewrite_workspace(workspace, forged, mutate)
    target = _materialize_target_from_image(source, tmp_path / "target")
    with pytest.raises(CustomizationApplyError, match="patch authority"):
        apply_customization_workspace(
            source, forged, target, tmp_path / "hide.gsrollback",
            confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
        )
    assert b"game-a.zip" in _control_payload(target / "000" / "000.DAT", "000/000.DAT", "filelist.txt")
    assert b"game-b.zip" in _control_payload(target / "000" / "000.DAT", "000/000.DAT", "filelist.txt")


def test_alpha15_rebinds_target_after_rollback_commit_and_refuses_substitution(tmp_path, monkeypatch):
    import gamestick.custom_apply as custom_apply

    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    original_target = tmp_path / "target-a"
    rollback = tmp_path / "hide.gsrollback"
    real_write_rollback = custom_apply._write_rollback_archive

    def swap_after_rollback(*args, **kwargs):
        result = real_write_rollback(*args, **kwargs)
        target.rename(original_target)
        _materialize_target_from_image(source, target)
        return result

    monkeypatch.setattr(custom_apply, "_write_rollback_archive", swap_after_rollback)
    with pytest.raises(CustomizationApplyError, match="identity changed"):
        apply_customization_workspace(
            source, workspace, target, rollback,
            confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
        )
    assert b"game-a.zip" in _control_payload(original_target / "000" / "000.DAT", "000/000.DAT", "filelist.txt")
    assert b"game-a.zip" in _control_payload(target / "000" / "000.DAT", "000/000.DAT", "filelist.txt")


def test_alpha15_receipt_commit_failure_restores_card_and_removes_pending_receipt(tmp_path, monkeypatch):
    import gamestick.custom_apply as custom_apply

    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    before_dat = (target / "000" / "000.DAT").read_bytes()
    before_root = (target / "ROOT.DAT").read_bytes()
    rollback = tmp_path / "hide.gsrollback"

    def fail_receipt(*_args, **_kwargs):
        raise OSError("injected receipt commit failure")

    monkeypatch.setattr(custom_apply, "_commit_receipt", fail_receipt)
    with pytest.raises(CustomizationApplyError, match="restored and reread-verified"):
        apply_customization_workspace(
            source, workspace, target, rollback,
            confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
        )
    assert (target / "000" / "000.DAT").read_bytes() == before_dat
    assert (target / "ROOT.DAT").read_bytes() == before_root
    assert rollback.is_file()
    assert not rollback.with_suffix(".apply.json").exists()


def test_alpha15_failed_rollback_compensates_back_to_complete_customized_state(tmp_path, monkeypatch):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    rollback = tmp_path / "hide.gsrollback"
    apply_customization_workspace(
        source, workspace, target, rollback,
        confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
    )
    customized_dat = (target / "000" / "000.DAT").read_bytes()
    customized_root = (target / "ROOT.DAT").read_bytes()

    real_open = Path.open
    failure = {"done": False}

    class FailOnceFile:
        def __init__(self, inner):
            self.inner = inner
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            self.inner.close()
            return False
        def __getattr__(self, name):
            return getattr(self.inner, name)
        def write(self, data):
            if not failure["done"]:
                failure["done"] = True
                raise OSError("injected second-control rollback failure")
            return self.inner.write(data)

    def patched_open(self, mode="r", *args, **kwargs):
        handle = real_open(self, mode, *args, **kwargs)
        if mode == "r+b" and self.name == "ROOT.DAT":
            return FailOnceFile(handle)
        return handle

    monkeypatch.setattr(Path, "open", patched_open)
    with pytest.raises(CustomizationApplyError, match="customized replacement state was restored"):
        rollback_customization(
            rollback, target, confirmation=f"ROLL BACK {target.name}",
            host_system="Linux", _test_allow_non_windows=True,
        )
    assert (target / "000" / "000.DAT").read_bytes() == customized_dat
    assert (target / "ROOT.DAT").read_bytes() == customized_root


def test_alpha15_rejects_rollback_output_on_same_physical_disk_policy(tmp_path):
    import gamestick.custom_apply as custom_apply

    identity = {"mode": "WINDOWS_PHYSICAL", "disk_number": 3}
    with pytest.raises(CustomizationApplyError, match="same physical disk"):
        custom_apply._safe_host_output(
            r"I:\\backup.gsrollback", Path(r"H:\\"), ".gsrollback", overwrite=False,
            target_identity=identity, host_system="Windows", _destination_disk_resolver=lambda _drive: 3,
        )


def test_alpha15_workspace_zip_expansion_is_bounded_before_manifest_read(tmp_path):
    import gamestick.custom_apply as custom_apply

    bad = tmp_path / "bomb.gscustom"
    with zipfile.ZipFile(bad, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", b"A" * (2 * 1024 * 1024))
    with pytest.raises(CustomizationApplyError, match="safety bound"):
        custom_apply._load_workspace(bad)


def test_alpha15_rollback_zip_expansion_is_bounded_before_manifest_read(tmp_path):
    import gamestick.custom_apply as custom_apply

    bad = tmp_path / "bomb.gsrollback"
    with zipfile.ZipFile(bad, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", b"A" * (2 * 1024 * 1024))
    with pytest.raises(CustomizationApplyError, match="safety bound"):
        custom_apply._load_rollback(bad)


def test_alpha15_receipt_backend_binds_actual_rollback_hash_and_rom(tmp_path):
    from gamestick.custom_apply import verify_rollback_receipt_for_rom

    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    rollback = tmp_path / "hide.gsrollback"
    result = apply_customization_workspace(
        source, workspace, target, rollback,
        confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
    )
    receipt = Path(result.receipt_path)
    verify_rollback_receipt_for_rom(
        rollback, receipt, target, "000", "game-a.zip",
        host_system="Linux", _test_allow_non_windows=True,
    )
    with pytest.raises(CustomizationApplyError, match="ROM identity"):
        verify_rollback_receipt_for_rom(
            rollback, receipt, target, "000", "game-b.zip",
            host_system="Linux", _test_allow_non_windows=True,
        )


def test_alpha15_existing_receipt_is_preserved_without_explicit_overwrite(tmp_path):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    before_dat = (target / "000" / "000.DAT").read_bytes()
    before_root = (target / "ROOT.DAT").read_bytes()
    rollback = tmp_path / "hide.gsrollback"
    receipt = rollback.with_suffix(".apply.json")
    receipt.write_text("DO NOT DELETE", encoding="utf-8")

    with pytest.raises(CustomizationApplyError, match="already exists"):
        apply_customization_workspace(
            source, workspace, target, rollback,
            confirmation=expected_confirmation(target),
            host_system="Linux", _test_allow_non_windows=True,
        )

    assert receipt.read_text(encoding="utf-8") == "DO NOT DELETE"
    assert not rollback.exists()
    assert (target / "000" / "000.DAT").read_bytes() == before_dat
    assert (target / "ROOT.DAT").read_bytes() == before_root


def test_alpha15_production_apply_is_windows_only(tmp_path):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")

    with pytest.raises(CustomizationApplyError, match="Windows"):
        apply_customization_workspace(
            source, workspace, target, tmp_path / "hide.gsrollback",
            confirmation=expected_confirmation(target), host_system="Linux",
        )


def _rewrite_rollback(rollback: Path, output: Path, mutator):
    with zipfile.ZipFile(rollback, "r") as zin, zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as zout:
        manifest = json.loads(zin.read("manifest.json"))
        replacements = mutator(manifest, zin) or {}
        referenced = {
            patch["payload_member"]
            for item in manifest.get("patched_files", [])
            for patch in item.get("patches", [])
        }
        zout.writestr("manifest.json", json.dumps(manifest))
        for name in zin.namelist():
            if name == "manifest.json" or name in replacements or name not in referenced:
                continue
            zout.writestr(name, zin.read(name))
        for name, payload in replacements.items():
            if name in referenced:
                zout.writestr(name, payload)


def test_alpha16_crafted_rollback_cannot_act_as_generic_dat_patch_engine(tmp_path):
    """Exact alpha15 review attack: rollback claims one unrelated DAT byte as authority."""
    import hashlib

    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    rollback = tmp_path / "valid.gsrollback"
    apply_customization_workspace(
        source, workspace, target, rollback,
        confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
    )
    before = (target / "000" / "000.DAT").read_bytes()

    forged = tmp_path / "forged.gsrollback"
    original_source_dat = _materialize_target_from_image(source, tmp_path / "source-view") / "000" / "000.DAT"
    original_bytes = original_source_dat.read_bytes()
    offset = len(before) - 1
    # Choose a byte outside every legitimate canonical range.
    with zipfile.ZipFile(rollback, "r") as zin:
        valid_manifest = json.loads(zin.read("manifest.json"))
    occupied = [
        (p["offset"], p["offset"] + p["length"])
        for item in valid_manifest["patched_files"]
        if item["path"] == "000/000.DAT"
        for p in item["patches"]
    ]
    while any(start <= offset < end for start, end in occupied):
        offset -= 1
    original = original_bytes[offset:offset + 1]
    replacement = before[offset:offset + 1]
    member = "originals/00/00.bin"

    def mutate(manifest, _zin):
        manifest["patched_files"] = [{
            "path": "000/000.DAT",
            "file_size_bytes": len(before),
            "source_control_sha256": valid_manifest["patched_files"][0]["replacement_control_sha256"],
            "replacement_control_sha256": valid_manifest["patched_files"][0]["replacement_control_sha256"],
            "patches": [{
                "offset": offset,
                "length": 1,
                "payload_member": member,
                "original_sha256": hashlib.sha256(original).hexdigest(),
                "replacement_sha256": hashlib.sha256(replacement).hexdigest(),
            }],
        }]
        return {member: original}

    _rewrite_rollback(rollback, forged, mutate)
    with pytest.raises(CustomizationApplyError, match="canonical hide inverse|semantic authority"):
        rollback_customization(
            forged, target, confirmation=f"ROLL BACK {target.name}",
            host_system="Linux", _test_allow_non_windows=True,
        )
    assert (target / "000" / "000.DAT").read_bytes() == before


def _inject_partial_target_write(monkeypatch, *, raise_after_partial: bool):
    real_open = Path.open
    state = {"done": False}

    class PartialWriteFile:
        def __init__(self, inner):
            self.inner = inner
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            self.inner.close()
            return False
        def __getattr__(self, name):
            return getattr(self.inner, name)
        def write(self, data):
            if not state["done"]:
                state["done"] = True
                amount = max(1, len(data) // 2)
                actual = self.inner.write(data[:amount])
                self.inner.flush()
                if raise_after_partial:
                    raise OSError("injected write-after-partial failure")
                return actual
            return self.inner.write(data)

    def patched_open(self, mode="r", *args, **kwargs):
        handle = real_open(self, mode, *args, **kwargs)
        if mode == "r+b" and self.name == "000.DAT":
            return PartialWriteFile(handle)
        return handle

    monkeypatch.setattr(Path, "open", patched_open)


def test_alpha16_short_write_is_treated_as_destructive_and_restored(tmp_path, monkeypatch):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    before_dat = (target / "000" / "000.DAT").read_bytes()
    before_root = (target / "ROOT.DAT").read_bytes()
    rollback = tmp_path / "hide.gsrollback"
    _inject_partial_target_write(monkeypatch, raise_after_partial=False)

    with pytest.raises(CustomizationApplyError, match="restored and reread-verified"):
        apply_customization_workspace(
            source, workspace, target, rollback,
            confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
        )
    assert (target / "000" / "000.DAT").read_bytes() == before_dat
    assert (target / "ROOT.DAT").read_bytes() == before_root
    assert rollback.is_file()
    assert not rollback.with_suffix(".apply.json").exists()


def test_alpha16_write_then_raise_is_treated_as_destructive_and_restored(tmp_path, monkeypatch):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    before_dat = (target / "000" / "000.DAT").read_bytes()
    before_root = (target / "ROOT.DAT").read_bytes()
    rollback = tmp_path / "hide.gsrollback"
    _inject_partial_target_write(monkeypatch, raise_after_partial=True)

    with pytest.raises(CustomizationApplyError, match="restored and reread-verified"):
        apply_customization_workspace(
            source, workspace, target, rollback,
            confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
        )
    assert (target / "000" / "000.DAT").read_bytes() == before_dat
    assert (target / "ROOT.DAT").read_bytes() == before_root
    assert rollback.is_file()
    assert not rollback.with_suffix(".apply.json").exists()


def test_alpha16_legacy_rollback_requires_explicit_recovery_opt_in_but_still_semantically_proves(tmp_path):
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    rollback = tmp_path / "v2.gsrollback"
    apply_customization_workspace(
        source, workspace, target, rollback,
        confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
    )
    legacy = tmp_path / "legacy.gsrollback"

    def mutate(manifest, _zin):
        manifest["schema"] = "gamestick-customization-rollback-v1"
        manifest.pop("action", None)
        manifest.pop("workspace_action", None)
        manifest.pop("canonical_topology", None)
        return {}

    _rewrite_rollback(rollback, legacy, mutate)
    with pytest.raises(CustomizationApplyError, match="Legacy rollback-v1"):
        rollback_customization(
            legacy, target, confirmation=f"ROLL BACK {target.name}",
            host_system="Linux", _test_allow_non_windows=True,
        )
    result = rollback_customization(
        legacy, target, confirmation=f"ROLL BACK {target.name}",
        host_system="Linux", _test_allow_non_windows=True, allow_legacy_recovery=True,
    )
    assert result.verification == "REREAD_SOURCE_CONTROL_AND_ORIGINAL_PATCH_BYTES_MATCHED_TRANSACTIONALLY"
    assert b"game-a.zip" in _control_payload(target / "000" / "000.DAT", "000/000.DAT", "filelist.txt")


def test_alpha16_four_range_rollback_with_one_unrelated_range_fails_semantic_inverse(tmp_path):
    """Keep 2-file/4-range topology but replace one canonical range with unrelated DAT metadata."""
    import hashlib

    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    rollback = tmp_path / "valid.gsrollback"
    apply_customization_workspace(
        source, workspace, target, rollback,
        confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
    )
    before = (target / "000" / "000.DAT").read_bytes()
    source_view = _materialize_target_from_image(source, tmp_path / "source-view-2")
    original_bytes = (source_view / "000" / "000.DAT").read_bytes()
    with zipfile.ZipFile(rollback, "r") as zin:
        valid_manifest = json.loads(zin.read("manifest.json"))
    cat = valid_manifest["patched_files"][0]
    occupied = [(p["offset"], p["offset"] + p["length"]) for p in cat["patches"]]
    offset = len(before) - 1
    while any(start <= offset < end for start, end in occupied):
        offset -= 1
    original = original_bytes[offset:offset + 1]
    replacement = before[offset:offset + 1]
    forged = tmp_path / "forged-four-range.gsrollback"

    def mutate(manifest, _zin):
        patch = manifest["patched_files"][0]["patches"][0]
        member = patch["payload_member"]
        patch.update({
            "offset": offset,
            "length": 1,
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "replacement_sha256": hashlib.sha256(replacement).hexdigest(),
        })
        # Keep the loader-supplied control hashes attacker-consistent with the live
        # replacement state; semantic reconstruction must still reject the claim.
        return {member: original}

    _rewrite_rollback(rollback, forged, mutate)
    with pytest.raises(CustomizationApplyError, match="semantic authority|canonical|reconstruct"):
        rollback_customization(
            forged, target, confirmation=f"ROLL BACK {target.name}",
            host_system="Linux", _test_allow_non_windows=True,
        )
    assert (target / "000" / "000.DAT").read_bytes() == before


def test_alpha17_apply_rejects_one_handle_redirected_to_bit_identical_clone_before_write(tmp_path, monkeypatch):
    """Exact alpha16 review attack: only one writable handle resolves to Clone B."""
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target_a = _materialize_target_from_image(source, tmp_path / "clone-a")
    target_b = _materialize_target_from_image(source, tmp_path / "clone-b")
    before_a_dat = (target_a / "000" / "000.DAT").read_bytes()
    before_a_root = (target_a / "ROOT.DAT").read_bytes()
    before_b_dat = (target_b / "000" / "000.DAT").read_bytes()
    before_b_root = (target_b / "ROOT.DAT").read_bytes()

    real_open = Path.open
    a_dat = (target_a / "000" / "000.DAT").resolve()
    b_dat = (target_b / "000" / "000.DAT").resolve()

    def redirected_open(self, mode="r", *args, **kwargs):
        if mode == "r+b" and self.resolve() == a_dat:
            return real_open(b_dat, mode, *args, **kwargs)
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", redirected_open)
    with pytest.raises(CustomizationApplyError, match="Opened writable handle is not bound"):
        apply_customization_workspace(
            source, workspace, target_a, tmp_path / "hide.gsrollback",
            confirmation=expected_confirmation(target_a),
            host_system="Linux", _test_allow_non_windows=True,
        )

    assert (target_a / "000" / "000.DAT").read_bytes() == before_a_dat
    assert (target_a / "ROOT.DAT").read_bytes() == before_a_root
    assert (target_b / "000" / "000.DAT").read_bytes() == before_b_dat
    assert (target_b / "ROOT.DAT").read_bytes() == before_b_root


def test_alpha17_rollback_rejects_one_handle_redirected_to_bit_identical_clone_before_write(tmp_path, monkeypatch):
    """Rollback must bind both already-open writable handles to Clone A itself."""
    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target_a = _materialize_target_from_image(source, tmp_path / "clone-a")
    target_b = _materialize_target_from_image(source, tmp_path / "clone-b")
    rollback_a = tmp_path / "a.gsrollback"
    rollback_b = tmp_path / "b.gsrollback"
    apply_customization_workspace(
        source, workspace, target_a, rollback_a,
        confirmation=expected_confirmation(target_a), host_system="Linux", _test_allow_non_windows=True,
    )
    apply_customization_workspace(
        source, workspace, target_b, rollback_b,
        confirmation=expected_confirmation(target_b), host_system="Linux", _test_allow_non_windows=True,
    )
    customized_a_dat = (target_a / "000" / "000.DAT").read_bytes()
    customized_a_root = (target_a / "ROOT.DAT").read_bytes()
    customized_b_dat = (target_b / "000" / "000.DAT").read_bytes()
    customized_b_root = (target_b / "ROOT.DAT").read_bytes()

    real_open = Path.open
    a_dat = (target_a / "000" / "000.DAT").resolve()
    b_dat = (target_b / "000" / "000.DAT").resolve()

    def redirected_open(self, mode="r", *args, **kwargs):
        if mode == "r+b" and self.resolve() == a_dat:
            return real_open(b_dat, mode, *args, **kwargs)
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", redirected_open)
    with pytest.raises(CustomizationApplyError, match="Opened writable handle is not bound"):
        rollback_customization(
            rollback_a, target_a, confirmation=f"ROLL BACK {target_a.name}",
            host_system="Linux", _test_allow_non_windows=True,
        )

    assert (target_a / "000" / "000.DAT").read_bytes() == customized_a_dat
    assert (target_a / "ROOT.DAT").read_bytes() == customized_a_root
    assert (target_b / "000" / "000.DAT").read_bytes() == customized_b_dat
    assert (target_b / "ROOT.DAT").read_bytes() == customized_b_root


def _fake_windows_identity(disk_number: int, *, serial: str = "a" * 64):
    return {
        "mode": "WINDOWS_PHYSICAL",
        "disk_number": disk_number,
        "disk_size": 64_000_000_000,
        "bus_type": "USB",
        "drive_type": "Removable",
        "partition_style": "MBR",
        "partition_number": 1,
        "partition_offset": 1_048_576,
        "partition_size": 62_500_000_000,
        "logical_sector_size": 512,
        "physical_sector_size": 512,
        "serial_sha256": serial,
        "unique_id_sha256": "b" * 64,
        "partition_layout_sha256": "c" * 64,
        "volume_guid_root": "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\",
        "identity_sha256": "d" * 64,
    }


def test_alpha17_durable_rollback_identity_survives_disk_number_reenumeration(tmp_path, monkeypatch):
    import gamestick.custom_apply as custom_apply

    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    rollback = tmp_path / "local.gsrollback"
    apply_customization_workspace(
        source, workspace, target, rollback,
        confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
    )

    disk4 = _fake_windows_identity(4)
    disk5 = _fake_windows_identity(5)
    rewritten = tmp_path / "windows-v3.gsrollback"

    def mutate(manifest, _zin):
        manifest["attachment_identity_at_apply"] = disk4
        manifest["durable_media_identity"] = custom_apply._durable_media_identity(disk4)
        return {}

    _rewrite_rollback(rollback, rewritten, mutate)
    monkeypatch.setattr(custom_apply, "_normalize_target_root", lambda *a, **k: (target.resolve(), disk5))
    monkeypatch.setattr(custom_apply, "_revalidate_target_identity", lambda *a, **k: None)
    monkeypatch.setattr(custom_apply, "_verify_open_handle_binding", lambda *a, **k: None)

    result = rollback_customization(
        rewritten, target, confirmation=f"ROLL BACK {target.name}",
        host_system="Linux", _test_allow_non_windows=True,
    )
    assert result.verification == "REREAD_SOURCE_CONTROL_AND_ORIGINAL_PATCH_BYTES_MATCHED_TRANSACTIONALLY"
    assert b"game-a.zip" in _control_payload(target / "000" / "000.DAT", "000/000.DAT", "filelist.txt")


def test_alpha17_durable_rollback_identity_refuses_different_device_even_if_disk_number_matches(tmp_path, monkeypatch):
    import gamestick.custom_apply as custom_apply

    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    rollback = tmp_path / "local.gsrollback"
    apply_customization_workspace(
        source, workspace, target, rollback,
        confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
    )

    intended = _fake_windows_identity(4, serial="a" * 64)
    different = _fake_windows_identity(4, serial="e" * 64)
    rewritten = tmp_path / "windows-v3.gsrollback"

    def mutate(manifest, _zin):
        manifest["attachment_identity_at_apply"] = intended
        manifest["durable_media_identity"] = custom_apply._durable_media_identity(intended)
        return {}

    _rewrite_rollback(rollback, rewritten, mutate)
    monkeypatch.setattr(custom_apply, "_normalize_target_root", lambda *a, **k: (target.resolve(), different))

    with pytest.raises(CustomizationApplyError, match="different durable"):
        rollback_customization(
            rewritten, target, confirmation=f"ROLL BACK {target.name}",
            host_system="Linux", _test_allow_non_windows=True,
        )


def test_alpha17_receipt_bound_unhide_survives_same_media_disk_number_change(tmp_path, monkeypatch):
    import hashlib
    import gamestick.custom_apply as custom_apply
    from gamestick.custom_apply import verify_rollback_receipt_for_rom

    source = _make_source_image(tmp_path / "golden.img")
    workspace = tmp_path / "hide.gscustom"
    build_hide_rom_workspace(source, "000:game-a.zip", workspace)
    target = _materialize_target_from_image(source, tmp_path / "target")
    rollback = tmp_path / "local.gsrollback"
    result = apply_customization_workspace(
        source, workspace, target, rollback,
        confirmation=expected_confirmation(target), host_system="Linux", _test_allow_non_windows=True,
    )
    original_receipt = Path(result.receipt_path)

    disk4 = _fake_windows_identity(4)
    disk5 = _fake_windows_identity(5)
    rewritten = tmp_path / "windows-v3.gsrollback"

    def mutate(manifest, _zin):
        manifest["attachment_identity_at_apply"] = disk4
        manifest["durable_media_identity"] = custom_apply._durable_media_identity(disk4)
        return {}

    _rewrite_rollback(rollback, rewritten, mutate)
    receipt_data = json.loads(original_receipt.read_text(encoding="utf-8"))
    receipt_data["attachment_identity_at_apply"] = disk4
    receipt_data["durable_media_identity"] = custom_apply._durable_media_identity(disk4)
    receipt_data["rollback_sha256"] = hashlib.sha256(rewritten.read_bytes()).hexdigest()
    receipt_data["rollback_archive"] = str(rewritten)
    rewritten_receipt = tmp_path / "windows-v3.apply.json"
    rewritten_receipt.write_text(json.dumps(receipt_data), encoding="utf-8")

    monkeypatch.setattr(custom_apply, "_normalize_target_root", lambda *a, **k: (target.resolve(), disk5))
    monkeypatch.setattr(custom_apply, "_revalidate_target_identity", lambda *a, **k: None)
    monkeypatch.setattr(custom_apply, "_verify_open_handle_binding", lambda *a, **k: None)

    verify_rollback_receipt_for_rom(
        rewritten, rewritten_receipt, target, "000", "game-a.zip",
        host_system="Linux", _test_allow_non_windows=True,
    )


def test_alpha17_durable_partition_layout_ignores_drive_letter_attachment():
    from types import SimpleNamespace
    import gamestick.custom_apply as custom_apply

    def mapping(letter):
        return SimpleNamespace(partitions=(SimpleNamespace(
            partition_number=1,
            drive_letter=letter,
            offset=1_048_576,
            size=62_500_000_000,
            partition_type="IFS",
            gpt_type=None,
            mbr_type="0C",
        ),))

    assert custom_apply._durable_partition_layout_sha256(mapping("H")) == custom_apply._durable_partition_layout_sha256(mapping("J"))
