import binascii
import struct
import zlib

import pytest

from gamestick.catalogue_image_lab import _read_wqw_control
from gamestick.fast_image_lab import FatEntry
from gamestick.repair_workspace import _BytesAccessor
from gamestick.rom_customization import (
    RomCustomizationError,
    _OverlayAccessor,
    _build_same_slot_patches,
    _filter_fileinfo,
    _filter_filelist,
    _read_control_layout,
    _rom_names,
)


def _wqw_one(control_name: str, payload: bytes) -> bytes:
    raw_name = bytes(b ^ 0xE5 for b in control_name.encode("cp437"))
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    comp = zlib.compressobj(level=6, method=zlib.DEFLATED, wbits=-15)
    compressed = comp.compress(payload) + comp.flush()
    local = struct.pack(
        "<4s5H3L2H",
        b"WQW\x03", 20, 0, 8, 0, 0, crc, len(compressed), len(payload), len(raw_name), 0,
    ) + raw_name + compressed
    central = struct.pack(
        "<4s6H3L5H2L",
        b"WQW\x02", 20, 20, 0, 8, 0, 0, crc, len(compressed), len(payload),
        len(raw_name), 0, 0, 0, 0, 0, 0,
    ) + raw_name
    eocd = struct.pack("<4s4H2LH", b"WQW\x01", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + eocd


def _entry(data: bytes, path="003/003.DAT"):
    return FatEntry(path=path, size_bytes=len(data), start_cluster=2, is_directory=False)


def test_hide_filelist_fixed_slot_virtual_verification():
    original = (
        b"Alpha.zip;Alpha;A\n"
        b"Solitaire.zip;Solitaire;S\n"
        b"Zulu.zip;Zulu;Z\n"
    )
    blob = _wqw_one("filelist.txt", original)
    entry = _entry(blob)
    base = _BytesAccessor(blob)
    layout = _read_control_layout(base, entry, "filelist.txt")
    replacement, removed = _filter_filelist(layout.payload, "Solitaire.zip")
    assert removed == 1
    patches = _build_same_slot_patches(layout, replacement)
    overlay = _OverlayAccessor(base, patches)
    container, status, payload, total, _names = _read_wqw_control(overlay, entry, "filelist.txt")
    assert container == "VALID_WQW"
    assert status == "VERIFIED"
    assert total == 1
    assert payload == replacement
    assert "solitaire.zip" not in {name.casefold() for name in _rom_names(payload)}


def test_hide_root_fileinfo_filters_only_selected_code_and_rom():
    payload = (
        b"003/Solitaire.zip;Solitaire;S;x;y\n"
        b"004/Solitaire.zip;Other;O;x;y\n"
        b"003/Alpha.zip;Alpha;A;x;y\n"
    )
    replacement, removed = _filter_fileinfo(payload, "003", "Solitaire.zip")
    assert removed == 1
    assert b"003/Solitaire.zip" not in replacement
    assert b"004/Solitaire.zip" in replacement
    assert b"003/Alpha.zip" in replacement


def test_fixed_slot_patch_preserves_container_byte_length():
    original = b"Alpha.zip;Alpha;A\nSolitaire.zip;Solitaire;S\n"
    blob = _wqw_one("filelist.txt", original)
    entry = _entry(blob)
    base = _BytesAccessor(blob)
    layout = _read_control_layout(base, entry, "filelist.txt")
    replacement, _ = _filter_filelist(original, "Solitaire.zip")
    patches = _build_same_slot_patches(layout, replacement)
    effective = bytearray(blob)
    for offset, data in patches:
        effective[offset:offset + len(data)] = data
    assert len(effective) == len(blob)


def test_data_descriptor_controls_fail_closed():
    original = b"Alpha.zip;Alpha;A\n"
    blob = bytearray(_wqw_one("filelist.txt", original))
    # flags field is offset 6 in the local header and offset 8 in central header.
    struct.pack_into("<H", blob, 6, 0x0008)
    central = bytes(blob).find(b"WQW\x02")
    struct.pack_into("<H", blob, central + 8, 0x0008)
    entry = _entry(bytes(blob))
    with pytest.raises(RomCustomizationError, match="data descriptor"):
        _read_control_layout(_BytesAccessor(bytes(blob)), entry, "filelist.txt")
