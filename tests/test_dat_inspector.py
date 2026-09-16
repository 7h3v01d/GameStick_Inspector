from dataclasses import asdict
import io
import json
import struct
import zipfile
from pathlib import Path

from gamestick.dat_inspector import inspect_dat_container
from gamestick.probe import inspect_volume
from gamestick.reporting import write_evidence_bundle


def _make_base(root: Path) -> None:
    for name in ("Roms", "cubegm", "image"):
        (root / name).mkdir()


def _write_dat(path: Path, members: dict[str, bytes], *, comment: bytes = b"") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.comment = comment
        for name, payload in members.items():
            archive.writestr(name, payload)


def test_bounded_dat_inspector_exports_only_control_semantics(tmp_path):
    dat = tmp_path / "000.dat"
    _write_dat(
        dat,
        {
            "filelist.txt": b"Private Game|Secret.zip\n",
            "Secret Game Name.raw": b"raw-preview",
            "Another Private Title.MySecretSuffix": b"x",
        },
    )

    evidence = inspect_dat_container(dat, relative_path="000/000.dat", role="platform-catalog")
    rendered = json.dumps(asdict(evidence), sort_keys=True)

    assert evidence.central_directory_valid is True
    assert evidence.container_format == "zip-central-directory"
    assert evidence.control_members == ["filelist.txt"]
    assert evidence.declared_member_count == 3
    assert evidence.member_extension_counts[".txt"] == 1
    assert evidence.member_extension_counts[".raw"] == 1
    assert evidence.member_extension_counts["<other>"] == 1
    assert evidence.member_names_redacted is True
    assert "Secret Game Name" not in rendered
    assert "Another Private Title" not in rendered
    assert "MySecretSuffix" not in rendered
    assert "Private Game" not in rendered


def test_eocd_signature_inside_zip_comment_does_not_break_detection(tmp_path):
    dat = tmp_path / "root.dat"
    _write_dat(dat, {"fileinfo.txt": b"catalog\n"}, comment=b"comment-PK\x05\x06-inside")
    evidence = inspect_dat_container(dat, relative_path="root.dat", role="global-catalog")
    assert evidence.central_directory_valid is True
    assert evidence.control_members == ["fileinfo.txt"]
    assert evidence.zip_comment_length == len(b"comment-PK\x05\x06-inside")


def test_real_device_numbered_dat_pattern_becomes_probable_and_overrides_generic_launcher(tmp_path):
    _make_base(tmp_path)
    _write_dat(tmp_path / "root.dat", {"fileinfo.txt": b"global-private-data\n"})
    for code in ("000", "001", "014"):
        _write_dat(
            tmp_path / code / f"{code}.dat",
            {
                "filelist.txt": b"private-game-row\n",
                f"Secret {code} Game.raw": b"raw",
            },
        )
    (tmp_path / "cubegm" / "filelist.xml").write_text("<files/>", encoding="utf-8")

    report = inspect_volume(tmp_path)
    dat_profile = report.numbered_dat_profile
    assert dat_profile is not None
    assert dat_profile.status == "PROBABLE"
    assert dat_profile.confidence == "high"
    assert dat_profile.root_catalog is not None
    assert dat_profile.root_catalog.control_members == ["fileinfo.txt"]
    assert dat_profile.filelist_control_count == 3
    assert dat_profile.catalogue_codes == ["000", "001", "014"]

    device = report.device_profile_candidate
    assert device is not None
    assert device.launcher_path == "root.dat"
    assert device.launcher_format == "numbered-dat-zip-catalog"
    assert device.launcher_resolution == "probable"
    assert device.launcher_confidence == "high"

    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert "Secret 000 Game" not in rendered
    assert "private-game-row" not in rendered
    assert "global-private-data" not in rendered


def test_numbered_catalog_directories_are_privacy_redacted_and_not_generic_metadata_scanned(tmp_path):
    _make_base(tmp_path)
    (tmp_path / "root.dat").write_bytes(b"not-a-zip")
    numbered = tmp_path / "004"
    numbered.mkdir()
    (numbered / "Secret Game Name.json").write_text('{"title":"Private"}', encoding="utf-8")
    (numbered / "Secret Game Name.zip").write_bytes(b"rom")
    (numbered / "004.dat").write_bytes(b"not-a-zip")

    report = inspect_volume(tmp_path)
    snapshot = next(item for item in report.directory_snapshots if item.path == "004")
    assert snapshot.file_names_redacted is True
    assert snapshot.file_names == []
    assert snapshot.file_extension_counts["<other>"] == 2  # .json + .dat are not privacy structural extensions
    assert snapshot.file_extension_counts[".zip"] == 1
    assert not any(artifact.path.replace("\\", "/").startswith("004/") for artifact in report.candidate_artifacts)
    assert "Secret Game Name" not in json.dumps(report.to_dict(), sort_keys=True)


def test_numbered_dat_profile_signature_ignores_private_member_names_and_counts(tmp_path):
    def build(root: Path, private_name: str, extra: bool):
        _make_base(root)
        root_members = {"fileinfo.txt": b"x"}
        if extra:
            root_members["Private Root Catalogue Name.raw"] = b"x"
        _write_dat(root / "root.dat", root_members)
        members = {"filelist.txt": b"x", f"{private_name}.raw": b"x"}
        if extra:
            members["Another Secret.raw"] = b"x"
        _write_dat(root / "000" / "000.dat", members)
        return inspect_volume(root)

    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = build(first_root, "Secret Game A", False)
    second = build(second_root, "Completely Different Private Title", True)

    assert first.numbered_dat_profile is not None
    assert second.numbered_dat_profile is not None
    assert first.numbered_dat_profile.structural_signature_sha256 == second.numbered_dat_profile.structural_signature_sha256
    assert first.numbered_dat_profile.candidate_id == second.numbered_dat_profile.candidate_id
    assert first.device_profile_candidate.profile_signature_sha256 == second.device_profile_candidate.profile_signature_sha256


def test_invalid_dat_is_reported_without_exception(tmp_path):
    dat = tmp_path / "root.dat"
    dat.write_bytes(b"not a zip container")
    evidence = inspect_dat_container(dat, relative_path="root.dat", role="global-catalog")
    assert evidence.central_directory_valid is False
    assert evidence.container_format == "not-standard-zip"
    assert evidence.member_names_redacted is True


def test_nested_control_like_member_does_not_corroborate_root_catalog(tmp_path):
    dat = tmp_path / "root.dat"
    _write_dat(dat, {"private/fileinfo.txt": b"not canonical"})
    evidence = inspect_dat_container(dat, relative_path="root.dat", role="global-catalog")
    assert evidence.central_directory_valid is True
    assert evidence.control_members == []


def test_central_directory_member_limit_fails_closed(tmp_path, monkeypatch):
    import gamestick.dat_inspector as dat_inspector

    dat = tmp_path / "root.dat"
    _write_dat(dat, {"fileinfo.txt": b"x", "a.raw": b"x"})
    monkeypatch.setattr(dat_inspector, "_MAX_CENTRAL_ENTRIES", 1)
    evidence = dat_inspector.inspect_dat_container(dat, relative_path="root.dat", role="global-catalog")
    assert evidence.central_directory_valid is False
    assert evidence.container_format == "zip-entry-limit-exceeded"
    assert evidence.declared_member_count == 2


def test_prepended_wrapper_bytes_are_supported_without_extracting(tmp_path):
    original = tmp_path / "plain.zip"
    _write_dat(original, {"fileinfo.txt": b"x", "Secret Game.raw": b"x"})
    wrapped = tmp_path / "root.dat"
    prefix = b"GAMESTICK-WRAPPER" * 4
    wrapped.write_bytes(prefix + original.read_bytes())
    evidence = inspect_dat_container(wrapped, relative_path="root.dat", role="global-catalog")
    assert evidence.central_directory_valid is True
    assert evidence.control_members == ["fileinfo.txt"]
    assert evidence.details["prepended_bytes"] == len(prefix)


def test_root_dat_case_is_normalized_in_profile(tmp_path):
    _make_base(tmp_path)
    _write_dat(tmp_path / "ROOT.DAT", {"FILEINFO.TXT": b"x"})
    _write_dat(tmp_path / "000" / "000.DAT", {"FILELIST.TXT": b"x"})
    report = inspect_volume(tmp_path)
    profile = report.numbered_dat_profile
    assert profile is not None
    assert profile.status == "PROBABLE"
    assert profile.root_catalog is not None
    assert profile.root_catalog.path == "root.dat"
    assert profile.root_catalog.control_members == ["fileinfo.txt"]
    assert profile.numbered_catalogs[0].path == "000/000.dat"
    assert profile.numbered_catalogs[0].control_members == ["filelist.txt"]


def test_fake_central_only_control_name_does_not_corroborate(tmp_path):
    dat = tmp_path / "root.dat"
    _write_dat(dat, {"private1.txt": b"x"})
    raw = bytearray(dat.read_bytes())
    central = raw.find(b"PK\x01\x02")
    assert central >= 0
    name_len = int.from_bytes(raw[central + 28:central + 30], "little")
    assert name_len == len(b"private1.txt") == len(b"fileinfo.txt")
    name_start = central + 46
    raw[name_start:name_start + name_len] = b"fileinfo.txt"
    dat.write_bytes(raw)

    evidence = inspect_dat_container(dat, relative_path="root.dat", role="global-catalog")
    assert evidence.central_directory_valid is True
    assert evidence.control_members == []


def _write_nonstandard_dat(path: Path, header: bytes, body_byte: bytes = b"X", *, embedded: bytes = b"") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    size = 1024 * 1024
    payload = bytearray(header + body_byte * max(0, size - len(header)))
    if embedded:
        midpoint = len(payload) // 2
        payload[midpoint:midpoint + len(embedded)] = embedded
    path.write_bytes(payload)


def test_real_style_nonstandard_numbered_dat_family_gets_bounded_binary_fingerprints(tmp_path):
    _make_base(tmp_path)
    _write_nonstandard_dat(tmp_path / "root.dat", b"ROOT-FORMAT-v1" + b"R" * 50)
    common = b"GS-NUMBERED-CATALOG-HEADER-000000"  # 32 bytes shared below
    for index in range(10):
        code = f"{index:03d}"
        unique = bytes([65 + (index % 26)]) * 64
        _write_nonstandard_dat(
            tmp_path / code / f"{code}.dat",
            common[:32] + unique,
            embedded=b"\xff\xd8\xff",
        )

    report = inspect_volume(tmp_path)
    profile = report.numbered_dat_profile
    assert profile is not None
    assert profile.status == "CANDIDATE"
    assert profile.confidence == "medium"
    assert profile.binary_family_assessment == "unidentified-binary"
    assert profile.binary_fingerprint_count == 11
    assert profile.zip_numbered_dat_count == 0
    assert profile.numbered_catalog_common_prefix_bytes == 32
    assert profile.root_matches_numbered_prefix_bytes == 0
    assert "jpeg" in profile.common_sampled_signatures

    assert profile.root_catalog is not None
    assert profile.root_catalog.binary_fingerprint is not None
    assert profile.root_catalog.binary_fingerprint.full_file_scan_performed is False
    assert all(item.binary_fingerprint is not None for item in profile.numbered_catalogs)

    device = report.device_profile_candidate
    assert device is not None
    assert device.launcher_path == "root.dat"
    assert device.launcher_format == "numbered-dat-binary-catalog"
    assert device.launcher_resolution == "candidate"
    assert device.launcher_confidence == "medium"


def test_nonstandard_binary_sample_hash_changes_do_not_change_numbered_profile_identity(tmp_path):
    def build(root: Path, private_byte: bytes):
        _make_base(root)
        _write_nonstandard_dat(root / "root.dat", b"ROOT-v1" + private_byte * 64, body_byte=private_byte)
        for index in range(10):
            code = f"{index:03d}"
            _write_nonstandard_dat(
                root / code / f"{code}.dat",
                b"SHARED-HEADER-012345678901234567" + private_byte * 64,
                body_byte=private_byte,
            )
        return inspect_volume(root)

    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = build(first_root, b"A")
    second = build(second_root, b"Z")

    assert first.numbered_dat_profile is not None
    assert second.numbered_dat_profile is not None
    # Content/sample commitments can differ while structural family identity stays stable.
    assert first.numbered_dat_profile.root_catalog.binary_fingerprint.prefix_sha256 != second.numbered_dat_profile.root_catalog.binary_fingerprint.prefix_sha256
    assert first.numbered_dat_profile.structural_signature_sha256 == second.numbered_dat_profile.structural_signature_sha256
    assert first.numbered_dat_profile.candidate_id == second.numbered_dat_profile.candidate_id


def test_small_numbered_pattern_does_not_outrank_generic_launcher_on_binary_fingerprint_alone(tmp_path):
    _make_base(tmp_path)
    _write_nonstandard_dat(tmp_path / "root.dat", b"ROOT" + b"X" * 64)
    for code in ("000", "001"):
        _write_nonstandard_dat(tmp_path / code / f"{code}.dat", b"CATALOG" + b"X" * 64)
    (tmp_path / "cubegm" / "games.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 256)

    report = inspect_volume(tmp_path)
    profile = report.numbered_dat_profile
    assert profile is not None
    assert profile.heuristic_score < 50
    device = report.device_profile_candidate
    assert device is not None
    assert not any(item.format_name == "numbered-dat-binary-catalog" for item in device.launcher_candidates)


def test_common_exact_known_header_is_reported_without_probable_promotion(tmp_path):
    _make_base(tmp_path)
    seven_zip = b"\x37\x7a\xbc\xaf\x27\x1c"
    _write_nonstandard_dat(tmp_path / "root.dat", seven_zip + b"R" * 64)
    for index in range(10):
        code = f"{index:03d}"
        _write_nonstandard_dat(tmp_path / code / f"{code}.dat", seven_zip + bytes([65 + index]) * 64)

    report = inspect_volume(tmp_path)
    profile = report.numbered_dat_profile
    assert profile is not None
    assert profile.binary_family_assessment == "known-header:7z"
    assert profile.common_header_signatures == ["7z"]
    assert profile.status == "CANDIDATE"
    assert report.device_profile_candidate.launcher_resolution == "candidate"



def _write_wqw(path: Path, members: dict[str, bytes], *, compression=zipfile.ZIP_DEFLATED) -> None:
    """Create a synthetic WQW fixture from an ordinary ZIP without using release code."""
    path.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
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
        assert fixed[:4] == b"PK\x01\x02"
        fields = struct.unpack("<4s6H3L5H2L", fixed)
        name_len, extra_len, entry_comment_len = fields[10], fields[11], fields[12]
        local_offset = fields[16]
        name_start = position + 46
        raw[position:position + 4] = b"WQW\x02"
        raw[name_start:name_start + name_len] = bytes(
            value ^ 0xE5 for value in raw[name_start:name_start + name_len]
        )
        local_offsets.append(local_offset)
        position += 46 + name_len + extra_len + entry_comment_len
    assert position == central_offset + central_size
    for local_offset in local_offsets:
        fixed = bytes(raw[local_offset:local_offset + 30])
        assert fixed[:4] == b"PK\x03\x04"
        fields = struct.unpack("<4s5H3L2H", fixed)
        name_len = fields[9]
        name_start = local_offset + 30
        raw[local_offset:local_offset + 4] = b"WQW\x03"
        raw[name_start:name_start + name_len] = bytes(
            value ^ 0xE5 for value in raw[name_start:name_start + name_len]
        )
    raw[eocd:eocd + 4] = b"WQW\x01"
    path.write_bytes(raw)


def test_wqw_catalogue_is_read_only_parsed_and_correlated_without_private_values(tmp_path):
    _make_base(tmp_path)
    fileinfo = (
        "008/Pac-Man.A26;Pac-Man;PAC-MAN;吃豆人;CDR\r\n"
        "008/Secret Game.A26;Secret Game;SECRET GAME;秘密游戏;MYKEY\r\n"
    ).encode("utf-8")
    filelist = (
        "Pac-Man.A26;Pac-Man;吃豆人\r\n"
        "Secret Game.A26;Secret Game;秘密游戏\r\n"
    ).encode("utf-8")
    _write_wqw(tmp_path / "root.dat", {"000.raw": b"root-art", "fileinfo.txt": fileinfo})
    _write_wqw(
        tmp_path / "008" / "008.dat",
        {
            "Pac-Man_000.raw": b"preview-a",
            "Secret Game_000.raw": b"preview-b",
            "filelist.txt": filelist,
        },
    )

    report = inspect_volume(tmp_path)
    profile = report.numbered_dat_profile
    assert profile is not None
    assert profile.status == "PROBABLE"
    assert profile.confidence == "high"
    assert profile.binary_family_assessment == "wqw-obfuscated-zip"
    assert profile.wqw_numbered_dat_count == 1
    assert profile.filelist_control_count == 1
    assert profile.root_catalog is not None
    assert profile.root_catalog.container_format == "wqw-obfuscated-zip"
    root_summary = profile.root_catalog.details["control_summaries"]["fileinfo.txt"]
    assert root_summary["crc32_verified"] is True
    assert root_summary["valid_record_count"] == 2
    platform_summary = profile.numbered_catalogs[0].details["control_summaries"]["filelist.txt"]
    assert platform_summary["crc32_verified"] is True
    assert platform_summary["valid_record_count"] == 2
    assert platform_summary["unique_rom_name_count"] == 2
    assert platform_summary["raw_artwork_member_count"] == 2
    assert platform_summary["unique_artwork_stem_count"] == 2
    assert platform_summary["catalogue_records_with_artwork_count"] == 2
    assert profile.catalogue_relationships["global_filelist_unique_match_count"] == 2
    assert profile.catalogue_relationships["filelist_unique_rom_name_count"] == 2

    device = report.device_profile_candidate
    assert device is not None
    assert device.launcher_path == "root.dat"
    assert device.launcher_format == "numbered-dat-wqw-catalog"
    assert device.launcher_resolution == "probable"

    rendered = json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=False)
    assert "Pac-Man.A26" not in rendered
    assert "Secret Game" not in rendered
    assert "MYKEY" not in rendered
    assert "秘密游戏" not in rendered


def test_wqw_fileinfo_mixed_utf8_gbk_is_counted_not_exported(tmp_path):
    payload = (
        b"008/game.A26;Title;TITLE;"
        + "吃豆人".encode("utf-8")
        + b";RZSG\xa3\xa8M\xa3\xa9\r\n"
    )
    dat = tmp_path / "root.dat"
    _write_wqw(dat, {"fileinfo.txt": payload})
    evidence = inspect_dat_container(dat, relative_path="root.dat", role="global-catalog")
    summary = evidence.details["control_summaries"]["fileinfo.txt"]
    assert summary["valid_record_count"] == 1
    assert summary["malformed_record_count"] == 0
    assert summary["field_gbk_fallback_counts"] == [0, 0, 0, 0, 1]
    rendered = json.dumps(asdict(evidence), sort_keys=True, ensure_ascii=False)
    assert "RZSG" not in rendered
    assert "game.A26" not in rendered


def test_wqw_control_crc_must_verify_before_it_can_corroborate(tmp_path):
    dat = tmp_path / "root.dat"
    _write_wqw(
        dat,
        {"fileinfo.txt": b"008/game.A26;Title;TITLE;CN;KEY\r\n"},
        compression=zipfile.ZIP_STORED,
    )
    raw = bytearray(dat.read_bytes())
    fixed = struct.unpack("<4s5H3L2H", raw[:30])
    name_len, extra_len = fixed[9], fixed[10]
    data_offset = 30 + name_len + extra_len
    raw[data_offset] ^= 0x01
    dat.write_bytes(raw)

    evidence = inspect_dat_container(dat, relative_path="root.dat", role="global-catalog")
    assert evidence.central_directory_valid is True
    assert evidence.container_format == "wqw-obfuscated-zip"
    assert evidence.control_members == []
    summary = evidence.details["control_summaries"]["fileinfo.txt"]
    assert summary["crc32_verified"] is False
    assert summary["read_status"] == "crc-mismatch"


def test_wqw_malformed_physical_lines_are_counted_without_silent_repair(tmp_path):
    payload = (
        b"008/good.A26;Good;GOOD;CN;KEY\r\n"
        b";;;;;008/also.A26;Also;ALSO;CN;KEY\r\n"
        b"008/one.A26;One;ONE;CN;KEY008/two.A26;Two;TWO;CN;KEY\r\n"
    )
    dat = tmp_path / "root.dat"
    _write_wqw(dat, {"fileinfo.txt": payload})
    evidence = inspect_dat_container(dat, relative_path="root.dat", role="global-catalog")
    summary = evidence.details["control_summaries"]["fileinfo.txt"]
    assert summary["record_count"] == 3
    assert summary["valid_record_count"] == 1
    assert summary["malformed_record_count"] == 2


def test_wqw_control_payload_limit_fails_closed_before_parse(tmp_path, monkeypatch):
    import gamestick.wqw as wqw

    dat = tmp_path / "root.dat"
    payload = b"008/game.A26;Title;TITLE;CN;KEY\r\n" * 4
    _write_wqw(dat, {"fileinfo.txt": payload})
    monkeypatch.setattr(wqw, "_MAX_CONTROL_UNCOMPRESSED", 32)

    evidence = inspect_dat_container(dat, relative_path="root.dat", role="global-catalog")
    assert evidence.central_directory_valid is True
    assert evidence.control_members == []
    summary = evidence.details["control_summaries"]["fileinfo.txt"]
    assert summary["read_status"] == "control-size-limit"
    assert summary["crc32_verified"] is False


def test_wqw_central_only_control_name_cannot_spoof_local_header(tmp_path):
    dat = tmp_path / "root.dat"
    _write_wqw(dat, {"private1.txt": b"not a control"})
    raw = bytearray(dat.read_bytes())
    central = raw.find(b"WQW\x02")
    assert central >= 0
    name_len = int.from_bytes(raw[central + 28:central + 30], "little")
    assert name_len == len(b"private1.txt") == len(b"fileinfo.txt")
    encoded_fileinfo = bytes(value ^ 0xE5 for value in b"fileinfo.txt")
    raw[central + 46:central + 46 + name_len] = encoded_fileinfo
    dat.write_bytes(raw)

    evidence = inspect_dat_container(dat, relative_path="root.dat", role="global-catalog")
    assert evidence.central_directory_valid is True
    assert evidence.control_members == []
    summary = evidence.details["control_summaries"]["fileinfo.txt"]
    assert summary["read_status"] == "local-name-mismatch"
    rendered = json.dumps(asdict(evidence), sort_keys=True)
    assert "private1" not in rendered


def test_wqw_control_record_count_is_bounded_and_reported(tmp_path, monkeypatch):
    import gamestick.wqw as wqw

    dat = tmp_path / "008.dat"
    payload = (
        b"one.A26;One;CN\r\n"
        b"two.A26;Two;CN\r\n"
    )
    _write_wqw(dat, {"one_000.raw": b"x", "two_000.raw": b"y", "filelist.txt": payload})
    monkeypatch.setattr(wqw, "_MAX_CONTROL_RECORDS", 1)

    evidence = inspect_dat_container(dat, relative_path="008/008.dat", role="platform-catalog")
    summary = evidence.details["control_summaries"]["filelist.txt"]
    assert summary["record_count"] == 1
    assert summary["valid_record_count"] == 1
    assert summary["records_truncated"] is True
    assert summary["record_limit"] == 1



def test_wqw_private_catalogue_values_absent_from_complete_evidence_bundle(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    _make_base(card)
    private_rom = "Private Catalogue Game.A26"
    private_title = "Private Catalogue Game"
    private_key = "SECRETSEARCHKEY"
    fileinfo = f"008/{private_rom};{private_title};PRIVATE CATALOGUE GAME;秘密标题;{private_key}\r\n".encode("utf-8")
    filelist = f"{private_rom};{private_title};秘密标题\r\n".encode("utf-8")
    _write_wqw(card / "root.dat", {"fileinfo.txt": fileinfo})
    _write_wqw(
        card / "008" / "008.dat",
        {f"{private_title}_000.raw": b"preview", "filelist.txt": filelist},
    )
    report = inspect_volume(card)
    destination = tmp_path / "out" / "evidence.zip"
    saved = write_evidence_bundle(report, destination, host_system="Linux")
    with zipfile.ZipFile(saved) as archive:
        combined = b"\n".join(archive.read(name) for name in archive.namelist())
    for secret in (private_rom, private_title, private_key, "秘密标题"):
        assert secret.encode("utf-8") not in combined
    assert b"wqw-obfuscated-zip" in combined
    assert b"global_filelist_unique_match_count" in combined



def test_wqw_header_without_complete_archive_is_classified_as_damaged_or_incomplete(tmp_path):
    dat = tmp_path / "003.dat"
    _write_wqw(dat, {"filelist.txt": b"game.zip;Game;CN\r\n", "Game_000.raw": b"preview"})
    raw = dat.read_bytes()
    assert raw.startswith(b"WQW\x03")
    dat.write_bytes(raw[:-22])  # remove the WQW EOCD while retaining the local record/header

    evidence = inspect_dat_container(dat, relative_path="003/003.dat", role="platform-catalog")
    assert evidence.central_directory_valid is False
    assert evidence.container_format == "damaged-or-incomplete-wqw"
    assert evidence.details["wqw_local_header_observed"] is True
    assert evidence.details["wqw_container_complete"] is False


def test_catalogue_consistency_audit_compares_filesystem_local_and_global_without_exporting_names(tmp_path):
    _make_base(tmp_path)
    code = "008"
    directory = tmp_path / code
    directory.mkdir()
    local_only = "Private Local Only.A26"
    physical_extra = "Private Physical Extra.A26"
    shared = "Shared Private Game.A26"
    filelist = (
        f"{shared};Shared;CN\r\n"
        f"{local_only};Local;CN\r\n"
    ).encode("utf-8")
    fileinfo = f"{code}/{shared};Shared;SHARED;CN;KEY\r\n".encode("utf-8")
    _write_wqw(tmp_path / "root.dat", {"fileinfo.txt": fileinfo})
    _write_wqw(directory / f"{code}.dat", {"filelist.txt": filelist, "Shared Private Game_000.raw": b"x", "Private Local Only_000.raw": b"y"})
    (directory / shared).write_bytes(b"rom")
    (directory / physical_extra).write_bytes(b"extra")

    report = inspect_volume(tmp_path)
    profile = report.numbered_dat_profile
    assert profile is not None
    audit = profile.catalogue_consistency
    row = audit["by_catalogue_code"][code]
    assert row["audit_status"] == "MISMATCH_OBSERVED"
    assert row["readable_content_file_count"] == 2
    assert row["readable_content_unique_name_count"] == 2
    assert row["filelist_unique_rom_name_count"] == 2
    assert row["global_unique_rom_name_count"] == 1
    assert row["present_local_global_unique_match_count"] == 1
    assert row["readable_not_filelist_count"] == 1
    assert row["filelist_missing_from_filesystem_observation_count"] == 1
    assert row["filelist_unique_missing_from_global_count"] == 1
    assert row["arbitrary_names_exported"] is False

    rendered = json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=False)
    assert shared not in rendered
    assert local_only not in rendered
    assert physical_extra not in rendered


def test_catalogue_consistency_audit_distinguishes_unreadable_catalogued_entry(tmp_path, monkeypatch):
    import gamestick.catalogue_audit as audit_module

    _make_base(tmp_path)
    code = "007"
    directory = tmp_path / code
    directory.mkdir()
    good = "Readable Private Game.iso"
    unreadable = "Unreadable Private Game.iso"
    filelist = (
        f"{good};Good;CN\r\n"
        f"{unreadable};Bad;CN\r\n"
    ).encode("utf-8")
    fileinfo = (
        f"{code}/{good};Good;GOOD;CN;KEY\r\n"
        f"{code}/{unreadable};Bad;BAD;CN;KEY\r\n"
    ).encode("utf-8")
    _write_wqw(tmp_path / "root.dat", {"fileinfo.txt": fileinfo})
    _write_wqw(directory / f"{code}.dat", {"filelist.txt": filelist, "Readable Private Game_000.raw": b"x", "Unreadable Private Game_000.raw": b"y"})
    (directory / good).write_bytes(b"ok")
    (directory / unreadable).write_bytes(b"bad")

    real_lstat = audit_module.lstat_non_reparse

    def fail_one(path):
        if Path(path).name == unreadable:
            raise PermissionError(13, "synthetic private path must not escape")
        return real_lstat(path)

    monkeypatch.setattr(audit_module, "lstat_non_reparse", fail_one)
    report = inspect_volume(tmp_path)
    row = report.numbered_dat_profile.catalogue_consistency["by_catalogue_code"][code]
    assert row["audit_status"] == "READ_ERRORS_ACCOUNT_FOR_GAP"
    assert row["readable_content_file_count"] == 1
    assert row["unreadable_entry_count"] == 1
    assert row["filelist_missing_from_readable_count"] == 1
    assert row["filelist_missing_but_seen_unreadable_count"] == 1
    assert row["filelist_missing_from_filesystem_observation_count"] == 0
    assert row["unreadable_entry_name_matches_filelist_count"] == 1
    assert unreadable not in json.dumps(report.to_dict(), sort_keys=True)


def test_catalogue_consistency_private_filesystem_names_do_not_change_structural_identity(tmp_path):
    def build(root: Path, physical_name: str):
        root.mkdir()
        _make_base(root)
        code = "008"
        directory = root / code
        directory.mkdir()
        filelist = b"catalogued.A26;Title;CN\r\n"
        fileinfo = b"008/catalogued.A26;Title;TITLE;CN;KEY\r\n"
        _write_wqw(root / "root.dat", {"fileinfo.txt": fileinfo})
        _write_wqw(directory / "008.dat", {"filelist.txt": filelist, "catalogued_000.raw": b"x"})
        (directory / physical_name).write_bytes(b"private")
        return inspect_volume(root)

    first = build(tmp_path / "first", "Secret Physical One.A26")
    second = build(tmp_path / "second", "Different Physical Two.A26")
    assert first.numbered_dat_profile.structural_signature_sha256 == second.numbered_dat_profile.structural_signature_sha256
    assert first.numbered_dat_profile.candidate_id == second.numbered_dat_profile.candidate_id
    assert first.device_profile_candidate.profile_signature_sha256 == second.device_profile_candidate.profile_signature_sha256


def test_catalogue_consistency_audit_is_bounded_and_marks_partial(tmp_path, monkeypatch):
    import gamestick.catalogue_audit as audit_module

    _make_base(tmp_path)
    code = "008"
    directory = tmp_path / code
    directory.mkdir()
    _write_wqw(tmp_path / "root.dat", {"fileinfo.txt": b"008/a.A26;A;A;CN;KEY\r\n"})
    _write_wqw(directory / "008.dat", {"filelist.txt": b"a.A26;A;CN\r\n", "a_000.raw": b"x"})
    (directory / "a.A26").write_bytes(b"a")
    (directory / "b.A26").write_bytes(b"b")
    monkeypatch.setattr(audit_module, "_MAX_AUDIT_ENTRIES_PER_DIRECTORY", 1)

    report = inspect_volume(tmp_path)
    row = report.numbered_dat_profile.catalogue_consistency["by_catalogue_code"][code]
    assert row["audit_status"] == "PARTIAL"
    assert row["filesystem_enumeration_truncated"] is True
    assert row["filesystem_enumeration_complete"] is False


def test_catalogue_consistency_private_names_absent_from_complete_evidence_bundle(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    _make_base(card)
    code = "008"
    directory = card / code
    directory.mkdir()
    secret_rom = "Top Secret Physical Game.A26"
    extra_rom = "Uncatalogued Private Extra.A26"
    filelist = f"{secret_rom};Private Title;CN\r\n".encode("utf-8")
    fileinfo = f"{code}/{secret_rom};Private Title;PRIVATE TITLE;CN;SECRETKEY\r\n".encode("utf-8")
    _write_wqw(card / "root.dat", {"fileinfo.txt": fileinfo})
    _write_wqw(directory / "008.dat", {"filelist.txt": filelist, "Top Secret Physical Game_000.raw": b"x"})
    (directory / secret_rom).write_bytes(b"rom")
    (directory / extra_rom).write_bytes(b"extra")

    report = inspect_volume(card)
    destination = tmp_path / "out" / "evidence.zip"
    saved = write_evidence_bundle(report, destination, host_system="Linux")
    with zipfile.ZipFile(saved) as archive:
        combined = b"\n".join(archive.read(name) for name in archive.namelist())
    for secret in (secret_rom, extra_rom, "Private Title", "SECRETKEY"):
        assert secret.encode("utf-8") not in combined
    assert b"catalogue-filesystem-consistency-v3" in combined
    assert b"MISMATCH_OBSERVED" in combined


def test_numbered_profile_counts_damaged_wqw_platforms(tmp_path):
    _make_base(tmp_path)
    _write_wqw(tmp_path / "root.dat", {"fileinfo.txt": b"008/a.A26;A;A;CN;KEY\r\n"})
    _write_wqw(tmp_path / "008" / "008.dat", {"filelist.txt": b"a.A26;A;CN\r\n", "a_000.raw": b"x"})
    _write_wqw(tmp_path / "003" / "003.dat", {"filelist.txt": b"b.zip;B;CN\r\n", "b_000.raw": b"x"})
    damaged = tmp_path / "003" / "003.dat"
    damaged.write_bytes(damaged.read_bytes()[:-22])

    report = inspect_volume(tmp_path)
    profile = report.numbered_dat_profile
    assert profile is not None
    assert profile.wqw_numbered_dat_count == 1
    assert profile.damaged_wqw_numbered_dat_count == 1
    formats = {item.path: item.container_format for item in profile.numbered_catalogs}
    assert formats["003/003.dat"] == "damaged-or-incomplete-wqw"
    assert profile.binary_family_assessment == "wqw-with-damaged-containers"


def test_numbered_dat_profile_integrates_structural_read_stability(tmp_path):
    _make_base(tmp_path)
    _write_wqw(
        tmp_path / "root.dat",
        {"fileinfo.txt": b"008/a.A26;A;A;CN;KEY\r\n"},
    )
    _write_wqw(
        tmp_path / "008" / "008.dat",
        {"filelist.txt": b"a.A26;A;CN\r\n", "a_000.raw": b"preview"},
    )
    (tmp_path / "008" / "a.A26").write_bytes(b"rom")

    report = inspect_volume(tmp_path)
    profile = report.numbered_dat_profile
    assert profile is not None
    stability = profile.read_stability
    assert stability["schema"] == "numbered-dat-read-stability-v2"
    assert stability["status_counts"] == {"READ_STABLE": 2}
    root_row = stability["by_path"]["root.dat"]
    platform_row = stability["by_path"]["008/008.dat"]
    assert set(root_row["regions"]) == {"prefix", "tail", "central-directory", "control-fileinfo.txt"}
    assert set(platform_row["regions"]) == {"prefix", "tail", "central-directory", "control-filelist.txt"}
    rendered_stability = json.dumps(stability, sort_keys=True)
    assert "digests" not in rendered_stability.casefold()
    assert "sha256" not in rendered_stability.casefold()


def test_catalogue_alias_auditor_resolves_missing_local_entry_in_other_numbered_directory(tmp_path):
    _make_base(tmp_path)
    private_name = "Private Shared Arcade Game.zip"
    root_info = (
        f"000/{private_name};Shared;SHARED;CN;KEY\r\n"
        f"011/{private_name};Shared;SHARED;CN;KEY\r\n"
    ).encode("utf-8")
    local = f"{private_name};Shared;CN\r\n".encode("utf-8")
    _write_wqw(tmp_path / "root.dat", {"fileinfo.txt": root_info})
    _write_wqw(tmp_path / "000" / "000.dat", {"filelist.txt": local, "Private Shared Arcade Game_000.raw": b"x"})
    _write_wqw(tmp_path / "011" / "011.dat", {"filelist.txt": local, "Private Shared Arcade Game_000.raw": b"x"})
    (tmp_path / "000" / private_name).write_bytes(b"rom")

    report = inspect_volume(tmp_path)
    audit = report.numbered_dat_profile.catalogue_consistency
    row = audit["by_catalogue_code"]["011"]
    assert audit["schema"] == "catalogue-filesystem-consistency-v3"
    assert row["audit_status"] == "CROSS_CATALOGUE_ALIAS"
    assert row["filelist_missing_from_filesystem_observation_count"] == 1
    assert row["cross_catalogue_resolved_unique_name_count"] == 1
    assert row["cross_catalogue_unresolved_unique_name_count"] == 0
    assert row["cross_catalogue_resolution_counts"] == {"000": 1}
    assert audit["alias_resolution_edges"] == {"011": {"000": 1}}
    assert private_name not in json.dumps(report.to_dict(), sort_keys=True)


def test_catalogue_alias_auditor_classifies_dominant_alias_with_small_residual_gap(tmp_path):
    _make_base(tmp_path)
    shared = [f"Shared Private Arcade {index}.zip" for index in range(99)]
    unresolved = "Residual Private Arcade.zip"
    root_lines = []
    local_lines = []
    for name in [*shared, unresolved]:
        root_lines.append(f"011/{name};Title;TITLE;CN;KEY\r\n")
        local_lines.append(f"{name};Title;CN\r\n")
    _write_wqw(tmp_path / "root.dat", {"fileinfo.txt": "".join(root_lines).encode("utf-8")})
    _write_wqw(
        tmp_path / "011" / "011.dat",
        {"filelist.txt": "".join(local_lines).encode("utf-8"), "shared_000.raw": b"x"},
    )
    _write_wqw(
        tmp_path / "000" / "000.dat",
        {"filelist.txt": "".join(f"{name};Title;CN\r\n" for name in shared).encode("utf-8"), "shared_000.raw": b"x"},
    )
    for name in shared:
        (tmp_path / "000" / name).write_bytes(b"rom")

    report = inspect_volume(tmp_path)
    row = report.numbered_dat_profile.catalogue_consistency["by_catalogue_code"]["011"]
    assert row["audit_status"] == "CROSS_CATALOGUE_ALIAS_WITH_RESIDUAL_GAP"
    assert row["cross_catalogue_resolved_unique_name_count"] == 99
    assert row["cross_catalogue_unresolved_unique_name_count"] == 1
    assert row["cross_catalogue_primary_target_code"] == "000"
    assert row["cross_catalogue_primary_target_match_count"] == 99
    assert row["cross_catalogue_resolution_rate_ppm"] == 990000
    assert row["cross_catalogue_primary_target_resolution_rate_ppm"] == 1000000
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert unresolved not in rendered
    assert shared[0] not in rendered


def test_inspect_volume_applies_manifest_verified_baseline_end_to_end(tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    _make_base(card)
    _write_wqw(card / "root.dat", {"fileinfo.txt": b"008/a.A26;A;A;CN;KEY\r\n"})
    _write_wqw(card / "008" / "008.dat", {"filelist.txt": b"a.A26;A;CN\r\n", "a_000.raw": b"preview"})
    (card / "008" / "a.A26").write_bytes(b"rom")

    baseline_report = inspect_volume(card)
    baseline_zip = tmp_path / "prior-evidence.zip"
    write_evidence_bundle(baseline_report, baseline_zip, host_system="Linux")

    current_report = inspect_volume(card, baseline_evidence=baseline_zip)
    longitudinal = current_report.numbered_dat_profile.longitudinal_integrity
    assert longitudinal["baseline_status"] == "BASELINE_VERIFIED"
    assert longitudinal["status_counts"] == {"UNCHANGED_SINCE_BASELINE": 2}
    assert set(longitudinal["by_path"]) == {"root.dat", "008/008.dat"}


def test_corrupt_wqw_control_payload_is_still_included_in_repeated_read_stability(tmp_path):
    _make_base(tmp_path)
    dat = tmp_path / "root.dat"
    _write_wqw(dat, {"fileinfo.txt": b"008/a.A26;A;A;CN;KEY\r\n"})

    raw = bytearray(dat.read_bytes())
    local = raw.find(b"WQW\x03")
    assert local >= 0
    fields = struct.unpack("<4s5H3L2H", bytes(raw[local:local + 30]))
    compressed_size = fields[7]
    name_len = fields[9]
    extra_len = fields[10]
    data_offset = local + 30 + name_len + extra_len
    assert compressed_size > 2
    raw[data_offset] ^= 0xFF
    dat.write_bytes(raw)

    # A second valid numbered catalogue keeps the numbered-DAT family active.
    _write_wqw(
        tmp_path / "008" / "008.dat",
        {"filelist.txt": b"a.A26;A;CN\r\n", "a_000.raw": b"preview"},
    )
    (tmp_path / "008" / "a.A26").write_bytes(b"rom")

    report = inspect_volume(tmp_path)
    profile = report.numbered_dat_profile
    assert profile is not None
    root = profile.root_catalog
    assert root is not None
    summary = root.details["control_summaries"]["fileinfo.txt"]
    assert summary["read_status"] in {"decompression-invalid", "crc-mismatch"}
    assert summary["crc32_verified"] is False

    stability = profile.read_stability["by_path"]["root.dat"]
    assert stability["status"] == "READ_STABLE_WITH_CORRUPT_CONTROL"
    assert stability["control_failure_assessment"] == "STABLE_CORRUPTION"
    assert stability["regions"]["control-fileinfo.txt"]["state"] == "STABLE"
    assert stability["region_count"] == 4
    rendered = json.dumps(report.to_dict(), sort_keys=True)
    assert '"digests":' not in rendered.casefold()


def test_damaged_wqw_container_is_not_reported_as_plain_read_stable(tmp_path):
    _make_base(tmp_path)
    _write_wqw(tmp_path / "root.dat", {"fileinfo.txt": b"003/b.zip;B;B;CN;KEY\r\n"})
    _write_wqw(tmp_path / "003" / "003.dat", {"filelist.txt": b"b.zip;B;CN\r\n"})
    damaged = tmp_path / "003" / "003.dat"
    damaged.write_bytes(damaged.read_bytes()[:-22])

    report = inspect_volume(tmp_path)
    profile = report.numbered_dat_profile
    assert profile is not None
    assert profile.numbered_catalogs[0].container_format == "damaged-or-incomplete-wqw"
    stability = profile.read_stability["by_path"]["003/003.dat"]
    assert stability["status"] == "READ_STABLE_PARTIAL"
