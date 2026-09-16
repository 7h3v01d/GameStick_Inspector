import json
from pathlib import Path

from gamestick.binary_fingerprint import (
    fingerprint_limits,
    inspect_binary_fingerprint,
)


def test_binary_fingerprint_is_bounded_and_never_claims_full_scan(tmp_path):
    path = tmp_path / "large.dat"
    path.write_bytes((b"A" * 1024) * 4096)  # 4 MiB

    evidence = inspect_binary_fingerprint(path, size=path.stat().st_size)
    limits = fingerprint_limits()

    assert evidence.sampled_window_count <= limits["max_sample_windows"]
    assert evidence.sampled_bytes_total <= limits["max_sampled_bytes_per_file"]
    assert evidence.unique_sampled_bytes <= evidence.sampled_bytes_total
    assert evidence.sample_covers_entire_file is False
    assert evidence.full_file_scan_performed is False
    assert evidence.arbitrary_strings_exported is False
    assert evidence.prefix_sha256
    assert evidence.tail_sha256


def test_exact_header_and_sampled_signature_detection_are_allowlisted(tmp_path):
    path = tmp_path / "sample.dat"
    payload = bytearray(b"\x37\x7a\xbc\xaf\x27\x1c" + b"\x00" * (1024 * 1024 - 6))
    midpoint = len(payload) // 2
    payload[midpoint:midpoint + 8] = b"\x89PNG\r\n\x1a\n"
    path.write_bytes(payload)

    evidence = inspect_binary_fingerprint(path, size=len(payload))

    assert "7z" in evidence.header_signatures
    assert "7z" in evidence.sampled_signature_hits
    assert "png" in evidence.sampled_signature_hits
    assert "middle" in evidence.sampled_signature_hits["png"]["locations"]


def test_structural_tokens_export_only_canonical_terms_not_surrounding_private_text(tmp_path):
    path = tmp_path / "tokens.dat"
    private = b"Secret Game Name 12345"
    path.write_bytes(
        b"\x00fileinfo\x00title\x00rom\x00image\x00" + private + b"\x00" + b"X" * 100_000
    )

    evidence = inspect_binary_fingerprint(path, size=path.stat().st_size)
    rendered = json.dumps(evidence.__dict__, sort_keys=True)

    assert "fileinfo" in evidence.structural_token_hits
    assert "title" in evidence.structural_token_hits
    assert "rom" in evidence.structural_token_hits
    assert "image" in evidence.structural_token_hits
    assert "Secret Game Name" not in rendered
    assert "12345" not in rendered


def test_fixed_position_tar_and_iso_signatures_are_detected_from_prefix_only(tmp_path):
    path = tmp_path / "fixed.dat"
    payload = bytearray(b"\x00" * (128 * 1024))
    payload[257:262] = b"ustar"
    payload[0x8001:0x8006] = b"CD001"
    path.write_bytes(payload)

    evidence = inspect_binary_fingerprint(path, size=len(payload))

    assert "tar-ustar" in evidence.header_signatures
    assert "iso9660-cd001" in evidence.header_signatures


def test_prefix_hash_commitments_change_without_exporting_raw_prefix(tmp_path):
    first = tmp_path / "first.dat"
    second = tmp_path / "second.dat"
    first.write_bytes(b"COMMON-HEADER-1234567890" + b"A" * 100_000)
    second.write_bytes(b"COMMON-HEADER-1234567890" + b"B" * 100_000)

    one = inspect_binary_fingerprint(first, size=first.stat().st_size)
    two = inspect_binary_fingerprint(second, size=second.stat().st_size)

    assert one.prefix_sha256 != two.prefix_sha256
    assert "COMMON-HEADER" not in json.dumps(one.__dict__, sort_keys=True)


def test_small_file_reports_bounded_sample_can_cover_entire_file(tmp_path):
    path = tmp_path / "small.dat"
    path.write_bytes(b"small bounded sample")
    evidence = inspect_binary_fingerprint(path, size=path.stat().st_size)
    assert evidence.sampled_window_count == 1
    assert evidence.sample_covers_entire_file is True
    assert evidence.full_file_scan_performed is False
