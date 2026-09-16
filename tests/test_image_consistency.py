import hashlib
import json

import pytest

from gamestick.image_consistency import ImageConsistencyError, compare_full_images


def _write(path, data):
    path.write_bytes(data)
    return path


def test_identical_images_are_unanimous(tmp_path):
    data = bytes(range(256)) * 16
    a = _write(tmp_path / "a.img", data)
    b = _write(tmp_path / "b.img", data)
    report = tmp_path / "map.json"

    result = compare_full_images([a, b], report_path=report, chunk_size=1024, sector_size=256)

    assert result.status == "IDENTICAL"
    assert result.split_sectors == 0
    assert result.majority_sectors == 0
    assert result.unanimous_sectors == len(data) // 256
    assert result.images[0].sha256 == hashlib.sha256(data).hexdigest()
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["safety"]["source_writes_performed"] is False
    assert payload["safety"]["consensus_image_created"] is False


def test_two_image_disagreement_is_split_not_arbitrary_consensus(tmp_path):
    a_data = b"A" * 1024
    b_data = bytearray(a_data)
    b_data[256:512] = b"B" * 256
    a = _write(tmp_path / "a.img", a_data)
    b = _write(tmp_path / "b.img", bytes(b_data))

    result = compare_full_images([a, b], chunk_size=1024, sector_size=256)

    assert result.status == "TWO_IMAGE_DIFFERENCE"
    assert result.split_sectors == 1
    assert result.majority_sectors == 0
    assert result.consensus_coverage_percent is None
    assert len(result.disagreement_ranges) == 1
    assert result.disagreement_ranges[0].classification == "SPLIT"
    assert result.disagreement_ranges[0].start_offset == 256
    assert result.disagreement_ranges[0].end_offset_exclusive == 512


def test_three_image_strict_majority_is_consensus_covered(tmp_path):
    good = b"A" * 1024
    bad = bytearray(good)
    bad[512:768] = b"Z" * 256
    a = _write(tmp_path / "a.img", good)
    b = _write(tmp_path / "b.img", good)
    c = _write(tmp_path / "c.img", bytes(bad))

    result = compare_full_images([a, b, c], chunk_size=1024, sector_size=256)

    assert result.status == "CONSENSUS_WITH_DISAGREEMENTS"
    assert result.majority_sectors == 1
    assert result.split_sectors == 0
    assert result.images[0].deviates_from_majority_sectors == 0
    assert result.images[1].deviates_from_majority_sectors == 0
    assert result.images[2].deviates_from_majority_sectors == 1
    assert result.consensus_coverage_percent == 100.0


def test_four_way_two_two_split_remains_ambiguous(tmp_path):
    a = _write(tmp_path / "a.img", b"A" * 512)
    b = _write(tmp_path / "b.img", b"A" * 512)
    c = _write(tmp_path / "c.img", b"B" * 512)
    d = _write(tmp_path / "d.img", b"B" * 512)

    result = compare_full_images([a, b, c, d], chunk_size=512, sector_size=512)

    assert result.status == "AMBIGUOUS_DISAGREEMENTS"
    assert result.split_sectors == 1
    assert result.consensus_coverage_percent == 0.0


def test_rejects_different_image_sizes(tmp_path):
    a = _write(tmp_path / "a.img", b"A" * 512)
    b = _write(tmp_path / "b.img", b"B" * 1024)
    with pytest.raises(ImageConsistencyError, match="equal-sized"):
        compare_full_images([a, b])


def test_rejects_duplicate_selection(tmp_path):
    a = _write(tmp_path / "a.img", b"A" * 512)
    with pytest.raises(ImageConsistencyError, match="same image"):
        compare_full_images([a, a])


def test_refuses_report_overwriting_an_input(tmp_path):
    a = _write(tmp_path / "a.img", b"A" * 512)
    b = _write(tmp_path / "b.img", b"A" * 512)
    with pytest.raises(ImageConsistencyError, match="replace an image"):
        compare_full_images([a, b], report_path=a, chunk_size=512, sector_size=512)


def test_range_output_is_bounded(tmp_path):
    # Alternate disagreement/unanimous sectors to prevent coalescing.
    sectors_a = []
    sectors_b = []
    for index in range(20):
        sectors_a.append(bytes([index]) * 16)
        sectors_b.append((bytes([index ^ 0xFF]) if index % 2 == 0 else bytes([index])) * 16)
    a = _write(tmp_path / "a.img", b"".join(sectors_a))
    b = _write(tmp_path / "b.img", b"".join(sectors_b))

    result = compare_full_images([a, b], chunk_size=320, sector_size=16, max_ranges=3)
    assert result.ranges_truncated is True
    assert len(result.disagreement_ranges) == 3
    assert result.split_sectors == 10


def test_cancellation_writes_no_report(tmp_path):
    a = _write(tmp_path / "a.img", b"A" * 2048)
    b = _write(tmp_path / "b.img", b"A" * 2048)
    report = tmp_path / "map.json"
    calls = {"n": 0}

    def cancelled():
        calls["n"] += 1
        return calls["n"] > 1

    with pytest.raises(ImageConsistencyError, match="cancelled"):
        compare_full_images([a, b], report_path=report, chunk_size=512, sector_size=512, cancelled=cancelled)
    assert not report.exists()
