from __future__ import annotations

import hashlib
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from .models import BinaryFingerprintEvidence
from .ordering import stable_text_key

# Binary fingerprinting is deliberately sample-bounded.  It never scans an
# entire DAT and never exports arbitrary strings found in media content.
_SAMPLE_WINDOW_BYTES = 64 * 1024
_MAX_SAMPLE_WINDOWS = 5
_PREFIX_HASH_BUCKETS = (8, 16, 32, 64)
_MAX_SIGNAL_HITS_PER_KIND = 64

# Exact byte signatures are allowlisted structural evidence.  Presence in a
# bounded sample is not, by itself, a claim that the entire file is that format.
_SIGNATURES: Tuple[Tuple[str, bytes], ...] = (
    ("zip-local", b"PK\x03\x04"),
    ("zip-central", b"PK\x01\x02"),
    ("zip-eocd", b"PK\x05\x06"),
    ("7z", b"\x37\x7a\xbc\xaf\x27\x1c"),
    ("gzip", b"\x1f\x8b\x08"),
    ("bzip2", b"BZh"),
    ("xz", b"\xfd7zXZ\x00"),
    ("rar4", b"Rar!\x1a\x07\x00"),
    ("rar5", b"Rar!\x1a\x07\x01\x00"),
    ("squashfs-le", b"hsqs"),
    ("squashfs-be", b"sqsh"),
    ("sqlite3", b"SQLite format 3\x00"),
    ("elf", b"\x7fELF"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("gif87a", b"GIF87a"),
    ("gif89a", b"GIF89a"),
    ("bmp", b"BM"),
)

# Canonical terms only.  Matching is ASCII/boundary-based and only the fixed
# canonical term is exported; surrounding media strings never leave the probe.
_STRUCTURAL_TOKENS: Tuple[str, ...] = (
    "filelist",
    "fileinfo",
    "catalog",
    "game",
    "games",
    "rom",
    "image",
    "artwork",
    "raw",
    "core",
    "emulator",
    "platform",
    "system",
    "title",
    "path",
)
_TOKEN_PATTERNS = {
    token: re.compile(rb"(?<![a-z0-9_])" + re.escape(token.encode("ascii")) + rb"(?![a-z0-9_])")
    for token in _STRUCTURAL_TOKENS
}


def fingerprint_limits() -> Dict[str, int]:
    return {
        "sample_window_bytes": _SAMPLE_WINDOW_BYTES,
        "max_sample_windows": _MAX_SAMPLE_WINDOWS,
        "max_sampled_bytes_per_file": _SAMPLE_WINDOW_BYTES * _MAX_SAMPLE_WINDOWS,
        "comparison_prefix_bytes": max(_PREFIX_HASH_BUCKETS),
        "max_signal_hits_per_kind": _MAX_SIGNAL_HITS_PER_KIND,
    }


def _sample_plan(size: int) -> List[Tuple[int, Tuple[str, ...]]]:
    if size <= 0:
        return []
    width = min(size, _SAMPLE_WINDOW_BYTES)
    targets: Sequence[Tuple[str, int]] = (
        ("prefix", 0),
        ("quarter", max(0, size // 4 - width // 2)),
        ("middle", max(0, size // 2 - width // 2)),
        ("three-quarter", max(0, (3 * size) // 4 - width // 2)),
        ("tail", max(0, size - width)),
    )
    by_offset: Dict[int, List[str]] = {}
    for label, start in targets:
        start = min(max(0, int(start)), max(0, size - width))
        by_offset.setdefault(start, []).append(label)
    rows = [
        (start, tuple(labels))
        for start, labels in sorted(by_offset.items(), key=lambda item: item[0])
    ]
    return rows[:_MAX_SAMPLE_WINDOWS]



def _covered_bytes(windows: Sequence[Dict[str, object]]) -> int:
    intervals = sorted(
        (int(row["offset"]), int(row["offset"]) + int(row["bytes_sampled"]))
        for row in windows
        if int(row["bytes_sampled"]) > 0
    )
    if not intervals:
        return 0
    total = 0
    start, end = intervals[0]
    for next_start, next_end in intervals[1:]:
        if next_start <= end:
            end = max(end, next_end)
        else:
            total += end - start
            start, end = next_start, next_end
    total += end - start
    return total

def _ratio_ppm(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        return 0
    return int(round((numerator * 1_000_000) / denominator))


def _entropy_bits_per_byte(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def _count_occurrences(data: bytes, needle: bytes, cap: int) -> int:
    if not needle or cap <= 0:
        return 0
    count = 0
    start = 0
    while count < cap:
        index = data.find(needle, start)
        if index < 0:
            break
        count += 1
        start = index + 1
    return count


def _header_signatures(prefix: bytes) -> List[str]:
    hits: set[str] = set()
    for name, signature in _SIGNATURES:
        if prefix.startswith(signature):
            hits.add(name)
    # Fixed-position signatures whose format contract places magic away from 0.
    if len(prefix) >= 262 and prefix[257:262] == b"ustar":
        hits.add("tar-ustar")
    if len(prefix) >= 0x8006 and prefix[0x8001:0x8006] == b"CD001":
        hits.add("iso9660-cd001")
    if len(prefix) >= 1082 and prefix[1080:1082] == b"\x53\xef":
        hits.add("ext-superblock")
    if prefix.startswith(b"\x45\x3d\xcd\x28") or prefix.startswith(b"\x28\xcd\x3d\x45"):
        hits.add("cramfs")
    return sorted(hits, key=stable_text_key)


def _signal_hits(
    windows: Sequence[Tuple[Tuple[str, ...], bytes]],
) -> Tuple[Dict[str, Dict[str, object]], Dict[str, Dict[str, object]]]:
    signature_counts: Counter[str] = Counter()
    signature_locations: Dict[str, set[str]] = defaultdict(set)
    token_counts: Counter[str] = Counter()
    token_locations: Dict[str, set[str]] = defaultdict(set)

    for labels, data in windows:
        lower = data.lower()
        for name, signature in _SIGNATURES:
            remaining = _MAX_SIGNAL_HITS_PER_KIND - signature_counts[name]
            if remaining <= 0:
                continue
            count = _count_occurrences(data, signature, remaining)
            if count:
                signature_counts[name] += count
                signature_locations[name].update(labels)
        for token, pattern in _TOKEN_PATTERNS.items():
            remaining = _MAX_SIGNAL_HITS_PER_KIND - token_counts[token]
            if remaining <= 0:
                continue
            count = 0
            for _match in pattern.finditer(lower):
                count += 1
                if count >= remaining:
                    break
            if count:
                token_counts[token] += count
                token_locations[token].update(labels)

    signature_result: Dict[str, Dict[str, object]] = {}
    for name in sorted(signature_counts, key=stable_text_key):
        signature_result[name] = {
            "count_capped": int(signature_counts[name]),
            "locations": sorted(signature_locations[name], key=stable_text_key),
        }
    token_result: Dict[str, Dict[str, object]] = {}
    for token in sorted(token_counts, key=stable_text_key):
        token_result[token] = {
            "count_capped": int(token_counts[token]),
            "locations": sorted(token_locations[token], key=stable_text_key),
        }
    return signature_result, token_result


def inspect_binary_fingerprint(path: Path, *, size: int) -> BinaryFingerprintEvidence:
    """Read a bounded set of windows and derive privacy-safe binary structure.

    No arbitrary strings or raw bytes are exported.  Prefix/tail digests are
    content commitments only and are intentionally excluded from Device Profile
    structural identity.
    """
    plan = _sample_plan(size)
    window_rows: List[Dict[str, object]] = []
    sampled: List[Tuple[Tuple[str, ...], bytes]] = []
    short_reads = 0

    with path.open("rb") as handle:
        for start, labels in plan:
            requested = min(_SAMPLE_WINDOW_BYTES, max(0, size - start))
            handle.seek(start)
            data = handle.read(requested)
            if len(data) != requested:
                short_reads += 1
            sampled.append((labels, data))
            window_rows.append(
                {
                    "labels": list(labels),
                    "offset": int(start),
                    "bytes_sampled": len(data),
                }
            )

    prefix = sampled[0][1] if sampled else b""
    # Select the sample whose plan includes tail; fall back to the last sample.
    tail = b""
    for labels, data in sampled:
        if "tail" in labels:
            tail = data
            break
    if not tail and sampled:
        tail = sampled[-1][1]

    combined = b"".join(data for _labels, data in sampled)
    unique_sampled_bytes = _covered_bytes(window_rows)
    signature_hits, token_hits = _signal_hits(sampled)
    printable = sum(1 for value in combined if value in (9, 10, 13) or 32 <= value <= 126)
    nul_count = combined.count(0)

    return BinaryFingerprintEvidence(
        schema_version=1,
        sample_strategy="five-position-bounded-v1",
        sample_window_bytes=_SAMPLE_WINDOW_BYTES,
        sampled_window_count=len(sampled),
        sampled_bytes_total=len(combined),
        unique_sampled_bytes=unique_sampled_bytes,
        sample_covers_entire_file=(size > 0 and unique_sampled_bytes >= size),
        short_read_window_count=short_reads,
        windows=window_rows,
        prefix_sha256=hashlib.sha256(prefix).hexdigest() if prefix else None,
        tail_sha256=hashlib.sha256(tail).hexdigest() if tail else None,
        header_signatures=_header_signatures(prefix),
        sampled_signature_hits=signature_hits,
        structural_token_hits=token_hits,
        entropy_bits_per_byte=_entropy_bits_per_byte(combined),
        printable_ratio_ppm=_ratio_ppm(printable, len(combined)),
        nul_ratio_ppm=_ratio_ppm(nul_count, len(combined)),
        arbitrary_strings_exported=False,
        full_file_scan_performed=False,
    )


def read_prefix_for_comparison(path: Path, *, max_bytes: int = max(_PREFIX_HASH_BUCKETS)) -> bytes:
    """Read a tiny private prefix for in-process family comparison only.

    The bytes returned by this helper must never be placed in evidence.  The
    numbered-DAT profile exports only the resulting common-prefix bucket size.
    """
    with path.open("rb") as handle:
        return handle.read(max(0, int(max_bytes)))


def largest_common_prefix_bucket(samples: Iterable[bytes]) -> int:
    rows = list(samples)
    if len(rows) < 2:
        return 0
    for length in reversed(_PREFIX_HASH_BUCKETS):
        if all(len(row) >= length for row in rows):
            first = rows[0][:length]
            if all(row[:length] == first for row in rows[1:]):
                return length
    return 0


def common_sampled_signatures(fingerprints: Iterable[BinaryFingerprintEvidence]) -> List[str]:
    rows = list(fingerprints)
    if len(rows) < 2:
        return []
    common = set(rows[0].sampled_signature_hits)
    for row in rows[1:]:
        common.intersection_update(row.sampled_signature_hits)
    return sorted(common, key=stable_text_key)

def common_header_signatures(fingerprints: Iterable[BinaryFingerprintEvidence]) -> List[str]:
    rows = list(fingerprints)
    if len(rows) < 2:
        return []
    common = set(rows[0].header_signatures)
    for row in rows[1:]:
        common.intersection_update(row.header_signatures)
    return sorted(common, key=stable_text_key)

