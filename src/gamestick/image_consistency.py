from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

ProgressCallback = Callable[[int, int], None]
CancelledCallback = Callable[[], bool]

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
DEFAULT_SECTOR_SIZE = 512
DEFAULT_MAX_RANGES = 4096


class ImageConsistencyError(RuntimeError):
    """Raised when a safe, meaningful image comparison cannot be performed."""


@dataclass(frozen=True)
class ImageDigest:
    name: str
    size_bytes: int
    sha256: str
    deviates_from_majority_sectors: int


@dataclass(frozen=True)
class DisagreementRange:
    start_offset: int
    end_offset_exclusive: int
    sector_count: int
    classification: str


@dataclass(frozen=True)
class ImageConsistencyResult:
    status: str
    image_count: int
    size_bytes: int
    chunk_size: int
    sector_size: int
    total_chunks: int
    unanimous_chunks: int
    majority_chunks: int
    split_chunks: int
    total_sectors: int
    unanimous_sectors: int
    majority_sectors: int
    split_sectors: int
    consensus_coverage_percent: Optional[float]
    ranges_truncated: bool
    disagreement_ranges: tuple[DisagreementRange, ...]
    images: tuple[ImageDigest, ...]
    report_path: Optional[str]
    created_at_utc: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _variant_groups(values: Sequence[bytes]) -> list[list[int]]:
    """Group byte-identical values without treating a hash as equality authority."""
    groups: list[list[int]] = []
    representatives: list[bytes] = []
    for index, value in enumerate(values):
        for group_index, representative in enumerate(representatives):
            if value == representative:
                groups[group_index].append(index)
                break
        else:
            representatives.append(value)
            groups.append([index])
    return groups


def _classification(groups: Sequence[Sequence[int]], image_count: int) -> tuple[str, Optional[Sequence[int]]]:
    if len(groups) == 1:
        return "UNANIMOUS", groups[0]
    winner = max(groups, key=len)
    if len(winner) > image_count / 2:
        return "MAJORITY", winner
    return "SPLIT", None


def _append_range(
    ranges: list[DisagreementRange],
    *,
    start: int,
    end: int,
    classification: str,
    sector_size: int,
    max_ranges: int,
) -> bool:
    """Append/coalesce a disagreement range. Returns True when output was truncated."""
    if ranges and ranges[-1].classification == classification and ranges[-1].end_offset_exclusive == start:
        previous = ranges[-1]
        ranges[-1] = DisagreementRange(
            start_offset=previous.start_offset,
            end_offset_exclusive=end,
            sector_count=math.ceil((end - previous.start_offset) / sector_size),
            classification=classification,
        )
        return False
    if len(ranges) >= max_ranges:
        return True
    ranges.append(
        DisagreementRange(
            start_offset=start,
            end_offset_exclusive=end,
            sector_count=math.ceil((end - start) / sector_size),
            classification=classification,
        )
    )
    return False


def _validate_paths(image_paths: Iterable[str | os.PathLike[str]]) -> tuple[Path, ...]:
    paths = tuple(Path(path) for path in image_paths)
    if len(paths) < 2:
        raise ImageConsistencyError("Select at least two full image files to compare.")

    canonical_seen: set[str] = set()
    for path in paths:
        if not path.is_file():
            raise ImageConsistencyError(f"Image does not exist or is not a regular file: {path}")
        canonical = os.path.normcase(str(path.resolve(strict=True)))
        if canonical in canonical_seen:
            raise ImageConsistencyError(f"The same image was selected more than once: {path}")
        canonical_seen.add(canonical)

    sizes = {path.stat().st_size for path in paths}
    if len(sizes) != 1:
        detail = ", ".join(f"{path.name}={path.stat().st_size}" for path in paths)
        raise ImageConsistencyError(
            "Full-image consensus comparison requires equal-sized acquisitions. " + detail
        )
    return paths


def _safe_write_report(path: Path, payload: dict, protected_images: Sequence[Path]) -> None:
    target = path.resolve(strict=False)
    protected = {os.path.normcase(str(p.resolve(strict=True))) for p in protected_images}
    if os.path.normcase(str(target)) in protected:
        raise ImageConsistencyError("Refusing to replace an image file with a comparison report.")

    if path.suffix.lower() != ".json":
        raise ImageConsistencyError("Comparison report destination must end in .json")

    parent = target.parent
    if not parent.exists() or not parent.is_dir():
        raise ImageConsistencyError(f"Report destination directory does not exist: {parent}")

    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(parent))
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        finally:
            raise


def compare_full_images(
    image_paths: Sequence[str | os.PathLike[str]],
    *,
    report_path: str | os.PathLike[str] | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    sector_size: int = DEFAULT_SECTOR_SIZE,
    max_ranges: int = DEFAULT_MAX_RANGES,
    progress: ProgressCallback | None = None,
    cancelled: CancelledCallback | None = None,
) -> ImageConsistencyResult:
    """Compare complete read-only image acquisitions and map byte disagreements.

    No consensus payload is materialized. With three or more images, sectors with a
    strict (>50%) byte-identical majority count as consensus-covered. Two-image
    disagreements are always SPLIT because neither image is privileged.
    """
    if chunk_size <= 0:
        raise ImageConsistencyError("chunk_size must be greater than zero")
    if sector_size <= 0:
        raise ImageConsistencyError("sector_size must be greater than zero")
    if chunk_size % sector_size:
        raise ImageConsistencyError("chunk_size must be an exact multiple of sector_size")
    if max_ranges <= 0:
        raise ImageConsistencyError("max_ranges must be greater than zero")

    paths = _validate_paths(image_paths)
    size = paths[0].stat().st_size
    image_count = len(paths)
    total_chunks = math.ceil(size / chunk_size) if size else 0
    total_sectors = math.ceil(size / sector_size) if size else 0

    hashers = [hashlib.sha256() for _ in paths]
    deviant_sectors = [0 for _ in paths]
    unanimous_chunks = majority_chunks = split_chunks = 0
    unanimous_sectors = majority_sectors = split_sectors = 0
    ranges: list[DisagreementRange] = []
    ranges_truncated = False
    done = 0

    handles = [path.open("rb", buffering=0) for path in paths]
    initial_handle_stats = [os.fstat(handle.fileno()) for handle in handles]
    try:
        while done < size:
            if cancelled and cancelled():
                raise ImageConsistencyError("Image comparison cancelled; no report was written.")

            want = min(chunk_size, size - done)
            chunks = [handle.read(want) for handle in handles]
            for path, chunk in zip(paths, chunks):
                if len(chunk) != want:
                    raise ImageConsistencyError(
                        f"Unexpected short read while comparing {path.name}: expected {want}, got {len(chunk)}"
                    )
            for hasher, chunk in zip(hashers, chunks):
                hasher.update(chunk)

            groups = _variant_groups(chunks)
            chunk_class, _ = _classification(groups, image_count)
            if chunk_class == "UNANIMOUS":
                unanimous_chunks += 1
                sectors_here = math.ceil(want / sector_size)
                unanimous_sectors += sectors_here
            else:
                if chunk_class == "MAJORITY":
                    majority_chunks += 1
                else:
                    split_chunks += 1

                for relative in range(0, want, sector_size):
                    sector_end = min(relative + sector_size, want)
                    values = [chunk[relative:sector_end] for chunk in chunks]
                    sector_groups = _variant_groups(values)
                    sector_class, winner = _classification(sector_groups, image_count)
                    absolute_start = done + relative
                    absolute_end = done + sector_end
                    if sector_class == "UNANIMOUS":
                        unanimous_sectors += 1
                        continue
                    if sector_class == "MAJORITY":
                        majority_sectors += 1
                        assert winner is not None
                        winner_set = set(winner)
                        for index in range(image_count):
                            if index not in winner_set:
                                deviant_sectors[index] += 1
                    else:
                        split_sectors += 1
                    if not ranges_truncated:
                        ranges_truncated = _append_range(
                            ranges,
                            start=absolute_start,
                            end=absolute_end,
                            classification=sector_class,
                            sector_size=sector_size,
                            max_ranges=max_ranges,
                        )

            done += want
            if progress:
                progress(done, size)

        # A host-side image changing during the pass could otherwise produce a
        # hybrid digest. Re-attest both the opened object and its pathname before
        # accepting the comparison evidence.
        for path, handle, initial in zip(paths, handles, initial_handle_stats):
            final = os.fstat(handle.fileno())
            initial_identity = (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns)
            final_identity = (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
            if final_identity != initial_identity:
                raise ImageConsistencyError(f"Input image changed during comparison: {path.name}")
            current = path.stat()
            if current.st_size != initial.st_size or current.st_mtime_ns != initial.st_mtime_ns:
                raise ImageConsistencyError(f"Input image pathname changed during comparison: {path.name}")
            if initial.st_ino and current.st_ino and (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino):
                raise ImageConsistencyError(f"Input image pathname was replaced during comparison: {path.name}")
    finally:
        for handle in handles:
            handle.close()

    digests = tuple(
        ImageDigest(
            name=path.name,
            size_bytes=size,
            sha256=hasher.hexdigest(),
            deviates_from_majority_sectors=deviant_sectors[index],
        )
        for index, (path, hasher) in enumerate(zip(paths, hashers))
    )

    if majority_chunks == 0 and split_chunks == 0:
        status = "IDENTICAL"
    elif image_count == 2:
        status = "TWO_IMAGE_DIFFERENCE"
    elif split_sectors == 0:
        status = "CONSENSUS_WITH_DISAGREEMENTS"
    else:
        status = "AMBIGUOUS_DISAGREEMENTS"

    if image_count >= 3 and total_sectors:
        coverage = round(((unanimous_sectors + majority_sectors) / total_sectors) * 100.0, 9)
    elif image_count >= 3:
        coverage = 100.0
    else:
        coverage = None

    created = _utc_now()
    report_string = str(Path(report_path).resolve(strict=False)) if report_path is not None else None
    result = ImageConsistencyResult(
        status=status,
        image_count=image_count,
        size_bytes=size,
        chunk_size=chunk_size,
        sector_size=sector_size,
        total_chunks=total_chunks,
        unanimous_chunks=unanimous_chunks,
        majority_chunks=majority_chunks,
        split_chunks=split_chunks,
        total_sectors=total_sectors,
        unanimous_sectors=unanimous_sectors,
        majority_sectors=majority_sectors,
        split_sectors=split_sectors,
        consensus_coverage_percent=coverage,
        ranges_truncated=ranges_truncated,
        disagreement_ranges=tuple(ranges),
        images=digests,
        report_path=report_string,
        created_at_utc=created,
    )

    if report_path is not None:
        payload = {
            "schema_version": 1,
            "report_type": "gamestick-full-image-consistency-map",
            "tool_version": "0.5.0-alpha8.2",
            "created_at_utc": created,
            "status": result.status,
            "safety": {
                "inputs_opened_read_only": True,
                "source_writes_performed": False,
                "consensus_image_created": False,
                "payload_bytes_exported": False,
            },
            "comparison": {
                "image_count": result.image_count,
                "size_bytes": result.size_bytes,
                "chunk_size": result.chunk_size,
                "sector_size": result.sector_size,
                "total_chunks": result.total_chunks,
                "unanimous_chunks": result.unanimous_chunks,
                "majority_chunks": result.majority_chunks,
                "split_chunks": result.split_chunks,
                "total_sectors": result.total_sectors,
                "unanimous_sectors": result.unanimous_sectors,
                "majority_sectors": result.majority_sectors,
                "split_sectors": result.split_sectors,
                "consensus_coverage_percent": result.consensus_coverage_percent,
                "ranges_truncated": result.ranges_truncated,
            },
            "images": [asdict(image) for image in result.images],
            "disagreement_ranges": [asdict(item) for item in result.disagreement_ranges],
        }
        _safe_write_report(Path(report_path), payload, paths)

    return result
