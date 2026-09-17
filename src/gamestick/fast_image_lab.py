from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

ProgressCallback = Callable[[str], None]
CancelledCallback = Callable[[], bool]

_MAX_ENTRIES_DEFAULT = 200_000
_MAX_DIFFS_DEFAULT = 5_000
_MAX_CONTROL_FILE_BYTES = 32 * 1024 * 1024
_DAT_RE = re.compile(r"^(\d{3})/\1\.dat$", re.IGNORECASE)
_CONTROL_EXTENSIONS = {".xml", ".ini", ".cfg", ".conf", ".json", ".txt", ".dat", ".sh", ".bat"}


class FastImageLabError(RuntimeError):
    """Raised when a raw image cannot be safely inspected as the expected FAT32 layout."""


@dataclass(frozen=True)
class Fat32Geometry:
    image_size_bytes: int
    partition_type: int
    partition_lba_start: int
    partition_sectors: int
    partition_offset_bytes: int
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size_bytes: int
    reserved_sectors: int
    fat_count: int
    fat_size_sectors: int
    root_cluster: int
    fat_offset_bytes: int
    data_offset_bytes: int


@dataclass(frozen=True)
class FatEntry:
    path: str
    size_bytes: int
    start_cluster: int
    is_directory: bool


@dataclass(frozen=True)
class CriticalFile:
    path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class ImageStructure:
    image_path: str
    geometry: Fat32Geometry
    file_count: int
    directory_count: int
    total_logical_file_bytes: int
    structure_sha256: str
    critical_files: tuple[CriticalFile, ...]
    top_level_entries: tuple[str, ...]
    bytes_hashed_for_controls: int


@dataclass(frozen=True)
class FastComparisonResult:
    status: str
    image_a: ImageStructure
    image_b: ImageStructure
    structure_identical: bool
    critical_files_identical: bool
    only_in_a_count: int
    only_in_b_count: int
    size_changed_count: int
    critical_hash_changed_count: int
    only_in_a: tuple[str, ...]
    only_in_b: tuple[str, ...]
    size_changed: tuple[str, ...]
    critical_hash_changed: tuple[str, ...]
    differences_truncated: bool
    report_path: Optional[str]
    created_at_utc: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_exact(handle, offset: int, size: int) -> bytes:
    handle.seek(offset)
    data = handle.read(size)
    if len(data) != size:
        raise FastImageLabError(f"Short read at image offset {offset}: expected {size}, got {len(data)}")
    return data


def _validate_image(path_like: str | os.PathLike[str]) -> Path:
    path = Path(path_like)
    try:
        st = path.lstat()
    except OSError as exc:
        raise FastImageLabError(f"Image is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise FastImageLabError(f"Image must be a regular non-symlink file: {path}")
    return path.resolve(strict=True)


def _parse_geometry(handle, image_size: int) -> Fat32Geometry:
    mbr = _read_exact(handle, 0, 512)
    if mbr[510:512] != b"\x55\xaa":
        raise FastImageLabError("Image does not contain a valid MBR signature.")

    partitions = []
    for index in range(4):
        entry = mbr[446 + index * 16 : 462 + index * 16]
        ptype = entry[4]
        lba_start = int.from_bytes(entry[8:12], "little")
        sectors = int.from_bytes(entry[12:16], "little")
        if ptype and sectors:
            partitions.append((ptype, lba_start, sectors))
    if not partitions:
        raise FastImageLabError("No populated MBR partition entry was found.")

    # GameStick evidence shows a single FAT32 LBA partition (type 0x0C). Prefer
    # FAT32 partition types, otherwise inspect the first populated entry.
    selected = next((p for p in partitions if p[0] in (0x0B, 0x0C)), partitions[0])
    ptype, lba_start, p_sectors = selected
    partition_offset = lba_start * 512
    if partition_offset + 512 > image_size:
        raise FastImageLabError("Partition starts beyond the end of the image.")

    boot = _read_exact(handle, partition_offset, 512)
    if boot[510:512] != b"\x55\xaa":
        raise FastImageLabError("Selected partition does not contain a valid FAT boot-sector signature.")

    bps = int.from_bytes(boot[11:13], "little")
    spc = boot[13]
    reserved = int.from_bytes(boot[14:16], "little")
    fats = boot[16]
    fat16_size = int.from_bytes(boot[22:24], "little")
    fat32_size = int.from_bytes(boot[36:40], "little")
    root_cluster = int.from_bytes(boot[44:48], "little")
    fat_size = fat32_size or fat16_size

    if bps not in (512, 1024, 2048, 4096):
        raise FastImageLabError(f"Unsupported FAT bytes/sector value: {bps}")
    if spc == 0 or spc & (spc - 1):
        raise FastImageLabError(f"Invalid FAT sectors/cluster value: {spc}")
    if not reserved or not fats or not fat_size or root_cluster < 2:
        raise FastImageLabError("Partition does not expose a valid FAT32 geometry.")

    cluster_size = bps * spc
    fat_offset = partition_offset + reserved * bps
    data_offset = partition_offset + (reserved + fats * fat_size) * bps
    partition_end = partition_offset + p_sectors * 512
    if data_offset >= min(partition_end, image_size):
        raise FastImageLabError("FAT32 data region lies outside the image.")

    return Fat32Geometry(
        image_size_bytes=image_size,
        partition_type=ptype,
        partition_lba_start=lba_start,
        partition_sectors=p_sectors,
        partition_offset_bytes=partition_offset,
        bytes_per_sector=bps,
        sectors_per_cluster=spc,
        cluster_size_bytes=cluster_size,
        reserved_sectors=reserved,
        fat_count=fats,
        fat_size_sectors=fat_size,
        root_cluster=root_cluster,
        fat_offset_bytes=fat_offset,
        data_offset_bytes=data_offset,
    )


class _Fat32Reader:
    def __init__(self, handle, geometry: Fat32Geometry, *, cancelled: CancelledCallback | None = None):
        self.handle = handle
        self.g = geometry
        self.cancelled = cancelled
        self._fat_cache: dict[int, int] = {}

    def _check_cancelled(self):
        if self.cancelled and self.cancelled():
            raise FastImageLabError("Fast image inspection cancelled; no report was written.")

    def cluster_offset(self, cluster: int) -> int:
        if cluster < 2:
            raise FastImageLabError(f"Invalid FAT32 cluster number: {cluster}")
        return self.g.data_offset_bytes + (cluster - 2) * self.g.cluster_size_bytes

    def fat_next(self, cluster: int) -> int:
        if cluster in self._fat_cache:
            return self._fat_cache[cluster]
        offset = self.g.fat_offset_bytes + cluster * 4
        value = int.from_bytes(_read_exact(self.handle, offset, 4), "little") & 0x0FFFFFFF
        self._fat_cache[cluster] = value
        return value

    def chain(self, start_cluster: int, *, max_clusters: int | None = None):
        if start_cluster < 2:
            return
        seen: set[int] = set()
        current = start_cluster
        count = 0
        max_possible = max(1, self.g.partition_sectors // self.g.sectors_per_cluster + 4)
        limit = min(max_possible, max_clusters) if max_clusters is not None else max_possible
        while 2 <= current < 0x0FFFFFF8:
            self._check_cancelled()
            if current in seen:
                raise FastImageLabError(f"FAT cluster loop detected at cluster {current}.")
            seen.add(current)
            yield current
            count += 1
            if count >= limit:
                if max_clusters is None:
                    raise FastImageLabError("FAT chain exceeded the bounded cluster limit.")
                return
            nxt = self.fat_next(current)
            if nxt == 0 or nxt == 0x0FFFFFF7:
                return
            current = nxt

    def _read_cluster(self, cluster: int) -> bytes:
        offset = self.cluster_offset(cluster)
        if offset + self.g.cluster_size_bytes > self.g.image_size_bytes:
            raise FastImageLabError(f"Cluster {cluster} maps beyond the end of the image.")
        return _read_exact(self.handle, offset, self.g.cluster_size_bytes)

    @staticmethod
    def _lfn_fragment(entry: bytes) -> str:
        raw = entry[1:11] + entry[14:26] + entry[28:32]
        chars = []
        for i in range(0, len(raw), 2):
            code = int.from_bytes(raw[i:i+2], "little")
            if code in (0x0000, 0xFFFF):
                break
            chars.append(chr(code))
        return "".join(chars)

    @staticmethod
    def _short_name(entry: bytes) -> str:
        base = bytearray(entry[0:8])
        if base and base[0] == 0x05:
            base[0] = 0xE5
        ext = entry[8:11]
        base_text = bytes(base).decode("cp437", errors="replace").rstrip(" ")
        ext_text = ext.decode("cp437", errors="replace").rstrip(" ")
        return f"{base_text}.{ext_text}" if ext_text else base_text

    def read_directory(self, start_cluster: int) -> list[FatEntry]:
        entries: list[FatEntry] = []
        lfn_parts: dict[int, str] = {}
        done = False
        for cluster in self.chain(start_cluster):
            data = self._read_cluster(cluster)
            for pos in range(0, len(data), 32):
                entry = data[pos:pos+32]
                first = entry[0]
                if first == 0x00:
                    done = True
                    break
                if first == 0xE5:
                    lfn_parts.clear()
                    continue
                attr = entry[11]
                if attr == 0x0F:
                    seq = entry[0] & 0x1F
                    if seq:
                        lfn_parts[seq] = self._lfn_fragment(entry)
                    continue
                if attr & 0x08:  # volume label
                    lfn_parts.clear()
                    continue
                name = "".join(lfn_parts[index] for index in sorted(lfn_parts)) if lfn_parts else self._short_name(entry)
                lfn_parts.clear()
                if name in (".", ".."):
                    continue
                high = int.from_bytes(entry[20:22], "little")
                low = int.from_bytes(entry[26:28], "little")
                start = (high << 16) | low
                size = int.from_bytes(entry[28:32], "little")
                entries.append(FatEntry(path=name, size_bytes=size, start_cluster=start, is_directory=bool(attr & 0x10)))
            if done:
                break
        return entries

    def read_file_chunks(self, entry: FatEntry):
        if entry.is_directory:
            raise FastImageLabError(f"Cannot read directory as file: {entry.path}")
        remaining = entry.size_bytes
        if remaining == 0:
            return
        if entry.start_cluster < 2:
            raise FastImageLabError(f"Non-empty file has invalid start cluster: {entry.path}")
        expected_clusters = (entry.size_bytes + self.g.cluster_size_bytes - 1) // self.g.cluster_size_bytes
        produced = 0
        for cluster in self.chain(entry.start_cluster, max_clusters=expected_clusters + 1):
            data = self._read_cluster(cluster)
            take = min(remaining, len(data))
            if take:
                yield data[:take]
                produced += take
                remaining -= take
            if remaining == 0:
                break
        if produced != entry.size_bytes:
            raise FastImageLabError(
                f"FAT chain for {entry.path} yielded {produced} bytes; expected {entry.size_bytes}."
            )


def _is_critical(path: str, size: int) -> bool:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    if size > _MAX_CONTROL_FILE_BYTES:
        return False
    if lower == "root.dat" or _DAT_RE.match(normalized):
        return True
    if lower.startswith("cubegm/") and Path(lower).suffix in _CONTROL_EXTENSIONS:
        return True
    if "/" not in normalized and Path(lower).suffix in _CONTROL_EXTENSIONS:
        return True
    return False


def inspect_image_structure(
    image_path: str | os.PathLike[str],
    *,
    max_entries: int = _MAX_ENTRIES_DEFAULT,
    progress: ProgressCallback | None = None,
    cancelled: CancelledCallback | None = None,
) -> tuple[ImageStructure, dict[str, FatEntry]]:
    if max_entries <= 0:
        raise FastImageLabError("max_entries must be greater than zero")
    path = _validate_image(image_path)
    initial = path.stat()
    with path.open("rb", buffering=0) as handle:
        opened = os.fstat(handle.fileno())
        geometry = _parse_geometry(handle, opened.st_size)
        reader = _Fat32Reader(handle, geometry, cancelled=cancelled)
        if progress:
            progress(f"Reading FAT32 directory metadata from {path.name}...")

        logical: dict[str, FatEntry] = {}
        queue: list[tuple[str, int]] = [("", geometry.root_cluster)]
        visited_dirs: set[int] = set()
        directory_count = 0
        file_count = 0
        total_file_bytes = 0
        top_level: list[str] = []

        while queue:
            if cancelled and cancelled():
                raise FastImageLabError("Fast image inspection cancelled; no report was written.")
            prefix, cluster = queue.pop(0)
            if cluster in visited_dirs:
                continue
            visited_dirs.add(cluster)
            directory_count += 1
            for child in reader.read_directory(cluster):
                full = f"{prefix}/{child.path}" if prefix else child.path
                normalized = full.replace("\\", "/")
                if len(logical) >= max_entries:
                    raise FastImageLabError(
                        f"Filesystem entry limit reached ({max_entries:,}); refusing to return a partial structural result."
                    )
                logical[normalized] = FatEntry(
                    path=normalized,
                    size_bytes=child.size_bytes,
                    start_cluster=child.start_cluster,
                    is_directory=child.is_directory,
                )
                if not prefix:
                    top_level.append(normalized)
                if child.is_directory:
                    if child.start_cluster >= 2:
                        queue.append((normalized, child.start_cluster))
                else:
                    file_count += 1
                    total_file_bytes += child.size_bytes
            if progress and directory_count % 64 == 0:
                progress(f"{path.name}: {file_count:,} files indexed; reading metadata only...")

        structure_hasher = hashlib.sha256()
        for name in sorted(logical, key=lambda x: x.casefold()):
            item = logical[name]
            kind = "D" if item.is_directory else "F"
            structure_hasher.update(f"{name}\0{kind}\0{item.size_bytes}\n".encode("utf-8", errors="surrogatepass"))

        critical: list[CriticalFile] = []
        bytes_hashed = 0
        for name in sorted(logical, key=lambda x: x.casefold()):
            item = logical[name]
            if item.is_directory or not _is_critical(name, item.size_bytes):
                continue
            if progress:
                progress(f"{path.name}: hashing control file {name} ({item.size_bytes:,} bytes)...")
            hasher = hashlib.sha256()
            for chunk in reader.read_file_chunks(item):
                hasher.update(chunk)
                bytes_hashed += len(chunk)
            critical.append(CriticalFile(path=name, size_bytes=item.size_bytes, sha256=hasher.hexdigest()))

        final_handle = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            final_handle.st_dev, final_handle.st_ino, final_handle.st_size, final_handle.st_mtime_ns
        ):
            raise FastImageLabError(f"Input image changed during fast inspection: {path.name}")

    final_path = path.stat()
    if final_path.st_size != initial.st_size or final_path.st_mtime_ns != initial.st_mtime_ns:
        raise FastImageLabError(f"Input image pathname changed during fast inspection: {path.name}")
    if initial.st_ino and final_path.st_ino and (initial.st_dev, initial.st_ino) != (final_path.st_dev, final_path.st_ino):
        raise FastImageLabError(f"Input image pathname was replaced during fast inspection: {path.name}")

    result = ImageStructure(
        image_path=str(path),
        geometry=geometry,
        file_count=file_count,
        directory_count=directory_count,
        total_logical_file_bytes=total_file_bytes,
        structure_sha256=structure_hasher.hexdigest(),
        critical_files=tuple(critical),
        top_level_entries=tuple(sorted(top_level, key=str.casefold)),
        bytes_hashed_for_controls=bytes_hashed,
    )
    return result, logical


def _safe_write_report(path: Path, payload: dict, protected_images: tuple[Path, Path]) -> None:
    target = path.resolve(strict=False)
    protected = {os.path.normcase(str(p.resolve(strict=True))) for p in protected_images}
    if os.path.normcase(str(target)) in protected:
        raise FastImageLabError("Refusing to replace an input image with a fast-comparison report.")
    if target.suffix.lower() != ".json":
        raise FastImageLabError("Fast comparison report destination must end in .json")
    if not target.parent.exists() or not target.parent.is_dir():
        raise FastImageLabError(f"Report destination directory does not exist: {target.parent}")
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def compare_fast_structures(
    image_a: str | os.PathLike[str],
    image_b: str | os.PathLike[str],
    *,
    report_path: str | os.PathLike[str] | None = None,
    max_entries: int = _MAX_ENTRIES_DEFAULT,
    max_differences: int = _MAX_DIFFS_DEFAULT,
    progress: ProgressCallback | None = None,
    cancelled: CancelledCallback | None = None,
) -> FastComparisonResult:
    if max_differences <= 0:
        raise FastImageLabError("max_differences must be greater than zero")
    a_path = _validate_image(image_a)
    b_path = _validate_image(image_b)
    if os.path.normcase(str(a_path)) == os.path.normcase(str(b_path)):
        raise FastImageLabError("Select two different image files.")

    a, a_entries = inspect_image_structure(a_path, max_entries=max_entries, progress=progress, cancelled=cancelled)
    b, b_entries = inspect_image_structure(b_path, max_entries=max_entries, progress=progress, cancelled=cancelled)

    if progress:
        progress("Comparing logical filesystem structure and launcher/control hashes...")

    a_keys = set(a_entries)
    b_keys = set(b_entries)
    only_a_all = sorted(a_keys - b_keys, key=str.casefold)
    only_b_all = sorted(b_keys - a_keys, key=str.casefold)
    size_changed_all = sorted(
        (name for name in a_keys & b_keys
         if a_entries[name].is_directory != b_entries[name].is_directory
         or a_entries[name].size_bytes != b_entries[name].size_bytes),
        key=str.casefold,
    )

    a_critical = {item.path: item for item in a.critical_files}
    b_critical = {item.path: item for item in b.critical_files}
    critical_changed_all = sorted(
        (name for name in set(a_critical) & set(b_critical)
         if a_critical[name].size_bytes != b_critical[name].size_bytes
         or a_critical[name].sha256 != b_critical[name].sha256),
        key=str.casefold,
    )
    # A missing critical file is already represented in only_in_A/B, but include it
    # in the critical count because launcher authority is the important distinction.
    critical_missing = sorted(set(a_critical) ^ set(b_critical), key=str.casefold)
    critical_combined = sorted(set(critical_changed_all) | set(critical_missing), key=str.casefold)

    all_count = len(only_a_all) + len(only_b_all) + len(size_changed_all) + len(critical_combined)
    truncated = all_count > max_differences
    budget = max_differences
    def take(values):
        nonlocal budget
        out = tuple(values[:budget])
        budget -= len(out)
        return out

    only_a = take(only_a_all)
    only_b = take(only_b_all)
    size_changed = take(size_changed_all)
    critical_changed = take(critical_combined)

    structure_identical = a.structure_sha256 == b.structure_sha256
    critical_identical = not critical_combined
    if structure_identical and critical_identical:
        status = "LOGICALLY_IDENTICAL"
    elif critical_identical:
        status = "CONTENT_LAYOUT_DIFFERS_CONTROLS_MATCH"
    else:
        status = "LAUNCHER_OR_CONTROL_DIFFERENCE"

    result = FastComparisonResult(
        status=status,
        image_a=a,
        image_b=b,
        structure_identical=structure_identical,
        critical_files_identical=critical_identical,
        only_in_a_count=len(only_a_all),
        only_in_b_count=len(only_b_all),
        size_changed_count=len(size_changed_all),
        critical_hash_changed_count=len(critical_combined),
        only_in_a=only_a,
        only_in_b=only_b,
        size_changed=size_changed,
        critical_hash_changed=critical_changed,
        differences_truncated=truncated,
        report_path=str(Path(report_path).resolve(strict=False)) if report_path else None,
        created_at_utc=_utc_now(),
    )

    if report_path:
        payload = asdict(result)
        payload["schema"] = "gamestick-fast-image-structure-v1"
        payload["read_policy"] = {
            "full_image_payload_scan_performed": False,
            "directory_metadata_enumerated": True,
            "launcher_control_files_hashed": True,
            "input_images_opened_read_only": True,
            "source_writes_performed": False,
        }
        _safe_write_report(Path(report_path), payload, (a_path, b_path))
    return result
