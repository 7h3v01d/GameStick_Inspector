from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .catalogue_image_lab import (
    CatalogueImageLabError,
    _FatAccessor,
    _locate_catalogues,
    _read_wqw_control,
    compare_catalogue_controls,
)
from .fast_image_lab import FatEntry, _parse_geometry, _validate_image
from .wqw import _parse_filelist

ProgressCallback = Callable[[str], None]
CancelledCallback = Callable[[], bool]

_MAX_REPAIR_FILE_BYTES = 128 * 1024 * 1024
_WORKSPACE_SCHEMA = "gamestick-repair-workspace-v1"


class RepairWorkspaceError(RuntimeError):
    """Raised when a safe host-side repair workspace cannot be created."""


@dataclass(frozen=True)
class RepairEntry:
    code: str
    path: str
    payload_member: str
    file_size_bytes: int
    cluster_count: int
    target_chain_sha256: str
    base_file_sha256: str
    replacement_file_sha256: str
    replacement_control_sha256: str
    replacement_unique_rom_name_count: int


@dataclass(frozen=True)
class RepairWorkspaceResult:
    workspace_path: str
    workspace_sha256: str
    workspace_size_bytes: int
    repair_count: int
    repaired_codes: tuple[str, ...]
    bytes_read_from_images: int
    archive_verified: bool
    source_writes_performed: bool
    created_at_utc: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _chain_sha256(chain: tuple[int, ...]) -> str:
    h = hashlib.sha256()
    for cluster in chain:
        h.update(int(cluster).to_bytes(4, "little", signed=False))
    return h.hexdigest()


class _BytesAccessor:
    def __init__(self, data: bytes):
        self.data = data

    def chain_for(self, _entry):
        return (2,)

    def read_range(self, _entry, offset: int, length: int, chain=None):
        if offset < 0 or length < 0 or offset + length > len(self.data):
            raise CatalogueImageLabError("Replacement payload range lies outside the payload.")
        return self.data[offset:offset + length]


def _validate_replacement_payload(code: str, payload: bytes) -> tuple[str, int]:
    entry = FatEntry(path=f"{code}/{code}.DAT", size_bytes=len(payload), start_cluster=2, is_directory=False)
    accessor = _BytesAccessor(payload)
    container, status, filelist, _members, member_names = _read_wqw_control(accessor, entry, "filelist.txt")
    if container != "VALID_WQW" or status != "VERIFIED" or filelist is None:
        raise RepairWorkspaceError(
            f"Golden replacement {code}/{code}.DAT did not validate as a usable WQW catalogue "
            f"({container}/{status})."
        )
    parsed, _roms = _parse_filelist(filelist, member_names)
    count = parsed.get("unique_rom_name_count")
    if not isinstance(count, int):
        raise RepairWorkspaceError(f"Golden replacement {code}/{code}.DAT has no usable ROM-name count.")
    return _sha256_bytes(filelist), count


def _read_dat_payload(
    image_path: Path,
    code: str,
    *,
    cancelled: CancelledCallback | None = None,
) -> tuple[bytes, tuple[int, ...], int, str, int]:
    initial = image_path.stat()
    with image_path.open("rb", buffering=0) as handle:
        opened = os.fstat(handle.fileno())
        geometry = _parse_geometry(handle, opened.st_size)
        catalogues, _root = _locate_catalogues(handle, geometry, cancelled=cancelled)
        entry = catalogues.get(code)
        if entry is None:
            raise RepairWorkspaceError(f"Catalogue {code}/{code}.DAT is missing from {image_path.name}.")
        if entry.size_bytes <= 0:
            raise RepairWorkspaceError(f"Catalogue {code}/{code}.DAT is empty in {image_path.name}.")
        if entry.size_bytes > _MAX_REPAIR_FILE_BYTES:
            raise RepairWorkspaceError(
                f"Catalogue {code}/{code}.DAT is {entry.size_bytes:,} bytes; fast repair workspace limit is "
                f"{_MAX_REPAIR_FILE_BYTES:,} bytes. No source was modified."
            )
        accessor = _FatAccessor(handle, geometry, cancelled=cancelled)
        chain = accessor.chain_for(entry)
        payload = accessor.read_range(entry, 0, entry.size_bytes, chain)
        final_handle = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            final_handle.st_dev, final_handle.st_ino, final_handle.st_size, final_handle.st_mtime_ns
        ):
            raise RepairWorkspaceError(f"Input image changed while reading {code}/{code}.DAT: {image_path.name}")
        bytes_read = accessor.bytes_read
    final = image_path.stat()
    if initial.st_size != final.st_size or initial.st_mtime_ns != final.st_mtime_ns:
        raise RepairWorkspaceError(f"Input image pathname changed while reading {code}/{code}.DAT: {image_path.name}")
    return payload, chain, geometry.partition_offset_bytes, _chain_sha256(chain), bytes_read


def _safe_output_path(output_path, protected: tuple[Path, Path], *, overwrite: bool) -> Path:
    target = Path(output_path).expanduser().resolve(strict=False)
    protected_paths = {os.path.normcase(str(p.resolve(strict=True))) for p in protected}
    if os.path.normcase(str(target)) in protected_paths:
        raise RepairWorkspaceError("Refusing to replace an input image with a repair workspace.")
    if target.suffix.casefold() != ".gsworkspace":
        raise RepairWorkspaceError("Repair workspace destination must end in .gsworkspace")
    parent = target.parent.resolve(strict=True)
    if not parent.is_dir():
        raise RepairWorkspaceError(f"Workspace destination directory is not a directory: {parent}")
    if target.exists():
        if target.is_dir() or target.is_symlink():
            raise RepairWorkspaceError("Refusing to replace a directory or symlink as the workspace output.")
        if not overwrite:
            raise RepairWorkspaceError(f"Workspace already exists: {target}")
    return target


def _archive_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _verify_workspace_archive(path: Path, expected_entries: tuple[RepairEntry, ...]) -> None:
    with zipfile.ZipFile(path, "r") as archive:
        names = set(archive.namelist())
        if "manifest.json" not in names:
            raise RepairWorkspaceError("Created workspace is missing manifest.json.")
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        if manifest.get("schema") != _WORKSPACE_SCHEMA:
            raise RepairWorkspaceError("Created workspace manifest schema verification failed.")
        for repair in expected_entries:
            if repair.payload_member not in names:
                raise RepairWorkspaceError(f"Created workspace is missing {repair.payload_member}.")
            payload = archive.read(repair.payload_member)
            if len(payload) != repair.file_size_bytes or _sha256_bytes(payload) != repair.replacement_file_sha256:
                raise RepairWorkspaceError(f"Created workspace payload verification failed for {repair.code}.")


def build_repair_workspace(
    golden_image,
    base_image,
    output_path,
    *,
    overwrite: bool = False,
    progress: ProgressCallback | None = None,
    cancelled: CancelledCallback | None = None,
) -> RepairWorkspaceResult:
    golden = _validate_image(golden_image)
    base = _validate_image(base_image)
    if os.path.normcase(str(golden)) == os.path.normcase(str(base)):
        raise RepairWorkspaceError("Select different golden and repair-base image files.")
    target = _safe_output_path(output_path, (golden, base), overwrite=overwrite)

    if progress:
        progress("Comparing catalogue controls to select safe repair candidates...")
    try:
        comparison = compare_catalogue_controls(golden, base, progress=progress, cancelled=cancelled)
    except CatalogueImageLabError as exc:
        raise RepairWorkspaceError(str(exc)) from exc

    candidates: list[str] = []
    for delta in comparison.deltas:
        if delta.status != "DAMAGED_OR_UNREADABLE":
            continue
        if delta.image_a_control_status == "VERIFIED" and delta.image_b_control_status != "VERIFIED":
            candidates.append(delta.code)

    if not candidates:
        raise RepairWorkspaceError(
            "No safe repair candidate was found: the golden image must have a VERIFIED catalogue where the repair base is damaged/unreadable."
        )

    repairs: list[RepairEntry] = []
    payloads: dict[str, bytes] = {}
    total_read = (
        comparison.image_a.bytes_read_for_fat + comparison.image_a.bytes_read_for_controls
        + comparison.image_b.bytes_read_for_fat + comparison.image_b.bytes_read_for_controls
    )

    for code in candidates:
        if cancelled and cancelled():
            raise RepairWorkspaceError("Repair workspace creation cancelled; no workspace was written.")
        if progress:
            progress(f"Repair candidate {code}: reading only the two {code}.DAT files...")
        golden_payload, _golden_chain, golden_part, _golden_chain_hash, golden_read = _read_dat_payload(
            golden, code, cancelled=cancelled
        )
        base_payload, base_chain, base_part, base_chain_hash, base_read = _read_dat_payload(
            base, code, cancelled=cancelled
        )
        total_read += golden_read + base_read
        if golden_part != comparison.image_a.partition_offset_bytes or base_part != comparison.image_b.partition_offset_bytes:
            raise RepairWorkspaceError("Partition geometry changed during repair workspace creation.")
        if len(golden_payload) != len(base_payload):
            raise RepairWorkspaceError(
                f"Catalogue {code} differs in file size ({len(golden_payload):,} vs {len(base_payload):,}); "
                "fast same-slot repair is not safe."
            )
        control_hash, rom_count = _validate_replacement_payload(code, golden_payload)
        member = f"replacements/{code}.dat"
        repair = RepairEntry(
            code=code,
            path=f"{code}/{code}.DAT",
            payload_member=member,
            file_size_bytes=len(golden_payload),
            cluster_count=len(base_chain),
            target_chain_sha256=base_chain_hash,
            base_file_sha256=_sha256_bytes(base_payload),
            replacement_file_sha256=_sha256_bytes(golden_payload),
            replacement_control_sha256=control_hash,
            replacement_unique_rom_name_count=rom_count,
        )
        repairs.append(repair)
        payloads[member] = golden_payload

    created = _utc_now()
    manifest = {
        "schema": _WORKSPACE_SCHEMA,
        "created_at_utc": created,
        "golden_image": {
            "name": golden.name,
            "size_bytes": comparison.image_a.image_size_bytes,
            "partition_offset_bytes": comparison.image_a.partition_offset_bytes,
            "root_control_sha256": comparison.image_a.root_control.control_sha256,
        },
        "base_image": {
            "name": base.name,
            "size_bytes": comparison.image_b.image_size_bytes,
            "partition_offset_bytes": comparison.image_b.partition_offset_bytes,
            "root_control_sha256": comparison.image_b.root_control.control_sha256,
        },
        "repairs": [repair.__dict__ for repair in repairs],
        "safety": {
            "source_images_opened_read_only": True,
            "source_writes_performed": False,
            "workspace_is_host_side_only": True,
            "game_stick_write_performed": False,
            "full_image_copy_performed": False,
            "future_apply_must_revalidate_base_file_hash_and_target_chain": True,
        },
    }

    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        if progress:
            progress(f"Writing host-side repair workspace ({sum(len(v) for v in payloads.values()):,} payload bytes)...")
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            for name, payload in payloads.items():
                archive.writestr(name, payload)
        _verify_workspace_archive(temp, tuple(repairs))
        os.replace(temp, target)
    except Exception:
        temp.unlink(missing_ok=True)
        raise

    workspace_sha = _archive_sha256(target)
    return RepairWorkspaceResult(
        workspace_path=str(target),
        workspace_sha256=workspace_sha,
        workspace_size_bytes=target.stat().st_size,
        repair_count=len(repairs),
        repaired_codes=tuple(repair.code for repair in repairs),
        bytes_read_from_images=total_read,
        archive_verified=True,
        source_writes_performed=False,
        created_at_utc=created,
    )
