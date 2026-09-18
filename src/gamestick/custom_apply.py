from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import tempfile
import zipfile
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Optional
from collections import Counter

from .catalogue_image_lab import _FatAccessor, _locate_catalogues
from .fast_image_lab import FatEntry, _parse_geometry, _validate_image
from .fs_safety import ForensicPathError, assert_contained_non_reparse, lstat_non_reparse
from .rom_customization import (
    RomCustomizationError,
    _ControlLayout,
    _build_same_slot_patches,
    _filter_fileinfo,
    _filter_filelist,
    _read_control_layout,
    _rom_names,
    build_hide_rom_workspace,
)

ProgressCallback = Callable[[str], None]
CancelledCallback = Callable[[], bool]

_WORKSPACE_SCHEMA = "gamestick-customization-workspace-v1"
_ROLLBACK_SCHEMA_V1 = "gamestick-customization-rollback-v1"
_ROLLBACK_SCHEMA_V2 = "gamestick-customization-rollback-v2"
_ROLLBACK_SCHEMA = "gamestick-customization-rollback-v3"
_RECEIPT_SCHEMA_V1 = "gamestick-customization-apply-receipt-v1"
_RECEIPT_SCHEMA = "gamestick-customization-apply-receipt-v2"
_MAX_WORKSPACE_BYTES = 32 * 1024 * 1024
_MAX_ROLLBACK_BYTES = 32 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 128
_MAX_ARCHIVE_EXPANDED_BYTES = 32 * 1024 * 1024
_MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_RECEIPT_BYTES = 1024 * 1024
_MAX_COMPRESSION_RATIO = 200
_MAX_PATCH_BYTES = 16 * 1024 * 1024
_MAX_PATCH_RANGES = 128
_DAT_PATH_RE = re.compile(r"^(\d{3})/\1\.dat$", re.IGNORECASE)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_EXTERNAL_BUSES = {"usb", "sd", "mmc"}


class CustomizationApplyError(RuntimeError):
    """Raised when a bounded customisation apply/rollback cannot be proven safe."""


class RecoveryRequiredError(CustomizationApplyError):
    """Compensation could not restore a coherent known state; manual recovery is required."""


@dataclass(frozen=True)
class ApplyResult:
    target_root: str
    workspace_path: str
    workspace_sha256: str
    rollback_path: str
    rollback_sha256: str
    receipt_path: str
    patched_file_count: int
    patch_range_count: int
    patch_payload_bytes: int
    rom: str
    catalogue_code: str
    verification: str
    created_at_utc: str


@dataclass(frozen=True)
class RollbackResult:
    target_root: str
    rollback_path: str
    restored_file_count: int
    restored_range_count: int
    restored_bytes: int
    verification: str
    created_at_utc: str


@dataclass
class _ReceiptReservation:
    path: Path
    stage_path: Path
    handle: Any
    binding: Any
    overwrite: bool


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb", buffering=0) as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _chain_sha256(chain: tuple[int, ...]) -> str:
    h = hashlib.sha256()
    for cluster in chain:
        h.update(int(cluster).to_bytes(4, "little", signed=False))
    return h.hexdigest()


def _identity_digest(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return _sha256(raw)


def _durable_media_identity(identity: dict[str, Any]) -> dict[str, Any]:
    """Return the long-lived media identity used by rollback provenance.

    Attachment-only fields such as PhysicalDriveN are intentionally excluded.
    They remain mandatory in the live transaction identity and its immediate
    pre-write revalidation, but may legitimately change after replug/reboot.
    """
    mode = identity.get("mode")
    if mode == "WINDOWS_PHYSICAL":
        durable = {
            "mode": mode,
            "disk_size": identity.get("disk_size"),
            "bus_type": str(identity.get("bus_type") or "").casefold() or None,
            "partition_style": str(identity.get("partition_style") or "").casefold() or None,
            "partition_number": identity.get("partition_number"),
            "partition_offset": identity.get("partition_offset"),
            "partition_size": identity.get("partition_size"),
            "logical_sector_size": identity.get("logical_sector_size"),
            "physical_sector_size": identity.get("physical_sector_size"),
            "serial_sha256": identity.get("serial_sha256"),
            "unique_id_sha256": identity.get("unique_id_sha256"),
            "partition_layout_sha256": identity.get("durable_partition_layout_sha256"),
            "volume_guid_root": str(identity.get("volume_guid_root") or "").casefold() or None,
        }
    elif mode == "TEST_NON_WINDOWS":
        # Private test-only destructive mode.  There is no production non-Windows
        # customisation path, so native inode/device identity is sufficient here.
        durable = {
            "mode": mode,
            "root": identity.get("root"),
            "st_dev": identity.get("st_dev"),
            "st_ino": identity.get("st_ino"),
        }
    else:
        raise CustomizationApplyError("Cannot derive durable media identity from an unsupported target identity.")
    durable["durable_identity_sha256"] = _identity_digest(durable)
    return durable


def _validate_durable_media_identity(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CustomizationApplyError(f"{label} durable media identity is required.")
    if "disk_number" in value:
        raise CustomizationApplyError(f"{label} durable media identity must not contain ephemeral disk_number.")
    supplied = _require_hex64(value.get("durable_identity_sha256"), f"{label} durable media identity digest")
    body = dict(value)
    body.pop("durable_identity_sha256", None)
    if _identity_digest(body) != supplied:
        raise CustomizationApplyError(f"{label} durable media identity digest does not match its fields.")
    return dict(value)


def _same_durable_media(recorded: dict[str, Any], current_attachment: dict[str, Any]) -> bool:
    try:
        current = _durable_media_identity(current_attachment)
    except CustomizationApplyError:
        return False
    return recorded == current


def _legacy_durable_identity(recorded_attachment: Any) -> dict[str, Any] | None:
    if not isinstance(recorded_attachment, dict):
        return None
    try:
        return _durable_media_identity(recorded_attachment)
    except CustomizationApplyError:
        return None


def _check_cancelled(cancelled: CancelledCallback | None) -> None:
    if cancelled and cancelled():
        raise CustomizationApplyError("Customisation transaction cancelled.")


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/"):
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)


def _zip_info_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (int(info.external_attr) >> 16) & 0xFFFF
    return bool(mode and stat.S_ISLNK(mode))


def _validate_archive_infos(infos: list[zipfile.ZipInfo], *, label: str) -> dict[str, zipfile.ZipInfo]:
    if not infos or len(infos) > _MAX_ARCHIVE_MEMBERS:
        raise CustomizationApplyError(f"{label} member count is invalid or exceeds the safety bound.")
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise CustomizationApplyError(f"{label} contains duplicate archive member names.")
    total_expanded = 0
    result: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        if not _safe_member_name(info.filename):
            raise CustomizationApplyError(f"Unsafe {label.lower()} member: {info.filename!r}")
        if _zip_info_is_symlink(info):
            raise CustomizationApplyError(f"{label} contains a symlink member: {info.filename!r}")
        if info.flag_bits & 0x1:
            raise CustomizationApplyError(f"Encrypted {label.lower()} members are unsupported.")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise CustomizationApplyError(f"Unsupported {label.lower()} compression method.")
        if info.file_size < 0 or info.file_size > _MAX_ARCHIVE_MEMBER_BYTES:
            raise CustomizationApplyError(f"{label} member exceeds expanded-size bound: {info.filename}")
        total_expanded += int(info.file_size)
        if total_expanded > _MAX_ARCHIVE_EXPANDED_BYTES:
            raise CustomizationApplyError(f"{label} total expanded size exceeds the safety bound.")
        if info.file_size and info.compress_size <= 0:
            raise CustomizationApplyError(f"{label} member has an invalid compression ratio: {info.filename}")
        if info.compress_size and info.file_size > info.compress_size * _MAX_COMPRESSION_RATIO:
            raise CustomizationApplyError(f"{label} member compression ratio exceeds the safety bound: {info.filename}")
        result[info.filename] = info
    manifest = result.get("manifest.json")
    if manifest is not None and manifest.file_size > _MAX_MANIFEST_BYTES:
        raise CustomizationApplyError(f"{label} manifest exceeds the safety bound.")
    return result


def _read_bounded_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, *, label: str) -> bytes:
    data = archive.read(info)
    if len(data) != int(info.file_size):
        raise CustomizationApplyError(f"{label} member expanded to an unexpected length: {info.filename}")
    return data


def _require_hex64(value, label: str) -> str:
    text = str(value or "").casefold()
    if not _HEX64_RE.fullmatch(text):
        raise CustomizationApplyError(f"{label} is not a valid SHA-256 digest.")
    return text


def _safe_target_relpath(value: str) -> str:
    text = value.replace("\\", "/").strip("/")
    if text.casefold() == "root.dat":
        return "ROOT.DAT"
    if _DAT_PATH_RE.fullmatch(text):
        code = text[:3]
        return f"{code}/{code}.DAT"
    raise CustomizationApplyError(f"Workspace requests an unsupported target file: {value!r}")


def _control_name_for(relpath: str) -> str:
    return "fileinfo.txt" if relpath.casefold() == "root.dat" else "filelist.txt"


class _DirectAccessor:
    """Read-only random-access adapter for an already-open mounted target file."""

    def __init__(self, handle):
        self.handle = handle
        self.bytes_read = 0

    def chain_for(self, entry: FatEntry):
        return ()

    def read_range(self, entry: FatEntry, offset: int, length: int, chain=None) -> bytes:
        if offset < 0 or length < 0 or offset + length > entry.size_bytes:
            raise CustomizationApplyError(
                f"Requested range {offset}+{length} lies outside {entry.path} ({entry.size_bytes} bytes)."
            )
        self.handle.seek(offset)
        data = self.handle.read(length)
        if len(data) != length:
            raise CustomizationApplyError(f"Short target read in {entry.path}: expected {length}, got {len(data)}.")
        self.bytes_read += len(data)
        return data


class _RollbackOverlayAccessor:
    """Virtual pre-hide view over an already-open customized target file.

    Reads current target bytes, then overlays only the original bytes carried by
    the rollback claim.  This is used to *prove* rollback semantics before any
    restore authority is granted; the rollback manifest itself is never treated
    as authorization.
    """

    def __init__(self, handle, overlays: tuple[tuple[int, bytes], ...]):
        self.handle = handle
        self.overlays = tuple(sorted(overlays, key=lambda item: item[0]))
        self.bytes_read = 0

    def chain_for(self, entry: FatEntry):
        return ()

    def read_range(self, entry: FatEntry, offset: int, length: int, chain=None) -> bytes:
        if offset < 0 or length < 0 or offset + length > entry.size_bytes:
            raise CustomizationApplyError(
                f"Requested rollback-authority range {offset}+{length} lies outside {entry.path}."
            )
        self.handle.seek(offset)
        raw = bytearray(self.handle.read(length))
        if len(raw) != length:
            raise CustomizationApplyError(
                f"Short target read while reconstructing rollback authority for {entry.path}."
            )
        end = offset + length
        for patch_offset, patch_data in self.overlays:
            patch_end = patch_offset + len(patch_data)
            overlap_start = max(offset, patch_offset)
            overlap_end = min(end, patch_end)
            if overlap_start >= overlap_end:
                continue
            raw_start = overlap_start - offset
            patch_start = overlap_start - patch_offset
            raw[raw_start:raw_start + (overlap_end - overlap_start)] = patch_data[
                patch_start:patch_start + (overlap_end - overlap_start)
            ]
        self.bytes_read += length
        return bytes(raw)


def _load_workspace(workspace_path) -> tuple[Path, str, dict, dict[str, bytes]]:
    path = Path(workspace_path).expanduser()
    try:
        st = path.lstat()
    except OSError as exc:
        raise CustomizationApplyError(f"Customisation workspace is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise CustomizationApplyError("Customisation workspace must be a regular non-symlink file.")
    if st.st_size <= 0 or st.st_size > _MAX_WORKSPACE_BYTES:
        raise CustomizationApplyError(f"Customisation workspace size is outside the bounded limit ({st.st_size:,} bytes).")
    path = path.resolve(strict=True)
    workspace_sha = _sha256_file(path)

    try:
        archive = zipfile.ZipFile(path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise CustomizationApplyError(f"Customisation workspace is not a valid ZIP container: {exc}") from exc

    with archive:
        infos = _validate_archive_infos(archive.infolist(), label="Customisation workspace")
        if "manifest.json" not in infos:
            raise CustomizationApplyError("Customisation workspace has no manifest.json.")
        try:
            manifest = json.loads(_read_bounded_member(archive, infos["manifest.json"], label="Customisation workspace").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CustomizationApplyError(f"Customisation manifest is unreadable: {exc}") from exc
        if not isinstance(manifest, dict) or manifest.get("schema") != _WORKSPACE_SCHEMA:
            raise CustomizationApplyError("Unsupported customisation workspace schema.")
        if manifest.get("action") != "HIDE_ROM_FROM_LAUNCHER":
            raise CustomizationApplyError("Only HIDE_ROM_FROM_LAUNCHER workspaces are accepted by this apply path.")
        safety = manifest.get("safety") or {}
        if safety.get("source_writes_performed") is not False or safety.get("game_stick_write_performed") is not False:
            raise CustomizationApplyError("Workspace provenance does not describe a pristine host-side overlay.")

        patched = manifest.get("patched_files")
        if not isinstance(patched, list) or not patched or len(patched) > 32:
            raise CustomizationApplyError("Workspace patched_files list is empty or exceeds the safety bound.")

        referenced: set[str] = set()
        total_patch = 0
        total_ranges = 0
        normalized_files: list[dict] = []
        for raw_item in patched:
            if not isinstance(raw_item, dict):
                raise CustomizationApplyError("Workspace patched_files contains a non-object entry.")
            relpath = _safe_target_relpath(str(raw_item.get("path") or ""))
            file_size = raw_item.get("file_size_bytes")
            cluster_count = raw_item.get("cluster_count")
            if not isinstance(file_size, int) or file_size <= 0:
                raise CustomizationApplyError(f"Workspace file size is invalid for {relpath}.")
            if not isinstance(cluster_count, int) or cluster_count <= 0:
                raise CustomizationApplyError(f"Workspace cluster count is invalid for {relpath}.")
            chain_sha = _require_hex64(raw_item.get("target_chain_sha256"), f"Workspace chain digest for {relpath}")
            source_control_sha = _require_hex64(raw_item.get("source_control_sha256"), f"Workspace source control digest for {relpath}")
            replacement_control_sha = _require_hex64(
                raw_item.get("replacement_control_sha256"), f"Workspace replacement control digest for {relpath}"
            )
            raw_patches = raw_item.get("patches")
            if not isinstance(raw_patches, list) or not raw_patches:
                raise CustomizationApplyError(f"Workspace contains no patch ranges for {relpath}.")
            ranges: list[dict] = []
            prior_end = -1
            for raw_patch in sorted(raw_patches, key=lambda item: int(item.get("offset", -1)) if isinstance(item, dict) else -1):
                if not isinstance(raw_patch, dict):
                    raise CustomizationApplyError(f"Workspace has an invalid patch range for {relpath}.")
                offset = raw_patch.get("offset")
                length = raw_patch.get("length")
                member = str(raw_patch.get("payload_member") or "")
                if not isinstance(offset, int) or not isinstance(length, int) or offset < 0 or length <= 0:
                    raise CustomizationApplyError(f"Workspace patch range is invalid for {relpath}.")
                if offset + length > file_size:
                    raise CustomizationApplyError(f"Workspace patch range exceeds {relpath}.")
                if offset < prior_end:
                    raise CustomizationApplyError(f"Workspace patch ranges overlap in {relpath}.")
                prior_end = offset + length
                if not _safe_member_name(member) or member == "manifest.json":
                    raise CustomizationApplyError(f"Workspace patch member is unsafe for {relpath}.")
                original_sha = _require_hex64(raw_patch.get("original_sha256"), f"Workspace original patch digest for {relpath}")
                replacement_sha = _require_hex64(raw_patch.get("replacement_sha256"), f"Workspace replacement patch digest for {relpath}")
                info = infos.get(member)
                if info is None:
                    raise CustomizationApplyError(f"Workspace patch member is missing: {member}")
                payload = _read_bounded_member(archive, info, label="Customisation workspace")
                if len(payload) != length or _sha256(payload) != replacement_sha:
                    raise CustomizationApplyError(f"Workspace patch payload failed length/SHA verification: {member}")
                referenced.add(member)
                total_patch += length
                total_ranges += 1
                if total_patch > _MAX_PATCH_BYTES or total_ranges > _MAX_PATCH_RANGES:
                    raise CustomizationApplyError("Workspace patch payload exceeds bounded apply limits.")
                ranges.append({
                    "offset": offset,
                    "length": length,
                    "payload_member": member,
                    "original_sha256": original_sha,
                    "replacement_sha256": replacement_sha,
                    "payload": payload,
                })
            normalized_files.append({
                "path": relpath,
                "file_size_bytes": file_size,
                "cluster_count": cluster_count,
                "target_chain_sha256": chain_sha,
                "source_control_sha256": source_control_sha,
                "replacement_control_sha256": replacement_control_sha,
                "patches": ranges,
            })

        extras = set(infos) - {"manifest.json"} - referenced
        if extras:
            raise CustomizationApplyError(
                "Customisation workspace contains unreferenced payload members: " + ", ".join(sorted(extras))
            )
        normalized = dict(manifest)
        normalized["patched_files"] = normalized_files
        payloads = {patch["payload_member"]: patch["payload"] for item in normalized_files for patch in item["patches"]}
        return path, workspace_sha, normalized, payloads


def _source_entries(handle, geometry, manifest: dict) -> dict[str, tuple[FatEntry, tuple[int, ...]]]:
    catalogues, root_entry = _locate_catalogues(handle, geometry)
    accessor = _FatAccessor(handle, geometry)
    out: dict[str, tuple[FatEntry, tuple[int, ...]]] = {}
    for item in manifest["patched_files"]:
        rel = item["path"]
        entry = root_entry if rel.casefold() == "root.dat" else catalogues.get(rel[:3])
        if entry is None:
            raise CustomizationApplyError(f"Source image no longer contains required file {rel}.")
        out[rel] = (entry, accessor.chain_for(entry))
    return out


def _verify_workspace_against_source_image(source_image, manifest: dict, *, progress=None) -> Path:
    image = _validate_image(source_image)
    source_meta = manifest.get("source_image") or {}
    expected_size = source_meta.get("size_bytes")
    if not isinstance(expected_size, int) or expected_size <= 0:
        raise CustomizationApplyError("Workspace source-image size provenance is missing.")
    if image.stat().st_size != expected_size:
        raise CustomizationApplyError(
            f"Source image size mismatch: workspace expects {expected_size:,}, selected image is {image.stat().st_size:,}."
        )
    if progress:
        progress("Revalidating canonical chain/control provenance against the healthy source image...")
    with image.open("rb", buffering=0) as handle:
        geometry = _parse_geometry(handle, image.stat().st_size)
        entries = _source_entries(handle, geometry, manifest)
        accessor = _FatAccessor(handle, geometry)
        for item in manifest["patched_files"]:
            rel = item["path"]
            entry, chain = entries[rel]
            if entry.size_bytes != item["file_size_bytes"]:
                raise CustomizationApplyError(f"Source image file-size mismatch for {rel}.")
            if len(chain) != item["cluster_count"] or _chain_sha256(chain) != item["target_chain_sha256"]:
                raise CustomizationApplyError(f"Source image FAT-chain fingerprint mismatch for {rel}.")
            layout = _read_control_layout(accessor, entry, _control_name_for(rel))
            if _sha256(layout.payload) != item["source_control_sha256"]:
                raise CustomizationApplyError(f"Source image control hash mismatch for {rel}.")
            for patch in item["patches"]:
                original = accessor.read_range(entry, patch["offset"], patch["length"], chain)
                if _sha256(original) != patch["original_sha256"]:
                    raise CustomizationApplyError(f"Source image original patch bytes mismatch for {rel}.")
    return image


def _workspace_authority_signature(manifest: dict) -> tuple:
    rom = manifest.get("rom") or {}
    source_meta = manifest.get("source_image") or {}
    files = []
    for item in manifest.get("patched_files") or []:
        patches = tuple(
            (
                int(patch["offset"]), int(patch["length"]), str(patch["payload_member"]),
                str(patch["original_sha256"]), str(patch["replacement_sha256"]), bytes(patch["payload"]),
            )
            for patch in item.get("patches") or []
        )
        files.append((
            str(item["path"]), int(item["file_size_bytes"]), int(item["cluster_count"]),
            str(item["target_chain_sha256"]), str(item["source_control_sha256"]),
            str(item["replacement_control_sha256"]), patches,
        ))
    return (
        str(manifest.get("action") or ""),
        str(rom.get("catalogue_code") or ""),
        str(rom.get("filename") or ""),
        int(rom.get("catalogue_records_removed") or 0),
        int(rom.get("root_records_removed") or 0),
        bool(rom.get("physical_rom_file_removed")),
        int(source_meta.get("size_bytes") or 0),
        int(source_meta.get("partition_offset_bytes") or 0),
        tuple(files),
    )


def _verify_workspace_semantic_authority(source_image, manifest: dict, *, progress=None) -> Path:
    """Re-derive the exact authorized hide from source + ROM identity and compare byte-for-byte."""
    rom = manifest.get("rom") or {}
    code = str(rom.get("catalogue_code") or "")
    filename = str(rom.get("filename") or "")
    if not re.fullmatch(r"\d{3}", code):
        raise CustomizationApplyError("Workspace ROM catalogue code is invalid.")
    if not filename or PurePosixPath(filename.replace("\\", "/")).name != filename:
        raise CustomizationApplyError("Workspace ROM filename is not a canonical basename.")
    patched = manifest.get("patched_files") or []
    expected_paths = [f"{code}/{code}.DAT", "ROOT.DAT"]
    if [item.get("path") for item in patched] != expected_paths or len(patched) != 2:
        raise CustomizationApplyError("Workspace write topology is not the canonical two-file hide operation.")
    if any(len(item.get("patches") or []) != 2 for item in patched):
        raise CustomizationApplyError("Workspace write topology is not the canonical four-range hide operation.")

    if progress:
        progress("Re-deriving canonical hide authority from healthy image + exact ROM identity...")
    image = _validate_image(source_image)
    with tempfile.TemporaryDirectory(prefix="gamestick-authority-") as temp_dir:
        canonical_path = Path(temp_dir) / "canonical.gscustom"
        try:
            build_hide_rom_workspace(image, f"{code}:{filename}", canonical_path)
        except RomCustomizationError as exc:
            raise CustomizationApplyError(f"Canonical hide derivation failed: {exc}") from exc
        _cp, _cs, canonical, _payloads = _load_workspace(canonical_path)
    if _workspace_authority_signature(manifest) != _workspace_authority_signature(canonical):
        raise CustomizationApplyError(
            "Workspace patch authority does not exactly equal the independently derived canonical hide operation."
        )
    return image


def _durable_partition_layout_sha256(mapping) -> str:
    """Hash partition geometry without transient drive-letter attachments."""
    parts = []
    for part in sorted(
        mapping.partitions,
        key=lambda p: (
            p.partition_number if p.partition_number is not None else 2**31,
            p.offset if p.offset is not None else 2**63,
        ),
    ):
        parts.append({
            "partition_number": part.partition_number,
            "offset": part.offset,
            "size": part.size,
            "partition_type": part.partition_type,
            "gpt_type": part.gpt_type,
            "mbr_type": part.mbr_type,
        })
    return _sha256(json.dumps(parts, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _capture_target_identity(
    root: Path,
    *,
    host_system: Optional[str],
    _test_allow_non_windows: bool = False,
    _mapping_resolver=None,
    _volume_root_resolver=None,
) -> dict[str, Any]:
    system = host_system or platform.system()
    if system != "Windows":
        if not _test_allow_non_windows:
            raise CustomizationApplyError("Destructive TEST/CLONE customisation is currently supported on Windows only.")
        st = root.stat()
        return {"mode": "TEST_NON_WINDOWS", "root": str(root), "st_dev": int(st.st_dev), "st_ino": int(st.st_ino)}

    from .imaging import _hash_identifier, _identity_sha256_from_values, _partition_layout_sha256
    from .probe import _physical_mapping
    from .safety import _default_windows_volume_root_resolver

    resolver = _mapping_resolver or _physical_mapping
    mapping = resolver(root)
    if mapping.mapping_error:
        raise CustomizationApplyError(f"Target physical mapping is not trustworthy: {mapping.mapping_error}")
    if mapping.disk_number is None or mapping.disk_size is None:
        raise CustomizationApplyError("Target physical disk identity is incomplete.")
    if mapping.is_boot is not False or mapping.is_system is not False:
        raise CustomizationApplyError("Refusing target: boot/system safety flags are true or unknown.")
    if mapping.is_offline is True:
        raise CustomizationApplyError("Refusing target: Windows reports the disk as offline.")
    bus = (mapping.bus_type or "").strip().casefold()
    dtype = (mapping.drive_type or "").strip().casefold()
    if bus not in _ALLOWED_EXTERNAL_BUSES and dtype != "removable":
        raise CustomizationApplyError(
            f"Refusing target: disk is not positively identified as removable USB/SD/MMC "
            f"(BusType={mapping.bus_type!r}, DriveType={mapping.drive_type!r})."
        )

    drive = root.drive
    if not drive or drive.startswith("\\\\") or root != Path(root.anchor):
        raise CustomizationApplyError("Target must be the root of a local mounted drive, for example H:\\.")
    system_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/").casefold()
    if drive.rstrip("\\/").casefold() == system_drive:
        raise CustomizationApplyError("Refusing to modify the Windows system drive.")

    volume_resolver = _volume_root_resolver or _default_windows_volume_root_resolver
    try:
        volume_root = str(volume_resolver(drive[0].upper()))
    except Exception as exc:
        raise CustomizationApplyError(f"Could not bind target to a stable Windows volume identity: {exc}") from exc

    layout_sha = _partition_layout_sha256(mapping)
    durable_layout_sha = _durable_partition_layout_sha256(mapping)
    serial_sha = _hash_identifier(mapping.serial_number)
    unique_sha = _hash_identifier(mapping.disk_unique_id)
    identity_sha = _identity_sha256_from_values(
        disk_number=int(mapping.disk_number), disk_size=int(mapping.disk_size), bus_type=mapping.bus_type,
        partition_style=mapping.partition_style, serial_sha256=serial_sha, unique_id_sha256=unique_sha,
        partition_number=mapping.partition_number, partition_offset=mapping.partition_offset,
        partition_size=mapping.partition_size, logical_sector_size=mapping.logical_sector_size,
        physical_sector_size=mapping.physical_sector_size, partition_layout_sha256=layout_sha,
    )
    return {
        "mode": "WINDOWS_PHYSICAL",
        "disk_number": int(mapping.disk_number),
        "disk_size": int(mapping.disk_size),
        "bus_type": mapping.bus_type,
        "drive_type": mapping.drive_type,
        "partition_style": mapping.partition_style,
        "partition_number": mapping.partition_number,
        "partition_offset": mapping.partition_offset,
        "partition_size": mapping.partition_size,
        "logical_sector_size": mapping.logical_sector_size,
        "physical_sector_size": mapping.physical_sector_size,
        "serial_sha256": serial_sha,
        "unique_id_sha256": unique_sha,
        "partition_layout_sha256": layout_sha,
        "durable_partition_layout_sha256": durable_layout_sha,
        "volume_guid_root": volume_root,
        "identity_sha256": identity_sha,
    }


def _normalize_target_root(
    target_root,
    *,
    host_system: Optional[str],
    _test_allow_non_windows: bool = False,
    _mapping_resolver=None,
    _volume_root_resolver=None,
) -> tuple[Path, dict[str, Any]]:
    root = Path(target_root).expanduser()
    try:
        st = lstat_non_reparse(root)
        if not stat.S_ISDIR(st.st_mode):
            raise CustomizationApplyError("Target GameStick volume must be a real directory.")
        root = assert_contained_non_reparse(root, root)
    except (OSError, ForensicPathError) as exc:
        raise CustomizationApplyError(f"Target GameStick volume is unavailable or reparse-backed: {root}: {exc}") from exc
    for marker in ("ROOT.DAT", "CUBEGM", "Roms"):
        if not (root / marker).exists():
            raise CustomizationApplyError(f"Target does not look like the expected GameStick layout: missing {marker}.")
    identity = _capture_target_identity(
        root, host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
        _mapping_resolver=_mapping_resolver, _volume_root_resolver=_volume_root_resolver,
    )
    return root, identity


def _revalidate_target_identity(
    root: Path,
    expected: dict[str, Any],
    *,
    host_system: Optional[str],
    _test_allow_non_windows: bool = False,
    _mapping_resolver=None,
    _volume_root_resolver=None,
) -> None:
    current = _capture_target_identity(
        root, host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
        _mapping_resolver=_mapping_resolver, _volume_root_resolver=_volume_root_resolver,
    )
    if current != expected:
        raise CustomizationApplyError(
            "Target physical identity changed between preflight and write authority; customisation refused."
        )


def _target_file(root: Path, relpath: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relpath).parts)
    try:
        resolved = assert_contained_non_reparse(root, candidate)
        st = lstat_non_reparse(resolved)
    except (OSError, ForensicPathError) as exc:
        raise CustomizationApplyError(f"Target file is unavailable, reparse-backed, or escapes the selected volume: {relpath}: {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise CustomizationApplyError(f"Target file must be a regular non-reparse file: {relpath}")
    return resolved


def _default_windows_handle_path_resolver(handle) -> str:
    """Return the stable Volume-GUID path for an already-open Windows handle."""
    if platform.system() != "Windows":
        raise RuntimeError("Windows handle binding is only available on Windows")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    FILE_NAME_NORMALIZED = 0x0
    VOLUME_NAME_GUID = 0x1
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = kernel32.GetFinalPathNameByHandleW
    fn.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    fn.restype = wintypes.DWORD
    os_handle = msvcrt.get_osfhandle(handle.fileno())
    if os_handle == -1:
        raise OSError("Could not obtain Windows OS handle for target file")
    size = 1024
    for _ in range(3):
        buf = ctypes.create_unicode_buffer(size)
        result = fn(wintypes.HANDLE(os_handle), buf, size, FILE_NAME_NORMALIZED | VOLUME_NAME_GUID)
        if result == 0:
            error = ctypes.get_last_error()
            raise OSError(error, "GetFinalPathNameByHandleW failed")
        if result < size:
            return buf.value
        size = int(result) + 1
    raise OSError("GetFinalPathNameByHandleW returned an unexpectedly long path")


def _default_test_handle_path_resolver(handle) -> str:
    # Test-only production-parity binding for Linux CI.  Destructive non-Windows
    # operation is otherwise disabled.
    fd_path = Path(f"/proc/self/fd/{handle.fileno()}")
    return str(fd_path.resolve(strict=True))


def _normalise_bound_path(value: str) -> str:
    return value.replace("/", "\\").rstrip("\\").casefold()


def _expected_handle_path(root: Path, identity: dict[str, Any], relpath: str, *, system: str) -> str:
    if system == "Windows":
        volume_root = str(identity.get("volume_guid_root") or "")
        if not volume_root.startswith("\\\\?\\Volume{") or not volume_root.endswith("\\"):
            raise CustomizationApplyError("Verified target identity has no stable Volume-GUID root.")
        return volume_root + relpath.replace("/", "\\")
    return str(root.joinpath(*PurePosixPath(relpath).parts).resolve(strict=True))


def _verify_open_handle_binding(
    handle,
    *,
    root: Path,
    identity: dict[str, Any],
    relpath: str,
    host_system: Optional[str],
    _test_allow_non_windows: bool = False,
    _handle_path_resolver=None,
) -> None:
    """Prove this exact open handle belongs to the verified volume and file.

    Revalidating H:\\ proves the current pathname mapping only.  This separately
    binds each already-open descriptor so a transient mount/drive-letter swap
    cannot redirect one half of the two-file launcher transaction.
    """
    system = host_system or platform.system()
    if system == "Windows":
        resolver = _handle_path_resolver or _default_windows_handle_path_resolver
    else:
        if not _test_allow_non_windows:
            raise CustomizationApplyError("Open-handle binding is production-supported on Windows only.")
        resolver = _handle_path_resolver or _default_test_handle_path_resolver
    try:
        actual = str(resolver(handle))
    except Exception as exc:
        raise CustomizationApplyError(f"Could not bind opened target handle for {relpath}: {type(exc).__name__}: {exc}") from exc
    expected = _expected_handle_path(root, identity, relpath, system=system)
    if _normalise_bound_path(actual) != _normalise_bound_path(expected):
        raise CustomizationApplyError(
            f"Opened writable handle is not bound to the verified target volume/path for {relpath}: "
            f"expected {expected!r}, got {actual!r}."
        )


def _verify_direct_target_handle(handle, item: dict, *, expected_replacement: bool) -> None:
    st = os.fstat(handle.fileno())
    if st.st_size != item["file_size_bytes"]:
        raise CustomizationApplyError(
            f"Target file-size mismatch for {item['path']}: expected {item['file_size_bytes']:,}, got {st.st_size:,}."
        )
    entry = FatEntry(path=item["path"], size_bytes=st.st_size, start_cluster=2, is_directory=False)
    accessor = _DirectAccessor(handle)
    try:
        layout = _read_control_layout(accessor, entry, _control_name_for(item["path"]))
    except RomCustomizationError as exc:
        raise CustomizationApplyError(f"Target control validation failed for {item['path']}: {exc}") from exc
    expected_control = item["replacement_control_sha256"] if expected_replacement else item["source_control_sha256"]
    if _sha256(layout.payload) != expected_control:
        which = "replacement" if expected_replacement else "source"
        raise CustomizationApplyError(f"Target {which} control hash mismatch for {item['path']}.")
    for patch in item["patches"]:
        handle.seek(patch["offset"])
        raw = handle.read(patch["length"])
        if len(raw) != patch["length"]:
            raise CustomizationApplyError(f"Short target read while validating {item['path']}.")
        expected = patch["replacement_sha256"] if expected_replacement else patch["original_sha256"]
        if _sha256(raw) != expected:
            which = "replacement" if expected_replacement else "original"
            raise CustomizationApplyError(f"Target {which} patch bytes mismatch for {item['path']}.")


def _verify_direct_target_file(path: Path, item: dict, *, expected_replacement: bool) -> None:
    with path.open("rb", buffering=0) as handle:
        _verify_direct_target_handle(handle, item, expected_replacement=expected_replacement)


def _semantic_candidate_from_controls(original_payload: bytes, current_payload: bytes) -> str:
    """Return the one exact ROM filename whose canonical removal yields current_payload."""
    original_names = _rom_names(original_payload)
    current_names = _rom_names(current_payload)
    original_counts = Counter(name.casefold() for name in original_names)
    current_counts = Counter(name.casefold() for name in current_names)
    changed = [
        folded for folded in sorted(set(original_counts) | set(current_counts))
        if original_counts[folded] != current_counts[folded]
    ]
    if len(changed) != 1:
        raise CustomizationApplyError(
            "Rollback semantic authority failed: catalogue transition is not exactly one ROM identity."
        )
    folded = changed[0]
    if original_counts[folded] < 1 or current_counts[folded] != 0:
        raise CustomizationApplyError(
            "Rollback semantic authority failed: transition is not a complete canonical hide of one ROM."
        )
    filename = next((name for name in original_names if name.casefold() == folded), None)
    if not filename:
        raise CustomizationApplyError("Rollback semantic authority could not recover the hidden ROM filename.")
    filtered, removed = _filter_filelist(original_payload, filename)
    if removed < 1 or filtered != current_payload:
        raise CustomizationApplyError(
            "Rollback semantic authority failed: current catalogue is not the canonical hide result."
        )
    return filename


def _verify_rollback_semantic_authority(
    handles: dict[str, Any],
    manifest: dict,
    payloads: dict[str, bytes],
    *,
    transaction_identity: dict[str, Any],
    allow_legacy_recovery: bool,
    expected_rom: tuple[str, str] | None = None,
) -> tuple[str, str]:
    """Independently prove a rollback is exactly the inverse of one canonical hide.

    The archive supplies evidence bytes only.  Authority is derived from the live
    customized controls plus a virtual reconstruction of their pre-hide state.
    """
    schema = manifest.get("schema")
    legacy = schema in (_ROLLBACK_SCHEMA_V1, _ROLLBACK_SCHEMA_V2)
    if schema not in (_ROLLBACK_SCHEMA, _ROLLBACK_SCHEMA_V2, _ROLLBACK_SCHEMA_V1):
        raise CustomizationApplyError("Unsupported rollback archive schema.")
    if legacy and not allow_legacy_recovery:
        raise CustomizationApplyError(
            "Legacy rollback-v1/v2 is recovery-only. Explicitly enable legacy recovery; semantic inverse proof still applies."
        )

    patched = manifest.get("patched_files") or []
    if len(patched) != 2 or any(len(item.get("patches") or []) != 2 for item in patched):
        raise CustomizationApplyError(
            "Rollback semantic authority failed: canonical hide inverse requires exactly two files and four ranges."
        )
    roots = [item for item in patched if item.get("path", "").casefold() == "root.dat"]
    catalogues = [item for item in patched if item.get("path", "").casefold() != "root.dat"]
    if len(roots) != 1 or len(catalogues) != 1:
        raise CustomizationApplyError(
            "Rollback semantic authority failed: expected one numbered DAT plus ROOT.DAT."
        )
    catalogue_item = catalogues[0]
    root_item = roots[0]
    match = _DAT_PATH_RE.fullmatch(str(catalogue_item.get("path") or ""))
    if not match:
        raise CustomizationApplyError("Rollback semantic authority failed: numbered catalogue path is invalid.")
    code = match.group(1)
    if set(handles) != {catalogue_item["path"], root_item["path"]}:
        raise CustomizationApplyError("Rollback semantic authority failed: bound target topology is not canonical.")

    if not legacy:
        if manifest.get("action") != "UNDO_CANONICAL_HIDE_ROM":
            raise CustomizationApplyError("Rollback-v3 action provenance is missing or invalid.")
        _require_hex64(manifest.get("workspace_sha256"), "Rollback-v3 workspace provenance")
        recorded_durable = _validate_durable_media_identity(
            manifest.get("durable_media_identity"), label="Rollback-v3"
        )
        if not _same_durable_media(recorded_durable, transaction_identity):
            raise CustomizationApplyError("Rollback-v3 durable media provenance does not match the selected TEST/CLONE.")
        declared_rom = manifest.get("rom")
        if not isinstance(declared_rom, dict):
            raise CustomizationApplyError("Rollback-v3 ROM provenance is missing.")
        declared_code = str(declared_rom.get("catalogue_code") or "")
        declared_name = str(declared_rom.get("filename") or "")
        if declared_code != code or not declared_name or PurePosixPath(declared_name.replace("\\", "/")).name != declared_name:
            raise CustomizationApplyError("Rollback-v3 ROM provenance is not canonical.")
    else:
        # Legacy v1/v2 remains explicit recovery-only.  When it carries an old
        # attachment identity, compare its *durable* portion so normal Windows
        # PhysicalDriveN re-enumeration does not destroy recovery availability.
        old_attachment = manifest.get("target_identity")
        old_durable = _legacy_durable_identity(old_attachment)
        if old_durable is not None and not _same_durable_media(old_durable, transaction_identity):
            raise CustomizationApplyError("Legacy rollback durable media provenance does not match this TEST/CLONE.")
        declared_rom = manifest.get("rom") if isinstance(manifest.get("rom"), dict) else {}
        declared_name = str(declared_rom.get("filename") or "")

    reconstructed: dict[str, tuple[_ControlLayout, _ControlLayout, _RollbackOverlayAccessor]] = {}
    for item in (catalogue_item, root_item):
        handle = handles[item["path"]]
        st = os.fstat(handle.fileno())
        if st.st_size != item["file_size_bytes"]:
            raise CustomizationApplyError(f"Rollback target size changed for {item['path']}.")
        entry = FatEntry(path=item["path"], size_bytes=st.st_size, start_cluster=2, is_directory=False)
        current_accessor = _DirectAccessor(handle)
        try:
            current_layout = _read_control_layout(current_accessor, entry, _control_name_for(item["path"]))
        except RomCustomizationError as exc:
            raise CustomizationApplyError(
                f"Rollback semantic authority cannot parse current control for {item['path']}: {exc}"
            ) from exc
        overlays = tuple(
            (patch["offset"], payloads[patch["payload_member"]]) for patch in item["patches"]
        )
        original_accessor = _RollbackOverlayAccessor(handle, overlays)
        try:
            original_layout = _read_control_layout(original_accessor, entry, _control_name_for(item["path"]))
        except RomCustomizationError as exc:
            raise CustomizationApplyError(
                f"Rollback semantic authority cannot reconstruct original control for {item['path']}: {exc}"
            ) from exc
        if _sha256(original_layout.payload) != item["source_control_sha256"]:
            raise CustomizationApplyError(f"Rollback reconstructed source-control hash mismatch for {item['path']}.")
        if _sha256(current_layout.payload) != item["replacement_control_sha256"]:
            raise CustomizationApplyError(f"Rollback current replacement-control hash mismatch for {item['path']}.")
        reconstructed[item["path"]] = (original_layout, current_layout, original_accessor)

    original_cat, current_cat, original_cat_accessor = reconstructed[catalogue_item["path"]]
    filename = _semantic_candidate_from_controls(original_cat.payload, current_cat.payload)

    original_root, current_root, original_root_accessor = reconstructed[root_item["path"]]
    expected_root, root_removed = _filter_fileinfo(original_root.payload, code, filename)
    if root_removed < 1 or expected_root != current_root.payload:
        raise CustomizationApplyError(
            "Rollback semantic authority failed: ROOT.DAT is not the matching canonical hide result."
        )

    if not legacy and str((manifest.get("rom") or {}).get("filename") or "") != filename:
        raise CustomizationApplyError(
            "Rollback-v3 declared ROM identity does not match the independently reconstructed hide operation."
        )
    if declared_name and declared_name.casefold() != filename.casefold():
        raise CustomizationApplyError(
            "Rollback archive ROM identity does not match the independently reconstructed hide operation."
        )
    if expected_rom is not None:
        expected_code, expected_name = expected_rom
        if expected_code != code or expected_name.casefold() != filename.casefold():
            raise CustomizationApplyError("Requested ROM identity does not match rollback semantic authority.")

    # Rebuild the canonical fixed-slot hide from the reconstructed pre-hide controls.
    for item, original_layout, current_layout, original_accessor in (
        (catalogue_item, original_cat, current_cat, original_cat_accessor),
        (root_item, original_root, current_root, original_root_accessor),
    ):
        try:
            expected_patches = _build_same_slot_patches(original_layout, current_layout.payload)
        except RomCustomizationError as exc:
            raise CustomizationApplyError(
                f"Rollback semantic authority could not derive canonical ranges for {item['path']}: {exc}"
            ) from exc
        actual = sorted(item["patches"], key=lambda patch: patch["offset"])
        expected = sorted(expected_patches, key=lambda patch: patch[0])
        if len(actual) != len(expected):
            raise CustomizationApplyError("Rollback range topology is not canonical.")
        entry = original_layout.entry
        for claim, (expected_offset, expected_replacement) in zip(actual, expected):
            if claim["offset"] != expected_offset or claim["length"] != len(expected_replacement):
                raise CustomizationApplyError(
                    f"Rollback range topology does not match canonical hide bytes for {item['path']}."
                )
            original_bytes = original_accessor.read_range(entry, expected_offset, len(expected_replacement))
            archive_original = payloads[claim["payload_member"]]
            if archive_original != original_bytes or _sha256(original_bytes) != claim["original_sha256"]:
                raise CustomizationApplyError(
                    f"Rollback original bytes do not match the canonical pre-hide state for {item['path']}."
                )
            handle = handles[item["path"]]
            handle.seek(expected_offset)
            current_bytes = handle.read(len(expected_replacement))
            if current_bytes != expected_replacement or _sha256(current_bytes) != claim["replacement_sha256"]:
                raise CustomizationApplyError(
                    f"Rollback replacement bytes do not match the canonical hide state for {item['path']}."
                )

    return code, filename


def _safe_host_output(
    path_like,
    target_root: Path,
    suffix: str,
    *,
    overwrite: bool,
    target_identity: dict[str, Any],
    host_system: Optional[str],
    _destination_disk_resolver=None,
    _volume_root_resolver=None,
    _volume_disk_resolver=None,
):
    from .safety import assert_output_outside_source_disk, bind_output_volume

    system = host_system or platform.system()
    requested = Path(path_like).expanduser()
    if not str(requested).casefold().endswith(suffix.casefold()):
        raise CustomizationApplyError(f"Output must end in {suffix}.")
    source_disk = target_identity.get("disk_number") if target_identity.get("mode") == "WINDOWS_PHYSICAL" else None
    try:
        path = assert_output_outside_source_disk(
            requested, target_root, source_disk_number=source_disk, host_system=system,
            destination_disk_resolver=_destination_disk_resolver,
        )
    except ValueError as exc:
        raise CustomizationApplyError(str(exc)) from exc
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise CustomizationApplyError("Rollback/evidence output parent is not a directory.")
    if path.exists():
        if path.is_dir() or path.is_symlink():
            raise CustomizationApplyError("Refusing to replace a directory or symlink output.")
        if not overwrite:
            raise CustomizationApplyError(f"Output already exists: {path}")

    binding = None
    if system == "Windows":
        try:
            binding = bind_output_volume(
                path, target_root, source_disk_number=int(source_disk), host_system=system,
                destination_disk_resolver=_destination_disk_resolver,
                volume_root_resolver=_volume_root_resolver,
                volume_disk_resolver=_volume_disk_resolver,
            )
        except ValueError as exc:
            raise CustomizationApplyError(str(exc)) from exc
        if binding is None:
            raise CustomizationApplyError("Could not bind output to a stable verified host volume.")
    return path, binding


def expected_confirmation(target_root) -> str:
    root = Path(target_root)
    drive = root.drive.upper() if root.drive else root.name
    return f"APPLY TO {drive or str(root)}"


def _write_rollback_archive(
    path: Path,
    workspace_sha: str,
    target_root: Path,
    target_identity: dict[str, Any],
    manifest: dict,
    originals: dict,
    *,
    overwrite: bool,
    binding=None,
    host_system: Optional[str] = None,
    _destination_disk_resolver=None,
    _volume_root_resolver=None,
    _volume_disk_resolver=None,
) -> str:
    rollback_manifest = {
        "schema": _ROLLBACK_SCHEMA,
        "created_at_utc": _utc_now(),
        "action": "UNDO_CANONICAL_HIDE_ROM",
        "workspace_action": "HIDE_ROM_FROM_LAUNCHER",
        "workspace_sha256": workspace_sha,
        "target_root_at_apply": str(target_root),
        "attachment_identity_at_apply": target_identity,
        "durable_media_identity": _durable_media_identity(target_identity),
        "rom": manifest.get("rom") or {},
        "canonical_topology": {"target_file_count": 2, "patch_range_count": 4},
        "patched_files": [],
    }
    payloads: dict[str, bytes] = {}
    for file_index, item in enumerate(manifest["patched_files"]):
        ranges = []
        for patch_index, patch in enumerate(item["patches"]):
            key = (item["path"], patch["offset"], patch["length"])
            original = originals[key]
            member = f"originals/{file_index:02d}/{patch_index:02d}.bin"
            payloads[member] = original
            ranges.append({
                "offset": patch["offset"], "length": patch["length"], "payload_member": member,
                "original_sha256": patch["original_sha256"], "replacement_sha256": patch["replacement_sha256"],
            })
        rollback_manifest["patched_files"].append({
            "path": item["path"], "file_size_bytes": item["file_size_bytes"],
            "source_control_sha256": item["source_control_sha256"],
            "replacement_control_sha256": item["replacement_control_sha256"], "patches": ranges,
        })

    from .safety import bind_output_volume, secure_stage_on_bound_volume

    if binding is not None:
        fd, temp = secure_stage_on_bound_volume(binding, suffix=".rollback.partial")
    else:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        temp = Path(temp_name)
    raw = None
    try:
        raw = os.fdopen(fd, "w+b", buffering=0)
        with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
            archive.writestr("manifest.json", json.dumps(rollback_manifest, indent=2, sort_keys=True) + "\n")
            for member, payload in sorted(payloads.items()):
                archive.writestr(member, payload)
        raw.flush()
        os.fsync(raw.fileno())
        raw.close()
        raw = None

        if binding is not None:
            current = bind_output_volume(
                path, target_root, source_disk_number=int(target_identity["disk_number"]),
                host_system=host_system or platform.system(), destination_disk_resolver=_destination_disk_resolver,
                volume_root_resolver=_volume_root_resolver, volume_disk_resolver=_volume_disk_resolver,
            )
            if (
                current is None
                or current.destination_disk_number != binding.destination_disk_number
                or current.volume_root.casefold() != binding.volume_root.casefold()
                or current.final_path != binding.final_path
            ):
                raise CustomizationApplyError("Rollback destination volume identity changed before commit.")
        if path.exists() and not overwrite:
            raise CustomizationApplyError(f"Rollback output appeared before commit: {path}")
        if path.exists() and (path.is_dir() or path.is_symlink()):
            raise CustomizationApplyError("Refusing to replace a directory or symlink rollback output.")
        os.replace(temp, path)
    except Exception:
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass
        temp.unlink(missing_ok=True)
        raise
    return _sha256_file(path)


def _reserve_receipt(
    path: Path,
    *,
    overwrite: bool,
    pending_payload: dict,
    binding=None,
) -> _ReceiptReservation:
    """Reserve receipt authority without touching the canonical receipt pathname.

    On Windows the reservation is staged directly on the already-bound safe
    volume. The final pathname is not replaced until the target mutation has
    been fully verified, so a failed apply cannot destroy a pre-existing receipt.
    """
    from .safety import secure_stage_on_bound_volume

    if path.exists():
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise CustomizationApplyError("Receipt destination must be a regular non-symlink file.")
        if not overwrite:
            raise CustomizationApplyError(f"Receipt already exists and overwrite was not authorised: {path}")
        if st.st_size > _MAX_RECEIPT_BYTES:
            raise CustomizationApplyError("Existing receipt is too large to replace transactionally.")

    if binding is not None:
        fd, stage_path = secure_stage_on_bound_volume(binding, suffix=".receipt.partial")
    else:
        fd, stage_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".pending", dir=str(path.parent))
        stage_path = Path(stage_name)
    handle = os.fdopen(fd, "w+b", buffering=0)
    try:
        pending = dict(pending_payload)
        pending["status"] = "PENDING_TARGET_TRANSACTION"
        raw = (json.dumps(pending, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(raw) > _MAX_RECEIPT_BYTES:
            raise CustomizationApplyError("Pending receipt exceeds size bound.")
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    except Exception:
        try:
            handle.close()
        finally:
            stage_path.unlink(missing_ok=True)
        raise
    return _ReceiptReservation(
        path=path,
        stage_path=stage_path,
        handle=handle,
        binding=binding,
        overwrite=overwrite,
    )


def _commit_receipt(
    reservation: _ReceiptReservation,
    receipt: dict,
    *,
    target_root: Path,
    target_identity: dict[str, Any],
    host_system: Optional[str],
    _destination_disk_resolver=None,
    _volume_root_resolver=None,
    _volume_disk_resolver=None,
) -> None:
    """Commit the final receipt only after target verification, on the bound host volume."""
    from .safety import bind_output_volume

    final = dict(receipt)
    final["status"] = "COMMITTED"
    raw = (json.dumps(final, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > _MAX_RECEIPT_BYTES:
        raise CustomizationApplyError("Final receipt exceeds size bound.")
    handle = reservation.handle
    handle.seek(0)
    handle.truncate(0)
    handle.write(raw)
    handle.flush()
    os.fsync(handle.fileno())
    handle.close()

    if reservation.binding is not None:
        try:
            current = bind_output_volume(
                reservation.path,
                target_root,
                source_disk_number=int(target_identity["disk_number"]),
                host_system=host_system or platform.system(),
                destination_disk_resolver=_destination_disk_resolver,
                volume_root_resolver=_volume_root_resolver,
                volume_disk_resolver=_volume_disk_resolver,
            )
        except ValueError as exc:
            raise CustomizationApplyError(str(exc)) from exc
        expected = reservation.binding
        if (
            current is None
            or current.destination_disk_number != expected.destination_disk_number
            or current.volume_root.casefold() != expected.volume_root.casefold()
            or current.final_path != expected.final_path
        ):
            raise CustomizationApplyError("Receipt destination volume identity changed before commit.")

    if reservation.path.exists():
        st = reservation.path.lstat()
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise CustomizationApplyError("Receipt destination became a directory/symlink before commit.")
        if not reservation.overwrite:
            raise CustomizationApplyError("Receipt destination appeared before commit; overwrite was not authorised.")
    os.replace(reservation.stage_path, reservation.path)


def _abort_receipt(reservation: _ReceiptReservation) -> list[str]:
    errors: list[str] = []
    try:
        if not reservation.handle.closed:
            reservation.handle.close()
    except Exception as exc:
        errors.append(f"receipt staging handle: {exc}")
    try:
        reservation.stage_path.unlink(missing_ok=True)
    except Exception as exc:
        errors.append(f"receipt staging cleanup: {exc}")
    return errors


def _restore_from_handles(handles: dict[str, Any], manifest: dict, originals: dict) -> list[str]:
    errors: list[str] = []
    for item in reversed(manifest["patched_files"]):
        handle = handles.get(item["path"])
        if handle is None:
            errors.append(f"{item['path']}: write handle unavailable")
            continue
        try:
            for patch in reversed(item["patches"]):
                key = (item["path"], patch["offset"], patch["length"])
                handle.seek(patch["offset"])
                written = handle.write(originals[key])
                if written != patch["length"]:
                    raise OSError(f"short compensating write {written}/{patch['length']}")
            handle.flush()
            os.fsync(handle.fileno())
        except Exception as exc:
            errors.append(f"{item['path']}: {exc}")
    return errors


def apply_customization_workspace(
    source_image,
    workspace_path,
    target_root,
    rollback_path,
    *,
    confirmation: str,
    overwrite_rollback: bool = False,
    overwrite_receipt: bool = False,
    host_system: Optional[str] = None,
    progress: ProgressCallback | None = None,
    cancelled: CancelledCallback | None = None,
    _test_allow_non_windows: bool = False,
    _mapping_resolver=None,
    _destination_disk_resolver=None,
    _volume_root_resolver=None,
    _volume_disk_resolver=None,
    _handle_path_resolver=None,
) -> ApplyResult:
    workspace, workspace_sha, manifest, _payloads = _load_workspace(workspace_path)
    _check_cancelled(cancelled)
    source = _verify_workspace_semantic_authority(source_image, manifest, progress=progress)
    _verify_workspace_against_source_image(source, manifest, progress=progress)
    _check_cancelled(cancelled)

    root, target_identity = _normalize_target_root(
        target_root, host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
        _mapping_resolver=_mapping_resolver, _volume_root_resolver=_volume_root_resolver,
    )
    if workspace == source:
        raise CustomizationApplyError("Workspace and source image unexpectedly resolve to the same file.")
    try:
        workspace.relative_to(root)
    except ValueError:
        pass
    else:
        raise CustomizationApplyError("Customisation workspace must be stored off the target GameStick volume.")

    phrase = expected_confirmation(root)
    if confirmation.strip() != phrase:
        raise CustomizationApplyError(f"Typed confirmation did not match exactly: {phrase}")

    rollback, rollback_binding = _safe_host_output(
        rollback_path, root, ".gsrollback", overwrite=overwrite_rollback, target_identity=target_identity,
        host_system=host_system, _destination_disk_resolver=_destination_disk_resolver,
        _volume_root_resolver=_volume_root_resolver, _volume_disk_resolver=_volume_disk_resolver,
    )
    receipt_path = rollback.with_suffix(".apply.json")
    receipt_path, receipt_binding = _safe_host_output(
        receipt_path, root, ".apply.json", overwrite=overwrite_receipt, target_identity=target_identity,
        host_system=host_system, _destination_disk_resolver=_destination_disk_resolver,
        _volume_root_resolver=_volume_root_resolver, _volume_disk_resolver=_volume_disk_resolver,
    )
    if rollback_binding is not None:
        if (
            receipt_binding is None
            or receipt_binding.destination_disk_number != rollback_binding.destination_disk_number
            or receipt_binding.volume_root.casefold() != rollback_binding.volume_root.casefold()
        ):
            raise CustomizationApplyError("Rollback and receipt must be bound to the same verified host volume.")

    target_paths: dict[str, Path] = {}
    originals: dict[tuple[str, int, int], bytes] = {}
    if progress:
        progress("Preflight: validating exact source-state controls and original patch bytes on the TEST/CLONE...")
    for item in manifest["patched_files"]:
        _check_cancelled(cancelled)
        path = _target_file(root, item["path"])
        _verify_direct_target_file(path, item, expected_replacement=False)
        target_paths[item["path"]] = path
        with path.open("rb", buffering=0) as handle:
            for patch in item["patches"]:
                handle.seek(patch["offset"])
                raw = handle.read(patch["length"])
                if len(raw) != patch["length"] or _sha256(raw) != patch["original_sha256"]:
                    raise CustomizationApplyError(f"Target original-byte attestation changed for {item['path']}.")
                originals[(item["path"], patch["offset"], patch["length"])] = raw

    rollback_sha = _write_rollback_archive(
        rollback, workspace_sha, root, target_identity, manifest, originals,
        overwrite=overwrite_rollback, binding=rollback_binding, host_system=host_system,
        _destination_disk_resolver=_destination_disk_resolver, _volume_root_resolver=_volume_root_resolver,
        _volume_disk_resolver=_volume_disk_resolver,
    )

    rom = manifest.get("rom") or {}
    pending_receipt = {
        "schema": _RECEIPT_SCHEMA,
        "created_at_utc": _utc_now(),
        "workspace_sha256": workspace_sha,
        "workspace_name": workspace.name,
        "source_image_name": source.name,
        "target_root": str(root),
        "attachment_identity_at_apply": target_identity,
        "durable_media_identity": _durable_media_identity(target_identity),
        "rom": rom,
        "rollback_archive": str(rollback),
        "rollback_sha256": rollback_sha,
        "semantic_authority_rederived": True,
    }
    reservation = _reserve_receipt(
        receipt_path, overwrite=overwrite_receipt, pending_payload=pending_receipt, binding=receipt_binding
    )
    _check_cancelled(cancelled)

    if progress:
        progress("Rollback + pending receipt committed. Rebinding target identity immediately before write authority...")

    write_may_have_started = False
    committed = False
    handles: dict[str, Any] = {}
    try:
        with ExitStack() as stack:
            # Open the exact files first; if drive-letter identity changes after this point,
            # these handles remain bound to the already-open files rather than a new path.
            for item in manifest["patched_files"]:
                current_path = _target_file(root, item["path"])
                handle = stack.enter_context(current_path.open("r+b", buffering=0))
                handles[item["path"]] = handle
                _verify_open_handle_binding(
                    handle, root=root, identity=target_identity, relpath=item["path"],
                    host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
                    _handle_path_resolver=_handle_path_resolver,
                )

            _revalidate_target_identity(
                root, target_identity, host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
                _mapping_resolver=_mapping_resolver, _volume_root_resolver=_volume_root_resolver,
            )
            for item in manifest["patched_files"]:
                _verify_direct_target_handle(handles[item["path"]], item, expected_replacement=False)

            if progress:
                progress("Target identity rebound. Applying canonical two-file/four-range launcher hide...")
            try:
                for item in manifest["patched_files"]:
                    _check_cancelled(cancelled)
                    handle = handles[item["path"]]
                    for patch in item["patches"]:
                        handle.seek(patch["offset"])
                        old = handle.read(patch["length"])
                        if len(old) != patch["length"] or _sha256(old) != patch["original_sha256"]:
                            raise CustomizationApplyError(
                                f"Target bytes changed after write-handle binding: {item['path']}."
                            )
                    for patch in item["patches"]:
                        handle.seek(patch["offset"])
                        # From the instant the writable mutation call is reached, any
                        # subsequent failure may have changed removable media.
                        write_may_have_started = True
                        written = handle.write(patch["payload"])
                        if written != patch["length"]:
                            raise CustomizationApplyError(
                                f"Short target write in {item['path']}: expected {patch['length']}, wrote {written}."
                            )
                    handle.flush()
                    os.fsync(handle.fileno())

                if progress:
                    progress("Write complete. Rereading replacement controls and committing receipt inside transaction...")
                for item in manifest["patched_files"]:
                    _verify_direct_target_handle(handles[item["path"]], item, expected_replacement=True)

                created = _utc_now()
                receipt = {
                    **pending_receipt,
                    "created_at_utc": created,
                    "patched_files": [
                        {
                            "path": item["path"],
                            "file_size_bytes": item["file_size_bytes"],
                            "replacement_control_sha256": item["replacement_control_sha256"],
                            "patch_range_count": len(item["patches"]),
                            "patch_payload_bytes": sum(p["length"] for p in item["patches"]),
                        }
                        for item in manifest["patched_files"]
                    ],
                    "verification": "REREAD_REPLACEMENT_CONTROL_AND_PATCH_BYTES_MATCHED",
                    "physical_rom_payload_removed": False,
                }
                _commit_receipt(
                    reservation, receipt, target_root=root, target_identity=target_identity,
                    host_system=host_system, _destination_disk_resolver=_destination_disk_resolver,
                    _volume_root_resolver=_volume_root_resolver, _volume_disk_resolver=_volume_disk_resolver,
                )
                committed = True
            except Exception as exc:
                if write_may_have_started:
                    restore_errors = _restore_from_handles(handles, manifest, originals)
                    verify_errors: list[str] = []
                    if not restore_errors:
                        for item in manifest["patched_files"]:
                            try:
                                _verify_direct_target_handle(handles[item["path"]], item, expected_replacement=False)
                            except Exception as verify_exc:
                                verify_errors.append(f"{item['path']}: {verify_exc}")
                    receipt_errors = _abort_receipt(reservation)
                    if restore_errors or verify_errors:
                        details = "; ".join(restore_errors + verify_errors + receipt_errors)
                        raise RecoveryRequiredError(
                            "RECOVERY REQUIRED: customisation failed and automatic restoration could not be fully verified. "
                            f"Host rollback archive retained at {rollback}. {details}"
                        ) from exc
                    suffix = f" Receipt cleanup warning: {'; '.join(receipt_errors)}" if receipt_errors else ""
                    raise CustomizationApplyError(
                        f"Customisation apply failed after target modification: {exc}. "
                        f"Original target bytes were restored and reread-verified. Host rollback retained at {rollback}.{suffix}"
                    ) from exc
                receipt_errors = _abort_receipt(reservation)
                suffix = f" Receipt cleanup warning: {'; '.join(receipt_errors)}" if receipt_errors else ""
                raise CustomizationApplyError(f"Customisation apply stopped before any target mutation attempt: {exc}.{suffix}") from exc
    except Exception:
        if not committed and not reservation.handle.closed:
            _abort_receipt(reservation)
        raise

    reservation.handle.close()
    created = _utc_now()
    return ApplyResult(
        target_root=str(root), workspace_path=str(workspace), workspace_sha256=workspace_sha,
        rollback_path=str(rollback), rollback_sha256=rollback_sha, receipt_path=str(receipt_path),
        patched_file_count=len(manifest["patched_files"]),
        patch_range_count=sum(len(item["patches"]) for item in manifest["patched_files"]),
        patch_payload_bytes=sum(p["length"] for item in manifest["patched_files"] for p in item["patches"]),
        rom=str(rom.get("filename") or ""), catalogue_code=str(rom.get("catalogue_code") or ""),
        verification="REREAD_REPLACEMENT_CONTROL_AND_PATCH_BYTES_MATCHED_AND_RECEIPT_COMMITTED",
        created_at_utc=created,
    )


def _load_rollback(path_like) -> tuple[Path, dict, dict[str, bytes]]:
    path = Path(path_like).expanduser()
    try:
        st = path.lstat()
    except OSError as exc:
        raise CustomizationApplyError(f"Rollback archive is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise CustomizationApplyError("Rollback archive must be a regular non-symlink file.")
    if st.st_size <= 0 or st.st_size > _MAX_ROLLBACK_BYTES:
        raise CustomizationApplyError("Rollback archive size exceeds the bounded safety limit.")
    path = path.resolve(strict=True)
    try:
        archive = zipfile.ZipFile(path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise CustomizationApplyError(f"Rollback archive is invalid: {exc}") from exc

    with archive:
        infos = _validate_archive_infos(archive.infolist(), label="Rollback archive")
        if "manifest.json" not in infos:
            raise CustomizationApplyError("Rollback archive has no manifest.json.")
        try:
            manifest = json.loads(_read_bounded_member(archive, infos["manifest.json"], label="Rollback archive").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CustomizationApplyError(f"Rollback manifest is unreadable: {exc}") from exc
        schema = manifest.get("schema") if isinstance(manifest, dict) else None
        if schema not in (_ROLLBACK_SCHEMA, _ROLLBACK_SCHEMA_V2, _ROLLBACK_SCHEMA_V1):
            raise CustomizationApplyError("Unsupported rollback archive schema.")
        if schema == _ROLLBACK_SCHEMA:
            if manifest.get("action") != "UNDO_CANONICAL_HIDE_ROM":
                raise CustomizationApplyError("Rollback-v3 action provenance is missing or invalid.")
            _require_hex64(manifest.get("workspace_sha256"), "Rollback-v3 workspace provenance")
            if not isinstance(manifest.get("attachment_identity_at_apply"), dict):
                raise CustomizationApplyError("Rollback-v3 attachment identity provenance is required.")
            _validate_durable_media_identity(manifest.get("durable_media_identity"), label="Rollback-v3")
            rom = manifest.get("rom")
            if not isinstance(rom, dict):
                raise CustomizationApplyError("Rollback-v3 ROM provenance is required.")
            code = str(rom.get("catalogue_code") or "")
            filename = str(rom.get("filename") or "")
            if not re.fullmatch(r"\d{3}", code):
                raise CustomizationApplyError("Rollback-v3 ROM catalogue code is invalid.")
            if not filename or PurePosixPath(filename.replace("\\", "/")).name != filename:
                raise CustomizationApplyError("Rollback-v3 ROM filename is not canonical.")
        patched_files = manifest.get("patched_files")
        if not isinstance(patched_files, list) or not patched_files or len(patched_files) > 32:
            raise CustomizationApplyError("Rollback patched_files list is invalid.")

        payloads: dict[str, bytes] = {}
        referenced = {"manifest.json"}
        total_bytes = 0
        total_ranges = 0
        normalized_files = []
        for raw_item in patched_files:
            if not isinstance(raw_item, dict):
                raise CustomizationApplyError("Rollback patched_files contains a non-object entry.")
            relpath = _safe_target_relpath(str(raw_item.get("path") or ""))
            file_size = raw_item.get("file_size_bytes")
            if not isinstance(file_size, int) or file_size <= 0:
                raise CustomizationApplyError(f"Rollback file size is invalid for {relpath}.")
            source_control = _require_hex64(raw_item.get("source_control_sha256"), "Rollback source control digest")
            replacement_control = _require_hex64(raw_item.get("replacement_control_sha256"), "Rollback replacement control digest")
            ranges = []
            prior_end = -1
            raw_patches = raw_item.get("patches")
            if not isinstance(raw_patches, list) or not raw_patches:
                raise CustomizationApplyError(f"Rollback contains no patch ranges for {relpath}.")
            for raw_patch in sorted(raw_patches, key=lambda p: int(p.get("offset", -1)) if isinstance(p, dict) else -1):
                if not isinstance(raw_patch, dict):
                    raise CustomizationApplyError("Rollback contains an invalid patch range.")
                offset = raw_patch.get("offset")
                length = raw_patch.get("length")
                if not isinstance(offset, int) or not isinstance(length, int) or offset < 0 or length <= 0:
                    raise CustomizationApplyError("Rollback patch range is invalid.")
                if offset + length > file_size or offset < prior_end:
                    raise CustomizationApplyError("Rollback patch ranges overlap or exceed the target file.")
                prior_end = offset + length
                member = str(raw_patch.get("payload_member") or "")
                if not _safe_member_name(member) or member == "manifest.json":
                    raise CustomizationApplyError("Rollback payload member is unsafe.")
                info = infos.get(member)
                if info is None:
                    raise CustomizationApplyError(f"Rollback payload member is missing: {member}")
                original_sha = _require_hex64(raw_patch.get("original_sha256"), "Rollback original patch digest")
                replacement_sha = _require_hex64(raw_patch.get("replacement_sha256"), "Rollback replacement patch digest")
                data = _read_bounded_member(archive, info, label="Rollback archive")
                if len(data) != length or _sha256(data) != original_sha:
                    raise CustomizationApplyError(f"Rollback payload verification failed: {member}")
                total_bytes += length
                total_ranges += 1
                if total_bytes > _MAX_PATCH_BYTES or total_ranges > _MAX_PATCH_RANGES:
                    raise CustomizationApplyError("Rollback payload exceeds bounded restore limits.")
                payloads[member] = data
                referenced.add(member)
                ranges.append({
                    "offset": offset, "length": length, "payload_member": member,
                    "original_sha256": original_sha, "replacement_sha256": replacement_sha,
                })
            normalized_files.append({
                "path": relpath, "file_size_bytes": file_size,
                "source_control_sha256": source_control, "replacement_control_sha256": replacement_control,
                "patches": ranges,
            })
        extras = set(infos) - referenced
        if extras:
            raise CustomizationApplyError("Rollback archive contains unreferenced payload members.")
        normalized = dict(manifest)
        normalized["patched_files"] = normalized_files
        return path, normalized, payloads


def _load_receipt(path_like) -> tuple[Path, dict]:
    path = Path(path_like).expanduser()
    try:
        st = path.lstat()
    except OSError as exc:
        raise CustomizationApplyError(f"Apply receipt is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise CustomizationApplyError("Apply receipt must be a regular non-symlink file.")
    if st.st_size <= 0 or st.st_size > _MAX_RECEIPT_BYTES:
        raise CustomizationApplyError("Apply receipt size is outside the safety bound.")
    path = path.resolve(strict=True)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CustomizationApplyError(f"Apply receipt is unreadable: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") not in (_RECEIPT_SCHEMA, _RECEIPT_SCHEMA_V1):
        raise CustomizationApplyError("Unsupported apply receipt schema.")
    status = data.get("status")
    if status not in (None, "COMMITTED"):
        raise CustomizationApplyError(f"Apply receipt is not committed: {status!r}")
    return path, data


def _verify_receipt_binding(
    rollback: Path,
    rollback_manifest: dict,
    receipt_path,
    *,
    expected_rom: tuple[str, str],
    target_identity: dict[str, Any],
) -> dict:
    _rp, receipt = _load_receipt(receipt_path)
    rollback_sha = _sha256_file(rollback)
    if str(receipt.get("rollback_sha256") or "").casefold() != rollback_sha:
        raise CustomizationApplyError("Apply receipt rollback SHA-256 does not match the selected .gsrollback archive.")
    if str(receipt.get("workspace_sha256") or "").casefold() != str(rollback_manifest.get("workspace_sha256") or "").casefold():
        raise CustomizationApplyError("Apply receipt workspace provenance does not match the rollback archive.")
    code, filename = expected_rom
    rom = receipt.get("rom") or {}
    if str(rom.get("catalogue_code") or "") != code or str(rom.get("filename") or "").casefold() != filename.casefold():
        raise CustomizationApplyError("Apply receipt ROM identity does not match the selected ROM.")
    rollback_rom = rollback_manifest.get("rom") or {}
    if rollback_rom:
        if str(rollback_rom.get("catalogue_code") or "") != code or str(rollback_rom.get("filename") or "").casefold() != filename.casefold():
            raise CustomizationApplyError("Rollback archive ROM identity does not match the selected ROM.")

    current_durable = _durable_media_identity(target_identity)
    if receipt.get("schema") == _RECEIPT_SCHEMA:
        receipt_durable = _validate_durable_media_identity(
            receipt.get("durable_media_identity"), label="Apply receipt"
        )
        if receipt_durable != current_durable:
            raise CustomizationApplyError("Apply receipt durable media identity does not match the currently selected TEST/CLONE.")
    else:
        # Legacy apply receipt: compare any full attachment identity by its durable
        # portion. It remains usable only in explicitly compatible recovery paths.
        legacy = _legacy_durable_identity(receipt.get("target_identity"))
        if legacy is not None and legacy != current_durable:
            raise CustomizationApplyError("Legacy apply receipt media identity does not match the selected TEST/CLONE.")
        if legacy is None and target_identity.get("mode") == "WINDOWS_PHYSICAL":
            old_size = receipt.get("target_disk_size")
            if old_size is not None and int(old_size) != int(target_identity["disk_size"]):
                raise CustomizationApplyError("Legacy receipt disk size does not match the selected TEST/CLONE.")

    schema = rollback_manifest.get("schema")
    if schema == _ROLLBACK_SCHEMA:
        rollback_durable = _validate_durable_media_identity(
            rollback_manifest.get("durable_media_identity"), label="Rollback-v3"
        )
        if rollback_durable != current_durable:
            raise CustomizationApplyError("Rollback durable media identity does not match the selected TEST/CLONE.")
    else:
        legacy_rb = _legacy_durable_identity(rollback_manifest.get("target_identity"))
        if legacy_rb is not None and legacy_rb != current_durable:
            raise CustomizationApplyError("Legacy rollback media identity does not match the selected TEST/CLONE.")
    return receipt


def verify_rollback_receipt_for_rom(
    rollback_path,
    receipt_path,
    target_root,
    catalogue_code: str,
    filename: str,
    *,
    host_system: Optional[str] = None,
    _test_allow_non_windows: bool = False,
    _mapping_resolver=None,
    _volume_root_resolver=None,
    _handle_path_resolver=None,
) -> dict:
    rollback, manifest, payloads = _load_rollback(rollback_path)
    if manifest.get("schema") != _ROLLBACK_SCHEMA:
        raise CustomizationApplyError(
            "ROM Manager unhide requires rollback-v3. Use the explicit legacy-recovery path for older rollback archives."
        )
    root, identity = _normalize_target_root(
        target_root, host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
        _mapping_resolver=_mapping_resolver, _volume_root_resolver=_volume_root_resolver,
    )
    receipt = _verify_receipt_binding(
        rollback, manifest, receipt_path, expected_rom=(catalogue_code, filename), target_identity=identity,
    )
    with ExitStack() as stack:
        handles: dict[str, Any] = {}
        for item in manifest["patched_files"]:
            handle = stack.enter_context(_target_file(root, item["path"]).open("rb", buffering=0))
            handles[item["path"]] = handle
            _verify_open_handle_binding(
                handle, root=root, identity=identity, relpath=item["path"],
                host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
                _handle_path_resolver=_handle_path_resolver,
            )
        _revalidate_target_identity(
            root, identity, host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
            _mapping_resolver=_mapping_resolver, _volume_root_resolver=_volume_root_resolver,
        )
        for item in manifest["patched_files"]:
            _verify_direct_target_handle(handles[item["path"]], item, expected_replacement=True)
        _verify_rollback_semantic_authority(
            handles, manifest, payloads, transaction_identity=identity, allow_legacy_recovery=False,
            expected_rom=(catalogue_code, filename),
        )
    return receipt


def rollback_customization(
    rollback_path,
    target_root,
    *,
    confirmation: str,
    host_system: Optional[str] = None,
    progress: ProgressCallback | None = None,
    receipt_path=None,
    expected_rom: tuple[str, str] | None = None,
    allow_legacy_recovery: bool = False,
    _test_allow_non_windows: bool = False,
    _mapping_resolver=None,
    _volume_root_resolver=None,
    _handle_path_resolver=None,
) -> RollbackResult:
    rollback, manifest, payloads = _load_rollback(rollback_path)
    schema = manifest.get("schema")
    if schema in (_ROLLBACK_SCHEMA_V1, _ROLLBACK_SCHEMA_V2) and not allow_legacy_recovery:
        raise CustomizationApplyError(
            "Legacy rollback-v1/v2 is recovery-only. Re-run with explicit legacy-recovery authority; semantic inverse proof is still mandatory."
        )
    root, transaction_identity = _normalize_target_root(
        target_root, host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
        _mapping_resolver=_mapping_resolver, _volume_root_resolver=_volume_root_resolver,
    )
    current_durable = _durable_media_identity(transaction_identity)
    if schema == _ROLLBACK_SCHEMA:
        recorded_durable = _validate_durable_media_identity(
            manifest.get("durable_media_identity"), label="Rollback-v3"
        )
        if recorded_durable != current_durable:
            raise CustomizationApplyError("Rollback archive belongs to a different durable physical TEST/CLONE target.")
    else:
        legacy_durable = _legacy_durable_identity(manifest.get("target_identity"))
        if legacy_durable is not None and legacy_durable != current_durable:
            raise CustomizationApplyError("Legacy rollback archive belongs to a different durable TEST/CLONE target.")
    if receipt_path is not None or expected_rom is not None:
        if receipt_path is None or expected_rom is None:
            raise CustomizationApplyError("Receipt-bound rollback requires both receipt_path and expected_rom.")
        _verify_receipt_binding(
            rollback, manifest, receipt_path, expected_rom=expected_rom, target_identity=transaction_identity,
        )

    phrase = f"ROLL BACK {root.drive.upper() if root.drive else root.name}"
    if confirmation.strip() != phrase:
        raise CustomizationApplyError(f"Typed rollback confirmation did not match exactly: {phrase}")

    target_paths: dict[str, Path] = {}
    for item in manifest["patched_files"]:
        path = _target_file(root, item["path"])
        _verify_direct_target_file(path, item, expected_replacement=True)
        target_paths[item["path"]] = path

    if progress:
        progress("Replacement state verified. Binding target handles before transactional rollback...")

    restored_bytes = 0
    restored_ranges = 0
    with ExitStack() as stack:
        handles: dict[str, Any] = {}
        for item in manifest["patched_files"]:
            handle = stack.enter_context(_target_file(root, item["path"]).open("r+b", buffering=0))
            handles[item["path"]] = handle
            _verify_open_handle_binding(
                handle, root=root, identity=transaction_identity, relpath=item["path"],
                host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
                _handle_path_resolver=_handle_path_resolver,
            )
        _revalidate_target_identity(
            root, transaction_identity, host_system=host_system, _test_allow_non_windows=_test_allow_non_windows,
            _mapping_resolver=_mapping_resolver, _volume_root_resolver=_volume_root_resolver,
        )
        for item in manifest["patched_files"]:
            _verify_direct_target_handle(handles[item["path"]], item, expected_replacement=True)

        if progress:
            progress("Proving rollback is the exact semantic inverse of one canonical hide operation...")
        authority_code, authority_filename = _verify_rollback_semantic_authority(
            handles, manifest, payloads, transaction_identity=transaction_identity,
            allow_legacy_recovery=allow_legacy_recovery, expected_rom=expected_rom,
        )
        if progress:
            progress(f"Rollback authority verified for {authority_code}:{authority_filename}. Capturing compensation state...")

        replacement_snapshots: dict[tuple[str, int, int], bytes] = {}
        for item in manifest["patched_files"]:
            handle = handles[item["path"]]
            for patch in item["patches"]:
                handle.seek(patch["offset"])
                current = handle.read(patch["length"])
                if len(current) != patch["length"] or _sha256(current) != patch["replacement_sha256"]:
                    raise CustomizationApplyError(f"Target changed before rollback write: {item['path']}.")
                replacement_snapshots[(item["path"], patch["offset"], patch["length"])] = current

        if progress:
            progress("Restoring original bounded control bytes transactionally...")
        try:
            for item in manifest["patched_files"]:
                handle = handles[item["path"]]
                for patch in item["patches"]:
                    original = payloads[patch["payload_member"]]
                    handle.seek(patch["offset"])
                    written = handle.write(original)
                    if written != len(original):
                        raise CustomizationApplyError(f"Short rollback write in {item['path']}.")
                    restored_bytes += len(original)
                    restored_ranges += 1
                handle.flush()
                os.fsync(handle.fileno())
            for item in manifest["patched_files"]:
                _verify_direct_target_handle(handles[item["path"]], item, expected_replacement=False)
        except Exception as exc:
            compensation_errors: list[str] = []
            for item in manifest["patched_files"]:
                handle = handles[item["path"]]
                try:
                    for patch in item["patches"]:
                        key = (item["path"], patch["offset"], patch["length"])
                        handle.seek(patch["offset"])
                        written = handle.write(replacement_snapshots[key])
                        if written != patch["length"]:
                            raise OSError(f"short compensation write {written}/{patch['length']}")
                    handle.flush()
                    os.fsync(handle.fileno())
                except Exception as comp_exc:
                    compensation_errors.append(f"{item['path']}: {comp_exc}")
            if not compensation_errors:
                for item in manifest["patched_files"]:
                    try:
                        _verify_direct_target_handle(handles[item["path"]], item, expected_replacement=True)
                    except Exception as verify_exc:
                        compensation_errors.append(f"{item['path']} verify: {verify_exc}")
            if compensation_errors:
                raise RecoveryRequiredError(
                    "RECOVERY REQUIRED: rollback failed and compensation could not restore the complete customized state. "
                    + "; ".join(compensation_errors)
                ) from exc
            raise CustomizationApplyError(
                f"Rollback failed: {exc}. The complete customized replacement state was restored and reread-verified."
            ) from exc

    return RollbackResult(
        target_root=str(root), rollback_path=str(rollback), restored_file_count=len(manifest["patched_files"]),
        restored_range_count=restored_ranges, restored_bytes=restored_bytes,
        verification="REREAD_SOURCE_CONTROL_AND_ORIGINAL_PATCH_BYTES_MATCHED_TRANSACTIONALLY",
        created_at_utc=_utc_now(),
    )
