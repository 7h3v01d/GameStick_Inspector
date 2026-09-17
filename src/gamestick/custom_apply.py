from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Optional

from .catalogue_image_lab import _FatAccessor, _locate_catalogues
from .fast_image_lab import FatEntry, _parse_geometry, _validate_image
from .rom_customization import RomCustomizationError, _read_control_layout

ProgressCallback = Callable[[str], None]
CancelledCallback = Callable[[], bool]

_WORKSPACE_SCHEMA = "gamestick-customization-workspace-v1"
_ROLLBACK_SCHEMA = "gamestick-customization-rollback-v1"
_RECEIPT_SCHEMA = "gamestick-customization-apply-receipt-v1"
_MAX_WORKSPACE_BYTES = 32 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 128
_MAX_PATCH_BYTES = 16 * 1024 * 1024
_MAX_PATCH_RANGES = 128
_DAT_PATH_RE = re.compile(r"^(\d{3})/\1\.dat$", re.IGNORECASE)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_EXTERNAL_BUSES = {"usb", "sd", "mmc"}


class CustomizationApplyError(RuntimeError):
    """Raised when a bounded customisation apply/rollback cannot be proven safe."""


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


def _check_cancelled(cancelled: CancelledCallback | None) -> None:
    if cancelled and cancelled():
        raise CustomizationApplyError("Customisation apply cancelled before target modification completed.")


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/"):
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)


def _require_hex64(value, label: str) -> str:
    text = str(value or "").casefold()
    if not _HEX64_RE.fullmatch(text):
        raise CustomizationApplyError(f"Workspace {label} is not a valid SHA-256 digest.")
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
    """Read-only random-access adapter for an already mounted target file."""

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


def _load_workspace(workspace_path) -> tuple[Path, str, dict, dict[str, bytes]]:
    path = Path(workspace_path).expanduser()
    try:
        st = path.lstat()
    except OSError as exc:
        raise CustomizationApplyError(f"Customisation workspace is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise CustomizationApplyError("Customisation workspace must be a regular non-symlink file.")
    if st.st_size <= 0 or st.st_size > _MAX_WORKSPACE_BYTES:
        raise CustomizationApplyError(
            f"Customisation workspace size is outside the bounded limit ({st.st_size:,} bytes)."
        )
    path = path.resolve(strict=True)
    workspace_sha = _sha256_file(path)

    try:
        archive = zipfile.ZipFile(path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise CustomizationApplyError(f"Customisation workspace is not a valid ZIP container: {exc}") from exc

    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > _MAX_ARCHIVE_MEMBERS:
            raise CustomizationApplyError("Customisation workspace member count is invalid or exceeds the bound.")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise CustomizationApplyError("Customisation workspace contains duplicate archive member names.")
        for info in infos:
            if not _safe_member_name(info.filename):
                raise CustomizationApplyError(f"Unsafe customisation archive member: {info.filename!r}")
            if info.flag_bits & 0x1:
                raise CustomizationApplyError("Encrypted customisation archive members are unsupported.")
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise CustomizationApplyError("Unsupported customisation archive compression method.")
        if "manifest.json" not in names:
            raise CustomizationApplyError("Customisation workspace has no manifest.json.")
        try:
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
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
            if not isinstance(file_size, int) or file_size <= 0:
                raise CustomizationApplyError(f"Workspace file size is invalid for {relpath}.")
            cluster_count = raw_item.get("cluster_count")
            if not isinstance(cluster_count, int) or cluster_count <= 0:
                raise CustomizationApplyError(f"Workspace cluster count is invalid for {relpath}.")
            chain_sha = _require_hex64(raw_item.get("target_chain_sha256"), f"chain digest for {relpath}")
            source_control_sha = _require_hex64(raw_item.get("source_control_sha256"), f"source control digest for {relpath}")
            replacement_control_sha = _require_hex64(
                raw_item.get("replacement_control_sha256"), f"replacement control digest for {relpath}"
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
                original_sha = _require_hex64(raw_patch.get("original_sha256"), f"original patch digest for {relpath}")
                replacement_sha = _require_hex64(
                    raw_patch.get("replacement_sha256"), f"replacement patch digest for {relpath}"
                )
                try:
                    payload = archive.read(member)
                except KeyError as exc:
                    raise CustomizationApplyError(f"Workspace patch member is missing: {member}") from exc
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

        extras = set(names) - {"manifest.json"} - referenced
        if extras:
            raise CustomizationApplyError(
                "Customisation workspace contains unreferenced payload members: " + ", ".join(sorted(extras))
            )
        manifest = dict(manifest)
        manifest["patched_files"] = normalized_files
        payloads = {patch["payload_member"]: patch["payload"] for item in normalized_files for patch in item["patches"]}
        return path, workspace_sha, manifest, payloads


def _source_entries(handle, geometry, manifest: dict) -> dict[str, tuple[FatEntry, tuple[int, ...]]]:
    catalogues, root_entry = _locate_catalogues(handle, geometry)
    accessor = _FatAccessor(handle, geometry)
    out: dict[str, tuple[FatEntry, tuple[int, ...]]] = {}
    for item in manifest["patched_files"]:
        rel = item["path"]
        if rel.casefold() == "root.dat":
            entry = root_entry
        else:
            entry = catalogues.get(rel[:3])
        if entry is None:
            raise CustomizationApplyError(f"Source image no longer contains required file {rel}.")
        chain = accessor.chain_for(entry)
        out[rel] = (entry, chain)
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
        progress("Revalidating workspace chain/control provenance against the healthy source image...")
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


def _normalize_target_root(target_root, *, host_system: Optional[str]) -> tuple[Path, Optional[object]]:
    system = host_system or platform.system()
    root = Path(target_root).expanduser()
    try:
        st = root.lstat()
    except OSError as exc:
        raise CustomizationApplyError(f"Target GameStick volume is unavailable: {root}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise CustomizationApplyError("Target GameStick volume must be a real directory, not a symlink/reparse alias.")
    root = root.resolve(strict=True)

    mapping = None
    if system == "Windows":
        # Destructive target authority is intentionally restricted to a local drive root.
        drive = root.drive
        if not drive or drive.startswith("\\\\") or root != Path(root.anchor):
            raise CustomizationApplyError("Target must be the root of a local mounted drive, for example H:\\.")
        system_drive = os.environ.get("SystemDrive", "C:").rstrip("\\/").casefold()
        if drive.rstrip("\\/").casefold() == system_drive:
            raise CustomizationApplyError("Refusing to modify the Windows system drive.")
        from .probe import _physical_mapping
        mapping = _physical_mapping(root)
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

    for marker in ("ROOT.DAT", "CUBEGM", "Roms"):
        if not (root / marker).exists():
            raise CustomizationApplyError(f"Target does not look like the expected GameStick layout: missing {marker}.")
    return root, mapping


def _target_file(root: Path, relpath: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relpath).parts)
    try:
        st = candidate.lstat()
    except OSError as exc:
        raise CustomizationApplyError(f"Target file is unavailable: {relpath}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise CustomizationApplyError(f"Target file must be a regular non-symlink file: {relpath}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise CustomizationApplyError(f"Target file escapes the selected GameStick volume: {relpath}") from exc
    return resolved


def _verify_direct_target_file(path: Path, item: dict, *, expected_replacement: bool) -> None:
    st = path.stat()
    if st.st_size != item["file_size_bytes"]:
        raise CustomizationApplyError(
            f"Target file-size mismatch for {item['path']}: expected {item['file_size_bytes']:,}, got {st.st_size:,}."
        )
    entry = FatEntry(path=item["path"], size_bytes=st.st_size, start_cluster=2, is_directory=False)
    with path.open("rb", buffering=0) as handle:
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


def _safe_host_output(path_like, target_root: Path, suffix: str, *, overwrite: bool) -> Path:
    path = Path(path_like).expanduser().resolve(strict=False)
    if path.suffix.casefold() != suffix.casefold():
        raise CustomizationApplyError(f"Output must end in {suffix}.")
    try:
        path.relative_to(target_root)
    except ValueError:
        pass
    else:
        raise CustomizationApplyError("Rollback/evidence output must not be stored on the GameStick target volume.")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise CustomizationApplyError("Rollback/evidence output parent is not a directory.")
    if path.exists():
        if path.is_dir() or path.is_symlink():
            raise CustomizationApplyError("Refusing to replace a directory or symlink output.")
        if not overwrite:
            raise CustomizationApplyError(f"Output already exists: {path}")
    return path


def expected_confirmation(target_root) -> str:
    root = Path(target_root)
    drive = root.drive.upper() if root.drive else root.name
    return f"APPLY TO {drive or str(root)}"


def _write_rollback_archive(path: Path, workspace_sha: str, target_root: Path, manifest: dict, originals: dict, *, overwrite: bool) -> str:
    rollback_manifest = {
        "schema": _ROLLBACK_SCHEMA,
        "created_at_utc": _utc_now(),
        "workspace_sha256": workspace_sha,
        "target_root_at_apply": str(target_root),
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
                "offset": patch["offset"],
                "length": patch["length"],
                "payload_member": member,
                "original_sha256": patch["original_sha256"],
                "replacement_sha256": patch["replacement_sha256"],
            })
        rollback_manifest["patched_files"].append({
            "path": item["path"],
            "file_size_bytes": item["file_size_bytes"],
            "source_control_sha256": item["source_control_sha256"],
            "replacement_control_sha256": item["replacement_control_sha256"],
            "patches": ranges,
        })

    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    os.close(fd)
    temp = Path(temp_name)
    try:
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
            archive.writestr("manifest.json", json.dumps(rollback_manifest, indent=2, sort_keys=True) + "\n")
            for member, payload in sorted(payloads.items()):
                archive.writestr(member, payload)
        with temp.open("r+b", buffering=0) as handle:
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and overwrite:
            path.unlink()
        os.replace(temp, path)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    return _sha256_file(path)


def _restore_from_memory(target_paths: dict[str, Path], manifest: dict, originals: dict) -> list[str]:
    errors: list[str] = []
    for item in reversed(manifest["patched_files"]):
        path = target_paths[item["path"]]
        try:
            with path.open("r+b", buffering=0) as handle:
                for patch in reversed(item["patches"]):
                    key = (item["path"], patch["offset"], patch["length"])
                    handle.seek(patch["offset"])
                    handle.write(originals[key])
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
    host_system: Optional[str] = None,
    progress: ProgressCallback | None = None,
    cancelled: CancelledCallback | None = None,
) -> ApplyResult:
    workspace, workspace_sha, manifest, _payloads = _load_workspace(workspace_path)
    _check_cancelled(cancelled)
    source = _verify_workspace_against_source_image(source_image, manifest, progress=progress)
    _check_cancelled(cancelled)
    root, mapping = _normalize_target_root(target_root, host_system=host_system)
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

    rollback = _safe_host_output(rollback_path, root, ".gsrollback", overwrite=overwrite_rollback)
    target_paths: dict[str, Path] = {}
    originals: dict[tuple[str, int, int], bytes] = {}

    if progress:
        progress("Preflight: validating target GameStick control hashes and exact original patch bytes...")
    for item in manifest["patched_files"]:
        _check_cancelled(cancelled)
        path = _target_file(root, item["path"])
        _verify_direct_target_file(path, item, expected_replacement=False)
        target_paths[item["path"]] = path
        with path.open("rb", buffering=0) as handle:
            for patch in item["patches"]:
                handle.seek(patch["offset"])
                raw = handle.read(patch["length"])
                if _sha256(raw) != patch["original_sha256"]:
                    raise CustomizationApplyError(f"Target original-byte attestation changed for {item['path']}.")
                originals[(item["path"], patch["offset"], patch["length"])] = raw

    rollback_sha = _write_rollback_archive(
        rollback, workspace_sha, root, manifest, originals, overwrite=overwrite_rollback
    )
    _check_cancelled(cancelled)

    if progress:
        progress("Rollback snapshot committed on host. Applying bounded control-byte patches to the test card...")
    write_started = False
    try:
        for item in manifest["patched_files"]:
            _check_cancelled(cancelled)
            path = target_paths[item["path"]]
            before = path.stat()
            if before.st_size != item["file_size_bytes"]:
                raise CustomizationApplyError(f"Target file size changed immediately before write: {item['path']}.")
            with path.open("r+b", buffering=0) as handle:
                # Re-attest every old range from the same write handle immediately before first write.
                for patch in item["patches"]:
                    handle.seek(patch["offset"])
                    old = handle.read(patch["length"])
                    if _sha256(old) != patch["original_sha256"]:
                        raise CustomizationApplyError(
                            f"Target bytes changed between preflight and write authority: {item['path']}."
                        )
                for patch in item["patches"]:
                    handle.seek(patch["offset"])
                    written = handle.write(patch["payload"])
                    if written != patch["length"]:
                        raise CustomizationApplyError(
                            f"Short target write in {item['path']}: expected {patch['length']}, wrote {written}."
                        )
                    write_started = True
                handle.flush()
                os.fsync(handle.fileno())
            # Preserve the visible file timestamp where the host filesystem permits it.
            try:
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            except OSError:
                pass

        if progress:
            progress("Write complete. Rereading patched controls and replacement bytes...")
        for item in manifest["patched_files"]:
            _verify_direct_target_file(target_paths[item["path"]], item, expected_replacement=True)
    except Exception as exc:
        if write_started:
            rollback_errors = _restore_from_memory(target_paths, manifest, originals)
            verify_errors: list[str] = []
            if not rollback_errors:
                for item in manifest["patched_files"]:
                    try:
                        _verify_direct_target_file(target_paths[item["path"]], item, expected_replacement=False)
                    except Exception as verify_exc:
                        verify_errors.append(f"{item['path']}: {verify_exc}")
            details = []
            if rollback_errors:
                details.append("rollback write errors: " + "; ".join(rollback_errors))
            if verify_errors:
                details.append("rollback verification errors: " + "; ".join(verify_errors))
            suffix = " " + " | ".join(details) if details else " Automatic rollback verified."
            raise CustomizationApplyError(
                f"Customisation apply failed after target modification: {exc}.{suffix} "
                f"Host rollback archive retained at {rollback}."
            ) from exc
        raise

    created = _utc_now()
    rom = manifest.get("rom") or {}
    receipt = {
        "schema": _RECEIPT_SCHEMA,
        "created_at_utc": created,
        "workspace_sha256": workspace_sha,
        "workspace_name": workspace.name,
        "source_image_name": source.name,
        "target_root": str(root),
        "target_disk_number": getattr(mapping, "disk_number", None) if mapping is not None else None,
        "target_disk_size": getattr(mapping, "disk_size", None) if mapping is not None else None,
        "rom": rom,
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
        "rollback_archive": str(rollback),
        "rollback_sha256": rollback_sha,
        "verification": "REREAD_REPLACEMENT_CONTROL_AND_PATCH_BYTES_MATCHED",
        "physical_rom_payload_removed": False,
    }
    receipt_path = rollback.with_suffix(".apply.json")
    if receipt_path.exists():
        receipt_path.unlink()
    fd, temp_name = tempfile.mkstemp(prefix=f".{receipt_path.name}.", suffix=".tmp", dir=str(receipt_path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, receipt_path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        Path(temp_name).unlink(missing_ok=True)
        raise

    return ApplyResult(
        target_root=str(root),
        workspace_path=str(workspace),
        workspace_sha256=workspace_sha,
        rollback_path=str(rollback),
        rollback_sha256=rollback_sha,
        receipt_path=str(receipt_path),
        patched_file_count=len(manifest["patched_files"]),
        patch_range_count=sum(len(item["patches"]) for item in manifest["patched_files"]),
        patch_payload_bytes=sum(p["length"] for item in manifest["patched_files"] for p in item["patches"]),
        rom=str(rom.get("filename") or ""),
        catalogue_code=str(rom.get("catalogue_code") or ""),
        verification="REREAD_REPLACEMENT_CONTROL_AND_PATCH_BYTES_MATCHED",
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
    path = path.resolve(strict=True)
    try:
        archive = zipfile.ZipFile(path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise CustomizationApplyError(f"Rollback archive is invalid: {exc}") from exc
    with archive:
        names = [info.filename for info in archive.infolist()]
        if len(names) != len(set(names)) or "manifest.json" not in names:
            raise CustomizationApplyError("Rollback archive member layout is invalid.")
        if any(not _safe_member_name(name) for name in names):
            raise CustomizationApplyError("Rollback archive contains an unsafe member name.")
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        if manifest.get("schema") != _ROLLBACK_SCHEMA:
            raise CustomizationApplyError("Unsupported rollback archive schema.")
        payloads: dict[str, bytes] = {}
        referenced = {"manifest.json"}
        for item in manifest.get("patched_files") or []:
            item["path"] = _safe_target_relpath(item.get("path", ""))
            item["source_control_sha256"] = _require_hex64(item.get("source_control_sha256"), "rollback source control")
            item["replacement_control_sha256"] = _require_hex64(
                item.get("replacement_control_sha256"), "rollback replacement control"
            )
            for patch in item.get("patches") or []:
                member = patch.get("payload_member")
                if not _safe_member_name(str(member or "")):
                    raise CustomizationApplyError("Rollback payload member is unsafe.")
                data = archive.read(member)
                if len(data) != patch.get("length") or _sha256(data) != patch.get("original_sha256"):
                    raise CustomizationApplyError(f"Rollback payload verification failed: {member}")
                patch["original_sha256"] = _require_hex64(patch.get("original_sha256"), "rollback original patch")
                patch["replacement_sha256"] = _require_hex64(
                    patch.get("replacement_sha256"), "rollback replacement patch"
                )
                payloads[member] = data
                referenced.add(member)
        extras = set(names) - referenced
        if extras:
            raise CustomizationApplyError("Rollback archive contains unreferenced payload members.")
        return path, manifest, payloads


def rollback_customization(
    rollback_path,
    target_root,
    *,
    confirmation: str,
    host_system: Optional[str] = None,
    progress: ProgressCallback | None = None,
) -> RollbackResult:
    rollback, manifest, payloads = _load_rollback(rollback_path)
    root, _mapping = _normalize_target_root(target_root, host_system=host_system)
    phrase = f"ROLL BACK {root.drive.upper() if root.drive else root.name}"
    if confirmation.strip() != phrase:
        raise CustomizationApplyError(f"Typed rollback confirmation did not match exactly: {phrase}")

    target_paths: dict[str, Path] = {}
    for item in manifest["patched_files"]:
        path = _target_file(root, item["path"])
        _verify_direct_target_file(path, item, expected_replacement=True)
        target_paths[item["path"]] = path

    if progress:
        progress("Replacement state verified. Restoring original bounded control bytes...")
    restored_bytes = 0
    restored_ranges = 0
    for item in manifest["patched_files"]:
        path = target_paths[item["path"]]
        before = path.stat()
        with path.open("r+b", buffering=0) as handle:
            for patch in item["patches"]:
                handle.seek(patch["offset"])
                current = handle.read(patch["length"])
                if _sha256(current) != patch["replacement_sha256"]:
                    raise CustomizationApplyError(f"Target changed before rollback write: {item['path']}.")
                original = payloads[patch["payload_member"]]
                handle.seek(patch["offset"])
                written = handle.write(original)
                if written != len(original):
                    raise CustomizationApplyError(f"Short rollback write in {item['path']}.")
                restored_bytes += len(original)
                restored_ranges += 1
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        except OSError:
            pass

    for item in manifest["patched_files"]:
        _verify_direct_target_file(target_paths[item["path"]], item, expected_replacement=False)

    return RollbackResult(
        target_root=str(root),
        rollback_path=str(rollback),
        restored_file_count=len(manifest["patched_files"]),
        restored_range_count=restored_ranges,
        restored_bytes=restored_bytes,
        verification="REREAD_SOURCE_CONTROL_AND_ORIGINAL_PATCH_BYTES_MATCHED",
        created_at_utc=_utc_now(),
    )
