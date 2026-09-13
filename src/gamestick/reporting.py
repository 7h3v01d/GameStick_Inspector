from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
import zipfile
from pathlib import Path

from .models import ProbeReport
from .imaging import revalidate_probe_source_identity
from .safety import (
    BoundOutputVolume,
    assert_output_outside_source_disk,
    bind_output_volume,
    secure_stage_on_bound_volume,
)


def _json_bytes(report: ProbeReport) -> bytes:
    return (
        json.dumps(report.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def render_text_summary(report: ProbeReport) -> str:
    mapping = report.physical_mapping
    lines = [
        "GameStick Inspector forensic summary",
        "===================================",
        f"Generated UTC: {report.generated_at_utc}",
        f"Probe status: {report.probe_status}",
        f"Selected root: {report.selected_root}",
        f"Profile: {report.profile.display_name}",
        f"Profile confidence: {report.profile.confidence} ({report.profile.score}%)",
        f"Structure SHA-256: {report.structure_sha256}",
        "",
        "Physical mapping",
        "----------------",
        f"Disk / partition: {mapping.disk_number} / {mapping.partition_number}",
        f"Disk name: {mapping.disk_name or 'Unknown'}",
        f"Bus: {mapping.bus_type or 'Unknown'}",
        f"Partition style: {mapping.partition_style or 'Unknown'}",
        f"Filesystem: {mapping.filesystem or 'Unknown'}",
        f"Filesystem label: {mapping.filesystem_label or 'Unknown'}",
        f"Disk size: {mapping.disk_size if mapping.disk_size is not None else 'Unknown'}",
        f"Logical / physical sector size: {mapping.logical_sector_size or 'Unknown'} / "
        f"{mapping.physical_sector_size or 'Unknown'}",
        f"Host read-only flag: {mapping.is_read_only}",
        f"Boot / system: {mapping.is_boot} / {mapping.is_system}",
        "",
        f"Partitions discovered: {len(mapping.partitions)}",
    ]
    for part in mapping.partitions:
        lines.append(
            f"  #{part.partition_number}: drive={part.drive_letter or '-'} offset={part.offset} "
            f"size={part.size} fs={part.filesystem or '-'} label={part.filesystem_label or '-'}"
        )

    lines += [
        "",
        f"Metadata/config candidates: {len(report.candidate_artifacts)}",
    ]
    for artifact in report.candidate_artifacts:
        lines.append(
            f"  {artifact.path} | {artifact.format_name or 'unknown'} | {artifact.size} bytes | "
            f"sha256={artifact.sha256 or 'not-hashed'}"
        )

    lines += ["", f"Directory snapshots: {len(report.directory_snapshots)}"]
    for snapshot in report.directory_snapshots:
        lines.append(
            f"  {snapshot.path}: dirs={len(snapshot.directory_names)} sampled={snapshot.entries_sampled} "
            f"truncated={snapshot.truncated} filenames_redacted={snapshot.file_names_redacted}"
        )
        if snapshot.directory_names:
            lines.append("    child dirs: " + ", ".join(snapshot.directory_names[:80]))

    if report.read_errors:
        lines += ["", "Filesystem read issues (non-fatal)", "----------------------------------"]
        lines.extend(f"- {error}" for error in report.read_errors)
    if report.warnings:
        lines += ["", "Warnings", "--------"]
        lines.extend(f"- {warning}" for warning in report.warnings)
    return "\n".join(lines) + "\n"


def _legacy_predictable_temp(path: Path) -> Path:
    """Return the temp name used by pre-alpha3 exporters.

    Alpha3 never writes to this predictable name. Refusing if it exists makes an
    old/staged object (including a symlink) explicit rather than accidentally
    trusting or overwriting it.
    """
    return path.with_suffix(path.suffix + ".tmp")


def _refuse_legacy_temp_object(path: Path) -> None:
    legacy = _legacy_predictable_temp(path)
    if os.path.lexists(legacy):
        raise ValueError(
            f"Refusing export because a legacy predictable temporary object exists: {legacy}. "
            "Inspect/remove it manually before retrying; it will never be overwritten."
        )


def _secure_temp_file(path: Path):
    """Portable non-Windows exclusive staging beside the destination."""
    fd, name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    return fd, Path(name)


def _prepare_export(
    report: ProbeReport,
    destination: str | Path,
    *,
    host_system: str | None = None,
    mapping_resolver=None,
    destination_disk_resolver=None,
    volume_root_resolver=None,
    volume_disk_resolver=None,
) -> tuple[Path, BoundOutputVolume | None]:
    """Freshly bind source identity and destination volume before any write."""
    system = host_system or platform.system()

    # On Windows, stale/unknown source identity is never allowed to degrade to
    # path-only output protection. Revalidation happens before mkdir/mkstemp.
    if system == "Windows":
        revalidate_probe_source_identity(report, mapping_resolver=mapping_resolver)

    binding = bind_output_volume(
        destination,
        report.selected_root,
        source_disk_number=report.physical_mapping.disk_number,
        host_system=system,
        destination_disk_resolver=destination_disk_resolver,
        volume_root_resolver=volume_root_resolver,
        volume_disk_resolver=volume_disk_resolver,
    )
    if binding is not None:
        path = binding.final_path
        # Do not create a user-supplied Windows parent after validation: an
        # indirection could redirect that metadata write onto the source device.
        if not path.parent.exists() or not path.parent.is_dir():
            raise ValueError(
                "Windows export destination parent must already exist; automatic directory creation is disabled "
                "to preserve the zero-write source invariant."
            )
    else:
        path = assert_output_outside_source_disk(
            destination,
            report.selected_root,
            source_disk_number=report.physical_mapping.disk_number,
            host_system=system,
            destination_disk_resolver=destination_disk_resolver,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
    return path, binding


def _make_stage(path: Path, binding: BoundOutputVolume | None):
    if binding is not None:
        return secure_stage_on_bound_volume(binding, suffix=path.suffix + ".tmp")
    return _secure_temp_file(path)


def _revalidate_export_boundary(
    report: ProbeReport,
    path: Path,
    original_binding: BoundOutputVolume | None,
    *,
    host_system: str | None = None,
    mapping_resolver=None,
    destination_disk_resolver=None,
    volume_root_resolver=None,
    volume_disk_resolver=None,
) -> None:
    """Revalidate source and final destination immediately before promotion."""
    system = host_system or platform.system()
    if system == "Windows":
        revalidate_probe_source_identity(report, mapping_resolver=mapping_resolver)

    current = bind_output_volume(
        path,
        report.selected_root,
        source_disk_number=report.physical_mapping.disk_number,
        host_system=system,
        destination_disk_resolver=destination_disk_resolver,
        volume_root_resolver=volume_root_resolver,
        volume_disk_resolver=volume_disk_resolver,
    )
    if original_binding is None:
        if current is not None:
            raise ValueError("Export destination binding changed unexpectedly; output refused.")
        return
    if current is None:
        raise ValueError("Export destination lost its Windows volume binding; output refused.")
    if (
        current.destination_disk_number != original_binding.destination_disk_number
        or current.drive_letter != original_binding.drive_letter
        or current.volume_root.casefold() != original_binding.volume_root.casefold()
        or current.final_path != original_binding.final_path
    ):
        raise ValueError(
            "Export destination identity changed after staging; output refused. Choose a stable local destination."
        )


def write_probe_report(
    report: ProbeReport,
    destination: str | Path,
    *,
    host_system: str | None = None,
    mapping_resolver=None,
    destination_disk_resolver=None,
    volume_root_resolver=None,
    volume_disk_resolver=None,
) -> Path:
    path, binding = _prepare_export(
        report,
        destination,
        host_system=host_system,
        mapping_resolver=mapping_resolver,
        destination_disk_resolver=destination_disk_resolver,
        volume_root_resolver=volume_root_resolver,
        volume_disk_resolver=volume_disk_resolver,
    )
    _refuse_legacy_temp_object(path)

    fd, temp = _make_stage(path, binding)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(_json_bytes(report))
            handle.flush()
            os.fsync(handle.fileno())
        _revalidate_export_boundary(
            report,
            path,
            binding,
            host_system=host_system,
            mapping_resolver=mapping_resolver,
            destination_disk_resolver=destination_disk_resolver,
            volume_root_resolver=volume_root_resolver,
            volume_disk_resolver=volume_disk_resolver,
        )
        # Windows staging lives on the bound safe volume root. If the final
        # pathname was redirected to another volume, os.replace fails rather
        # than copying the staged bytes across that boundary.
        os.replace(temp, path)
    except Exception:
        if os.path.lexists(temp):
            try:
                temp.unlink()
            except OSError:
                pass
        raise
    return path


def write_evidence_bundle(
    report: ProbeReport,
    destination: str | Path,
    *,
    host_system: str | None = None,
    mapping_resolver=None,
    destination_disk_resolver=None,
    volume_root_resolver=None,
    volume_disk_resolver=None,
) -> Path:
    path, binding = _prepare_export(
        report,
        destination,
        host_system=host_system,
        mapping_resolver=mapping_resolver,
        destination_disk_resolver=destination_disk_resolver,
        volume_root_resolver=volume_root_resolver,
        volume_disk_resolver=volume_disk_resolver,
    )
    _refuse_legacy_temp_object(path)

    report_bytes = _json_bytes(report)
    summary_bytes = render_text_summary(report).encode("utf-8")
    manifest = {
        "bundle_schema_version": 1,
        "source_probe_schema_version": report.schema_version,
        "files": {
            "gamestick_probe.json": {
                "sha256": hashlib.sha256(report_bytes).hexdigest(),
                "size": len(report_bytes),
            },
            "SUMMARY.txt": {
                "sha256": hashlib.sha256(summary_bytes).hexdigest(),
                "size": len(summary_bytes),
            },
        },
    }
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    fd, temp = _make_stage(path, binding)
    try:
        with os.fdopen(fd, "w+b") as handle:
            with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("gamestick_probe.json", report_bytes)
                archive.writestr("SUMMARY.txt", summary_bytes)
                archive.writestr("MANIFEST.json", manifest_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        _revalidate_export_boundary(
            report,
            path,
            binding,
            host_system=host_system,
            mapping_resolver=mapping_resolver,
            destination_disk_resolver=destination_disk_resolver,
            volume_root_resolver=volume_root_resolver,
            volume_disk_resolver=volume_disk_resolver,
        )
        os.replace(temp, path)
    except Exception:
        if os.path.lexists(temp):
            try:
                temp.unlink()
            except OSError:
                pass
        raise
    return path

