from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QInputDialog,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .browser_model import safe_browser_listing
from .fs_safety import ForensicPathError, assert_contained_non_reparse, lstat_non_reparse
from .imaging import create_raw_image, preflight_physical_image, sha256_file
from .image_consistency import compare_full_images
from .fast_image_lab import compare_fast_structures
from .catalogue_image_lab import compare_catalogue_controls
from .repair_workspace import build_repair_workspace
from .rom_customization import build_hide_rom_workspace
from .rom_manager import scan_rom_manager
from .custom_apply import apply_customization_workspace, expected_confirmation, rollback_customization, verify_rollback_receipt_for_rom
from .probe import find_candidate_volumes, inspect_volume
from .reporting import write_evidence_bundle, write_probe_report
from .windows_privilege import is_process_elevated, relaunch_current_app_elevated

VERSION = "0.5.0-alpha17"
_BROWSER_PER_DIRECTORY_LIMIT = 1000
_BROWSER_TOTAL_NODE_LIMIT = 5000


def _fmt_bytes(value):
    if value is None:
        return "Unknown"
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{amount:.2f} TiB"


def _detail_text(details: dict) -> str:
    if not details:
        return ""
    text = json.dumps(details, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return text if len(text) <= 500 else text[:497] + "..."


class InspectorTab(QWidget):
    report_invalidated = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.report = None
        self._report_inputs = None
        layout = QVBoxLayout(self)

        safety = QLabel(
            "SAFETY-FIRST BUILD — raw restore, format, firmware flash and ROM-payload add/remove remain disabled. "
            "Host-side overlays remain non-destructive; the Customise page can apply only pre-attested launcher-control "
            "byte ranges to an explicitly confirmed TEST/CLONE card, with rollback-before-write and reread verification."
        )
        safety.setWordWrap(True)
        safety.setStyleSheet("font-weight: bold; padding: 8px; border: 1px solid #888;")
        layout.addWidget(safety)

        select_group = QGroupBox("GameStick Volume")
        select_layout = QVBoxLayout(select_group)
        row = QHBoxLayout()
        self.path = QLineEdit()
        self.path.setPlaceholderText("Select the mounted GameStick volume...")
        browse = QPushButton("Browse...")
        browse.clicked.connect(self.browse)
        detect = QPushButton("Auto-detect")
        detect.clicked.connect(self.auto_detect)
        probe = QPushButton("Probe Read-Only")
        probe.clicked.connect(self.probe)
        row.addWidget(self.path, 1)
        row.addWidget(browse)
        row.addWidget(detect)
        row.addWidget(probe)
        select_layout.addLayout(row)

        baseline_row = QHBoxLayout()
        baseline_label = QLabel("Optional prior evidence baseline:")
        self.baseline = QLineEdit()
        self.baseline.setPlaceholderText("Select prior gamestick_evidence.zip or gamestick_probe.json...")
        baseline_browse = QPushButton("Baseline...")
        baseline_browse.clicked.connect(self.browse_baseline)
        baseline_clear = QPushButton("Clear")
        baseline_clear.clicked.connect(self.baseline.clear)
        baseline_row.addWidget(baseline_label)
        baseline_row.addWidget(self.baseline, 1)
        baseline_row.addWidget(baseline_browse)
        baseline_row.addWidget(baseline_clear)
        select_layout.addLayout(baseline_row)

        self.probe_input_state = QLabel("No probe has been run for the current inputs.")
        self.probe_input_state.setWordWrap(True)
        select_layout.addWidget(self.probe_input_state)
        layout.addWidget(select_group)

        self.path.textChanged.connect(self._probe_inputs_changed)
        self.baseline.textChanged.connect(self._probe_inputs_changed)

        self.summary = QTextEdit()
        self.summary.setReadOnly(True)
        self.summary.setMinimumHeight(155)
        layout.addWidget(self.summary)

        self.partitions = QTreeWidget()
        self.partitions.setHeaderLabels(["Partition", "Drive", "Offset", "Size", "Filesystem", "Label", "Boot", "System"])
        self.partitions.setMaximumHeight(155)
        layout.addWidget(self.partitions)

        self.artifacts = QTreeWidget()
        self.artifacts.setHeaderLabels(["Candidate metadata/index", "Format", "Size", "SHA-256", "Schema/details"])
        layout.addWidget(self.artifacts, 1)

        export_row = QHBoxLayout()
        export_json = QPushButton("Export Diagnostic JSON")
        export_json.clicked.connect(self.export_report)
        export_bundle = QPushButton("Export Evidence Bundle (.zip)")
        export_bundle.clicked.connect(self.export_bundle)
        export_row.addWidget(export_json)
        export_row.addWidget(export_bundle)
        layout.addLayout(export_row)


    def _current_probe_inputs(self):
        return (self.path.text().strip(), self.baseline.text().strip())

    def _probe_inputs_changed(self):
        if self.report is None:
            return
        if self._report_inputs == self._current_probe_inputs():
            return
        self.report = None
        self._report_inputs = None
        self.probe_input_state.setText(
            "Probe inputs changed. Run Probe Read-Only again before viewing or exporting evidence."
        )
        self.probe_input_state.setStyleSheet("font-weight: bold;")
        self.report_invalidated.emit()

    def has_current_report(self) -> bool:
        return self.report is not None and self._report_inputs == self._current_probe_inputs()

    def browse(self):
        selected = QFileDialog.getExistingDirectory(self, "Select mounted GameStick volume")
        if selected:
            self.path.setText(selected)

    def browse_baseline(self):
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "Select prior GameStick evidence baseline",
            "",
            "GameStick Evidence (*.zip *.json);;ZIP Archives (*.zip);;JSON Files (*.json)",
        )
        if selected:
            self.baseline.setText(selected)

    def auto_detect(self):
        candidates = find_candidate_volumes()
        if not candidates:
            QMessageBox.information(self, "No candidate", "No GameStick-like mounted volume was detected.")
            return
        root, match = candidates[0]
        self.path.setText(str(root))
        QMessageBox.information(
            self,
            "Candidate detected",
            f"Selected {root}\nProfile: {match.display_name}\nHeuristic score: {match.score}/100\nConfidence band: {match.confidence}",
        )

    def probe(self):
        selected_root = self.path.text().strip()
        selected_baseline = self.baseline.text().strip()
        try:
            report = inspect_volume(
                selected_root,
                baseline_evidence=(selected_baseline or None),
            )
        except Exception as exc:
            QMessageBox.critical(self, "Probe failed", str(exc))
            return

        if (
            selected_baseline
            and report.numbered_dat_profile is not None
            and not report.numbered_dat_profile.longitudinal_integrity
        ):
            QMessageBox.critical(
                self,
                "Baseline comparison missing",
                "A prior-evidence baseline was selected, but the completed numbered-DAT probe did not "
                "contain a longitudinal comparison result. The report has not been accepted or exported. "
                "Please retry; if this persists, treat it as a software defect.",
            )
            return

        self.report = report
        self._report_inputs = (selected_root, selected_baseline)
        if selected_baseline:
            longitudinal = report.numbered_dat_profile.longitudinal_integrity if report.numbered_dat_profile else {}
            baseline_status = longitudinal.get("baseline_status", "NOT_APPLICABLE") if longitudinal else "NOT_APPLICABLE"
            self.probe_input_state.setText(f"Current report includes selected baseline: {baseline_status}.")
        else:
            self.probe_input_state.setText("Current report was generated without a longitudinal baseline.")
        self.probe_input_state.setStyleSheet("")
        mapping = report.physical_mapping
        lines = [
            f"Probe status: {report.probe_status}",
            f"Selected root: {report.selected_root}",
            f"Profile: {report.profile.display_name}",
            f"Confidence band: {report.profile.confidence}   Heuristic score: {report.profile.score}/100",
            f"Volume size: {_fmt_bytes(report.volume_total)}   Free: {_fmt_bytes(report.volume_free)}",
            f"Filesystem: {mapping.filesystem or 'Unknown'}   Label: {mapping.filesystem_label or 'Unknown'}",
            f"Structure SHA-256: {report.structure_sha256}",
            f"Disk / partition: {mapping.disk_number if mapping.disk_number is not None else '?'} / "
            f"{mapping.partition_number if mapping.partition_number is not None else '?'}",
            f"Disk: {mapping.disk_name or 'Unknown'}   Bus: {mapping.bus_type or 'Unknown'}   "
            f"Style: {mapping.partition_style or 'Unknown'}",
            f"Disk size: {_fmt_bytes(mapping.disk_size)}   Sectors: "
            f"{mapping.logical_sector_size or '?'} logical / {mapping.physical_sector_size or '?'} physical",
            f"Host flags: read-only={mapping.is_read_only} offline={mapping.is_offline} "
            f"boot={mapping.is_boot} system={mapping.is_system}",
            f"Mapping backend: {mapping.mapping_backend or 'Unavailable'}",
        ]
        if mapping.mapping_error:
            lines.append(f"Mapping note: {mapping.mapping_error}")
        if report.numbered_dat_profile is not None and report.numbered_dat_profile.longitudinal_integrity:
            longitudinal = report.numbered_dat_profile.longitudinal_integrity
            lines.append(
                f"Longitudinal baseline: {longitudinal.get('baseline_status', 'unknown')}"
            )
        if report.read_errors:
            lines.append(f"\nFilesystem read issues: {len(report.read_errors)} (non-fatal; probe continued)")
        if report.warnings:
            lines.append("\nWarnings:")
            lines.extend(f"- {warning}" for warning in report.warnings)
        self.summary.setPlainText("\n".join(lines))

        if report.probe_status == "DEGRADED":
            QMessageBox.warning(
                self,
                "Probe completed with filesystem errors",
                "The safety/device probe completed, but some filesystem objects could not be read. "
                "They were skipped and recorded as evidence. Recovery & Images remains available if its independent "
                "safety preflight passes.\n\n"
                f"Recorded read issues: {len(report.read_errors)}",
            )

        self.partitions.clear()
        for partition in mapping.partitions:
            QTreeWidgetItem(
                self.partitions,
                [
                    str(partition.partition_number if partition.partition_number is not None else "?"),
                    partition.drive_letter or "-",
                    _fmt_bytes(partition.offset),
                    _fmt_bytes(partition.size),
                    partition.filesystem or "-",
                    partition.filesystem_label or "-",
                    str(partition.is_boot),
                    str(partition.is_system),
                ],
            )
        for column in range(8):
            self.partitions.resizeColumnToContents(column)

        self.artifacts.clear()
        for artifact in report.candidate_artifacts:
            QTreeWidgetItem(
                self.artifacts,
                [
                    artifact.path,
                    artifact.format_name or "unknown",
                    _fmt_bytes(artifact.size),
                    artifact.sha256 or "(not hashed: large file)",
                    _detail_text(artifact.details),
                ],
            )
        self.artifacts.resizeColumnToContents(0)
        self.artifacts.resizeColumnToContents(1)

    def export_report(self):
        if not self.has_current_report():
            QMessageBox.warning(self, "Nothing current to export", "Run Probe Read-Only for the currently selected device/baseline first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save diagnostic report", "gamestick_probe.json", "JSON Files (*.json)"
        )
        if not path:
            return
        try:
            saved = write_probe_report(self.report, path)
            QMessageBox.information(self, "Saved", f"Diagnostic report saved to:\n{saved}")
        except Exception as exc:
            QMessageBox.critical(self, "Save failed", str(exc))

    def export_bundle(self):
        if not self.has_current_report():
            QMessageBox.warning(self, "Nothing current to export", "Run Probe Read-Only for the currently selected device/baseline first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save evidence bundle", "gamestick_evidence.zip", "ZIP Archives (*.zip)"
        )
        if not path:
            return
        if not path.lower().endswith(".zip"):
            path += ".zip"
        try:
            saved = write_evidence_bundle(self.report, path)
            QMessageBox.information(
                self,
                "Evidence bundle saved",
                "Saved a structural evidence bundle containing JSON, a text summary and an integrity manifest.\n\n"
                f"{saved}\n\nNo files were copied from the GameStick into the bundle.",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Save failed", str(exc))


class StructureTab(QWidget):
    def __init__(self, inspector: InspectorTab):
        super().__init__()
        self.inspector = inspector
        self.inspector.report_invalidated.connect(self.clear_view)
        layout = QVBoxLayout(self)
        note = QLabel(
            "Structural evidence only. ROM/artwork/numbered-catalogue names are privacy-redacted; the 0.5 DAT inspector "
            "exports only bounded container structure and canonical control-member semantics."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        refresh = QPushButton("Show Latest Probe Structure")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)

        self.profiles = QTreeWidget()
        self.profiles.setHeaderLabels(["Profile candidate", "Heuristic score (/100)", "Confidence", "Matched", "Missing"])
        self.profiles.setMaximumHeight(160)
        layout.addWidget(self.profiles)

        self.device_profile = QTextEdit()
        self.device_profile.setReadOnly(True)
        self.device_profile.setMaximumHeight(145)
        layout.addWidget(self.device_profile)

        self.dat_profile = QTextEdit()
        self.dat_profile.setReadOnly(True)
        self.dat_profile.setMaximumHeight(145)
        layout.addWidget(self.dat_profile)

        self.dat_containers = QTreeWidget()
        self.dat_containers.setHeaderLabels([
            "Numbered-DAT catalogue", "Role", "Container", "Members", "Control members",
            "Member extensions", "Binary header", "Sampled signatures", "Entropy"
        ])
        self.dat_containers.setMaximumHeight(190)
        layout.addWidget(self.dat_containers)

        self.consistency = QTreeWidget()
        self.consistency.setHeaderLabels([
            "Catalogue", "Audit status", "Readable files", "Unreadable/rejected",
            "Local unique", "Global unique", "Present+local+global",
            "Local missing from observed FS", "Physical not local", "Local not global",
            "Resolved in other catalogues", "Still unresolved", "Primary alias", "Alias resolution"
        ])
        self.consistency.setMaximumHeight(190)
        layout.addWidget(self.consistency)

        self.stability = QTreeWidget()
        self.stability.setHeaderLabels([
            "DAT", "Read status", "Control assessment", "Regions", "Stable", "Unstable", "Incomplete", "Size stable"
        ])
        self.stability.setMaximumHeight(170)
        layout.addWidget(self.stability)

        self.longitudinal = QTreeWidget()
        self.longitudinal.setHeaderLabels([
            "DAT", "Baseline status", "Current read", "Prefix", "Tail", "Structure"
        ])
        self.longitudinal.setMaximumHeight(175)
        layout.addWidget(self.longitudinal)

        self.launchers = QTreeWidget()
        self.launchers.setHeaderLabels(["Launcher/index candidate", "Format", "Heuristic score (/100)", "Confidence", "Roles", "Evidence"])
        self.launchers.setMaximumHeight(190)
        layout.addWidget(self.launchers)

        self.content_roots = QTreeWidget()
        self.content_roots.setHeaderLabels(["Content root", "Role", "Heuristic score (/100)", "Evidence"])
        self.content_roots.setMaximumHeight(160)
        layout.addWidget(self.content_roots)

        self.snapshots = QTreeWidget()
        self.snapshots.setHeaderLabels(["Directory", "Child directories", "File extensions", "Sampled", "Truncated", "Filenames redacted"])
        layout.addWidget(self.snapshots, 1)

    def clear_view(self):
        self.profiles.clear()
        self.device_profile.clear()
        self.dat_profile.clear()
        self.dat_containers.clear()
        self.consistency.clear()
        self.stability.clear()
        self.longitudinal.clear()
        self.launchers.clear()
        self.content_roots.clear()
        self.snapshots.clear()

    def refresh(self):
        if not self.inspector.has_current_report():
            self.clear_view()
            QMessageBox.information(
                self,
                "Probe required",
                "The device path or baseline selection has changed. Run Probe Read-Only in Device Inspector first.",
            )
            return
        report = self.inspector.report
        self.profiles.clear()
        for match in report.profile_candidates:
            QTreeWidgetItem(
                self.profiles,
                [
                    match.display_name,
                    str(match.score),
                    match.confidence,
                    ", ".join(match.matched_markers),
                    ", ".join(match.missing_markers),
                ],
            )
        discovery = report.device_profile_candidate
        dat_profile = report.numbered_dat_profile
        self.launchers.clear()
        self.content_roots.clear()
        self.dat_containers.clear()
        self.consistency.clear()
        self.stability.clear()
        self.longitudinal.clear()
        if dat_profile is None:
            self.dat_profile.setPlainText("Numbered-DAT firmware profile: not detected in bounded root evidence.")
        else:
            root_control_summary = {}
            if dat_profile.root_catalog is not None:
                controls = dat_profile.root_catalog.details.get("control_summaries", {})
                if isinstance(controls, dict):
                    candidate = controls.get("fileinfo.txt", {})
                    if isinstance(candidate, dict):
                        root_control_summary = candidate
            filelist_valid = 0
            filelist_malformed = 0
            artwork_matches = 0
            for row in dat_profile.numbered_catalogs:
                controls = row.details.get("control_summaries", {})
                if not isinstance(controls, dict):
                    continue
                summary = controls.get("filelist.txt", {})
                if not isinstance(summary, dict):
                    continue
                filelist_valid += int(summary.get("valid_record_count") or 0)
                filelist_malformed += int(summary.get("malformed_record_count") or 0)
                artwork_matches += int(summary.get("catalogue_records_with_artwork_count") or 0)
            self.dat_profile.setPlainText(
                "\n".join([
                    f"Numbered-DAT profile: {dat_profile.candidate_id}",
                    f"Status: {dat_profile.status}   Confidence: {dat_profile.confidence}   Heuristic score: {dat_profile.heuristic_score}/100",
                    f"root.dat present: {dat_profile.root_dat_present}",
                    f"Numbered roots / matching DATs: {dat_profile.numbered_directory_count} / {dat_profile.matched_numbered_dat_count}",
                    f"Central-directory-readable numbered DATs: {dat_profile.zip_numbered_dat_count}",
                    f"WQW numbered DATs: {dat_profile.wqw_numbered_dat_count}",
                    f"Damaged/incomplete WQW numbered DATs: {dat_profile.damaged_wqw_numbered_dat_count}",
                    f"Verified filelist.txt controls observed: {dat_profile.filelist_control_count}",
                    f"fileinfo.txt valid / malformed physical records: {root_control_summary.get('valid_record_count', 0)} / {root_control_summary.get('malformed_record_count', 0)}",
                    f"filelist.txt valid / malformed records (inspected): {filelist_valid} / {filelist_malformed}",
                    f"ROM-stem / artwork matches (inspected): {artwork_matches}",
                    f"Binary family assessment: {dat_profile.binary_family_assessment}",
                    f"Binary fingerprints captured: {dat_profile.binary_fingerprint_count}",
                    f"Common exact numbered-DAT prefix bucket: {dat_profile.numbered_catalog_common_prefix_bytes} bytes",
                    f"root.dat matches all numbered DATs through: {dat_profile.root_matches_numbered_prefix_bytes} bytes",
                    f"Common exact header signatures: {', '.join(dat_profile.common_header_signatures) or 'none observed'}",
                    f"Common allowlisted sampled signatures: {', '.join(dat_profile.common_sampled_signatures) or 'none observed'}",
                    f"Global/platform correlation matches: {dat_profile.catalogue_relationships.get('global_filelist_unique_match_count', 0)} / {dat_profile.catalogue_relationships.get('filelist_unique_rom_name_count', 0)} inspected filelist names",
                    "Consistency audit status counts: " + ", ".join(
                        f"{key}={value}" for key, value in dat_profile.catalogue_consistency.get("status_counts", {}).items()
                    ) if dat_profile.catalogue_consistency else "Consistency audit: unavailable",
                    "Read-stability status counts: " + ", ".join(
                        f"{key}={value}" for key, value in dat_profile.read_stability.get("status_counts", {}).items()
                    ) if dat_profile.read_stability else "Read stability: unavailable",
                    "Longitudinal baseline status: " + str(dat_profile.longitudinal_integrity.get("baseline_status", "not provided"))
                    if dat_profile.longitudinal_integrity else "Longitudinal baseline: not provided",
                    "Longitudinal comparison statuses: " + ", ".join(
                        f"{key}={value}" for key, value in dat_profile.longitudinal_integrity.get("status_counts", {}).items()
                    ) if dat_profile.longitudinal_integrity and dat_profile.longitudinal_integrity.get("status_counts") else "Longitudinal comparison: unavailable",
                    f"Cross-catalogue names resolved elsewhere: {dat_profile.catalogue_consistency.get('total_cross_catalogue_resolved_unique_name_count', 0)}" if dat_profile.catalogue_consistency else "Cross-catalogue alias resolution: unavailable",
                    f"Structural signature SHA-256: {dat_profile.structural_signature_sha256}",
                    "Member/media strings are privacy-redacted; DATs are never extracted or fully scanned.",
                ])
            )
            audit_rows = dat_profile.catalogue_consistency.get("by_catalogue_code", {})
            if isinstance(audit_rows, dict):
                for code in sorted(audit_rows):
                    row = audit_rows.get(code, {})
                    if not isinstance(row, dict):
                        continue
                    QTreeWidgetItem(
                        self.consistency,
                        [
                            str(code),
                            str(row.get("audit_status", "?")),
                            str(row.get("readable_content_file_count", 0)),
                            f"{row.get('unreadable_entry_count', 0)}/{row.get('rejected_entry_count', 0)}",
                            str(row.get("filelist_unique_rom_name_count", 0)),
                            str(row.get("global_unique_rom_name_count", 0)),
                            str(row.get("present_local_global_unique_match_count", 0)),
                            str(row.get("filelist_missing_from_filesystem_observation_count", 0)),
                            str(row.get("readable_not_filelist_count", 0)),
                            str(row.get("filelist_unique_missing_from_global_count", 0)),
                            str(row.get("cross_catalogue_resolved_unique_name_count", 0)),
                            str(row.get("cross_catalogue_unresolved_unique_name_count", 0)),
                            str(row.get("cross_catalogue_primary_target_code") or "-"),
                            f"{int(row.get('cross_catalogue_resolution_rate_ppm', 0)) / 10000:.2f}%",
                        ],
                    )

            stability_rows = dat_profile.read_stability.get("by_path", {}) if dat_profile.read_stability else {}
            if isinstance(stability_rows, dict):
                for path in sorted(stability_rows):
                    row = stability_rows.get(path, {})
                    if not isinstance(row, dict):
                        continue
                    QTreeWidgetItem(
                        self.stability,
                        [
                            str(path),
                            str(row.get("status", "?")),
                            str(row.get("control_failure_assessment", "?")),
                            str(row.get("region_count", 0)),
                            str(row.get("stable_region_count", 0)),
                            str(row.get("unstable_region_count", 0)),
                            str(row.get("incomplete_region_count", 0)),
                            str(row.get("size_stable", False)),
                        ],
                    )

            longitudinal_rows = dat_profile.longitudinal_integrity.get("by_path", {}) if dat_profile.longitudinal_integrity else {}
            if isinstance(longitudinal_rows, dict):
                for path in sorted(longitudinal_rows):
                    row = longitudinal_rows.get(path, {})
                    if not isinstance(row, dict):
                        continue
                    QTreeWidgetItem(
                        self.longitudinal,
                        [
                            str(path),
                            str(row.get("status", "?")),
                            str(row.get("current_read_status", "?")),
                            str(row.get("prefix_comparison", "?")),
                            str(row.get("tail_comparison", "?")),
                            str(row.get("structure_comparison", "?")),
                        ],
                    )

            dat_rows = []
            if dat_profile.root_catalog is not None:
                dat_rows.append(dat_profile.root_catalog)
            dat_rows.extend(dat_profile.numbered_catalogs)
            for container in dat_rows:
                ext_text = ", ".join(f"{key}:{value}" for key, value in container.member_extension_counts.items())
                fingerprint = container.binary_fingerprint
                header_text = ", ".join(fingerprint.header_signatures) if fingerprint else "unavailable"
                signal_text = (
                    ", ".join(fingerprint.sampled_signature_hits) if fingerprint else "unavailable"
                )
                entropy_text = (
                    f"{fingerprint.entropy_bits_per_byte:.4f}" if fingerprint else "unavailable"
                )
                QTreeWidgetItem(
                    self.dat_containers,
                    [
                        container.path,
                        container.role,
                        container.container_format,
                        str(container.declared_member_count if container.declared_member_count is not None else "?"),
                        ", ".join(container.control_members) or "none observed",
                        ext_text,
                        header_text or "none observed",
                        signal_text or "none observed",
                        entropy_text,
                    ],
                )
        if discovery is None:
            self.device_profile.setPlainText("Device Profile candidate synthesis unavailable for this probe.")
        else:
            self.device_profile.setPlainText(
                "\n".join([
                    f"Device Profile candidate: {discovery.candidate_id}",
                    f"Status: {discovery.status}",
                    f"Base filesystem profile: {discovery.base_profile_id} (heuristic score {discovery.base_profile_score}/100)",
                    f"Launcher resolution: {discovery.launcher_resolution}",
                    f"Top launcher/index: {discovery.launcher_path or 'unresolved'}",
                    f"Format: {discovery.launcher_format or 'unresolved'}   Confidence: {discovery.launcher_confidence}",
                    f"Profile signature SHA-256: {discovery.profile_signature_sha256}",
                    f"Recognized ROM platform semantics: {', '.join(discovery.platform_directories) or 'none in bounded evidence'}",
                ])
            )
            for candidate in discovery.launcher_candidates:
                QTreeWidgetItem(
                    self.launchers,
                    [
                        candidate.path,
                        candidate.format_name,
                        str(candidate.score),
                        candidate.confidence,
                        ", ".join(candidate.role_hints),
                        "; ".join(candidate.evidence),
                    ],
                )
            for content_root in discovery.content_roots:
                QTreeWidgetItem(
                    self.content_roots,
                    [
                        content_root.path,
                        content_root.role,
                        str(content_root.score),
                        "; ".join(content_root.evidence),
                    ],
                )

        self.snapshots.clear()
        for snapshot in report.directory_snapshots:
            ext_text = ", ".join(f"{key}:{value}" for key, value in snapshot.file_extension_counts.items())
            QTreeWidgetItem(
                self.snapshots,
                [
                    snapshot.path,
                    ", ".join(snapshot.directory_names),
                    ext_text,
                    str(snapshot.entries_sampled),
                    str(snapshot.truncated),
                    str(snapshot.file_names_redacted),
                ],
            )
        self.profiles.resizeColumnToContents(0)
        self.dat_containers.resizeColumnToContents(0)
        self.launchers.resizeColumnToContents(0)
        self.content_roots.resizeColumnToContents(0)
        self.snapshots.resizeColumnToContents(0)


class BrowserTab(QWidget):
    def __init__(self, inspector: InspectorTab):
        super().__init__()
        self.inspector = inspector
        layout = QVBoxLayout(self)
        note = QLabel("Read-only filesystem browser. It does not add, remove, rename or edit files.")
        note.setWordWrap(True)
        layout.addWidget(note)
        refresh = QPushButton("Load Root Tree")
        refresh.clicked.connect(self.load)
        layout.addWidget(refresh)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Type / size"])
        layout.addWidget(self.tree, 1)
        self.inspector.report_invalidated.connect(self.clear_view)

    def clear_view(self):
        """Clear stale browser results when Device Inspector inputs change."""
        self.tree.clear()
        self._browser_nodes_remaining = 0

    def load(self):
        root_text = self.inspector.path.text().strip()
        if not root_text:
            QMessageBox.warning(self, "No volume", "Select a mounted volume in Device Inspector first.")
            return
        root = Path(root_text)
        try:
            safe_root = assert_contained_non_reparse(root, root)
            st = lstat_non_reparse(safe_root)
            if not stat.S_ISDIR(st.st_mode):
                raise ForensicPathError(f"Selected path is not a directory: {root}")
        except (OSError, ForensicPathError) as exc:
            QMessageBox.warning(self, "Unsafe/unavailable volume", str(exc))
            return
        self.tree.clear()
        self._browser_nodes_remaining = _BROWSER_TOTAL_NODE_LIMIT
        root_item = QTreeWidgetItem(self.tree, [safe_root.name or str(safe_root), "volume"])
        self._populate(root_item, safe_root, safe_root, depth=0)
        root_item.setExpanded(True)

    def _populate(self, parent, root: Path, path: Path, depth: int):
        if depth >= 2 or self._browser_nodes_remaining <= 0:
            return
        per_directory_limit = min(_BROWSER_PER_DIRECTORY_LIMIT, self._browser_nodes_remaining)
        try:
            listing = safe_browser_listing(root, path, limit=per_directory_limit)
        except (OSError, ForensicPathError):
            return

        if listing.error is not None:
            QTreeWidgetItem(
                parent,
                [f"[unable to enumerate directory: {listing.error}]", "filesystem error"],
            )
            return

        for child in listing.entries:
            if self._browser_nodes_remaining <= 0:
                break
            self._browser_nodes_remaining -= 1
            if child.is_directory:
                info = "directory"
            elif child.is_regular_file:
                info = _fmt_bytes(child.size)
            else:
                info = "other"
            item = QTreeWidgetItem(parent, [child.name, info])
            if child.is_directory:
                self._populate(item, root, child.path, depth + 1)

        if listing.truncated:
            QTreeWidgetItem(
                parent,
                [f"[listing truncated at {listing.limit:,} entries]", "bounded sample"],
            )
        if self._browser_nodes_remaining <= 0:
            QTreeWidgetItem(
                parent,
                [f"[browser tree limit reached: {_BROWSER_TOTAL_NODE_LIMIT:,} nodes]", "bounded tree"],
            )


class RawImageThread(QThread):
    progress = pyqtSignal(str, object, object)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, plan, *, second_full_source_read: bool = False):
        super().__init__()
        self.plan = plan
        self.second_full_source_read = second_full_source_read

    def run(self):
        try:
            result = create_raw_image(
                self.plan,
                progress=lambda phase, done, total: self.progress.emit(phase, done, total),
                cancelled=self.isInterruptionRequested,
                second_full_source_read=self.second_full_source_read,
            )
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class FastImageCompareThread(QThread):
    progress = pyqtSignal(str)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, image_a, image_b, report_path):
        super().__init__()
        self.image_a = image_a
        self.image_b = image_b
        self.report_path = report_path

    def run(self):
        try:
            result = compare_fast_structures(
                self.image_a,
                self.image_b,
                report_path=self.report_path,
                progress=self.progress.emit,
                cancelled=self.isInterruptionRequested,
            )
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class CatalogueCompareThread(QThread):
    progress = pyqtSignal(str)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, image_a, image_b, report_path):
        super().__init__()
        self.image_a = image_a
        self.image_b = image_b
        self.report_path = report_path

    def run(self):
        try:
            result = compare_catalogue_controls(
                self.image_a,
                self.image_b,
                report_path=self.report_path,
                progress=self.progress.emit,
                cancelled=self.isInterruptionRequested,
            )
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class RepairWorkspaceThread(QThread):
    progress = pyqtSignal(str)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, golden_image, base_image, output_path, *, overwrite=False):
        super().__init__()
        self.golden_image = golden_image
        self.base_image = base_image
        self.output_path = output_path
        self.overwrite = overwrite

    def run(self):
        try:
            result = build_repair_workspace(
                self.golden_image,
                self.base_image,
                self.output_path,
                overwrite=self.overwrite,
                progress=self.progress.emit,
                cancelled=self.isInterruptionRequested,
            )
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class RomHideWorkspaceThread(QThread):
    progress = pyqtSignal(str)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, source_image, rom_query, output_path, *, overwrite=False):
        super().__init__()
        self.source_image = source_image
        self.rom_query = rom_query
        self.output_path = output_path
        self.overwrite = overwrite

    def run(self):
        try:
            result = build_hide_rom_workspace(
                self.source_image,
                self.rom_query,
                self.output_path,
                overwrite=self.overwrite,
                progress=self.progress.emit,
                cancelled=self.isInterruptionRequested,
            )
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class RomManagerScanThread(QThread):
    progress = pyqtSignal(str)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, reference_image, target_root=None):
        super().__init__()
        self.reference_image = reference_image
        self.target_root = target_root

    def run(self):
        try:
            result = scan_rom_manager(
                self.reference_image,
                self.target_root,
                progress=self.progress.emit,
                cancelled=self.isInterruptionRequested,
            )
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class CustomApplyThread(QThread):
    progress = pyqtSignal(str)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, source_image, workspace, target_root, rollback_path, *, confirmation, overwrite_rollback=False, overwrite_receipt=False):
        super().__init__()
        self.source_image = source_image
        self.workspace = workspace
        self.target_root = target_root
        self.rollback_path = rollback_path
        self.confirmation = confirmation
        self.overwrite_rollback = overwrite_rollback
        self.overwrite_receipt = overwrite_receipt

    def run(self):
        try:
            result = apply_customization_workspace(
                self.source_image,
                self.workspace,
                self.target_root,
                self.rollback_path,
                confirmation=self.confirmation,
                overwrite_rollback=self.overwrite_rollback,
                overwrite_receipt=self.overwrite_receipt,
                progress=self.progress.emit,
                cancelled=self.isInterruptionRequested,
            )
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class CustomRollbackThread(QThread):
    progress = pyqtSignal(str)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, rollback_path, target_root, *, confirmation, receipt_path=None, expected_rom=None, allow_legacy_recovery=False):
        super().__init__()
        self.rollback_path = rollback_path
        self.target_root = target_root
        self.confirmation = confirmation
        self.receipt_path = receipt_path
        self.expected_rom = expected_rom
        self.allow_legacy_recovery = allow_legacy_recovery

    def run(self):
        try:
            result = rollback_customization(
                self.rollback_path,
                self.target_root,
                confirmation=self.confirmation,
                progress=self.progress.emit,
                receipt_path=self.receipt_path,
                expected_rom=self.expected_rom,
                allow_legacy_recovery=self.allow_legacy_recovery,
            )
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class ImageCompareThread(QThread):
    progress = pyqtSignal(object, object)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, image_paths, report_path):
        super().__init__()
        self.image_paths = tuple(image_paths)
        self.report_path = report_path

    def run(self):
        try:
            result = compare_full_images(
                self.image_paths,
                report_path=self.report_path,
                progress=lambda done, total: self.progress.emit(done, total),
                cancelled=self.isInterruptionRequested,
            )
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class RecoveryTab(QWidget):
    def __init__(self, inspector: InspectorTab):
        super().__init__()
        self.inspector = inspector
        self.worker = None
        self.fast_compare_worker = None
        self.fast_compare_images = []
        self.catalogue_compare_worker = None
        self.catalogue_compare_images = []
        self.repair_workspace_worker = None
        self.repair_workspace_images = []
        self.rom_hide_worker = None
        self.rom_hide_image = None
        self.rom_manager_worker = None
        self.rom_manager_rollback_worker = None
        self.rom_manager_entries = ()
        self._rom_manager_summary_base = "Manager not loaded."
        self.custom_apply_worker = None
        self.custom_rollback_worker = None
        self.compare_worker = None
        self.compare_images = []
        layout = QVBoxLayout(self)

        # Recovery used to be one very tall QVBox containing every workflow.
        # As features accumulated Qt compressed each group until the controls were
        # technically visible but practically unreadable. Keep the global safety
        # banner/status fixed, then give each workflow its own page.
        self.workflow_tabs = QTabWidget()
        self.workflow_tabs.setDocumentMode(True)

        def make_workflow_page():
            page = QWidget()
            page_layout = QVBoxLayout(page)
            page_layout.setContentsMargins(0, 0, 0, 0)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            content = QWidget()
            content_layout = QVBoxLayout(content)
            scroll.setWidget(content)
            page_layout.addWidget(scroll)
            return page, content_layout

        imaging_page, imaging_layout = make_workflow_page()
        analysis_page, analysis_layout = make_workflow_page()
        repair_page, repair_page_layout = make_workflow_page()
        customise_page, customise_page_layout = make_workflow_page()
        advanced_page, advanced_layout = make_workflow_page()

        self.workflow_tabs.addTab(imaging_page, "Image & Verify")
        self.workflow_tabs.addTab(analysis_page, "Fast Analysis")
        self.workflow_tabs.addTab(repair_page, "Repair")
        self.workflow_tabs.addTab(customise_page, "Customise")
        self.workflow_tabs.addTab(advanced_page, "Advanced")

        warning = QLabel(
            "Raw READ imaging is now available after a successful device probe. The GameStick is opened read-only. "
            "Raw restore, firmware flashing and ROM-payload writes remain locked. The Customise page contains one explicit "
            "bounded launcher-control write path for a TEST/CLONE card, with host-side rollback and reread verification."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("font-weight: bold; padding: 6px; border: 1px solid #888;")
        layout.addWidget(warning)

        elevation_row = QHBoxLayout()
        self.elevation_status = QLabel()
        self.elevation_status.setWordWrap(True)
        self.elevate_button = QPushButton("Relaunch as Administrator for Raw Imaging")
        self.elevate_button.clicked.connect(self.relaunch_elevated)
        elevation_row.addWidget(self.elevation_status, 1)
        elevation_row.addWidget(self.elevate_button)
        layout.addLayout(elevation_row)
        self._refresh_elevation_status()
        layout.addWidget(self.workflow_tabs, 1)

        create_group = QGroupBox("Create Verified-Transfer Full SD Image — READ-ONLY SOURCE")
        create_layout = QVBoxLayout(create_group)
        self.raw_source = QLabel("Run Device Inspector → Probe Read-Only first.")
        self.raw_source.setWordWrap(True)
        create_layout.addWidget(self.raw_source)

        output_row = QHBoxLayout()
        self.raw_output = QLineEdit()
        self.raw_output.setReadOnly(True)
        choose_output = QPushButton("Choose .img destination...")
        choose_output.clicked.connect(self.select_raw_destination)
        output_row.addWidget(self.raw_output, 1)
        output_row.addWidget(choose_output)
        create_layout.addLayout(output_row)

        self.second_source_read = QCheckBox(
            "After transfer verification, perform a second full READ of the physical source to test static-media consistency"
        )
        self.second_source_read.setChecked(False)
        self.second_source_read.setToolTip(
            "Optional. Doubles the amount of data read from the source. A mismatch is recorded as source instability; "
            "the first transfer-verified image remains valid evidence."
        )
        create_layout.addWidget(self.second_source_read)

        action_row = QHBoxLayout()
        self.create_raw_button = QPushButton("Create & Verify Raw Image")
        self.create_raw_button.clicked.connect(self.create_raw)
        self.cancel_raw_button = QPushButton("Cancel")
        self.cancel_raw_button.setEnabled(False)
        self.cancel_raw_button.clicked.connect(self.cancel_raw)
        action_row.addWidget(self.create_raw_button)
        action_row.addWidget(self.cancel_raw_button)
        create_layout.addLayout(action_row)

        self.raw_progress = QProgressBar()
        self.raw_progress.setRange(0, 100)
        self.raw_progress.setValue(0)
        create_layout.addWidget(self.raw_progress)
        self.raw_status = QTextEdit()
        self.raw_status.setReadOnly(True)
        self.raw_status.setMinimumHeight(120)
        self.raw_status.setMaximumHeight(220)
        create_layout.addWidget(self.raw_status)
        imaging_layout.addWidget(create_group)

        verify_group = QGroupBox("Verify Existing SD Image")
        inner = QVBoxLayout(verify_group)
        row = QHBoxLayout()
        self.image_path = QLineEdit()
        self.image_path.setReadOnly(True)
        browse = QPushButton("Select .img/.bin...")
        browse.clicked.connect(self.select_image)
        row.addWidget(self.image_path, 1)
        row.addWidget(browse)
        inner.addLayout(row)
        verify = QPushButton("Calculate SHA-256")
        verify.clicked.connect(self.verify)
        inner.addWidget(verify)
        self.result = QTextEdit()
        self.result.setReadOnly(True)
        self.result.setMinimumHeight(100)
        self.result.setMaximumHeight(180)
        inner.addWidget(self.result)
        imaging_layout.addWidget(verify_group)

        fast_group = QGroupBox("FAST Image Lab — Golden vs Original (metadata/control files only)")
        fast_layout = QVBoxLayout(fast_group)
        fast_note = QLabel(
            "Recommended path. Reads FAT32 directory metadata plus small launcher/control files only — "
            "it does NOT scan/hash the complete 60 GB images."
        )
        fast_note.setWordWrap(True)
        fast_layout.addWidget(fast_note)
        self.fast_compare_selection = QLabel("No images selected. Select the golden SanDisk image and original_read1 image.")
        self.fast_compare_selection.setWordWrap(True)
        fast_layout.addWidget(self.fast_compare_selection)
        fast_select = QPushButton("Select Golden + Original Images...")
        fast_select.clicked.connect(self.select_fast_compare_images)
        fast_layout.addWidget(fast_select)

        fast_report_row = QHBoxLayout()
        self.fast_compare_report = QLineEdit()
        self.fast_compare_report.setReadOnly(True)
        fast_report_button = QPushButton("Choose fast report .json...")
        fast_report_button.clicked.connect(self.select_fast_compare_report)
        fast_report_row.addWidget(self.fast_compare_report, 1)
        fast_report_row.addWidget(fast_report_button)
        fast_layout.addLayout(fast_report_row)

        fast_actions = QHBoxLayout()
        self.fast_compare_button = QPushButton("FAST Compare Structure + Launcher Controls")
        self.fast_compare_button.clicked.connect(self.run_fast_compare_images)
        self.cancel_fast_compare_button = QPushButton("Cancel")
        self.cancel_fast_compare_button.setEnabled(False)
        self.cancel_fast_compare_button.clicked.connect(self.cancel_fast_compare_images)
        fast_actions.addWidget(self.fast_compare_button)
        fast_actions.addWidget(self.cancel_fast_compare_button)
        fast_layout.addLayout(fast_actions)
        self.fast_compare_result = QTextEdit()
        self.fast_compare_result.setReadOnly(True)
        self.fast_compare_result.setMinimumHeight(110)
        self.fast_compare_result.setMaximumHeight(190)
        fast_layout.addWidget(self.fast_compare_result)
        analysis_layout.addWidget(fast_group)

        catalogue_group = QGroupBox("SURGICAL Catalogue Lab — RECOMMENDED NEXT")
        catalogue_layout = QVBoxLayout(catalogue_group)
        catalogue_note = QLabel(
            "Reads only the WQW central directory plus filelist.txt from 000-014 and fileinfo.txt from ROOT.DAT. "
            "ROM payloads and artwork are never scanned. Designed for seconds/minutes, not hours."
        )
        catalogue_note.setWordWrap(True)
        catalogue_layout.addWidget(catalogue_note)
        self.catalogue_compare_selection = QLabel("No images selected. Select golden/reference + original_read1.")
        self.catalogue_compare_selection.setWordWrap(True)
        catalogue_layout.addWidget(self.catalogue_compare_selection)
        catalogue_select = QPushButton("Select Golden + Original Images...")
        catalogue_select.clicked.connect(self.select_catalogue_compare_images)
        catalogue_layout.addWidget(catalogue_select)

        catalogue_report_row = QHBoxLayout()
        self.catalogue_compare_report = QLineEdit()
        self.catalogue_compare_report.setReadOnly(True)
        catalogue_report_button = QPushButton("Choose catalogue report .json...")
        catalogue_report_button.clicked.connect(self.select_catalogue_compare_report)
        catalogue_report_row.addWidget(self.catalogue_compare_report, 1)
        catalogue_report_row.addWidget(catalogue_report_button)
        catalogue_layout.addLayout(catalogue_report_row)

        catalogue_actions = QHBoxLayout()
        self.catalogue_compare_button = QPushButton("Compare 000-014 Catalogues — Surgical")
        self.catalogue_compare_button.clicked.connect(self.run_catalogue_compare_images)
        self.cancel_catalogue_compare_button = QPushButton("Cancel")
        self.cancel_catalogue_compare_button.setEnabled(False)
        self.cancel_catalogue_compare_button.clicked.connect(self.cancel_catalogue_compare_images)
        catalogue_actions.addWidget(self.catalogue_compare_button)
        catalogue_actions.addWidget(self.cancel_catalogue_compare_button)
        catalogue_layout.addLayout(catalogue_actions)
        self.catalogue_compare_result = QTextEdit()
        self.catalogue_compare_result.setReadOnly(True)
        self.catalogue_compare_result.setMinimumHeight(110)
        self.catalogue_compare_result.setMaximumHeight(210)
        catalogue_layout.addWidget(self.catalogue_compare_result)
        analysis_layout.addWidget(catalogue_group)

        repair_group = QGroupBox("FAST Repair Workspace — Host-side overlay only")
        repair_layout = QVBoxLayout(repair_group)
        repair_note = QLabel(
            "Detects damaged catalogue controls in the repair base, copies only same-size VERIFIED replacements "
            "from the golden image into a small .gsworkspace archive, and leaves both source images untouched. "
            "No 60 GB copy and no GameStick write is performed."
        )
        repair_note.setWordWrap(True)
        repair_layout.addWidget(repair_note)
        self.repair_workspace_selection = QLabel("No images selected. Select golden/reference + original_read1 repair base.")
        self.repair_workspace_selection.setWordWrap(True)
        repair_layout.addWidget(self.repair_workspace_selection)
        repair_select = QPushButton("Select Golden + Repair Base Images...")
        repair_select.clicked.connect(self.select_repair_workspace_images)
        repair_layout.addWidget(repair_select)

        repair_output_row = QHBoxLayout()
        self.repair_workspace_output = QLineEdit()
        self.repair_workspace_output.setReadOnly(True)
        repair_output_button = QPushButton("Choose .gsworkspace output...")
        repair_output_button.clicked.connect(self.select_repair_workspace_output)
        repair_output_row.addWidget(self.repair_workspace_output, 1)
        repair_output_row.addWidget(repair_output_button)
        repair_layout.addLayout(repair_output_row)

        repair_actions = QHBoxLayout()
        self.repair_workspace_button = QPushButton("Build Verified Repair Workspace")
        self.repair_workspace_button.clicked.connect(self.run_repair_workspace)
        self.cancel_repair_workspace_button = QPushButton("Cancel")
        self.cancel_repair_workspace_button.setEnabled(False)
        self.cancel_repair_workspace_button.clicked.connect(self.cancel_repair_workspace)
        repair_actions.addWidget(self.repair_workspace_button)
        repair_actions.addWidget(self.cancel_repair_workspace_button)
        repair_layout.addLayout(repair_actions)
        self.repair_workspace_result = QTextEdit()
        self.repair_workspace_result.setReadOnly(True)
        self.repair_workspace_result.setMinimumHeight(140)
        self.repair_workspace_result.setMaximumHeight(260)
        repair_layout.addWidget(self.repair_workspace_result)
        repair_page_layout.addWidget(repair_group)

        custom_group = QGroupBox("ROM Manager — browse/search + exact launcher state")
        custom_layout = QVBoxLayout(custom_group)
        custom_note = QLabel(
            "Fast manager for the proven launcher controls. It inventories the healthy reference image and, optionally, "
            "compares a mounted TEST/CLONE card read-only. Identity is catalogue code + exact ROM filename, so similarly "
            "named games remain independent. ROM payloads are never read by the manager."
        )
        custom_note.setWordWrap(True)
        custom_layout.addWidget(custom_note)

        custom_image_row = QHBoxLayout()
        self.rom_hide_image_path = QLineEdit()
        self.rom_hide_image_path.setReadOnly(True)
        custom_image_button = QPushButton("Select healthy reference .img...")
        custom_image_button.clicked.connect(self.select_rom_hide_image)
        custom_image_row.addWidget(self.rom_hide_image_path, 1)
        custom_image_row.addWidget(custom_image_button)
        custom_layout.addLayout(custom_image_row)

        target_row = QHBoxLayout()
        self.rom_manager_target = QLineEdit()
        self.rom_manager_target.setReadOnly(True)
        self.rom_manager_target.setPlaceholderText("Optional mounted TEST/CLONE card — enables VISIBLE/HIDDEN state")
        target_button = QPushButton("Select mounted TEST card...")
        target_button.clicked.connect(self.select_rom_manager_target)
        target_clear = QPushButton("Clear target")
        target_clear.clicked.connect(self.clear_rom_manager_target)
        target_row.addWidget(self.rom_manager_target, 1)
        target_row.addWidget(target_button)
        target_row.addWidget(target_clear)
        custom_layout.addLayout(target_row)

        scan_row = QHBoxLayout()
        self.rom_manager_scan_button = QPushButton("Load / Refresh ROM Manager")
        self.rom_manager_scan_button.setStyleSheet("font-weight: bold;")
        self.rom_manager_scan_button.clicked.connect(self.run_rom_manager_scan)
        self.cancel_rom_manager_scan_button = QPushButton("Cancel scan")
        self.cancel_rom_manager_scan_button.setEnabled(False)
        self.cancel_rom_manager_scan_button.clicked.connect(self.cancel_rom_manager_scan)
        self.rom_manager_summary = QLabel("Manager not loaded.")
        self.rom_manager_summary.setWordWrap(True)
        scan_row.addWidget(self.rom_manager_scan_button)
        scan_row.addWidget(self.cancel_rom_manager_scan_button)
        scan_row.addWidget(self.rom_manager_summary, 1)
        custom_layout.addLayout(scan_row)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Search:"))
        self.rom_manager_search = QLineEdit()
        self.rom_manager_search.setPlaceholderText("filename, title fragment, or 003:filename")
        self.rom_manager_search.textChanged.connect(self._refresh_rom_manager_view)
        self.rom_manager_hidden_only = QCheckBox("Hidden only")
        self.rom_manager_hidden_only.stateChanged.connect(self._refresh_rom_manager_view)
        filter_row.addWidget(self.rom_manager_search, 1)
        filter_row.addWidget(self.rom_manager_hidden_only)
        custom_layout.addLayout(filter_row)

        self.rom_manager_tree = QTreeWidget()
        self.rom_manager_tree.setHeaderLabels(["Code", "ROM filename", "State"])
        self.rom_manager_tree.setRootIsDecorated(False)
        self.rom_manager_tree.setAlternatingRowColors(True)
        self.rom_manager_tree.setMinimumHeight(320)
        self.rom_manager_tree.setColumnWidth(0, 70)
        self.rom_manager_tree.setColumnWidth(1, 560)
        self.rom_manager_tree.itemSelectionChanged.connect(self._rom_manager_selection_changed)
        custom_layout.addWidget(self.rom_manager_tree)

        custom_output_row = QHBoxLayout()
        self.rom_hide_output = QLineEdit()
        self.rom_hide_output.setReadOnly(True)
        self.rom_hide_output.setPlaceholderText("Hide overlay output is chosen automatically from the selected ROM")
        custom_output_button = QPushButton("Choose .gscustom output...")
        custom_output_button.clicked.connect(self.select_rom_hide_output)
        custom_output_row.addWidget(self.rom_hide_output, 1)
        custom_output_row.addWidget(custom_output_button)
        custom_layout.addLayout(custom_output_row)

        custom_actions = QHBoxLayout()
        self.rom_hide_button = QPushButton("Build Hide Overlay for Selected")
        self.rom_hide_button.clicked.connect(self.run_rom_hide_workspace)
        self.rom_manager_unhide_button = QPushButton("Unhide Selected via .gsrollback")
        self.rom_manager_unhide_button.clicked.connect(self.run_rom_manager_unhide)
        self.cancel_rom_hide_button = QPushButton("Cancel overlay build")
        self.cancel_rom_hide_button.setEnabled(False)
        self.cancel_rom_hide_button.clicked.connect(self.cancel_rom_hide_workspace)
        custom_actions.addWidget(self.rom_hide_button)
        custom_actions.addWidget(self.rom_manager_unhide_button)
        custom_actions.addWidget(self.cancel_rom_hide_button)
        custom_layout.addLayout(custom_actions)
        self.rom_hide_result = QTextEdit()
        self.rom_hide_result.setReadOnly(True)
        self.rom_hide_result.setMinimumHeight(130)
        self.rom_hide_result.setMaximumHeight(240)
        custom_layout.addWidget(self.rom_hide_result)
        customise_page_layout.addWidget(custom_group)

        apply_group = QGroupBox("Apply Overlay to TEST/CLONE Card — BOUNDED WRITE")
        apply_layout = QVBoxLayout(apply_group)
        apply_note = QLabel(
            "Hardware test path. This does NOT rewrite 60 GB and does NOT delete a ROM payload. It revalidates the "
            "healthy source image + .gscustom provenance, then overwrites only the pre-attested byte ranges inside the "
            "existing ROOT.DAT and numbered DAT on a mounted TEST/CLONE GameStick card. A host-side .gsrollback is "
            "committed before the first write and reread verification is mandatory."
        )
        apply_note.setWordWrap(True)
        apply_layout.addWidget(apply_note)

        apply_source_row = QHBoxLayout()
        self.custom_apply_source = QLineEdit()
        self.custom_apply_source.setReadOnly(True)
        apply_source_button = QPushButton("Select healthy source .img...")
        apply_source_button.clicked.connect(self.select_custom_apply_source)
        apply_source_row.addWidget(self.custom_apply_source, 1)
        apply_source_row.addWidget(apply_source_button)
        apply_layout.addLayout(apply_source_row)

        apply_workspace_row = QHBoxLayout()
        self.custom_apply_workspace = QLineEdit()
        self.custom_apply_workspace.setReadOnly(True)
        apply_workspace_button = QPushButton("Select .gscustom...")
        apply_workspace_button.clicked.connect(self.select_custom_apply_workspace)
        apply_workspace_row.addWidget(self.custom_apply_workspace, 1)
        apply_workspace_row.addWidget(apply_workspace_button)
        apply_layout.addLayout(apply_workspace_row)

        apply_target_row = QHBoxLayout()
        self.custom_apply_target = QLineEdit()
        self.custom_apply_target.setReadOnly(True)
        apply_target_button = QPushButton("Select mounted TEST card root...")
        apply_target_button.clicked.connect(self.select_custom_apply_target)
        apply_target_row.addWidget(self.custom_apply_target, 1)
        apply_target_row.addWidget(apply_target_button)
        apply_layout.addLayout(apply_target_row)

        apply_rollback_row = QHBoxLayout()
        self.custom_apply_rollback = QLineEdit()
        self.custom_apply_rollback.setReadOnly(True)
        apply_rollback_button = QPushButton("Choose host .gsrollback...")
        apply_rollback_button.clicked.connect(self.select_custom_apply_rollback)
        apply_rollback_row.addWidget(self.custom_apply_rollback, 1)
        apply_rollback_row.addWidget(apply_rollback_button)
        apply_layout.addLayout(apply_rollback_row)

        self.custom_legacy_rollback = QCheckBox(
            "Explicit legacy rollback-v1/v2 recovery (semantic inverse proof still mandatory)"
        )
        self.custom_legacy_rollback.setToolTip(
            "Use only for alpha13-alpha16 rollback archives. Normal alpha17 rollback-v3 does not need this."
        )
        apply_layout.addWidget(self.custom_legacy_rollback)

        apply_actions = QHBoxLayout()
        self.custom_apply_button = QPushButton("Preflight + Apply Tiny Overlay to TEST Card")
        self.custom_apply_button.setStyleSheet("font-weight: bold;")
        self.custom_apply_button.clicked.connect(self.run_custom_apply)
        self.custom_rollback_button = QPushButton("Undo Using .gsrollback")
        self.custom_rollback_button.clicked.connect(self.run_custom_rollback)
        self.cancel_custom_apply_button = QPushButton("Cancel")
        self.cancel_custom_apply_button.setEnabled(False)
        self.cancel_custom_apply_button.clicked.connect(self.cancel_custom_apply)
        apply_actions.addWidget(self.custom_apply_button)
        apply_actions.addWidget(self.custom_rollback_button)
        apply_actions.addWidget(self.cancel_custom_apply_button)
        apply_layout.addLayout(apply_actions)

        self.custom_apply_result = QTextEdit()
        self.custom_apply_result.setReadOnly(True)
        self.custom_apply_result.setMinimumHeight(170)
        self.custom_apply_result.setMaximumHeight(320)
        apply_layout.addWidget(self.custom_apply_result)
        customise_page_layout.addWidget(apply_group)

        compare_group = QGroupBox("Deep Full SD Image Compare — OPTIONAL / SLOW")
        compare_layout = QVBoxLayout(compare_group)
        self.compare_selection = QLabel("No images selected. Choose at least two equal-sized full acquisitions.")
        self.compare_selection.setWordWrap(True)
        compare_layout.addWidget(self.compare_selection)
        compare_select = QPushButton("Select 2+ .img/.bin files...")
        compare_select.clicked.connect(self.select_compare_images)
        compare_layout.addWidget(compare_select)

        compare_report_row = QHBoxLayout()
        self.compare_report = QLineEdit()
        self.compare_report.setReadOnly(True)
        compare_report_button = QPushButton("Choose report .json...")
        compare_report_button.clicked.connect(self.select_compare_report)
        compare_report_row.addWidget(self.compare_report, 1)
        compare_report_row.addWidget(compare_report_button)
        compare_layout.addLayout(compare_report_row)

        compare_actions = QHBoxLayout()
        self.compare_button = QPushButton("Analyze Image Consistency")
        self.compare_button.clicked.connect(self.run_compare_images)
        self.cancel_compare_button = QPushButton("Cancel")
        self.cancel_compare_button.setEnabled(False)
        self.cancel_compare_button.clicked.connect(self.cancel_compare_images)
        compare_actions.addWidget(self.compare_button)
        compare_actions.addWidget(self.cancel_compare_button)
        compare_layout.addLayout(compare_actions)

        self.compare_progress = QProgressBar()
        self.compare_progress.setRange(0, 100)
        self.compare_progress.setValue(0)
        compare_layout.addWidget(self.compare_progress)
        self.compare_result = QTextEdit()
        self.compare_result.setReadOnly(True)
        self.compare_result.setMinimumHeight(140)
        self.compare_result.setMaximumHeight(260)
        compare_layout.addWidget(self.compare_result)
        advanced_layout.addWidget(compare_group)

        locked = QGroupBox("Destructive Operations — LOCKED")
        locked_layout = QHBoxLayout(locked)
        for text in ("Restore raw image", "Flash firmware", "Modify ROM library"):
            button = QPushButton(text)
            button.setEnabled(False)
            locked_layout.addWidget(button)
        advanced_layout.addWidget(locked)
        imaging_layout.addStretch(1)
        analysis_layout.addStretch(1)
        repair_page_layout.addStretch(1)
        customise_page_layout.addStretch(1)
        advanced_layout.addStretch(1)

    def _refresh_elevation_status(self):
        elevated = is_process_elevated()
        if elevated:
            self.elevation_status.setText(
                "Process privilege: Administrator — raw physical-disk READ access is available if Windows allows it."
            )
            self.elevate_button.setVisible(False)
        else:
            self.elevation_status.setText(
                "Process privilege: Standard user — inspection works normally, but Windows generally blocks "
                r"\\.\PhysicalDriveN reads until this app is elevated."
            )
            self.elevate_button.setVisible(True)

    def relaunch_elevated(self):
        answer = QMessageBox.question(
            self,
            "Relaunch with Administrator rights",
            "Windows requires an elevated process to read the physical SD device sector-by-sector, even though "
            "GameStick Inspector requests read access only.\n\n"
            "Relaunch this same .venv Python application with a UAC prompt now?\n\n"
            "The current probe is intentionally not transferred across the privilege boundary. After relaunch, "
            "run Auto-detect / Probe Read-Only again before imaging.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if answer != QMessageBox.Yes:
            return False

        try:
            entry_script = Path(sys.argv[0]).resolve()
            # run.bat starts .venv\Scripts\python.exe, so sys.executable preserves the user's chosen venv.
            relaunch_current_app_elevated(
                entry_script=entry_script,
                python_executable=sys.executable,
                working_directory=entry_script.parent.parent,
            )
        except Exception as exc:
            QMessageBox.critical(self, "Elevation failed", str(exc))
            return False

        QApplication.instance().quit()
        return True

    def _refresh_source_label(self):
        report = self.inspector.report
        if report is None:
            self.raw_source.setText("Run Device Inspector → Probe Read-Only first.")
            return
        mapping = report.physical_mapping
        self.raw_source.setText(
            f"Latest probe: Disk {mapping.disk_number if mapping.disk_number is not None else '?'} — "
            f"{mapping.disk_name or 'Unknown'} — {_fmt_bytes(mapping.disk_size)} — "
            f"Bus {mapping.bus_type or 'Unknown'} — profile {report.profile.display_name} "
            f"(heuristic score {report.profile.score}/100)."
        )

    def select_raw_destination(self):
        self._refresh_source_label()
        report = self.inspector.report
        disk_number = report.physical_mapping.disk_number if report else None
        suggested = f"gamestick_disk{disk_number if disk_number is not None else 'X'}_factory.img"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save full GameStick SD image", suggested, "Raw Disk Images (*.img *.bin)"
        )
        if path:
            if not Path(path).suffix:
                path += ".img"
            self.raw_output.setText(path)

    def create_raw(self):
        self._refresh_source_label()
        report = self.inspector.report
        if report is None:
            QMessageBox.warning(self, "Probe required", "Run a fresh read-only device probe before imaging.")
            return
        destination = self.raw_output.text().strip()
        if not destination:
            QMessageBox.warning(self, "Destination required", "Choose a host-PC .img destination first.")
            return

        if not is_process_elevated():
            answer = QMessageBox.question(
                self,
                "Administrator rights required for raw read",
                "The device probe is valid, but Windows normally denies sector-level reads from "
                r"\\.\PhysicalDriveN to a standard-user process. GameStick Inspector still requests "
                "GENERIC_READ only.\n\nRelaunch elevated now?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if answer == QMessageBox.Yes:
                self.relaunch_elevated()
            return

        destination_path = Path(destination)
        manifest_path = Path(str(destination_path) + ".manifest.json")
        overwrite = False
        if destination_path.exists() or manifest_path.exists():
            answer = QMessageBox.question(
                self,
                "Existing recovery artifact",
                "The image or its manifest already exists. Replace the existing host-side recovery artifact?\n\n"
                "The GameStick source itself will still be opened read-only.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            overwrite = True

        try:
            plan = preflight_physical_image(report, destination, overwrite=overwrite)
        except Exception as exc:
            QMessageBox.critical(self, "Raw imaging preflight refused", str(exc))
            return

        mapping = report.physical_mapping
        summary = (
            "The source device will be READ ONLY. No sectors will be written to the GameStick.\n\n"
            f"Physical disk: {plan.disk_number}\n"
            f"Device: {plan.disk_name}\n"
            f"Capacity: {_fmt_bytes(plan.source_size)}\n"
            f"Bus: {mapping.bus_type or 'Unknown'}\n"
            f"Profile: {report.profile.display_name} (heuristic score {report.profile.score}/100)\n"
            f"Destination: {plan.destination}\n\n"
            f"Type exactly: {plan.confirmation_phrase}"
        )
        typed, ok = QInputDialog.getText(self, "Confirm physical source", summary)
        if not ok or typed.strip() != plan.confirmation_phrase:
            if ok:
                QMessageBox.warning(self, "Confirmation mismatch", "Physical-disk confirmation did not match.")
            return

        self.raw_progress.setValue(0)
        do_second_read = self.second_source_read.isChecked()
        pass_total = 3 if do_second_read else 2
        self.raw_status.setPlainText(
            f"Opening {plan.source_path} READ ONLY.\n"
            f"Pass 1/{pass_total}: creating image and calculating streaming SHA-256..."
        )
        self.create_raw_button.setEnabled(False)
        self.cancel_raw_button.setEnabled(True)
        self.worker = RawImageThread(plan, second_full_source_read=do_second_read)
        self.worker.progress.connect(self._raw_progress)
        self.worker.succeeded.connect(self._raw_success)
        self.worker.failed.connect(self._raw_failure)
        self.worker.finished.connect(self._raw_finished)
        self.worker.start()

    def cancel_raw(self):
        if self.worker is not None and self.worker.isRunning():
            self.worker.requestInterruption()
            self.cancel_raw_button.setEnabled(False)
            self.raw_status.append("Cancellation requested. The current read will stop at the next chunk boundary.")

    def _raw_progress(self, phase: str, done: int, total: int):
        ratio = max(0.0, min(1.0, (done / total) if total else 0.0))
        do_second_read = bool(self.worker and self.worker.second_full_source_read)
        if do_second_read:
            if phase == "imaging":
                percent = int(ratio * 34)
                label = "Pass 1/3: imaging source + streaming SHA-256"
            elif phase == "verifying":
                percent = 34 + int(ratio * 33)
                label = "Pass 2/3: rereading destination + verification SHA-256"
            else:
                percent = 67 + int(ratio * 33)
                label = "Pass 3/3: independent full source reread + SHA-256"
        else:
            if phase == "imaging":
                percent = int(ratio * 50)
                label = "Pass 1/2: imaging source + streaming SHA-256"
            else:
                percent = 50 + int(ratio * 50)
                label = "Pass 2/2: rereading destination + verification SHA-256"
        self.raw_progress.setValue(percent)
        phase_percent = int(ratio * 100)
        self.raw_status.setPlainText(
            f"{label}\n"
            f"{_fmt_bytes(done)} / {_fmt_bytes(total)}  (pass progress: {phase_percent}%)\n"
            f"Overall progress: {percent}%"
        )

    def _raw_success(self, result):
        self.raw_progress.setValue(100)
        self.raw_status.setPlainText(
            "VERIFIED TRANSFER IMAGE CREATED\n"
            f"Image: {result.image_path}\n"
            f"Manifest: {result.manifest_path}\n"
            f"Bytes: {result.bytes_written}\n"
            f"SHA-256: {result.streaming_sha256}\n"
            f"Reread match: {result.verified}\n"
            f"Source consistency: {result.source_consistency_status}"
        )
        QMessageBox.information(
            self,
            "Verified transfer image complete",
            "The raw image was created and the destination reread matched the acquired bytes.\n"
            "This verifies transfer integrity.\n"
            f"Optional source-consistency result: {result.source_consistency_status}.\n\n"
            f"SHA-256:\n{result.streaming_sha256}\n\n"
            f"Manifest:\n{result.manifest_path}",
        )

    def _raw_failure(self, message: str):
        self.raw_status.setPlainText("RAW IMAGE NOT COMPLETED\n\n" + message)
        QMessageBox.warning(self, "Raw imaging stopped", message)

    def _raw_finished(self):
        self.create_raw_button.setEnabled(True)
        self.cancel_raw_button.setEnabled(False)
        if self.worker is not None:
            self.worker.deleteLater()
            self.worker = None

    def select_fast_compare_images(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select golden SanDisk image and original image",
            "",
            "Disk Images (*.img *.bin);;All Files (*)",
        )
        if paths:
            if len(paths) != 2:
                QMessageBox.warning(self, "Exactly two images", "Select exactly two images: golden SanDisk + original_read1.")
                return
            self.fast_compare_images = list(paths)
            self.fast_compare_selection.setText(
                f"Golden/reference: {Path(paths[0]).name}    |    Original: {Path(paths[1]).name}"
            )
            if not self.fast_compare_report.text().strip():
                default = str(Path(paths[0]).resolve().parent / "gamestick_fast_structure_compare.json")
                self.fast_compare_report.setText(default)

    def select_fast_compare_report(self):
        suggested = self.fast_compare_report.text().strip() or "gamestick_fast_structure_compare.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save fast image comparison report", suggested, "JSON Reports (*.json)"
        )
        if path:
            if not path.lower().endswith(".json"):
                path += ".json"
            self.fast_compare_report.setText(path)

    def run_fast_compare_images(self):
        if len(self.fast_compare_images) != 2:
            QMessageBox.warning(self, "Images required", "Select exactly two image files first.")
            return
        report = self.fast_compare_report.text().strip()
        if not report:
            QMessageBox.warning(self, "Report required", "Choose a host-side JSON report destination first.")
            return
        if Path(report).exists():
            answer = QMessageBox.question(
                self,
                "Existing fast comparison report",
                "Replace the existing host-side JSON report?\n\nNeither input image will be modified.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
        self.fast_compare_result.setPlainText(
            "FAST comparison started. Reading FAT32 directory metadata and launcher/control files only.\n"
            "No complete-image payload scan will be performed."
        )
        self.fast_compare_button.setEnabled(False)
        self.cancel_fast_compare_button.setEnabled(True)
        self.fast_compare_worker = FastImageCompareThread(
            self.fast_compare_images[0], self.fast_compare_images[1], report
        )
        self.fast_compare_worker.progress.connect(self._fast_compare_progress)
        self.fast_compare_worker.succeeded.connect(self._fast_compare_success)
        self.fast_compare_worker.failed.connect(self._fast_compare_failure)
        self.fast_compare_worker.finished.connect(self._fast_compare_finished)
        self.fast_compare_worker.start()

    def cancel_fast_compare_images(self):
        if self.fast_compare_worker is not None and self.fast_compare_worker.isRunning():
            self.fast_compare_worker.requestInterruption()
            self.cancel_fast_compare_button.setEnabled(False)
            self.fast_compare_result.append("Cancellation requested; no incomplete report will be written.")

    def _fast_compare_progress(self, message: str):
        self.fast_compare_result.setPlainText(message)

    def _fast_compare_success(self, result):
        a = result.image_a
        b = result.image_b
        self.fast_compare_result.setPlainText(
            "FAST IMAGE LAB COMPLETE\n"
            f"Status: {result.status}\n"
            f"Logical structure identical: {result.structure_identical}\n"
            f"Launcher/control files identical: {result.critical_files_identical}\n"
            f"Only in golden/reference: {result.only_in_a_count}\n"
            f"Only in original: {result.only_in_b_count}\n"
            f"Size/type changes: {result.size_changed_count}\n"
            f"Launcher/control changes: {result.critical_hash_changed_count}\n"
            f"Files indexed: {a.file_count:,} vs {b.file_count:,}\n"
            f"Control bytes hashed: {_fmt_bytes(a.bytes_hashed_for_controls + b.bytes_hashed_for_controls)}\n"
            f"Report: {result.report_path}"
        )
        QMessageBox.information(
            self,
            "Fast image comparison complete",
            f"{result.status}\n\n"
            f"Launcher/control differences: {result.critical_hash_changed_count}\n"
            f"Filesystem-only additions/removals: {result.only_in_a_count + result.only_in_b_count}\n\n"
            "No full-image scan was performed and neither source image was modified."
        )

    def _fast_compare_failure(self, message: str):
        self.fast_compare_result.setPlainText("FAST IMAGE LAB FAILED\n\n" + message)
        QMessageBox.warning(self, "Fast image comparison stopped", message)

    def _fast_compare_finished(self):
        self.fast_compare_button.setEnabled(True)
        self.cancel_fast_compare_button.setEnabled(False)
        if self.fast_compare_worker is not None:
            self.fast_compare_worker.deleteLater()
            self.fast_compare_worker = None

    def select_catalogue_compare_images(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select golden/reference image and original image",
            "",
            "Disk Images (*.img *.bin);;All Files (*)",
        )
        if paths:
            if len(paths) != 2:
                QMessageBox.warning(self, "Exactly two images", "Select exactly two images: golden/reference + original_read1.")
                return
            self.catalogue_compare_images = list(paths)
            self.catalogue_compare_selection.setText(
                f"Golden/reference: {Path(paths[0]).name}    |    Original: {Path(paths[1]).name}"
            )
            if not self.catalogue_compare_report.text().strip():
                default = str(Path(paths[0]).resolve().parent / "gamestick_catalogue_compare.json")
                self.catalogue_compare_report.setText(default)

    def select_catalogue_compare_report(self):
        suggested = self.catalogue_compare_report.text().strip() or "gamestick_catalogue_compare.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save surgical catalogue comparison report", suggested, "JSON Reports (*.json)"
        )
        if path:
            if not path.lower().endswith(".json"):
                path += ".json"
            self.catalogue_compare_report.setText(path)

    def run_catalogue_compare_images(self):
        if len(self.catalogue_compare_images) != 2:
            QMessageBox.warning(self, "Images required", "Select exactly two image files first.")
            return
        report = self.catalogue_compare_report.text().strip()
        if not report:
            QMessageBox.warning(self, "Report required", "Choose a host-side JSON report destination first.")
            return
        if Path(report).exists():
            answer = QMessageBox.question(
                self,
                "Existing catalogue report",
                "Replace the existing host-side JSON report?\n\nNeither input image will be modified.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
        self.catalogue_compare_result.setPlainText(
            "Starting surgical catalogue comparison...\n"
            "Only WQW central directories + filelist.txt/fileinfo.txt are read."
        )
        self.catalogue_compare_button.setEnabled(False)
        self.cancel_catalogue_compare_button.setEnabled(True)
        self.catalogue_compare_worker = CatalogueCompareThread(
            self.catalogue_compare_images[0], self.catalogue_compare_images[1], report
        )
        self.catalogue_compare_worker.progress.connect(self._catalogue_compare_progress)
        self.catalogue_compare_worker.succeeded.connect(self._catalogue_compare_success)
        self.catalogue_compare_worker.failed.connect(self._catalogue_compare_failure)
        self.catalogue_compare_worker.finished.connect(self._catalogue_compare_finished)
        self.catalogue_compare_worker.start()

    def cancel_catalogue_compare_images(self):
        if self.catalogue_compare_worker is not None and self.catalogue_compare_worker.isRunning():
            self.catalogue_compare_worker.requestInterruption()
            self.cancel_catalogue_compare_button.setEnabled(False)
            self.catalogue_compare_result.append("Cancellation requested; no incomplete report will be written.")

    def _catalogue_compare_progress(self, message: str):
        self.catalogue_compare_result.setPlainText(message)

    def _catalogue_compare_success(self, result):
        total_read = (
            result.image_a.bytes_read_for_fat + result.image_a.bytes_read_for_controls
            + result.image_b.bytes_read_for_fat + result.image_b.bytes_read_for_controls
        )
        self.catalogue_compare_result.setPlainText(
            "SURGICAL CATALOGUE LAB COMPLETE\n"
            f"Status: {result.status}\n"
            f"Identical catalogues: {result.identical_catalogue_count}/15\n"
            f"Catalogue-list differences: {result.differing_catalogue_count}\n"
            f"Byte-only control differences: {result.byte_only_catalogue_count}\n"
            f"Damaged/unreadable: {result.damaged_or_unreadable_count}\n"
            f"List-different codes: {', '.join(result.differing_catalogue_codes) or 'none'}\n"
            f"Byte-only codes: {', '.join(result.byte_only_catalogue_codes) or 'none'}\n"
            f"Damaged codes: {', '.join(result.damaged_or_unreadable_codes) or 'none'}\n"
            f"ROOT fileinfo: {result.root_fileinfo_status}\n"
            f"Approx bytes read (both images): {_fmt_bytes(total_read)}\n"
            f"Report: {result.report_path}"
        )
        QMessageBox.information(
            self,
            "Surgical catalogue comparison complete",
            f"{result.status}\n\n"
            f"Different catalogues: {', '.join(result.differing_catalogue_codes) or 'none'}\n"
            f"Damaged/unreadable: {', '.join(result.damaged_or_unreadable_codes) or 'none'}\n\n"
            "No ROM payloads were scanned and neither source image was modified."
        )

    def _catalogue_compare_failure(self, message: str):
        self.catalogue_compare_result.setPlainText("SURGICAL CATALOGUE LAB FAILED\n\n" + message)
        QMessageBox.warning(self, "Catalogue comparison stopped", message)

    def _catalogue_compare_finished(self):
        self.catalogue_compare_button.setEnabled(True)
        self.cancel_catalogue_compare_button.setEnabled(False)
        if self.catalogue_compare_worker is not None:
            self.catalogue_compare_worker.deleteLater()
            self.catalogue_compare_worker = None

    def select_repair_workspace_images(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select golden/reference image and repair-base image",
            "",
            "Disk Images (*.img *.bin);;All Files (*)",
        )
        if paths:
            if len(paths) != 2:
                QMessageBox.warning(self, "Exactly two images", "Select exactly two images: golden/reference first, repair base second.")
                return
            self.repair_workspace_images = list(paths)
            self.repair_workspace_selection.setText(
                f"Golden/reference: {Path(paths[0]).name}    |    Repair base: {Path(paths[1]).name}"
            )
            if not self.repair_workspace_output.text().strip():
                default = str(Path(paths[0]).resolve().parent / "gamestick_repair.gsworkspace")
                self.repair_workspace_output.setText(default)

    def select_repair_workspace_output(self):
        suggested = self.repair_workspace_output.text().strip() or "gamestick_repair.gsworkspace"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save repair workspace", suggested, "GameStick Workspace (*.gsworkspace)"
        )
        if path:
            if not path.lower().endswith(".gsworkspace"):
                path += ".gsworkspace"
            self.repair_workspace_output.setText(path)

    def run_repair_workspace(self):
        if len(self.repair_workspace_images) != 2:
            QMessageBox.warning(self, "Images required", "Select golden/reference and repair-base images first.")
            return
        output = self.repair_workspace_output.text().strip()
        if not output:
            QMessageBox.warning(self, "Workspace required", "Choose a host-side .gsworkspace output first.")
            return
        overwrite = False
        if Path(output).exists():
            answer = QMessageBox.question(
                self,
                "Existing repair workspace",
                "Replace the existing host-side repair workspace?\n\nNeither source image will be modified.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            overwrite = True
        self.repair_workspace_result.setPlainText(
            "Building fast host-side repair workspace...\n"
            "Source images remain read-only; only damaged same-size catalogue candidates will be copied."
        )
        self.repair_workspace_button.setEnabled(False)
        self.cancel_repair_workspace_button.setEnabled(True)
        self.repair_workspace_worker = RepairWorkspaceThread(
            self.repair_workspace_images[0], self.repair_workspace_images[1], output, overwrite=overwrite
        )
        self.repair_workspace_worker.progress.connect(self._repair_workspace_progress)
        self.repair_workspace_worker.succeeded.connect(self._repair_workspace_success)
        self.repair_workspace_worker.failed.connect(self._repair_workspace_failure)
        self.repair_workspace_worker.finished.connect(self._repair_workspace_finished)
        self.repair_workspace_worker.start()

    def cancel_repair_workspace(self):
        if self.repair_workspace_worker is not None and self.repair_workspace_worker.isRunning():
            self.repair_workspace_worker.requestInterruption()
            self.cancel_repair_workspace_button.setEnabled(False)
            self.repair_workspace_result.append("Cancellation requested; no incomplete workspace will be promoted.")

    def _repair_workspace_progress(self, message: str):
        self.repair_workspace_result.setPlainText(message)

    def _repair_workspace_success(self, result):
        self.repair_workspace_result.setPlainText(
            "REPAIR WORKSPACE CREATED\n"
            f"Repair catalogues: {', '.join(result.repaired_codes) or 'none'}\n"
            f"Workspace: {result.workspace_path}\n"
            f"Workspace size: {_fmt_bytes(result.workspace_size_bytes)}\n"
            f"Bytes read from the two images: {_fmt_bytes(result.bytes_read_from_images)}\n"
            f"SHA-256: {result.workspace_sha256}\n"
            f"Archive verified: {result.archive_verified}\n"
            "Source images modified: NO"
        )
        QMessageBox.information(
            self,
            "Repair workspace created",
            f"Repair codes: {', '.join(result.repaired_codes)}\n\n"
            f"Created: {result.workspace_path}\n\n"
            "Both source images remain untouched. No GameStick write was performed."
        )

    def _repair_workspace_failure(self, message: str):
        self.repair_workspace_result.setPlainText("REPAIR WORKSPACE FAILED\n\n" + message)
        QMessageBox.warning(self, "Repair workspace stopped", message)

    def _repair_workspace_finished(self):
        self.repair_workspace_button.setEnabled(True)
        self.cancel_repair_workspace_button.setEnabled(False)
        if self.repair_workspace_worker is not None:
            self.repair_workspace_worker.deleteLater()
            self.repair_workspace_worker = None

    def select_rom_manager_target(self):
        path = QFileDialog.getExistingDirectory(self, "Select mounted TEST/CLONE GameStick card root")
        if path:
            self.rom_manager_target.setText(path)
            if hasattr(self, "custom_apply_target"):
                self.custom_apply_target.setText(path)

    def clear_rom_manager_target(self):
        self.rom_manager_target.clear()
        self.rom_manager_hidden_only.setChecked(False)
        self.rom_manager_summary.setText("Target cleared. Refresh to browse the healthy reference catalogue only.")

    def run_rom_manager_scan(self):
        image = self.rom_hide_image_path.text().strip()
        if not image:
            QMessageBox.warning(self, "Reference image required", "Select the healthy/reference GameStick image first.")
            return
        if self.rom_manager_worker is not None and self.rom_manager_worker.isRunning():
            return
        target = self.rom_manager_target.text().strip() or None
        self.rom_manager_summary.setText("Loading verified launcher catalogues...")
        self.rom_manager_scan_button.setEnabled(False)
        self.cancel_rom_manager_scan_button.setEnabled(True)
        self.rom_manager_worker = RomManagerScanThread(image, target)
        self.rom_manager_worker.progress.connect(self.rom_manager_summary.setText)
        self.rom_manager_worker.succeeded.connect(self._rom_manager_scan_success)
        self.rom_manager_worker.failed.connect(self._rom_manager_scan_failure)
        self.rom_manager_worker.finished.connect(self._rom_manager_scan_finished)
        self.rom_manager_worker.start()

    def cancel_rom_manager_scan(self):
        if self.rom_manager_worker is not None and self.rom_manager_worker.isRunning():
            self.rom_manager_worker.requestInterruption()
            self.cancel_rom_manager_scan_button.setEnabled(False)
            self.rom_manager_summary.setText("Cancellation requested...")

    def _rom_manager_scan_success(self, snapshot):
        self.rom_manager_entries = snapshot.entries
        if snapshot.target_root:
            unreadable = ", ".join(snapshot.unreadable_catalogues) if snapshot.unreadable_catalogues else "none"
            self._rom_manager_summary_base = (
                f"Reference ROMs: {snapshot.reference_entry_count:,} | "
                f"Visible: {snapshot.visible_count:,} | Hidden: {snapshot.hidden_count:,} | "
                f"Inconsistent: {snapshot.inconsistent_count:,} | Target-only: {snapshot.target_only_count:,} | "
                f"Unreadable catalogues: {unreadable}"
            )
        else:
            self._rom_manager_summary_base = (
                f"Reference ROMs: {snapshot.reference_entry_count:,} | No target selected — state shown as REFERENCE."
            )
        self.rom_manager_summary.setText(self._rom_manager_summary_base)
        self._refresh_rom_manager_view()

    def _rom_manager_scan_failure(self, message: str):
        self.rom_manager_entries = ()
        self.rom_manager_tree.clear()
        self._rom_manager_summary_base = "ROM Manager scan failed."
        self.rom_manager_summary.setText(self._rom_manager_summary_base)
        self.rom_hide_result.setPlainText("ROM MANAGER SCAN FAILED\n\n" + message)
        QMessageBox.warning(self, "ROM Manager stopped", message)

    def _rom_manager_scan_finished(self):
        self.rom_manager_scan_button.setEnabled(True)
        self.cancel_rom_manager_scan_button.setEnabled(False)
        if self.rom_manager_worker is not None:
            self.rom_manager_worker.deleteLater()
            self.rom_manager_worker = None

    def _refresh_rom_manager_view(self):
        if not hasattr(self, "rom_manager_tree"):
            return
        query = self.rom_manager_search.text().strip().casefold() if hasattr(self, "rom_manager_search") else ""
        hidden_only = self.rom_manager_hidden_only.isChecked() if hasattr(self, "rom_manager_hidden_only") else False
        selected_identity = None
        current = self.rom_manager_tree.selectedItems()
        if current:
            selected_identity = (current[0].text(0), current[0].text(1).casefold())
        self.rom_manager_tree.clear()
        shown = 0
        total_matches = 0
        display_limit = 1000
        for entry in self.rom_manager_entries:
            if hidden_only and entry.state != "HIDDEN":
                continue
            haystack = f"{entry.catalogue_code}:{entry.filename}".casefold()
            if query and query not in haystack:
                continue
            total_matches += 1
            if shown >= display_limit:
                continue
            item = QTreeWidgetItem([entry.catalogue_code, entry.filename, entry.state])
            item.setData(0, Qt.UserRole, entry.catalogue_code)
            item.setData(1, Qt.UserRole, entry.filename)
            self.rom_manager_tree.addTopLevelItem(item)
            if selected_identity == (entry.catalogue_code, entry.filename.casefold()):
                self.rom_manager_tree.setCurrentItem(item)
            shown += 1
        summary = self._rom_manager_summary_base
        if total_matches > display_limit:
            summary += f" | Showing first {display_limit:,} of {total_matches:,} matches — type to narrow."
        elif query or hidden_only:
            summary += f" | Matching rows: {total_matches:,}."
        self.rom_manager_summary.setText(summary)

    def _selected_rom_identity(self):
        items = self.rom_manager_tree.selectedItems()
        if len(items) != 1:
            return None
        item = items[0]
        return item.text(0), item.text(1), item.text(2)

    def _rom_manager_selection_changed(self):
        selected = self._selected_rom_identity()
        if not selected:
            return
        code, filename, state = selected
        safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in Path(filename).stem)[:80]
        image = self.rom_hide_image_path.text().strip()
        if image:
            suggested = Path(image).resolve().parent / f"gamestick_hide_{code}_{safe_name}.gscustom"
            self.rom_hide_output.setText(str(suggested))
        self.rom_hide_result.setPlainText(
            f"Selected: {code}:{filename}\nState: {state}\n\n"
            "Hide creates a tiny launcher-control overlay. Unhide uses the matching rollback archive from a prior apply."
        )

    def run_rom_manager_unhide(self):
        selected = self._selected_rom_identity()
        if not selected:
            QMessageBox.warning(self, "ROM required", "Select one ROM in the manager first.")
            return
        code, filename, state = selected
        if state != "HIDDEN":
            QMessageBox.warning(self, "ROM is not hidden", f"{code}:{filename} is currently {state}, not HIDDEN.")
            return
        target = self.rom_manager_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Target required", "Select the mounted TEST/CLONE card and refresh the manager first.")
            return
        start = self.custom_apply_rollback.text().strip() if hasattr(self, "custom_apply_rollback") else ""
        rollback, _ = QFileDialog.getOpenFileName(
            self, "Select matching rollback archive", start, "GameStick Rollback (*.gsrollback);;All Files (*)"
        )
        if not rollback:
            return
        receipt = Path(rollback).with_suffix(".apply.json")
        if not receipt.is_file():
            QMessageBox.warning(
                self,
                "Matching receipt required",
                "The rollback's .apply.json receipt is required so the backend can verify rollback SHA-256, ROM identity and target provenance.",
            )
            return
        try:
            verify_rollback_receipt_for_rom(rollback, receipt, target, code, filename)
        except Exception as exc:
            QMessageBox.warning(self, "Rollback provenance check failed", str(exc))
            return
        drive = Path(target).drive.upper() or Path(target).name
        phrase = f"ROLL BACK {drive}"
        typed, ok = QInputDialog.getText(
            self,
            "Confirm selected-ROM unhide",
            f"Restore the bounded launcher-control bytes for {code}:{filename}.\n\nType exactly: {phrase}",
        )
        if not ok:
            return
        self.rom_hide_result.setPlainText(f"Validating rollback state for {code}:{filename}...")
        self.rom_manager_unhide_button.setEnabled(False)
        self.rom_manager_rollback_worker = CustomRollbackThread(rollback, target, confirmation=typed, receipt_path=str(receipt), expected_rom=(code, filename))
        self.rom_manager_rollback_worker.progress.connect(self.rom_hide_result.setPlainText)
        self.rom_manager_rollback_worker.succeeded.connect(self._rom_manager_unhide_success)
        self.rom_manager_rollback_worker.failed.connect(self._rom_manager_unhide_failure)
        self.rom_manager_rollback_worker.finished.connect(self._rom_manager_unhide_finished)
        self.rom_manager_rollback_worker.start()

    def _rom_manager_unhide_success(self, result):
        self.rom_hide_result.setPlainText(
            "ROM UNHIDDEN / ROLLBACK VERIFIED\n"
            f"Target: {result.target_root}\n"
            f"Restored files / ranges: {result.restored_file_count} / {result.restored_range_count}\n"
            f"Restored bytes: {_fmt_bytes(result.restored_bytes)}\n"
            f"Verification: {result.verification}"
        )
        QMessageBox.information(self, "ROM restored", "The selected hide operation was rolled back and reread-verified.")

    def _rom_manager_unhide_failure(self, message: str):
        self.rom_hide_result.setPlainText("ROM UNHIDE FAILED\n\n" + message)
        QMessageBox.warning(self, "ROM unhide stopped", message)

    def _rom_manager_unhide_finished(self):
        self.rom_manager_unhide_button.setEnabled(True)
        if self.rom_manager_rollback_worker is not None:
            self.rom_manager_rollback_worker.deleteLater()
            self.rom_manager_rollback_worker = None
        # Refresh target state so HIDDEN becomes VISIBLE immediately after a successful rollback.
        if self.rom_hide_image_path.text().strip() and self.rom_manager_target.text().strip():
            self.run_rom_manager_scan()

    def select_rom_hide_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select healthy GameStick reference image",
            "",
            "Disk Images (*.img *.bin);;All Files (*)",
        )
        if path:
            self.rom_hide_image = path
            self.rom_hide_image_path.setText(path)
            if hasattr(self, "custom_apply_source"):
                self.custom_apply_source.setText(path)
            self.rom_manager_entries = ()
            if hasattr(self, "rom_manager_tree"):
                self.rom_manager_tree.clear()
                self.rom_manager_summary.setText("Reference selected. Click Load / Refresh ROM Manager.")

    def select_rom_hide_output(self):
        suggested = self.rom_hide_output.text().strip() or "gamestick_custom_hide.gscustom"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save customisation workspace", suggested, "GameStick Customisation (*.gscustom)"
        )
        if path:
            if not path.lower().endswith(".gscustom"):
                path += ".gscustom"
            self.rom_hide_output.setText(path)

    def run_rom_hide_workspace(self):
        image = self.rom_hide_image_path.text().strip()
        selected = self._selected_rom_identity()
        if not image:
            QMessageBox.warning(self, "Image required", "Select the healthy/reference GameStick image first.")
            return
        if not selected:
            QMessageBox.warning(self, "ROM required", "Load the ROM Manager and select exactly one ROM first.")
            return
        code, filename, state = selected
        if state in ("HIDDEN", "INCONSISTENT", "UNREADABLE", "TARGET_ONLY"):
            QMessageBox.warning(self, "ROM state is not eligible", f"{code}:{filename} is {state}. Refresh/repair that state before hiding it.")
            return
        query = f"{code}:{filename}"
        output = self.rom_hide_output.text().strip()
        if not output:
            safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in Path(filename).stem)[:80]
            output = str(Path(image).resolve().parent / f"gamestick_hide_{code}_{safe_name}.gscustom")
            self.rom_hide_output.setText(output)
        overwrite = False
        if Path(output).exists():
            answer = QMessageBox.question(
                self,
                "Existing customisation workspace",
                "Replace the existing host-side customisation workspace?\n\nThe source image will remain read-only.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            overwrite = True
        self.rom_hide_result.setPlainText(
            "Building launcher-hide overlay...\n"
            "Only WQW control metadata will be patched virtually; source image and ROM payload remain untouched."
        )
        self.rom_hide_button.setEnabled(False)
        self.cancel_rom_hide_button.setEnabled(True)
        self.rom_hide_worker = RomHideWorkspaceThread(image, query, output, overwrite=overwrite)
        self.rom_hide_worker.progress.connect(self._rom_hide_progress)
        self.rom_hide_worker.succeeded.connect(self._rom_hide_success)
        self.rom_hide_worker.failed.connect(self._rom_hide_failure)
        self.rom_hide_worker.finished.connect(self._rom_hide_finished)
        self.rom_hide_worker.start()

    def cancel_rom_hide_workspace(self):
        if self.rom_hide_worker is not None and self.rom_hide_worker.isRunning():
            self.rom_hide_worker.requestInterruption()
            self.cancel_rom_hide_button.setEnabled(False)
            self.rom_hide_result.append("Cancellation requested; no incomplete customisation workspace will be promoted.")

    def _rom_hide_progress(self, message: str):
        self.rom_hide_result.setPlainText(message)

    def _rom_hide_success(self, result):
        self.rom_hide_result.setPlainText(
            "CUSTOMISATION WORKSPACE CREATED\n"
            f"ROM hidden from launcher: {result.catalogue_code}:{result.rom_filename}\n"
            f"Catalogue records removed: {result.catalogue_records_removed}\n"
            f"ROOT records removed: {result.root_records_removed}\n"
            f"Patch payload: {_fmt_bytes(result.patch_payload_bytes)}\n"
            f"Workspace: {result.workspace_path}\n"
            f"SHA-256: {result.workspace_sha256}\n"
            "Source image modified: NO\n"
            "Physical ROM payload removed: NO\n\n"
            "The Apply section below has been prefilled for the selected TEST/CLONE card."
        )
        if hasattr(self, "custom_apply_source"):
            self.custom_apply_source.setText(self.rom_hide_image_path.text().strip())
            self.custom_apply_workspace.setText(result.workspace_path)
            target = self.rom_manager_target.text().strip()
            if target:
                self.custom_apply_target.setText(target)
            self.custom_apply_rollback.setText(str(Path(result.workspace_path).with_suffix(".gsrollback")))
        QMessageBox.information(
            self,
            "Hide-ROM overlay created",
            f"{result.catalogue_code}:{result.rom_filename} is absent from the virtually patched launcher controls.\n\n"
            "The 60 GB image and physical ROM payload remain untouched."
        )

    def _rom_hide_failure(self, message: str):
        self.rom_hide_result.setPlainText("CUSTOMISATION WORKSPACE FAILED\n\n" + message)
        QMessageBox.warning(self, "Customisation stopped", message)

    def _rom_hide_finished(self):
        self.rom_hide_button.setEnabled(True)
        self.cancel_rom_hide_button.setEnabled(False)
        if self.rom_hide_worker is not None:
            self.rom_hide_worker.deleteLater()
            self.rom_hide_worker = None

    def select_custom_apply_source(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select healthy source image", "", "Disk Images (*.img *.bin);;All Files (*)"
        )
        if path:
            self.custom_apply_source.setText(path)

    def select_custom_apply_workspace(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select customisation overlay", "", "GameStick Customisation (*.gscustom);;All Files (*)"
        )
        if path:
            self.custom_apply_workspace.setText(path)
            if not self.custom_apply_rollback.text().strip():
                self.custom_apply_rollback.setText(str(Path(path).resolve().with_suffix(".gsrollback")))

    def select_custom_apply_target(self):
        path = QFileDialog.getExistingDirectory(self, "Select mounted TEST/CLONE GameStick card root")
        if path:
            self.custom_apply_target.setText(path)

    def select_custom_apply_rollback(self):
        suggested = self.custom_apply_rollback.text().strip() or "gamestick_custom.gsrollback"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save host-side rollback archive", suggested, "GameStick Rollback (*.gsrollback)"
        )
        if path:
            if not path.lower().endswith(".gsrollback"):
                path += ".gsrollback"
            self.custom_apply_rollback.setText(path)

    def run_custom_apply(self):
        source = self.custom_apply_source.text().strip()
        workspace = self.custom_apply_workspace.text().strip()
        target = self.custom_apply_target.text().strip()
        rollback = self.custom_apply_rollback.text().strip()
        if not source or not workspace or not target or not rollback:
            QMessageBox.warning(
                self,
                "Apply inputs required",
                "Select the healthy source image, .gscustom overlay, mounted TEST/CLONE card root, and host rollback output.",
            )
            return
        phrase = expected_confirmation(target)
        warning = (
            "This operation WILL modify the selected mounted GameStick card.\n\n"
            "Use a TEST/CLONE card only — not your only preserved original.\n"
            "Only pre-attested launcher-control byte ranges are eligible; no file is resized and no ROM payload is deleted.\n"
            "A host-side rollback archive is committed before the first write.\n\n"
            f"Type exactly: {phrase}"
        )
        typed, ok = QInputDialog.getText(self, "Confirm bounded GameStick write", warning)
        if not ok:
            return
        overwrite = False
        overwrite_receipt = False
        receipt_path = Path(rollback).with_suffix(".apply.json")
        if Path(rollback).exists():
            answer = QMessageBox.question(
                self,
                "Existing rollback archive",
                "Replace the existing host-side rollback archive?\n\nThis authorises replacement of that rollback artifact only; the target card has not been modified yet.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            overwrite = True
        if receipt_path.exists():
            answer = QMessageBox.question(
                self,
                "Existing apply receipt",
                "Replace the existing apply receipt transactionally?\n\nThis is separate overwrite authority from the rollback archive.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
            overwrite_receipt = True
        self.custom_apply_result.setPlainText(
            "Preflighting source image, overlay provenance and mounted TEST card...\nNo target write occurs until every attestation passes."
        )
        self.custom_apply_button.setEnabled(False)
        self.custom_rollback_button.setEnabled(False)
        self.cancel_custom_apply_button.setEnabled(True)
        self.custom_apply_worker = CustomApplyThread(
            source, workspace, target, rollback,
            confirmation=typed, overwrite_rollback=overwrite, overwrite_receipt=overwrite_receipt,
        )
        self.custom_apply_worker.progress.connect(self.custom_apply_result.setPlainText)
        self.custom_apply_worker.succeeded.connect(self._custom_apply_success)
        self.custom_apply_worker.failed.connect(self._custom_apply_failure)
        self.custom_apply_worker.finished.connect(self._custom_apply_finished)
        self.custom_apply_worker.start()

    def cancel_custom_apply(self):
        if self.custom_apply_worker is not None and self.custom_apply_worker.isRunning():
            self.custom_apply_worker.requestInterruption()
            self.cancel_custom_apply_button.setEnabled(False)
            self.custom_apply_result.append(
                "Cancellation requested. If target writing has begun, automatic rollback is attempted before failure returns."
            )

    def _custom_apply_success(self, result):
        self.custom_apply_result.setPlainText(
            "CUSTOMISATION APPLIED AND VERIFIED\n"
            f"ROM hidden: {result.catalogue_code}:{result.rom}\n"
            f"Target: {result.target_root}\n"
            f"Patched files / ranges: {result.patched_file_count} / {result.patch_range_count}\n"
            f"Bytes changed: {_fmt_bytes(result.patch_payload_bytes)}\n"
            f"Rollback: {result.rollback_path}\n"
            f"Rollback SHA-256: {result.rollback_sha256}\n"
            f"Receipt: {result.receipt_path}\n"
            f"Verification: {result.verification}\n"
            "Physical ROM payload removed: NO\n\n"
            f"Safely eject the TEST card and boot the GameStick. {result.catalogue_code}:{result.rom} should be absent from the launcher."
        )
        QMessageBox.information(
            self,
            "Bounded customisation applied",
            "The tiny launcher overlay was written and reread-verified.\n\n"
            "Safely eject the TEST/CLONE card and boot it. The rollback archive is retained on the host.",
        )

    def _custom_apply_failure(self, message: str):
        self.custom_apply_result.setPlainText("CUSTOMISATION APPLY FAILED\n\n" + message)
        QMessageBox.warning(self, "Customisation apply stopped", message)

    def _custom_apply_finished(self):
        self.custom_apply_button.setEnabled(True)
        self.custom_rollback_button.setEnabled(True)
        self.cancel_custom_apply_button.setEnabled(False)
        if self.custom_apply_worker is not None:
            self.custom_apply_worker.deleteLater()
            self.custom_apply_worker = None
        if self.rom_hide_image_path.text().strip() and self.rom_manager_target.text().strip():
            self.run_rom_manager_scan()

    def run_custom_rollback(self):
        rollback = self.custom_apply_rollback.text().strip()
        target = self.custom_apply_target.text().strip()
        if not rollback or not target:
            QMessageBox.warning(self, "Rollback inputs required", "Select the .gsrollback archive and mounted TEST card root.")
            return
        drive = Path(target).drive.upper() or Path(target).name
        phrase = f"ROLL BACK {drive}"
        typed, ok = QInputDialog.getText(
            self,
            "Confirm bounded rollback",
            "This restores only after independently proving the rollback is the exact inverse of one canonical hide.\n\n"
            f"Type exactly: {phrase}",
        )
        if not ok:
            return
        self.custom_apply_result.setPlainText("Validating replacement state before rollback...")
        self.custom_apply_button.setEnabled(False)
        self.custom_rollback_button.setEnabled(False)
        self.cancel_custom_apply_button.setEnabled(False)
        self.custom_rollback_worker = CustomRollbackThread(
            rollback, target, confirmation=typed,
            allow_legacy_recovery=self.custom_legacy_rollback.isChecked(),
        )
        self.custom_rollback_worker.progress.connect(self.custom_apply_result.setPlainText)
        self.custom_rollback_worker.succeeded.connect(self._custom_rollback_success)
        self.custom_rollback_worker.failed.connect(self._custom_apply_failure)
        self.custom_rollback_worker.finished.connect(self._custom_rollback_finished)
        self.custom_rollback_worker.start()

    def _custom_rollback_success(self, result):
        self.custom_apply_result.setPlainText(
            "CUSTOMISATION ROLLED BACK AND VERIFIED\n"
            f"Target: {result.target_root}\n"
            f"Restored files / ranges: {result.restored_file_count} / {result.restored_range_count}\n"
            f"Restored bytes: {_fmt_bytes(result.restored_bytes)}\n"
            f"Verification: {result.verification}"
        )
        QMessageBox.information(self, "Rollback complete", "Original launcher-control bytes were restored and reread-verified.")

    def _custom_rollback_finished(self):
        self.custom_apply_button.setEnabled(True)
        self.custom_rollback_button.setEnabled(True)
        if self.custom_rollback_worker is not None:
            self.custom_rollback_worker.deleteLater()
            self.custom_rollback_worker = None
        if self.rom_hide_image_path.text().strip() and self.rom_manager_target.text().strip():
            self.run_rom_manager_scan()

    def select_compare_images(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select full SD images to compare",
            "",
            "Disk Images (*.img *.bin);;All Files (*)",
        )
        if paths:
            self.compare_images = list(paths)
            names = ", ".join(Path(path).name for path in paths)
            self.compare_selection.setText(f"{len(paths)} image(s): {names}")
            if not self.compare_report.text().strip():
                default = str(Path(paths[0]).resolve().parent / "gamestick_image_consistency.json")
                self.compare_report.setText(default)

    def select_compare_report(self):
        suggested = self.compare_report.text().strip() or "gamestick_image_consistency.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save image consistency report", suggested, "JSON Reports (*.json)"
        )
        if path:
            if not path.lower().endswith(".json"):
                path += ".json"
            self.compare_report.setText(path)

    def run_compare_images(self):
        if len(self.compare_images) < 2:
            QMessageBox.warning(self, "Images required", "Select at least two complete image files first.")
            return
        report = self.compare_report.text().strip()
        if not report:
            QMessageBox.warning(self, "Report required", "Choose a host-side JSON report destination first.")
            return
        if Path(report).exists():
            answer = QMessageBox.question(
                self,
                "Existing comparison report",
                "The host-side JSON report already exists. Replace it?\n\nNo input image will be modified.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
        self.compare_progress.setValue(0)
        self.compare_result.setPlainText(
            "Opening selected image files READ ONLY. No source image will be modified.\n"
            "Comparing complete images and mapping disagreements..."
        )
        self.compare_button.setEnabled(False)
        self.cancel_compare_button.setEnabled(True)
        self.compare_worker = ImageCompareThread(self.compare_images, report)
        self.compare_worker.progress.connect(self._compare_progress)
        self.compare_worker.succeeded.connect(self._compare_success)
        self.compare_worker.failed.connect(self._compare_failure)
        self.compare_worker.finished.connect(self._compare_finished)
        self.compare_worker.start()

    def cancel_compare_images(self):
        if self.compare_worker is not None and self.compare_worker.isRunning():
            self.compare_worker.requestInterruption()
            self.cancel_compare_button.setEnabled(False)
            self.compare_result.append("Cancellation requested; no incomplete report will be written.")

    def _compare_progress(self, done: int, total: int):
        percent = int((done / total) * 100) if total else 100
        self.compare_progress.setValue(max(0, min(100, percent)))
        self.compare_result.setPlainText(
            f"Read-only comparison in progress\n{_fmt_bytes(done)} / {_fmt_bytes(total)}\nProgress: {percent}%"
        )

    def _compare_success(self, result):
        self.compare_progress.setValue(100)
        coverage = (
            "n/a (two-image comparison has no majority authority)"
            if result.consensus_coverage_percent is None
            else f"{result.consensus_coverage_percent:.9f}%"
        )
        text = (
            f"Status: {result.status}\n"
            f"Images: {result.image_count} × {_fmt_bytes(result.size_bytes)}\n"
            f"Majority sectors: {result.majority_sectors:,}\n"
            f"Split/ambiguous sectors: {result.split_sectors:,}\n"
            f"Consensus coverage: {coverage}\n"
            f"Disagreement ranges: {len(result.disagreement_ranges):,}"
            + (" (report range list truncated)" if result.ranges_truncated else "")
            + f"\nReport: {result.report_path}"
        )
        self.compare_result.setPlainText(text)
        QMessageBox.information(
            self,
            "Image consistency analysis complete",
            text + "\n\nNo consensus image was created and no input image was modified.",
        )

    def _compare_failure(self, message: str):
        self.compare_result.setPlainText("IMAGE COMPARISON NOT COMPLETED\n\n" + message)
        QMessageBox.warning(self, "Image comparison stopped", message)

    def _compare_finished(self):
        self.compare_button.setEnabled(True)
        self.cancel_compare_button.setEnabled(False)
        if self.compare_worker is not None:
            self.compare_worker.deleteLater()
            self.compare_worker = None

    def select_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select SD image", "", "Disk Images (*.img *.bin);;All Files (*)")
        if path:
            self.image_path.setText(path)

    def verify(self):
        path = self.image_path.text().strip()
        try:
            digest = sha256_file(path)
            size = Path(path).stat().st_size
            self.result.setPlainText(f"File: {path}\nSize: {_fmt_bytes(size)}\nSHA-256: {digest}")
        except Exception as exc:
            QMessageBox.critical(self, "Verification failed", str(exc))


class AboutTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(
            f"GameStick Inspector {VERSION}\n\n"
            "Goal: identify the exact card, partition layout, launcher metadata and visible structure before "
            "any customization code is permitted.\n\n"
            "Safety invariant: raw restore, format, erase, firmware flash and ROM-payload write paths remain absent. "
            "The only GameStick modification authority is the Customise page's bounded .gscustom apply path: it requires "
            "a verified source image, exact control/original-byte attestations, a TEST/CLONE target, typed confirmation, "
            "a host-side rollback snapshot before first write, and mandatory reread verification.\n\n"
            "Evidence bundles contain only generated structural reports and integrity metadata; they do not copy "
            "ROMs or configuration files from the card.\n\n"
            "Executable legacy destructive prototype code is intentionally excluded from release archives."
        )
        layout.addWidget(text)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"GameStick Inspector — {VERSION} (Safety-First Customisation Build)")
        self.resize(1120, 760)
        tabs = QTabWidget()
        inspector = InspectorTab()
        tabs.addTab(inspector, "Device Inspector")
        tabs.addTab(StructureTab(inspector), "Profile Evidence")
        tabs.addTab(BrowserTab(inspector), "Read-Only Browser")
        tabs.addTab(RecoveryTab(inspector), "Recovery & Images")
        tabs.addTab(AboutTab(), "About / Safety")
        self.setCentralWidget(tabs)
