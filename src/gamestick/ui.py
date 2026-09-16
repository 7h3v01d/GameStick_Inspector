from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from PyQt5.QtCore import QThread, pyqtSignal
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
from .probe import find_candidate_volumes, inspect_volume
from .reporting import write_evidence_bundle, write_probe_report
from .windows_privilege import is_process_elevated, relaunch_current_app_elevated

VERSION = "0.5.0-alpha8"
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
            "SAFETY-FIRST BUILD — GameStick filesystem writes, raw-device writes, restore, format, firmware flash, "
            "ROM add/remove, DAT regeneration/extraction, and launcher-database modification remain disabled. Verified raw-device READ imaging is available."
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
    progress = pyqtSignal(str, int, int)
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


class ImageCompareThread(QThread):
    progress = pyqtSignal(int, int)
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
        self.compare_worker = None
        self.compare_images = []
        layout = QVBoxLayout(self)
        warning = QLabel(
            "Raw READ imaging is now available after a successful device probe. The GameStick is opened read-only. "
            "Raw restore, firmware flashing and all GameStick write operations remain locked."
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
        self.raw_status.setMaximumHeight(130)
        create_layout.addWidget(self.raw_status)
        layout.addWidget(create_group)

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
        self.result.setMaximumHeight(105)
        inner.addWidget(self.result)
        layout.addWidget(verify_group)

        compare_group = QGroupBox("Compare Full SD Images — READ-ONLY INPUTS")
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
        self.compare_result.setMaximumHeight(150)
        compare_layout.addWidget(self.compare_result)
        layout.addWidget(compare_group)

        locked = QGroupBox("Destructive Operations — LOCKED")
        locked_layout = QHBoxLayout(locked)
        for text in ("Restore raw image", "Flash firmware", "Modify ROM library"):
            button = QPushButton(text)
            button.setEnabled(False)
            locked_layout.addWidget(button)
        layout.addWidget(locked)
        layout.addStretch(1)

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
        self.raw_status.setPlainText(
            f"{label}\n{_fmt_bytes(done)} / {_fmt_bytes(total)}\nOverall progress: {percent}%"
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
            "Safety invariant: the active build can read the physical GameStick device to create a verified-transfer full image, "
            "but contains no code path that writes raw sectors, formats, erases, restores, flashes, copies ROMs to, "
            "or otherwise modifies the selected GameStick volume.\n\n"
            "Evidence bundles contain only generated structural reports and integrity metadata; they do not copy "
            "ROMs or configuration files from the card.\n\n"
            "Executable legacy destructive prototype code is intentionally excluded from release archives."
        )
        layout.addWidget(text)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"GameStick Inspector — {VERSION} (Safety-First Imaging Build)")
        self.resize(1120, 760)
        tabs = QTabWidget()
        inspector = InspectorTab()
        tabs.addTab(inspector, "Device Inspector")
        tabs.addTab(StructureTab(inspector), "Profile Evidence")
        tabs.addTab(BrowserTab(inspector), "Read-Only Browser")
        tabs.addTab(RecoveryTab(inspector), "Recovery & Images")
        tabs.addTab(AboutTab(), "About / Safety")
        self.setCentralWidget(tabs)
