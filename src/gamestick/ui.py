from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
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
from .probe import find_candidate_volumes, inspect_volume
from .reporting import write_evidence_bundle, write_probe_report
from .windows_privilege import is_process_elevated, relaunch_current_app_elevated

VERSION = "0.3.4-alpha2"
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
    def __init__(self):
        super().__init__()
        self.report = None
        layout = QVBoxLayout(self)

        safety = QLabel(
            "SAFETY-FIRST BUILD — GameStick filesystem writes, raw-device writes, restore, format, firmware flash, "
            "ROM add/remove, and launcher-database modification remain disabled. Verified raw-device READ imaging is available."
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
        layout.addWidget(select_group)

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

    def browse(self):
        selected = QFileDialog.getExistingDirectory(self, "Select mounted GameStick volume")
        if selected:
            self.path.setText(selected)

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
            f"Selected {root}\nProfile: {match.display_name}\nConfidence score: {match.score}%",
        )

    def probe(self):
        try:
            report = inspect_volume(self.path.text().strip())
        except Exception as exc:
            QMessageBox.critical(self, "Probe failed", str(exc))
            return
        self.report = report
        mapping = report.physical_mapping
        lines = [
            f"Probe status: {report.probe_status}",
            f"Selected root: {report.selected_root}",
            f"Profile: {report.profile.display_name}",
            f"Confidence: {report.profile.confidence} ({report.profile.score}%)",
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
        if self.report is None:
            QMessageBox.warning(self, "Nothing to export", "Run a read-only probe first.")
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
        if self.report is None:
            QMessageBox.warning(self, "Nothing to export", "Run a read-only probe first.")
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
        layout = QVBoxLayout(self)
        note = QLabel(
            "Structural evidence only. ROM-root filenames are deliberately not exported; platform/subdirectory "
            "names and metadata schemas are enough for profiling."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        refresh = QPushButton("Show Latest Probe Structure")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)

        self.profiles = QTreeWidget()
        self.profiles.setHeaderLabels(["Profile candidate", "Score", "Confidence", "Matched", "Missing"])
        self.profiles.setMaximumHeight(180)
        layout.addWidget(self.profiles)

        self.snapshots = QTreeWidget()
        self.snapshots.setHeaderLabels(["Directory", "Child directories", "File extensions", "Sampled", "Truncated", "Filenames redacted"])
        layout.addWidget(self.snapshots, 1)

    def refresh(self):
        report = self.inspector.report
        if report is None:
            QMessageBox.information(self, "No probe yet", "Run Probe Read-Only in Device Inspector first.")
            return
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

    def __init__(self, plan):
        super().__init__()
        self.plan = plan

    def run(self):
        try:
            result = create_raw_image(
                self.plan,
                progress=lambda phase, done, total: self.progress.emit(phase, done, total),
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
            f"({report.profile.score}%)."
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
            f"Profile: {report.profile.display_name} ({report.profile.score}%)\n"
            f"Destination: {plan.destination}\n\n"
            f"Type exactly: {plan.confirmation_phrase}"
        )
        typed, ok = QInputDialog.getText(self, "Confirm physical source", summary)
        if not ok or typed.strip() != plan.confirmation_phrase:
            if ok:
                QMessageBox.warning(self, "Confirmation mismatch", "Physical-disk confirmation did not match.")
            return

        self.raw_progress.setValue(0)
        self.raw_status.setPlainText(
            f"Opening {plan.source_path} READ ONLY.\n"
            "Pass 1/2: creating image and calculating streaming SHA-256..."
        )
        self.create_raw_button.setEnabled(False)
        self.cancel_raw_button.setEnabled(True)
        self.worker = RawImageThread(plan)
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
        ratio = (done / total) if total else 0.0
        if phase == "imaging":
            percent = int(max(0.0, min(1.0, ratio)) * 50)
            label = "Pass 1/2: imaging source + streaming SHA-256"
        else:
            percent = 50 + int(max(0.0, min(1.0, ratio)) * 50)
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
            f"Reread match: {result.verified}"
        )
        QMessageBox.information(
            self,
            "Verified transfer image complete",
            "The raw image was created and the destination reread matched the acquired bytes.\n"
            "This verifies transfer integrity; it does not prove the source card stayed unchanged during acquisition.\n\n"
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
