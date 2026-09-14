import os
import shutil
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QLabel, QLineEdit, QGroupBox, 
                             QMessageBox, QProgressBar, QFileDialog)
from PyQt5.QtCore import QThread, pyqtSignal

# --- QThread for Backup and Restore Operations with Progress Tracking ---
class BackupWorker(QThread):
    progress_updated = pyqtSignal(int)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, source, destination, operation, parent=None):
        super().__init__(parent)
        self.source = source
        self.destination = destination
        self.operation = operation # 'backup' or 'restore'

    def run(self):
        try:
            if self.operation == 'backup':
                # First, get the total number of files to be copied for accurate progress tracking
                total_files = sum([len(files) for r, d, files in os.walk(self.source)])
                files_copied = 0
                
                # Start the actual copy operation with progress updates
                for root, dirs, files in os.walk(self.source):
                    # Construct the destination path, preserving the directory structure
                    relative_path = os.path.relpath(root, self.source)
                    dest_path = os.path.join(self.destination, relative_path)
                    
                    # Create the directory in the destination if it doesn't exist
                    os.makedirs(dest_path, exist_ok=True)
                    
                    # Copy files one by one
                    for file_name in files:
                        source_file = os.path.join(root, file_name)
                        dest_file = os.path.join(dest_path, file_name)
                        
                        # Use shutil.copy2 to preserve file metadata
                        shutil.copy2(source_file, dest_file)
                        
                        files_copied += 1
                        
                        # Emit progress signal
                        if total_files > 0:
                            progress = int((files_copied / total_files) * 100)
                            self.progress_updated.emit(progress)
            
            elif self.operation == 'restore':
                total_files = sum([len(files) for r, d, files in os.walk(self.source)])
                files_copied = 0

                # Clear the destination directory first
                for filename in os.listdir(self.destination):
                    file_path = os.path.join(self.destination, filename)
                    if os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                    else:
                        os.remove(file_path)
                
                for root, dirs, files in os.walk(self.source):
                    relative_path = os.path.relpath(root, self.source)
                    dest_path = os.path.join(self.destination, relative_path)
                    
                    os.makedirs(dest_path, exist_ok=True)
                    
                    for file_name in files:
                        source_file = os.path.join(root, file_name)
                        dest_file = os.path.join(dest_path, file_name)
                        
                        shutil.copy2(source_file, dest_file)
                        files_copied += 1
                        
                        if total_files > 0:
                            progress = int((files_copied / total_files) * 100)
                            self.progress_updated.emit(progress)

            self.finished.emit()
        except Exception as e:
            self.error.emit(f"An error occurred: {e}")

# --- Admin Tools Widget ---
class AdminTools(QWidget):
    sd_card_path_selected = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        backup_group = QGroupBox("SD Card Backup & Restore")
        backup_layout = QVBoxLayout()
        backup_group.setLayout(backup_layout)

        backup_layout.addWidget(QLabel("Select a drive (e.g., 'E:/' on Windows or '/media/user/GAMESTICK' on Linux)"))
        
        drive_layout = QHBoxLayout()
        self.drive_path_input = QLineEdit()
        self.drive_path_input.setPlaceholderText("Enter SD card path...")
        self.browse_drive_btn = QPushButton("Browse...")
        self.browse_drive_btn.clicked.connect(self.select_drive)
        drive_layout.addWidget(self.drive_path_input)
        drive_layout.addWidget(self.browse_drive_btn)
        backup_layout.addLayout(drive_layout)
        
        button_layout = QHBoxLayout()
        self.backup_btn = QPushButton("Backup SD Card")
        self.backup_btn.clicked.connect(self.start_backup)
        self.restore_btn = QPushButton("Restore to SD Card")
        self.restore_btn.clicked.connect(self.start_restore)
        button_layout.addWidget(self.backup_btn)
        button_layout.addWidget(self.restore_btn)
        backup_layout.addLayout(button_layout)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        backup_layout.addWidget(self.progress_bar)

        main_layout.addWidget(backup_group)
        main_layout.addStretch(1)

    def select_drive(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select SD Card Root Directory")
        if dir_path:
            self.drive_path_input.setText(dir_path)
            self.sd_card_path_selected.emit(dir_path)

    def start_backup(self):
        sd_path = self.drive_path_input.text()
        if not sd_path or not os.path.exists(sd_path):
            QMessageBox.warning(self, "Error", "Please select a valid SD card path.")
            return

        backup_path = QFileDialog.getExistingDirectory(self, "Select Backup Destination")
        if not backup_path:
            return
        
        dest_path = os.path.join(backup_path, "gamestick_backup")
        if os.path.exists(dest_path):
            reply = QMessageBox.question(self, "Warning",
                                         "Backup directory already exists. Overwrite?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                return

        QMessageBox.information(self, "Backup In Progress", "Backup started. The application will remain responsive.")
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.worker = BackupWorker(sd_path, dest_path, 'backup')
        self.worker.progress_updated.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.backup_finished)
        self.worker.error.connect(self.operation_error)
        self.worker.start()

    def start_restore(self):
        sd_path = self.drive_path_input.text()
        if not sd_path or not os.path.exists(sd_path):
            QMessageBox.warning(self, "Error", "Please select a valid SD card path.")
            return

        backup_path = QFileDialog.getExistingDirectory(self, "Select Backup Directory to Restore From")
        if not backup_path:
            return

        reply = QMessageBox.question(self, "Warning",
                                     "This will **DELETE ALL DATA** on the SD card and replace it with the backup. This is irreversible. Are you sure?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            QMessageBox.information(self, "Restore In Progress", "Restore started. The application will remain responsive.")
            
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            self.worker = BackupWorker(backup_path, sd_path, 'restore')
            self.worker.progress_updated.connect(self.progress_bar.setValue)
            self.worker.finished.connect(self.restore_finished)
            self.worker.error.connect(self.operation_error)
            self.worker.start()

    def backup_finished(self):
        self.progress_bar.setVisible(False)
        QMessageBox.information(self, "Success", "Backup completed successfully!")

    def restore_finished(self):
        self.progress_bar.setVisible(False)
        QMessageBox.information(self, "Success", "SD Card restored successfully!")

    def operation_error(self, message):
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Error", f"An error occurred: {message}")