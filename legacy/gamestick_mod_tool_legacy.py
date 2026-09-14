import sys
import os
import shutil
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QListWidget, QListWidgetItem, QLabel, 
                             QFileDialog, QColorDialog, QLineEdit, QGroupBox, 
                             QMessageBox, QTabWidget, QProgressBar, QComboBox,
                             QTreeWidget, QTreeWidgetItem)
from PyQt5.QtCore import QSize, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor

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

# --- Theme Editor Widget ---
class ThemeEditor(QWidget):
    def __init__(self):
        super().__init__()
        self.theme_settings = {
            "background_color": "#282c34",
            "text_color": "#abb2bf",
            "highlight_color": "#61afef",
            "menu_font": "Arial",
            "menu_font_size": 16
        }
        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout()
        self.setLayout(main_layout)

        # Left Panel (Menu List)
        left_panel = QGroupBox("Menu Items")
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        
        self.menu_list = QListWidget()
        self.menu_list.setSelectionMode(QListWidget.SingleSelection)
        self.menu_list.itemClicked.connect(self.load_item_settings)
        left_layout.addWidget(self.menu_list)

        # Right Panel (Editor)
        right_panel = QGroupBox("Editor")
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)

        # Add buttons and widgets for theme properties
        # Background color
        bg_layout = QHBoxLayout()
        bg_layout.addWidget(QLabel("Background Color:"))
        self.bg_color_btn = QPushButton("Select Color")
        self.bg_color_btn.clicked.connect(self.set_background_color)
        bg_layout.addWidget(self.bg_color_btn)
        right_layout.addLayout(bg_layout)

        # Text color
        text_layout = QHBoxLayout()
        text_layout.addWidget(QLabel("Text Color:"))
        self.text_color_btn = QPushButton("Select Color")
        self.text_color_btn.clicked.connect(self.set_text_color)
        text_layout.addWidget(self.text_color_btn)
        right_layout.addLayout(text_layout)

        # Highlight color
        highlight_layout = QHBoxLayout()
        highlight_layout.addWidget(QLabel("Highlight Color:"))
        self.highlight_color_btn = QPushButton("Select Color")
        self.highlight_color_btn.clicked.connect(self.set_highlight_color)
        highlight_layout.addWidget(self.highlight_color_btn)
        right_layout.addLayout(highlight_layout)

        # Font size
        font_size_layout = QHBoxLayout()
        font_size_layout.addWidget(QLabel("Menu Font Size:"))
        self.font_size_input = QLineEdit()
        self.font_size_input.setPlaceholderText("Enter size (e.g., 16)")
        font_size_layout.addWidget(self.font_size_input)
        right_layout.addLayout(font_size_layout)
        self.font_size_input.textChanged.connect(self.update_preview)

        # Save/Load Buttons
        button_layout = QHBoxLayout()
        self.save_btn = QPushButton("Save Theme")
        self.save_btn.clicked.connect(self.save_theme)
        self.load_btn = QPushButton("Load Theme")
        self.load_btn.clicked.connect(self.load_theme)
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.load_btn)
        right_layout.addLayout(button_layout)
        
        # Add a preview area
        preview_group = QGroupBox("Live Preview")
        preview_layout = QVBoxLayout()
        preview_group.setLayout(preview_layout)
        self.preview_label = QLabel("Preview Text")
        self.preview_label.setAlignment(Qt.AlignCenter)
        preview_layout.addWidget(self.preview_label)
        right_layout.addWidget(preview_group)

        right_layout.addStretch(1)

        main_layout.addWidget(left_panel, 1)
        main_layout.addWidget(right_panel, 2)

        self.populate_menu_list()
        self.update_ui()

    def populate_menu_list(self):
        items = ["Main Menu", "Game List", "Settings", "Favorites"]
        for item_name in items:
            item = QListWidgetItem(item_name)
            self.menu_list.addItem(item)
    
    def load_item_settings(self, item):
        QMessageBox.information(self, "Item Selected", f"You selected: {item.text()}")
        
    def update_ui(self):
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {self.theme_settings['background_color']};
                color: {self.theme_settings['text_color']};
            }}
            QGroupBox {{
                border: 1px solid {self.theme_settings['text_color']};
                margin-top: 10px;
                padding-top: 15px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
            }}
            QPushButton {{
                background-color: {self.theme_settings['highlight_color']};
                color: {self.theme_settings['background_color']};
                border: none;
                padding: 5px;
            }}
            QListWidget::item:selected {{
                background-color: {self.theme_settings['highlight_color']};
                color: {self.theme_settings['background_color']};
            }}
        """)
        self.bg_color_btn.setStyleSheet(f"background-color: {self.theme_settings['background_color']};")
        self.text_color_btn.setStyleSheet(f"background-color: {self.theme_settings['text_color']};")
        self.highlight_color_btn.setStyleSheet(f"background-color: {self.theme_settings['highlight_color']};")
        self.font_size_input.setText(str(self.theme_settings['menu_font_size']))
        self.update_preview()

    def update_preview(self):
        font_size = self.font_size_input.text()
        if font_size.isdigit():
            self.preview_label.setStyleSheet(f"font-size: {font_size}px; color: {self.theme_settings['text_color']};")

    def set_background_color(self):
        color = QColorDialog.getColor(QColor(self.theme_settings['background_color']))
        if color.isValid():
            self.theme_settings['background_color'] = color.name()
            self.update_ui()

    def set_text_color(self):
        color = QColorDialog.getColor(QColor(self.theme_settings['text_color']))
        if color.isValid():
            self.theme_settings['text_color'] = color.name()
            self.update_ui()

    def set_highlight_color(self):
        color = QColorDialog.getColor(QColor(self.theme_settings['highlight_color']))
        if color.isValid():
            self.theme_settings['highlight_color'] = color.name()
            self.update_ui()

    def save_theme(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Theme", "", "Theme Files (*.theme)")
        if file_path:
            with open(file_path, 'w') as f:
                for key, value in self.theme_settings.items():
                    f.write(f"{key}={value}\n")
            QMessageBox.information(self, "Success", "Theme saved successfully!")

    def load_theme(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Theme", "", "Theme Files (*.theme)")
        if file_path:
            try:
                new_settings = {}
                with open(file_path, 'r') as f:
                    for line in f:
                        key, value = line.strip().split('=', 1)
                        new_settings[key] = value
                self.theme_settings.update(new_settings)
                self.update_ui()
                QMessageBox.information(self, "Success", "Theme loaded successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load theme: {e}")

# --- Game Management Widget ---
class GameManager(QWidget):
    def __init__(self):
        super().__init__()
        self.sd_card_path = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        game_group = QGroupBox("Add Game ROMs")
        game_layout = QVBoxLayout()
        game_group.setLayout(game_layout)

        game_layout.addWidget(QLabel("Select an emulator to add games to:"))
        self.emulator_combo = QComboBox()
        self.populate_emulators()
        game_layout.addWidget(self.emulator_combo)

        game_layout.addWidget(QLabel("Select one or more ROM files to add:"))
        self.add_roms_btn = QPushButton("Add ROMs")
        self.add_roms_btn.clicked.connect(self.add_roms)
        game_layout.addWidget(self.add_roms_btn)

        main_layout.addWidget(game_group)
        main_layout.addStretch(1)

    def set_sd_card_path(self, path):
        self.sd_card_path = path

    def populate_emulators(self):
        # This list should be updated based on the actual Game Stick Lite emulators
        emulators = {
            "PS1": "ps1", "NES": "nes", "SNES": "snes",
            "Game Boy": "gb", "Game Boy Color": "gbc", "Game Boy Advance": "gba",
            "Sega Genesis": "genesis", "Arcade": "arcade"
        }
        self.emulator_combo.clear()
        for name, path in emulators.items():
            self.emulator_combo.addItem(name, path)

    def add_roms(self):
        if not self.sd_card_path or not os.path.exists(self.sd_card_path):
            QMessageBox.warning(self, "Error", "SD card not found. Please connect it and reload.")
            return

        emulator_path = self.emulator_combo.currentData()
        if not emulator_path:
            QMessageBox.warning(self, "Error", "Please select an emulator.")
            return
        
        roms_folder = os.path.join(self.sd_card_path, 'roms', emulator_path)
        if not os.path.exists(roms_folder):
            QMessageBox.warning(self, "Error", f"ROMs folder for '{self.emulator_combo.currentText()}' not found on SD card.")
            return

        file_paths, _ = QFileDialog.getOpenFileNames(self, "Select ROM Files", "", "All Files (*)")
        
        if file_paths:
            try:
                for file_path in file_paths:
                    shutil.copy(file_path, roms_folder)
                QMessageBox.information(self, "Success", f"Successfully added {len(file_paths)} ROMs to {self.emulator_combo.currentText()}.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add ROMs: {e}")

# --- Firmware Flasher Widget ---
class FirmwareFlasher(QWidget):
    def __init__(self):
        super().__init__()
        self.sd_card_path = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        firmware_group = QGroupBox("Flash New Firmware")
        firmware_layout = QVBoxLayout()
        firmware_group.setLayout(firmware_layout)

        firmware_layout.addWidget(QLabel("Select a firmware file (.img or .bin) to flash:"))
        self.firmware_path_input = QLineEdit()
        self.firmware_path_input.setPlaceholderText("No file selected...")
        self.firmware_path_input.setReadOnly(True)
        firmware_layout.addWidget(self.firmware_path_input)

        browse_layout = QHBoxLayout()
        self.browse_firmware_btn = QPushButton("Browse...")
        self.browse_firmware_btn.clicked.connect(self.select_firmware)
        self.flash_firmware_btn = QPushButton("Flash Firmware")
        self.flash_firmware_btn.clicked.connect(self.flash_firmware)
        browse_layout.addWidget(self.browse_firmware_btn)
        browse_layout.addWidget(self.flash_firmware_btn)
        firmware_layout.addLayout(browse_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        firmware_layout.addWidget(self.progress_bar)

        main_layout.addWidget(firmware_group)
        main_layout.addStretch(1)

    def set_sd_card_path(self, path):
        self.sd_card_path = path

    def select_firmware(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Firmware File", "", "Firmware Files (*.img *.bin)")
        if file_path:
            self.firmware_path_input.setText(file_path)

    def flash_firmware(self):
        if not self.sd_card_path or not os.path.exists(self.sd_card_path):
            QMessageBox.warning(self, "Error", "SD card not found. Please connect it and reload.")
            return
        
        firmware_file = self.firmware_path_input.text()
        if not firmware_file or not os.path.exists(firmware_file):
            QMessageBox.warning(self, "Error", "Please select a valid firmware file.")
            return

        reply = QMessageBox.question(self, "Warning",
                                     "Flashing new firmware will **ERASE ALL DATA** on your SD card. This is irreversible. Are you sure?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                # Flashing is a simple copy operation of the firmware file
                # The assumption is that the Game Stick Lite's bootloader looks for a specific file name/location.
                dest_path = os.path.join(self.sd_card_path, os.path.basename(firmware_file))
                
                self.progress_bar.setVisible(True)
                self.progress_bar.setValue(0)
                
                # A simple copy for firmware, not a complex folder structure
                shutil.copy(firmware_file, dest_path)
                self.progress_bar.setValue(100)
                
                QMessageBox.information(self, "Success", "Firmware flashed successfully! Please safely eject the SD card.")
                self.progress_bar.setVisible(False)
            except Exception as e:
                self.progress_bar.setVisible(False)
                QMessageBox.critical(self, "Error", f"Failed to flash firmware: {e}")

# --- Game Browser Widget ---
class GameBrowser(QWidget):
    def __init__(self):
        super().__init__()
        self.sd_card_path = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("<h2>Installed Games</h2>"))
        self.refresh_btn = QPushButton("Refresh List")
        self.refresh_btn.clicked.connect(self.load_games)
        header_layout.addWidget(self.refresh_btn)
        main_layout.addLayout(header_layout)

        self.game_list_tree = QTreeWidget()
        self.game_list_tree.setHeaderLabels(["Emulator", "Game Title"])
        self.game_list_tree.setColumnCount(2)
        main_layout.addWidget(self.game_list_tree)
        main_layout.addStretch(1)
        
    def set_sd_card_path(self, path):
        self.sd_card_path = path
        if path:
            self.load_games()

    def load_games(self):
        if not self.sd_card_path or not os.path.exists(os.path.join(self.sd_card_path, 'roms')):
            QMessageBox.warning(self, "Error", "SD card not found or 'roms' folder is missing.")
            self.game_list_tree.clear()
            return

        self.game_list_tree.clear()
        roms_path = os.path.join(self.sd_card_path, 'roms')
        
        # A mapping of folder names to display names
        emulator_display_names = {
            'ps1': 'PlayStation', 'nes': 'Nintendo (NES)', 'snes': 'Super Nintendo (SNES)',
            'gb': 'Game Boy', 'gbc': 'Game Boy Color', 'gba': 'Game Boy Advance',
            'genesis': 'Sega Genesis', 'arcade': 'Arcade'
        }
        
        for emulator_folder in os.listdir(roms_path):
            emulator_path = os.path.join(roms_path, emulator_folder)
            if os.path.isdir(emulator_path):
                # Use the display name or fall back to the folder name
                display_name = emulator_display_names.get(emulator_folder.lower(), emulator_folder)
                emulator_item = QTreeWidgetItem(self.game_list_tree)
                emulator_item.setText(0, display_name) # Set text for the first column

                for game_file in os.listdir(emulator_path):
                    # Filter out non-ROM files like ._ files on macOS
                    if not game_file.startswith('.'):
                        game_item = QTreeWidgetItem(emulator_item)
                        game_item.setText(1, game_file) # Set text for the second column
                        
        self.game_list_tree.expandAll()

# --- Admin Tools Widget ---
class AdminTools(QWidget):
    # Create a signal to communicate the SD card path to the main window
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
            # Emit the signal with the selected path
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

# --- Main Application Window ---
class MainWindow(QTabWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Game Stick Lite Modding Utility")
        self.setFixedSize(800, 600)
        self.setStyleSheet("font-size: 14px;")

        self.theme_editor = ThemeEditor()
        self.game_manager = GameManager()
        self.firmware_flasher = FirmwareFlasher()
        self.game_browser = GameBrowser()
        self.admin_tools = AdminTools()
        
        # Connect the custom signal from AdminTools to the main window's method
        self.admin_tools.sd_card_path_selected.connect(self.set_sd_card_path)

        # Create and add the tabs
        self.addTab(self.theme_editor, "Theme Editor")
        self.addTab(self.game_manager, "Game Manager")
        self.addTab(self.game_browser, "Game Browser")
        self.addTab(self.firmware_flasher, "Firmware Flasher")
        self.addTab(self.admin_tools, "Admin Tools")

        self.find_and_set_sd_card_path()

    def find_and_set_sd_card_path(self):
        """Automatically detects and sets the SD card path."""
        import platform
        
        # A list of folders expected to be found on the Game Stick's SD card
        known_dirs = ['roms', 'themes', 'emus']
        found_path = None

        system = platform.system()
        if system == "Windows":
            try:
                import win32api
                import win32file
                drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
                for drive in drives:
                    try:
                        if os.path.exists(drive) and win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                            if all(os.path.exists(os.path.join(drive, d)) for d in known_dirs):
                                found_path = drive
                                break
                    except Exception:
                        continue
            except ImportError:
                QMessageBox.warning(self, "Missing Library", "pywin32 library is not installed. Please run 'pip install pywin32' to enable automatic SD card detection.")

        elif system == "Darwin":  # macOS
            base_path = '/Volumes'
            if os.path.exists(base_path):
                for drive in os.listdir(base_path):
                    full_path = os.path.join(base_path, drive)
                    if all(os.path.exists(os.path.join(full_path, d)) for d in known_dirs):
                        found_path = full_path
                        break
        elif system == "Linux":
            base_path = '/media'
            if os.path.exists(base_path):
                for user_dir in os.listdir(base_path):
                    user_path = os.path.join(base_path, user_dir)
                    if os.path.isdir(user_path):
                        for drive in os.listdir(user_path):
                            full_path = os.path.join(user_path, drive)
                            if all(os.path.exists(os.path.join(full_path, d)) for d in known_dirs):
                                found_path = full_path
                                break
                    if found_path:
                        break

        if found_path:
            # Set the detected path in all relevant widgets
            self.set_sd_card_path(found_path)
            QMessageBox.information(self, "SD Card Found", f"Automatically detected SD card at:\n{found_path}")
        else:
             QMessageBox.warning(self, "SD Card Not Found", "Could not automatically detect Game Stick Lite SD card. Please select it manually in the Admin Tools tab.")

    def set_sd_card_path(self, path):
        self.admin_tools.drive_path_input.setText(path)
        self.game_manager.set_sd_card_path(path)
        self.game_browser.set_sd_card_path(path)
        self.firmware_flasher.set_sd_card_path(path)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    editor = MainWindow()
    editor.show()
    sys.exit(app.exec_())