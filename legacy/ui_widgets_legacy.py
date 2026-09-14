import os
import shutil
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QListWidget, QListWidgetItem, QLabel, 
                             QFileDialog, QColorDialog, QLineEdit, QGroupBox, 
                             QMessageBox, QComboBox, QTreeWidget, QTreeWidgetItem,
                             QProgressBar)  # <-- Add QProgressBar here
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

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
                dest_path = os.path.join(self.sd_card_path, os.path.basename(firmware_file))
                
                self.progress_bar.setVisible(True)
                self.progress_bar.setValue(0)
                
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
        
        emulator_display_names = {
            'ps1': 'PlayStation', 'nes': 'Nintendo (NES)', 'snes': 'Super Nintendo (SNES)',
            'gb': 'Game Boy', 'gbc': 'Game Boy Color', 'gba': 'Game Boy Advance',
            'genesis': 'Sega Genesis', 'arcade': 'Arcade'
        }
        
        for emulator_folder in os.listdir(roms_path):
            emulator_path = os.path.join(roms_path, emulator_folder)
            if os.path.isdir(emulator_path):
                display_name = emulator_display_names.get(emulator_folder.lower(), emulator_folder)
                emulator_item = QTreeWidgetItem(self.game_list_tree, [display_name, ''])
                
                for game_file in os.listdir(emulator_path):
                    if not game_file.startswith('.'):
                        game_item = QTreeWidgetItem(emulator_item, ['', game_file])
                        
        self.game_list_tree.expandAll()