import os
import platform
from PyQt5.QtWidgets import QMessageBox

def find_sd_card_path():
    """Automatically detects and returns the path of a Game Stick SD card."""
    # Updated list of known directories based on the user's SD card
    known_dirs = ['Roms', 'cubegm', 'image']
    found_path = None
    system = platform.system()

    if system == "Windows":
        try:
            import win32api
            drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
            for drive in drives:
                # The os.path.exists() check handles the drive existence
                if os.path.exists(drive) and all(os.path.exists(os.path.join(drive, d)) for d in known_dirs):
                    found_path = drive
                    break
        except ImportError:
            QMessageBox.warning(None, "Missing Library", "pywin32 library is not installed. Please run 'pip install pywin32' to enable automatic SD card detection.")
            
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
    return found_path