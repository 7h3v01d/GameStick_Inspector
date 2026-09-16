import ast
import os
from pathlib import Path

import pytest


def test_browser_tab_defines_report_invalidation_slot_statically():
    """Catch missing signal targets even on test hosts without PyQt5 installed."""
    root = Path(__file__).resolve().parents[1]
    ui_path = root / "src" / "gamestick" / "ui.py"
    tree = ast.parse(ui_path.read_text(encoding="utf-8"), filename=str(ui_path))

    browser = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "BrowserTab"
    )
    methods = {
        node.name for node in browser.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "clear_view" in methods

    source = ui_path.read_text(encoding="utf-8")
    assert "self.inspector.report_invalidated.connect(self.clear_view)" in source


def test_main_window_constructs_with_browser_invalidation_slot():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PyQt5")
    from PyQt5.QtWidgets import QApplication
    from gamestick.ui import BrowserTab, MainWindow

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        assert hasattr(BrowserTab, "clear_view")
        assert "0.5.0-alpha8" in window.windowTitle()
    finally:
        window.close()
        app.processEvents()
