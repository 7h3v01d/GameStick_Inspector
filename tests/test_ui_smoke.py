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
        assert "0.5.0-alpha12.1" in window.windowTitle()
    finally:
        window.close()
        app.processEvents()


def test_recovery_ui_is_split_into_scrollable_workflows_statically():
    root = Path(__file__).resolve().parents[1]
    source = (root / "src" / "gamestick" / "ui.py").read_text(encoding="utf-8")

    assert "self.workflow_tabs = QTabWidget()" in source
    assert "scroll = QScrollArea()" in source
    assert "scroll.setWidgetResizable(True)" in source
    for label in ("Image & Verify", "Fast Analysis", "Repair", "Customise", "Advanced"):
        assert f'addTab(' in source and f'"{label}"' in source

    # Regression guard: each major recovery workflow belongs to one page, not the root stack.
    assert "imaging_layout.addWidget(create_group)" in source
    assert "analysis_layout.addWidget(fast_group)" in source
    assert "analysis_layout.addWidget(catalogue_group)" in source
    assert "repair_page_layout.addWidget(repair_group)" in source
    assert "customise_page_layout.addWidget(custom_group)" in source
    assert "advanced_layout.addWidget(compare_group)" in source
