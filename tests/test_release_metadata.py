from pathlib import Path

import gamestick


def test_release_version_metadata_is_consistent():
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    ui = (root / "src" / "gamestick" / "ui.py").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert gamestick.__version__ == "0.5.0-alpha17"
    assert 'version = "0.5.0a17"' in pyproject
    assert 'VERSION = "0.5.0-alpha17"' in ui
    assert readme.startswith("# GameStick Inspector 0.5.0-alpha17")


def test_release_owned_tree_contains_no_executable_legacy_package():
    root = Path(__file__).resolve().parents[1]
    # A developer may extract a new release over an old workspace that still has
    # a historical top-level legacy/ directory. That stale local directory is
    # not evidence that the current release archive contains executable legacy
    # code. Check the release-owned Python/package tree instead.
    assert not (root / "src" / "gamestick" / "legacy").exists()
    assert not any(path.name.casefold() == "legacy" for path in (root / "src").rglob("*"))
    assert (root / "docs" / "LEGACY.md").is_file()


def test_qt_progress_signals_preserve_large_byte_counts():
    root = Path(__file__).resolve().parents[1]
    ui = (root / "src" / "gamestick" / "ui.py").read_text(encoding="utf-8")
    assert "progress = pyqtSignal(str, object, object)" in ui
    assert "class ImageCompareThread(QThread):\n    progress = pyqtSignal(object, object)" in ui
    assert "pyqtSignal(str, int, int)" not in ui



def test_windows_launchers_bootstrap_fresh_extract():
    root = Path(__file__).resolve().parents[1]
    run_bat = (root / "run.bat").read_text(encoding="utf-8")
    setup_bat = (root / "setup.bat").read_text(encoding="utf-8")

    assert 'set "PYTHON_EXE=%~dp0.venv\\Scripts\\python.exe"' in run_bat
    assert 'if not exist "%PYTHON_EXE%"' in run_bat
    assert 'call "%~dp0setup.bat"' in run_bat
    assert '"%PYTHON_EXE%" "%~dp0src\\main.py"' in run_bat
    assert '.venv\\Scripts\\python.exe src\\main.py' not in run_bat

    assert 'where py.exe >nul 2>&1' in setup_bat
    assert 'py -3 -m venv "%~dp0.venv"' in setup_bat
    assert 'where python.exe >nul 2>&1' in setup_bat
    assert 'python -m venv "%~dp0.venv"' in setup_bat
    assert '"%VENV_PY%" -m pip install -r "%~dp0requirements.txt"' in setup_bat

    for launcher in ("run_admin.bat", "probe.bat", "image.bat", "compare.bat", "fast_compare.bat", "catalogue_compare.bat", "repair_workspace.bat", "rom_hide.bat", "rom_manager.bat", "custom_apply.bat", "test.bat"):
        text = (root / launcher).read_text(encoding="utf-8")
        assert 'call "%~dp0setup.bat"' in text


def test_all_cli_entrypoints_are_syntactically_valid():
    import ast

    root = Path(__file__).resolve().parents[1]
    for path in sorted((root / "src").glob("*_cli.py")):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
