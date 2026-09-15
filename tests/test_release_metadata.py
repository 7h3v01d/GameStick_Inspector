from pathlib import Path

import gamestick


def test_release_version_metadata_is_consistent():
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    ui = (root / "src" / "gamestick" / "ui.py").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert gamestick.__version__ == "0.4.0-alpha6"
    assert 'version = "0.4.0a6"' in pyproject
    assert 'VERSION = "0.4.0-alpha6"' in ui
    assert readme.startswith("# GameStick Inspector 0.4.0-alpha6")


def test_release_archive_tree_contains_no_executable_legacy_directory():
    root = Path(__file__).resolve().parents[1]
    assert not (root / "legacy").exists()
    assert (root / "docs" / "LEGACY.md").is_file()
