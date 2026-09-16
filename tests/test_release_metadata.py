from pathlib import Path

import gamestick


def test_release_version_metadata_is_consistent():
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    ui = (root / "src" / "gamestick" / "ui.py").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert gamestick.__version__ == "0.5.0-alpha8"
    assert 'version = "0.5.0a8"' in pyproject
    assert 'VERSION = "0.5.0-alpha8"' in ui
    assert readme.startswith("# GameStick Inspector 0.5.0-alpha8")


def test_release_owned_tree_contains_no_executable_legacy_package():
    root = Path(__file__).resolve().parents[1]
    # A developer may extract a new release over an old workspace that still has
    # a historical top-level legacy/ directory. That stale local directory is
    # not evidence that the current release archive contains executable legacy
    # code. Check the release-owned Python/package tree instead.
    assert not (root / "src" / "gamestick" / "legacy").exists()
    assert not any(path.name.casefold() == "legacy" for path in (root / "src").rglob("*"))
    assert (root / "docs" / "LEGACY.md").is_file()
