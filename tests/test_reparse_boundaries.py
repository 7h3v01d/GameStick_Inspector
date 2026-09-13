from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import gamestick.fs_safety as fs_safety
from gamestick.browser_model import safe_browser_children
from gamestick.fs_safety import ForensicPathError, assert_contained_non_reparse, is_reparse_point
from gamestick.probe import inspect_volume
from gamestick.profiles import best_profile


class _StatWithReparse:
    def __init__(self, base):
        self._base = base
        self.st_file_attributes = int(getattr(base, "st_file_attributes", 0) or 0) | 0x0400

    def __getattr__(self, name):
        return getattr(self._base, name)


def _mark_as_windows_reparse(monkeypatch, target: Path) -> None:
    original = fs_safety._lstat
    target_key = str(target.absolute()).casefold()

    def fake_lstat(path: Path):
        base = original(path)
        if str(Path(path).absolute()).casefold() == target_key:
            return _StatWithReparse(base)
        return base

    monkeypatch.setattr(fs_safety, "_lstat", fake_lstat)


def _make_layout(root: Path) -> None:
    for name in ("Roms", "cubegm", "image"):
        (root / name).mkdir()


def test_windows_reparse_attribute_is_rejected_without_symlink_semantics(tmp_path, monkeypatch):
    junction_like = tmp_path / "junction-like"
    junction_like.mkdir()
    _mark_as_windows_reparse(monkeypatch, junction_like)

    assert is_reparse_point(junction_like) is True
    with pytest.raises(ForensicPathError, match="Reparse point"):
        assert_contained_non_reparse(tmp_path, junction_like)


def test_reparse_subtree_contributes_no_artifacts_snapshots_or_browser_entries(tmp_path, monkeypatch):
    card = tmp_path / "card"
    card.mkdir()
    _make_layout(card)

    escaped = card / "cubegm" / "outside"
    escaped.mkdir()
    (escaped / "secret.cfg").write_text("[private]\napi_key=do-not-export\n", encoding="utf-8")
    db = escaped / "secret.db"
    con = sqlite3.connect(db)
    con.execute("create table host_secrets(value text)")
    con.commit()
    con.close()

    _mark_as_windows_reparse(monkeypatch, escaped)

    report = inspect_volume(card)
    rendered = json.dumps(report.to_dict(), sort_keys=True)

    assert "do-not-export" not in rendered
    assert "api_key" not in rendered
    assert "host_secrets" not in rendered
    assert not any("outside/" in artifact.path.replace("\\", "/") for artifact in report.candidate_artifacts)

    cubegm = next(snapshot for snapshot in report.directory_snapshots if snapshot.path.casefold() == "cubegm")
    assert "outside" not in [name.casefold() for name in cubegm.directory_names]

    browser_names = [entry.name.casefold() for entry in safe_browser_children(card, card / "cubegm")]
    assert "outside" not in browser_names


def test_top_level_reparse_entry_is_absent_from_root_snapshot_and_browser(tmp_path, monkeypatch):
    card = tmp_path / "card"
    card.mkdir()
    _make_layout(card)
    outside = card / "outside"
    outside.mkdir()
    (outside / "secret.json").write_text('{"token":"private"}', encoding="utf-8")
    _mark_as_windows_reparse(monkeypatch, outside)

    report = inspect_volume(card)

    assert "outside" not in [entry["name"].casefold() for entry in report.root_entries]
    assert "outside" not in [snapshot.path.casefold() for snapshot in report.directory_snapshots]
    assert "outside" not in [entry.name.casefold() for entry in safe_browser_children(card, card)]


def test_profile_markers_must_be_real_non_reparse_directories(tmp_path, monkeypatch):
    # Ordinary files with the right names must no longer earn the 90/high profile.
    for name in ("Roms", "cubegm", "image"):
        (tmp_path / name).write_text("not a directory", encoding="utf-8")
    assert best_profile(tmp_path).confidence == "none"

    # Nor may a directory marker count if it is a Windows reparse point.
    for name in ("Roms", "cubegm", "image"):
        (tmp_path / name).unlink()
        (tmp_path / name).mkdir()
    _mark_as_windows_reparse(monkeypatch, tmp_path / "cubegm")
    match = best_profile(tmp_path)
    assert match.confidence != "high"
    assert "cubegm" in [name.casefold() for name in match.missing_markers]


def test_canonical_containment_is_defence_in_depth_if_link_flag_is_hidden(tmp_path, monkeypatch):
    card = tmp_path / "card"
    host = tmp_path / "host"
    card.mkdir()
    host.mkdir()
    link = card / "outside"
    try:
        link.symlink_to(host, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation unavailable in this test environment")

    original = fs_safety._lstat

    class _HiddenLinkStat:
        def __init__(self, base):
            self._base = base
            # Deliberately lie about the object type so the primary reparse test
            # cannot save us; resolve/containment must still reject the escape.
            self.st_mode = (base.st_mode & ~0o170000) | 0o040000
            self.st_file_attributes = 0

        def __getattr__(self, name):
            return getattr(self._base, name)

    def hide_link(path: Path):
        base = original(path)
        if Path(path).absolute() == link.absolute():
            return _HiddenLinkStat(base)
        return base

    monkeypatch.setattr(fs_safety, "_lstat", hide_link)
    with pytest.raises(ForensicPathError, match="Resolved path escapes"):
        assert_contained_non_reparse(card, link)


def test_selected_root_itself_cannot_be_a_reparse_point(tmp_path, monkeypatch):
    card = tmp_path / "card"
    card.mkdir()
    _make_layout(card)
    _mark_as_windows_reparse(monkeypatch, card)

    with pytest.raises(ValueError, match="unsafe"):
        inspect_volume(card)
