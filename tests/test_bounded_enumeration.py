from __future__ import annotations

import pytest

from contextlib import AbstractContextManager
from pathlib import Path

import gamestick.fs_safety as fs_safety
import gamestick.probe as probe
import gamestick.profiles as profiles
from gamestick.browser_model import safe_browser_listing
from gamestick.fs_safety import BoundedScandirResult, bounded_scandir_names


class _FakeEntry:
    def __init__(self, name: str):
        self.name = name


class _CountingScandir(AbstractContextManager):
    def __init__(self, count: int, counter: dict[str, int]):
        self.count = count
        self.counter = counter
        self.index = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.index >= self.count:
            raise StopIteration
        value = _FakeEntry(f"entry-{self.index:06d}")
        self.index += 1
        self.counter["consumed"] = self.counter.get("consumed", 0) + 1
        return value

    def __exit__(self, exc_type, exc, tb):
        return False


def test_bounded_scandir_stops_after_limit_plus_one(monkeypatch, tmp_path):
    counter: dict[str, int] = {}
    monkeypatch.setattr(
        fs_safety.os,
        "scandir",
        lambda _path: _CountingScandir(10_000, counter),
    )

    result = bounded_scandir_names(tmp_path, limit=1)

    assert result.names == ["entry-000000"]
    assert result.truncated is True
    assert result.enumerated == 2
    assert counter["consumed"] == 2


def test_browser_limit_bounds_enumeration_not_only_output(tmp_path, monkeypatch):
    for index in range(10):
        (tmp_path / f"item-{index:02d}.txt").write_text("x", encoding="utf-8")

    original = fs_safety.os.scandir
    counter = {"consumed": 0}

    class _WrappedScandir(AbstractContextManager):
        def __init__(self, path):
            self._inner_cm = original(path)
            self._inner = None

        def __enter__(self):
            self._inner = self._inner_cm.__enter__()
            return self

        def __iter__(self):
            return self

        def __next__(self):
            assert self._inner is not None
            entry = next(self._inner)
            counter["consumed"] += 1
            return entry

        def __exit__(self, exc_type, exc, tb):
            return self._inner_cm.__exit__(exc_type, exc, tb)

    monkeypatch.setattr(fs_safety.os, "scandir", lambda path: _WrappedScandir(path))

    listing = safe_browser_listing(tmp_path, tmp_path, limit=1)

    assert len(listing.entries) == 1
    assert listing.truncated is True
    assert listing.entries_enumerated == 2
    assert counter["consumed"] == 2


def test_snapshot_directory_uses_bounded_sample(tmp_path, monkeypatch):
    directory = tmp_path / "cubegm"
    directory.mkdir()
    for index in range(10):
        (directory / f"item-{index:02d}.cfg").write_text("k=v", encoding="utf-8")

    monkeypatch.setattr(probe, "_MAX_SNAPSHOT_ENTRIES", 3)
    seen_limits: list[int] = []
    original = probe.bounded_scandir_names

    def wrapped(path, limit):
        seen_limits.append(limit)
        return original(path, limit)

    monkeypatch.setattr(probe, "bounded_scandir_names", wrapped)
    snapshot, warnings = probe._snapshot_directory(tmp_path, directory)

    assert seen_limits == [3]
    assert snapshot.entries_sampled == 3
    assert snapshot.truncated is True
    assert any("truncated" in warning.casefold() for warning in warnings)


def test_top_level_snapshot_discovery_has_hard_root_enumeration_cap(tmp_path, monkeypatch):
    for index in range(20):
        (tmp_path / f"dir-{index:02d}").mkdir()

    monkeypatch.setattr(probe, "_MAX_TOP_LEVEL_SNAPSHOT_ENUM_ENTRIES", 4)
    monkeypatch.setattr(probe, "_MAX_SNAPSHOT_DIRS", 32)
    seen_limits: list[int] = []
    original = probe.bounded_scandir_names

    def wrapped(path, limit):
        seen_limits.append(limit)
        return original(path, limit)

    monkeypatch.setattr(probe, "bounded_scandir_names", wrapped)
    snapshots, warnings = probe._directory_snapshots(tmp_path)

    assert seen_limits[0] == 4
    assert len(snapshots) <= 4
    assert any("Top-level snapshot discovery truncated" in warning for warning in warnings)


def test_metadata_scan_has_global_and_per_directory_enumeration_caps(tmp_path, monkeypatch):
    for index in range(20):
        (tmp_path / f"file-{index:02d}.txt").write_text("x", encoding="utf-8")

    monkeypatch.setattr(probe, "_MAX_SCAN_ENUMERATED_ENTRIES", 6)
    monkeypatch.setattr(probe, "_MAX_SCAN_ENTRIES_PER_DIRECTORY", 4)
    calls: list[tuple[int, int]] = []
    original = probe.bounded_scandir_names

    def wrapped(path, limit):
        result = original(path, limit)
        calls.append((limit, result.enumerated))
        return result

    monkeypatch.setattr(probe, "bounded_scandir_names", wrapped)
    artifacts, warnings = probe._candidate_artifacts(tmp_path)

    assert artifacts == []
    assert calls == [(4, 5)]
    assert sum(enumerated for _, enumerated in calls) <= 6
    assert any("truncated" in warning.casefold() for warning in warnings)


def test_profile_root_scan_is_bounded(monkeypatch, tmp_path):
    captured: list[int] = []

    def fake_bounded(_path, limit):
        captured.append(limit)
        return BoundedScandirResult(
            names=["Roms", "cubegm", "image"],
            truncated=True,
            enumerated=limit + 1,
        )

    for name in ("Roms", "cubegm", "image"):
        (tmp_path / name).mkdir()

    monkeypatch.setattr(profiles, "bounded_scandir_names", fake_bounded)
    match = profiles.best_profile(tmp_path)

    assert captured
    assert all(limit == profiles._MAX_PROFILE_ROOT_ENTRIES for limit in captured)
    assert match.profile_id == "observed_cubegm_layout"


def test_probe_policy_exposes_enumeration_bounds(tmp_path):
    for name in ("Roms", "cubegm", "image"):
        (tmp_path / name).mkdir()

    report = probe.inspect_volume(tmp_path)

    assert report.probe_policy["directory_enumeration_is_bounded"] is True
    assert report.probe_policy["max_metadata_enumerated_entries"] == probe._MAX_SCAN_ENUMERATED_ENTRIES
    assert report.probe_policy["max_metadata_entries_per_directory"] == probe._MAX_SCAN_ENTRIES_PER_DIRECTORY
    assert report.probe_policy["max_snapshot_entries_per_directory"] == probe._MAX_SNAPSHOT_ENTRIES

class _ErrorAfterScandir(AbstractContextManager):
    def __init__(self, names: list[str], counter: dict[str, int], error_after: int):
        self.names = names
        self.counter = counter
        self.error_after = error_after
        self.index = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.counter["next_calls"] = self.counter.get("next_calls", 0) + 1
        if self.index >= self.error_after:
            raise OSError("corrupt directory")
        if self.index >= len(self.names):
            raise StopIteration
        value = _FakeEntry(self.names[self.index])
        self.index += 1
        return value

    def __exit__(self, exc_type, exc, tb):
        return False


def test_bounded_scandir_preserves_partial_accounting_on_oserror(monkeypatch, tmp_path):
    counter: dict[str, int] = {}
    monkeypatch.setattr(
        fs_safety.os,
        "scandir",
        lambda _path: _ErrorAfterScandir(
            ["a", "b"], counter, error_after=2
        ),
    )

    result = bounded_scandir_names(tmp_path, limit=4)

    assert result.names == ["a", "b"]
    assert result.truncated is False
    assert isinstance(result.error, OSError)
    # Two yielded records plus the failed iterator advance are all budgeted.
    assert result.enumerated == 3
    assert counter["next_calls"] == 3


def test_bounded_scandir_accounts_error_in_truncation_probe_slot(monkeypatch, tmp_path):
    counter: dict[str, int] = {}
    monkeypatch.setattr(
        fs_safety.os,
        "scandir",
        lambda _path: _ErrorAfterScandir(
            ["a", "b"], counter, error_after=2
        ),
    )

    result = bounded_scandir_names(tmp_path, limit=2)

    assert result.names == ["a", "b"]
    assert result.truncated is False
    assert isinstance(result.error, OSError)
    assert result.enumerated == 3
    assert counter["next_calls"] == 3


def test_metadata_global_budget_counts_corrupt_directory_work(monkeypatch, tmp_path):
    # Real directories are required for the containment/lstat layer.  Scandir is
    # then replaced with a hostile iterator that fails after partial progress.
    for name in ("d0", "d1", "d2"):
        (tmp_path / name).mkdir()

    original_scandir = fs_safety.os.scandir
    counter = {"next_calls": 0}

    class _BudgetedScandir(AbstractContextManager):
        def __init__(self, path):
            self.path = Path(path)
            self.inner_cm = None
            self.inner = None
            self.child_index = 0

        def __enter__(self):
            if self.path == tmp_path:
                self.inner_cm = original_scandir(self.path)
                self.inner = self.inner_cm.__enter__()
            return self

        def __iter__(self):
            return self

        def __next__(self):
            counter["next_calls"] += 1
            if self.path == tmp_path:
                assert self.inner is not None
                return next(self.inner)
            # One successful entry, then a corrupt-directory error.  The
            # successful name is intentionally discarded by the metadata scan.
            if self.child_index == 0:
                self.child_index += 1
                return _FakeEntry("partial.cfg")
            raise OSError("corrupt directory")

        def __exit__(self, exc_type, exc, tb):
            if self.inner_cm is not None:
                return self.inner_cm.__exit__(exc_type, exc, tb)
            return False

    monkeypatch.setattr(fs_safety.os, "scandir", lambda path: _BudgetedScandir(path))
    monkeypatch.setattr(probe, "_MAX_SCAN_ENUMERATED_ENTRIES", 6)
    monkeypatch.setattr(probe, "_MAX_SCAN_ENTRIES_PER_DIRECTORY", 4)

    artifacts, warnings = probe._candidate_artifacts(tmp_path)

    assert artifacts == []
    assert counter["next_calls"] <= 6
    assert any("Could not enumerate" in warning for warning in warnings)
    assert any("enumeration stopped" in warning for warning in warnings)


def test_metadata_does_not_process_partial_names_from_corrupt_directory(monkeypatch, tmp_path):
    child = tmp_path / "child"
    child.mkdir()
    (child / "partial.cfg").write_text("[private]\napi_key=secret\n", encoding="utf-8")

    original_scandir = fs_safety.os.scandir

    class _RootThenCorruptChild(AbstractContextManager):
        def __init__(self, path):
            self.path = Path(path)
            self.inner_cm = None
            self.inner = None
            self.index = 0

        def __enter__(self):
            if self.path == tmp_path:
                self.inner_cm = original_scandir(self.path)
                self.inner = self.inner_cm.__enter__()
            return self

        def __iter__(self):
            return self

        def __next__(self):
            if self.path == tmp_path:
                assert self.inner is not None
                return next(self.inner)
            if self.index == 0:
                self.index += 1
                return _FakeEntry("partial.cfg")
            raise OSError("corrupt directory")

        def __exit__(self, exc_type, exc, tb):
            if self.inner_cm is not None:
                return self.inner_cm.__exit__(exc_type, exc, tb)
            return False

    monkeypatch.setattr(fs_safety.os, "scandir", lambda path: _RootThenCorruptChild(path))

    artifacts, warnings = probe._candidate_artifacts(tmp_path)

    assert artifacts == []
    assert any("Could not enumerate" in warning for warning in warnings)


def test_browser_listing_exposes_corrupt_enumeration_error(monkeypatch, tmp_path):
    import gamestick.browser_model as browser_model

    monkeypatch.setattr(
        browser_model,
        "bounded_scandir_names",
        lambda _path, _limit: BoundedScandirResult(
            names=[],
            truncated=False,
            enumerated=1,
            error=OSError("corrupt directory"),
        ),
    )

    listing = browser_model.safe_browser_listing(tmp_path, tmp_path, limit=1000)

    assert listing.entries == []
    assert listing.truncated is False
    assert listing.entries_enumerated == 1
    assert listing.error == "corrupt directory"


def test_browser_ui_contains_visible_enumeration_error_marker():
    root = Path(__file__).resolve().parents[1]
    ui = (root / "src" / "gamestick" / "ui.py").read_text(encoding="utf-8")
    assert "[unable to enumerate directory:" in ui


def test_rom_manager_casefold_resolution_uses_bounded_scandir(monkeypatch, tmp_path):
    import gamestick.rom_manager as rom_manager
    from gamestick.fs_safety import BoundedScandirResult

    parent = tmp_path / "root"
    parent.mkdir()
    monkeypatch.setattr(
        rom_manager,
        "bounded_scandir_names",
        lambda _parent, limit: BoundedScandirResult(names=["x"] * limit, truncated=True, enumerated=limit + 1),
    )
    with pytest.raises(rom_manager.RomManagerError, match="safety bound"):
        rom_manager._resolve_casefold_child(parent, "ROOT.DAT")
