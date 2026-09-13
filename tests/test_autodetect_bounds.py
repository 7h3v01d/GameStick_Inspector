from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path

import gamestick.fs_safety as fs_safety
import gamestick.probe as probe
from gamestick.models import ProfileMatch


def _mountinfo_line(index: int, mount_point: str) -> str:
    return (
        f"{1000 + index} 1 8:{index % 255} / {mount_point} rw,relatime "
        f"- vfat /dev/fake{index} rw\n"
    )


def test_linux_mountinfo_discovery_caps_hostile_candidate_stream(monkeypatch):
    consumed = {"lines": 0}

    def hostile_lines():
        for index in range(10_000):
            consumed["lines"] += 1
            yield _mountinfo_line(index, f"/mnt/card-{index:05d}")

    monkeypatch.setattr(probe.platform, "system", lambda: "Linux")
    monkeypatch.setattr(probe, "_linux_mountinfo_lines", hostile_lines)

    roots = list(probe.iter_mount_roots())

    assert len(roots) == probe._MAX_AUTO_DETECT_CANDIDATES
    assert consumed["lines"] == probe._MAX_AUTO_DETECT_CANDIDATES
    assert roots[0] == Path("/mnt/card-00000")


def test_find_candidate_volumes_caps_profile_probes(monkeypatch):
    yielded = {"roots": 0}
    probed = {"profiles": 0}

    def hostile_roots():
        for index in range(10_000):
            yielded["roots"] += 1
            yield Path(f"/mnt/fake-{index:05d}")

    def fake_best_profile(_root):
        probed["profiles"] += 1
        return ProfileMatch(
            profile_id="none",
            display_name="none",
            score=0,
            confidence="none",
        )

    monkeypatch.setattr(probe, "iter_mount_roots", hostile_roots)
    monkeypatch.setattr(probe, "best_profile", fake_best_profile)

    assert probe.find_candidate_volumes() == []
    assert probed["profiles"] == probe._MAX_AUTO_DETECT_CANDIDATES
    assert yielded["roots"] == probe._MAX_AUTO_DETECT_CANDIDATES


def test_linux_mountinfo_escape_decoding_and_scope(monkeypatch):
    lines = [
        _mountinfo_line(1, r"/media/leon/My\040Card"),
        _mountinfo_line(2, "/var/lib/not-an-autodetect-root"),
        _mountinfo_line(3, "/run/media/leon/card"),
    ]
    monkeypatch.setattr(probe.platform, "system", lambda: "Linux")
    monkeypatch.setattr(probe, "_linux_mountinfo_lines", lambda: iter(lines))

    roots = list(probe.iter_mount_roots())

    assert Path("/media/leon/My Card") in roots
    assert Path("/run/media/leon/card") in roots
    assert all(not str(root).startswith("/var/lib") for root in roots)


def test_macos_volumes_enumeration_is_bounded(monkeypatch, tmp_path):
    for index in range(600):
        (tmp_path / f"Volume-{index:04d}").mkdir()

    original_scandir = fs_safety.os.scandir
    counter = {"next_calls": 0}

    class CountingScandir(AbstractContextManager):
        def __init__(self, path):
            self._cm = original_scandir(path)
            self._it = None

        def __enter__(self):
            self._it = self._cm.__enter__()
            return self

        def __iter__(self):
            return self

        def __next__(self):
            counter["next_calls"] += 1
            return next(self._it)

        def __exit__(self, exc_type, exc, tb):
            return self._cm.__exit__(exc_type, exc, tb)

    monkeypatch.setattr(fs_safety.os, "scandir", lambda path: CountingScandir(path))
    monkeypatch.setattr(probe.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(probe, "_MACOS_VOLUMES_ROOT", tmp_path)

    roots = list(probe.iter_mount_roots())

    assert len(roots) == probe._MAX_MACOS_VOLUME_ENTRIES
    assert counter["next_calls"] <= probe._MAX_MACOS_VOLUME_ENTRIES + 1


def test_probe_policy_exposes_autodetect_bounds(tmp_path):
    for name in ("Roms", "cubegm", "image"):
        (tmp_path / name).mkdir()

    report = probe.inspect_volume(tmp_path)

    assert report.probe_policy["max_auto_detect_candidates"] == probe._MAX_AUTO_DETECT_CANDIDATES
    assert report.probe_policy["max_linux_mountinfo_lines"] == probe._MAX_LINUX_MOUNTINFO_LINES
    assert (
        report.probe_policy["max_linux_fallback_enumerated_entries"]
        == probe._MAX_LINUX_FALLBACK_ENUMERATED_ENTRIES
    )
    assert report.probe_policy["max_macos_volume_entries"] == probe._MAX_MACOS_VOLUME_ENTRIES


def test_linux_mountinfo_reader_has_hard_line_cap(monkeypatch):
    counter = {"next_calls": 0}

    class _HugeMountInfo(AbstractContextManager):
        def __iter__(self):
            return self

        def __next__(self):
            counter["next_calls"] += 1
            if counter["next_calls"] > 10_000:
                raise StopIteration
            return _mountinfo_line(counter["next_calls"], f"/mnt/card-{counter['next_calls']:05d}")

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(Path, "open", lambda self, *args, **kwargs: _HugeMountInfo())

    lines = list(probe._linux_mountinfo_lines())

    assert len(lines) == probe._MAX_LINUX_MOUNTINFO_LINES
    assert counter["next_calls"] == probe._MAX_LINUX_MOUNTINFO_LINES


def test_linux_fallback_has_global_enumeration_operation_budget(monkeypatch, tmp_path):
    bases = []
    for base_index in range(3):
        base = tmp_path / f"base-{base_index}"
        base.mkdir()
        bases.append(base)
        for first_index in range(8):
            first = base / f"user-{first_index}"
            first.mkdir()
            for second_index in range(8):
                (first / f"card-{second_index}").mkdir()

    original_scandir = fs_safety.os.scandir
    counter = {"next_calls": 0}

    class CountingScandir(AbstractContextManager):
        def __init__(self, path):
            self._cm = original_scandir(path)
            self._it = None

        def __enter__(self):
            self._it = self._cm.__enter__()
            return self

        def __iter__(self):
            return self

        def __next__(self):
            counter["next_calls"] += 1
            return next(self._it)

        def __exit__(self, exc_type, exc, tb):
            return self._cm.__exit__(exc_type, exc, tb)

    monkeypatch.setattr(fs_safety.os, "scandir", lambda path: CountingScandir(path))
    monkeypatch.setattr(probe, "_LINUX_MOUNT_BASES", tuple(bases))
    monkeypatch.setattr(probe, "_MAX_LINUX_FALLBACK_ENUMERATED_ENTRIES", 20)
    monkeypatch.setattr(probe, "_MAX_LINUX_FALLBACK_ENTRIES_PER_DIRECTORY", 8)

    list(probe._iter_linux_fallback_roots())

    assert counter["next_calls"] <= 20
