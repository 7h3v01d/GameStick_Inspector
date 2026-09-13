import json
import subprocess

import gamestick.probe as probe


def test_standard_windows_powershell_paths_include_system32_and_sysnative():
    paths = probe._standard_windows_powershell_paths(r"C:\\Windows")
    assert any("System32" in path and path.lower().endswith("powershell.exe") for path in paths)
    assert any("Sysnative" in path and path.lower().endswith("powershell.exe") for path in paths)


def test_mapping_runner_falls_through_missing_backend(monkeypatch):
    monkeypatch.setattr(
        probe,
        "_windows_powershell_candidates",
        lambda: [r"C:\\missing\\powershell.exe", r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"],
    )
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args[0])
        if "missing" in args[0]:
            raise FileNotFoundError(2, "not found", args[0])
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps({"DiskNumber": 7}), stderr="")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    payload, backend = probe._run_windows_mapping_script("ignored")
    assert payload["DiskNumber"] == 7
    assert backend.endswith("powershell.exe")
    assert len(calls) == 2


def test_mapping_runner_reports_all_backend_failures(monkeypatch):
    monkeypatch.setattr(probe, "_windows_powershell_candidates", lambda: ["first.exe", "second.exe"])

    def fake_run(args, **kwargs):
        raise subprocess.CalledProcessError(1, args, output="", stderr="backend failed")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    try:
        probe._run_windows_mapping_script("ignored")
    except RuntimeError as exc:
        text = str(exc)
        assert "first.exe" in text
        assert "second.exe" in text
        assert "backend failed" in text
    else:
        raise AssertionError("expected RuntimeError")


def test_elevated_candidate_selection_never_uses_path_resolved_powershell(monkeypatch):
    monkeypatch.setattr(probe.os.path, "isfile", lambda path: "WindowsPowerShell" in path)
    monkeypatch.setattr(probe.shutil, "which", lambda name: rf"C:\evil\{name}")

    candidates = probe._windows_powershell_candidates(
        elevated=True,
        windows_directory=r"C:\Windows",
    )

    assert candidates
    assert all(r"C:\evil" not in candidate for candidate in candidates)
    assert any("System32" in candidate for candidate in candidates)


def test_non_elevated_candidate_selection_also_refuses_path_helpers(monkeypatch):
    monkeypatch.setattr(probe.os.path, "isfile", lambda path: "WindowsPowerShell" in path)
    monkeypatch.setattr(probe.shutil, "which", lambda name: rf"C:\tools\{name}")

    candidates = probe._windows_powershell_candidates(
        elevated=False,
        windows_directory=r"C:\Windows",
    )

    assert candidates
    assert all(r"C:\tools" not in candidate for candidate in candidates)
    assert any("System32" in candidate for candidate in candidates)


def test_standard_paths_use_windows_semantics_even_on_test_host():
    paths = probe._standard_windows_powershell_paths(r"C:\Windows")
    assert paths[0] == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
