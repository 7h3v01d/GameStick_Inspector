from pathlib import Path

import pytest

from gamestick.windows_privilege import (
    ElevationError,
    is_process_elevated,
    relaunch_current_app_elevated,
)


def test_is_process_elevated_uses_injected_checker():
    assert is_process_elevated(host_system="Windows", admin_checker=lambda: 1) is True
    assert is_process_elevated(host_system="Windows", admin_checker=lambda: 0) is False


def test_is_process_elevated_fails_closed_when_checker_errors():
    def broken():
        raise OSError("no token")

    assert is_process_elevated(host_system="Windows", admin_checker=broken) is False


def test_is_process_elevated_non_windows_is_false():
    assert is_process_elevated(host_system="Linux", admin_checker=lambda: 1) is False


def test_relaunch_uses_runas_and_existing_venv_python(tmp_path):
    python_exe = tmp_path / "python.exe"
    script = tmp_path / "src" / "main.py"
    workdir = tmp_path
    python_exe.write_bytes(b"")
    script.parent.mkdir()
    script.write_text("pass\n", encoding="utf-8")
    calls = []

    def fake_shell_execute(hwnd, verb, executable, params, cwd, show):
        calls.append((verb, executable, params, cwd, show))
        return 42

    relaunch_current_app_elevated(
        entry_script=script,
        python_executable=python_exe,
        working_directory=workdir,
        host_system="Windows",
        shell_execute=fake_shell_execute,
    )

    assert calls
    verb, executable, params, cwd, show = calls[0]
    assert verb == "runas"
    assert Path(executable) == python_exe.resolve()
    assert str(script.resolve()) in params
    assert Path(cwd) == workdir.resolve()
    assert show == 1


def test_relaunch_rejects_shell_execute_failure(tmp_path):
    python_exe = tmp_path / "python.exe"
    script = tmp_path / "src" / "main.py"
    python_exe.write_bytes(b"")
    script.parent.mkdir()
    script.write_text("pass\n", encoding="utf-8")

    with pytest.raises(ElevationError, match="did not start"):
        relaunch_current_app_elevated(
            entry_script=script,
            python_executable=python_exe,
            working_directory=tmp_path,
            host_system="Windows",
            shell_execute=lambda *args: 5,
        )


def test_relaunch_rejects_non_windows(tmp_path):
    with pytest.raises(ElevationError, match="Windows only"):
        relaunch_current_app_elevated(
            entry_script=tmp_path / "main.py",
            host_system="Linux",
        )
