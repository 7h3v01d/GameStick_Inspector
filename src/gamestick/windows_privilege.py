from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional


class ElevationError(RuntimeError):
    """Raised when a Windows elevation request cannot be started."""


def is_process_elevated(*, host_system: Optional[str] = None, admin_checker=None) -> bool:
    """Return whether the current process has an elevated Windows token.

    Non-Windows hosts return False because raw physical-device imaging is Windows-only.
    The injectable checker keeps the function deterministic in tests.
    """

    system = host_system or platform.system()
    if system != "Windows":
        return False
    if admin_checker is not None:
        try:
            return bool(admin_checker())
        except Exception:
            return False

    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _quote_windows_args(args: list[str]) -> str:
    # list2cmdline follows Windows CreateProcess quoting rules and avoids hand-built
    # quoting bugs for paths containing spaces.
    return subprocess.list2cmdline(args)


def relaunch_current_app_elevated(
    *,
    entry_script: str | Path,
    python_executable: str | Path | None = None,
    working_directory: str | Path | None = None,
    extra_args: Optional[list[str]] = None,
    host_system: Optional[str] = None,
    shell_execute=None,
) -> None:
    """Launch the same venv Python entry point through the Windows UAC `runas` verb.

    This function does not change any GameStick media. It only starts a second,
    elevated instance of the application. The caller decides whether/when to exit
    the current non-elevated process.
    """

    system = host_system or platform.system()
    if system != "Windows":
        raise ElevationError("Administrator relaunch is available on Windows only.")

    executable = Path(python_executable or sys.executable).resolve()
    script = Path(entry_script).resolve()
    workdir = Path(working_directory or script.parent.parent).resolve()

    if not executable.is_file():
        raise ElevationError(f"Python executable not found: {executable}")
    if not script.is_file():
        raise ElevationError(f"Application entry script not found: {script}")
    if not workdir.is_dir():
        raise ElevationError(f"Working directory not found: {workdir}")

    args = [str(script)]
    if extra_args:
        args.extend(str(value) for value in extra_args)
    parameters = _quote_windows_args(args)

    if shell_execute is None:
        import ctypes

        shell_execute = ctypes.windll.shell32.ShellExecuteW

    result = int(
        shell_execute(
            None,
            "runas",
            str(executable),
            parameters,
            str(workdir),
            1,
        )
    )
    if result <= 32:
        raise ElevationError(
            "Windows did not start the elevated GameStick Inspector instance "
            f"(ShellExecuteW result {result})."
        )
