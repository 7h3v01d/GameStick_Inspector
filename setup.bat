@echo off
setlocal EnableExtensions
cd /d "%~dp0" || (
  echo ERROR: Unable to enter the GameStick Inspector folder:
  echo   %~dp0
  pause
  exit /b 1
)

set "VENV_PY=%~dp0.venv\Scripts\python.exe"
if not exist "%VENV_PY%" (
  echo Creating GameStick Inspector virtual environment...
  where py.exe >nul 2>&1
  if not errorlevel 1 (
    py -3 -m venv "%~dp0.venv"
  ) else (
    where python.exe >nul 2>&1
    if errorlevel 1 (
      echo ERROR: Python 3 was not found on PATH.
      echo Install Python 3, then run setup.bat again.
      pause
      exit /b 1
    )
    python -m venv "%~dp0.venv"
  )
  if errorlevel 1 (
    echo ERROR: Failed to create the virtual environment.
    pause
    exit /b 1
  )
)

if not exist "%VENV_PY%" (
  echo ERROR: Virtual environment Python was not created:
  echo   %VENV_PY%
  pause
  exit /b 1
)

echo Installing/verifying runtime requirements...
"%VENV_PY%" -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 (
  echo ERROR: Runtime dependency installation failed.
  pause
  exit /b 1
)

echo.
echo Setup complete.
exit /b 0
