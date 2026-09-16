@echo off
setlocal EnableExtensions
cd /d "%~dp0" || exit /b 1
set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
  echo GameStick Inspector environment is missing. Running setup.bat before elevation...
  call "%~dp0setup.bat"
  if errorlevel 1 (
    pause
    exit /b 1
  )
)
if not exist "%PYTHON_EXE%" (
  echo ERROR: Virtual environment Python is unavailable.
  pause
  exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -Verb RunAs -FilePath '%PYTHON_EXE%' -ArgumentList 'src\main.py' -WorkingDirectory '%CD%'"
if errorlevel 1 (
  echo.
  echo Administrator relaunch was cancelled or failed.
  pause
  exit /b 1
)
exit /b 0
