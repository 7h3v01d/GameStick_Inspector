@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo .venv is missing. Run setup.bat first.
  pause
  exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -Verb RunAs -FilePath '%CD%\.venv\Scripts\python.exe' -ArgumentList 'src\main.py' -WorkingDirectory '%CD%'"
if errorlevel 1 (
  echo.
  echo Administrator relaunch was cancelled or failed.
  pause
)
