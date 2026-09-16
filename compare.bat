@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment not found. Run setup.bat first.
  exit /b 1
)
.venv\Scripts\python.exe src\compare_cli.py %*
if errorlevel 1 pause
