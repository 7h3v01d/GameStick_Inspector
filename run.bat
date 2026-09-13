@echo off
setlocal
cd /d "%~dp0"
.venv\Scripts\python.exe src\main.py
if errorlevel 1 (
  echo.
  echo If PyQt5 is missing, run setup.bat first.
  pause
)
