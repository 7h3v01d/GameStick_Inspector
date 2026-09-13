@echo off
setlocal
cd /d "%~dp0"
.venv\Scripts\python.exe src\image_cli.py %*
if errorlevel 1 pause
