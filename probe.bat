@echo off
setlocal
cd /d "%~dp0"
.venv\Scripts\python.exe src\probe_cli.py %*
if errorlevel 1 pause
