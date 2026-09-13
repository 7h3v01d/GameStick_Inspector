@echo off
setlocal
cd /d "%~dp0"
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
