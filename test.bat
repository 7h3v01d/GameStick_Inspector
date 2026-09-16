@echo off
setlocal EnableExtensions
cd /d "%~dp0" || exit /b 1
set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
  echo GameStick Inspector environment is missing. Running setup.bat...
  call "%~dp0setup.bat"
  if errorlevel 1 exit /b 1
)
"%PYTHON_EXE%" -m pip install -r "%~dp0requirements-dev.txt"
if errorlevel 1 exit /b 1
"%PYTHON_EXE%" -m pytest -v
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
