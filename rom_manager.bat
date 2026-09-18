@echo off
setlocal
set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
  echo Local Python environment not found. Bootstrapping with setup.bat...
  call "%~dp0setup.bat"
  if errorlevel 1 exit /b %errorlevel%
)
if not exist "%PYTHON_EXE%" (
  echo Failed to create local Python environment.
  exit /b 1
)
"%PYTHON_EXE%" "%~dp0src\rom_manager_cli.py" %*
endlocal
