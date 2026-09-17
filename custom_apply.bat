@echo off
setlocal EnableExtensions
cd /d "%~dp0" || exit /b 1
set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
  echo GameStick Inspector environment is missing. Running setup.bat...
  call "%~dp0setup.bat"
  if errorlevel 1 exit /b 1
)
if "%~1"=="" (
  echo Usage:
  echo   custom_apply.bat apply ^<healthy.img^> ^<overlay.gscustom^> ^<target-root^> ^<rollback.gsrollback^> [--overwrite-rollback]
  echo   custom_apply.bat rollback ^<rollback.gsrollback^> ^<target-root^>
  exit /b 2
)
"%PYTHON_EXE%" "%~dp0src\custom_apply_cli.py" %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" pause
exit /b %RC%
