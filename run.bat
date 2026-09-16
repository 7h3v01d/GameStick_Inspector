@echo off
setlocal EnableExtensions
cd /d "%~dp0" || (
  echo ERROR: Unable to enter the GameStick Inspector folder:
  echo   %~dp0
  pause
  exit /b 1
)

set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
  echo GameStick Inspector first-run environment is not present.
  echo Running setup.bat now...
  echo.
  call "%~dp0setup.bat"
  if errorlevel 1 (
    echo.
    echo ERROR: Setup failed. GameStick Inspector was not started.
    pause
    exit /b 1
  )
)

if not exist "%PYTHON_EXE%" (
  echo ERROR: Setup completed without creating:
  echo   %PYTHON_EXE%
  pause
  exit /b 1
)

"%PYTHON_EXE%" "%~dp0src\main.py"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo GameStick Inspector exited with code %RC%.
  pause
)
exit /b %RC%
