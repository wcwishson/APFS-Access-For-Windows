@echo off
setlocal
if /I not "%APFSACCESS_VISIBLE_CONSOLE%"=="1" if /I not "%APFSACCESS_LAUNCHED_MINIMIZED%"=="1" (
  set "APFSACCESS_LAUNCHED_MINIMIZED=1"
  start "" /min "%~f0" %*
  exit /b
)
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\run_pilot_validation.ps1" %*
set "EXITCODE=%ERRORLEVEL%"
echo.
if not "%EXITCODE%"=="0" (
  echo Pilot validation failed with exit code %EXITCODE%.
)
pause
exit /b %EXITCODE%
