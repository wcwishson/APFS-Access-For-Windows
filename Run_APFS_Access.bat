@echo off
setlocal
if /I not "%APFSACCESS_VISIBLE_CONSOLE%"=="1" if exist "%~dp0Run_APFS_Access_Silent.vbs" (
  wscript.exe "%~dp0Run_APFS_Access_Silent.vbs"
  exit /b %ERRORLEVEL%
)
if /I not "%APFSACCESS_VISIBLE_CONSOLE%"=="1" if /I not "%APFSACCESS_LAUNCHED_MINIMIZED%"=="1" (
  set "APFSACCESS_LAUNCHED_MINIMIZED=1"
  start "" /min "%~f0" %*
  exit /b
)
cd /d "%~dp0"
set "APP_DIR=%~dp0artifacts\publish\click-run"
if not exist "%APP_DIR%\ApfsAccess.Tray.exe" (
  echo APFS Access app is not published yet.
  echo Build it with:
  echo   pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64
  pause
  exit /b 1
)
start "" /min "%APP_DIR%\ApfsAccess.Tray.exe"
