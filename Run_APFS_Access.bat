@echo off
setlocal
cd /d "%~dp0"
set "APP_DIR=%~dp0artifacts\publish\click-run"
if not exist "%APP_DIR%\ApfsAccess.Tray.exe" (
  echo APFS Access app is not published yet.
  echo Build it with:
  echo   pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64
  pause
  exit /b 1
)
start "" "%APP_DIR%\ApfsAccess.Tray.exe"
