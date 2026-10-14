@echo off
rem HumID Server for Windows: install, or update an existing install (settings and data are kept).
rem Asks for administrator rights, then runs humid.ps1 install from this folder.
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Asking for administrator rights...
  powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0humid.ps1" install
echo.
pause
