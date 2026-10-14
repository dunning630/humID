@echo off
rem HumID Server for Windows: remove the program and its background task.
rem Accounts, sealed documents and server keys stay in C:\ProgramData\HumID unless you choose to delete them.
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0humid.ps1" uninstall
echo.
pause
