@echo off
setlocal

:: Check for administrative privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: This script must be run as Administrator.
    pause
    exit /b 1
)

set "SERVICE_NAME=mini-proxy"
set "INSTALL_DIR=C:\mini-proxy"

echo Stopping service...
sc stop %SERVICE_NAME%

echo Deleting service...
sc delete %SERVICE_NAME%

echo Note: The installation directory %INSTALL_DIR% was NOT deleted.
echo You can remove it manually if no longer needed.

pause
