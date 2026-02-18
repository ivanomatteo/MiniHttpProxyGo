@echo off
setlocal

:: Check for administrative privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: This script must be run as Administrator.
    pause
    exit /b 1
)

set "INSTALL_DIR=C:\mini-proxy"
set "SERVICE_NAME=mini-proxy"
set "EXE_NAME=mini-proxy.exe"
set "CONFIG_NAME=config.json"

echo Creating installation directory: %INSTALL_DIR%
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

echo Copying files...
if exist "%EXE_NAME%" (
    copy /Y "%EXE_NAME%" "%INSTALL_DIR%"
) else (
    echo Warning: %EXE_NAME% not found in current directory.
)

if exist "%CONFIG_NAME%" (
    copy /Y "%CONFIG_NAME%" "%INSTALL_DIR%"
) else (
    echo Warning: %CONFIG_NAME% not found in current directory.
)

echo Creating Windows Service...
:: Note: The binary must be compatible with Windows Service Control Manager.
:: If it's a standard Go binary, it might fail to start via 'sc create' 
:: without a wrapper like NSSM or internal service handling logic.
sc create %SERVICE_NAME% binPath= ""%INSTALL_DIR%\%EXE_NAME%" -config "%INSTALL_DIR%\%CONFIG_NAME%"" start= auto DisplayName= "Mini HTTP Proxy"
sc description %SERVICE_NAME% "Mini HTTP Proxy with parent proxy and authentication"

echo Starting service...
sc start %SERVICE_NAME%

echo Installation complete.
pause
