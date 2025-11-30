@echo off
setlocal

set "DOMAIN_ARG=%1"

if defined DOMAIN_ARG (
    echo === Generating SSL certificate for domain: %DOMAIN_ARG% ===
    powershell -ExecutionPolicy Bypass -File "%~dp0generate-cert.ps1" -DomainName "%DOMAIN_ARG%"
) else (
    echo === Generating SSL certificate for local machine ===
    powershell -ExecutionPolicy Bypass -File "%~dp0generate-cert.ps1"
)

if errorlevel 1 (
    echo ERROR: Failed to generate SSL files.
    pause
    exit /b 1
)

echo.
echo Success! Certificate files are ready.
pause
endlocal