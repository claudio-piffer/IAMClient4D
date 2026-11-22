@echo off
rem Follows the logs of the sample environment (Ctrl+C to leave). Usage: logs.cmd [service]
rem   service: keycloak, db, spid-saml-check, cie-simulator or gateway (default: all)
setlocal
where docker >nul 2>nul || goto :wsl
cd /d "%~dp0"
docker compose --profile brokering --profile tls logs -f %*
exit /b

:wsl
wsl.exe --cd "%~dp0" -- bash ./logs.sh %*
exit /b
