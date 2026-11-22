@echo off
rem Stops the sample environment and deletes its database: the next start imports the realm again
rem from config\keycloak\realm\realm.json. Passwords in secrets\ and the certificate are kept.
setlocal
where docker >nul 2>nul || goto :wsl
cd /d "%~dp0"
docker compose --profile brokering --profile tls down --volumes
exit /b

:wsl
wsl.exe --cd "%~dp0" -- bash ./delete-volumes.sh
set "RC=%errorlevel%"
rem The keep-alive window of start.cmd
powershell.exe -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='wsl.exe'\" | Where-Object { $_.CommandLine -like '*iam4d-keepalive*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
exit /b %RC%
