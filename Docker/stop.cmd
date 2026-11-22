@echo off
rem Stops and removes the containers of the sample environment, of every profile.
rem Data (realm, users, identity providers saved by the samples) stays in the volume: see delete-volumes.cmd.
setlocal
where docker >nul 2>nul || goto :wsl
cd /d "%~dp0"
docker compose --profile brokering --profile tls down
exit /b

:wsl
wsl.exe --cd "%~dp0" -- bash ./stop.sh
set "RC=%errorlevel%"
rem The keep-alive window of start.cmd
powershell.exe -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='wsl.exe'\" | Where-Object { $_.CommandLine -like '*iam4d-keepalive*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
exit /b %RC%
