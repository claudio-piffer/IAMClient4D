@echo off
rem Stops and removes the test Keycloak (the database is in memory: nothing is kept).
setlocal
where docker >nul 2>nul
if errorlevel 1 (
  wsl.exe --cd "%~dp0" -- docker compose down
) else (
  docker compose -f "%~dp0docker-compose.yml" down
)
