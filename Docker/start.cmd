@echo off
rem Starts the Keycloak of the samples and waits until it is ready; can be run again at any time.
rem Usage: start.cmd [brokering] [tls] [logs]
rem   brokering  also the SPID demo identity provider and the CIE simulator
rem   tls        also the HTTPS gateway: Keycloak on https://DOMAIN_NAME:GATEWAY_PORT/auth (.env)
rem   logs       then follow the logs (Ctrl+C leaves them, the services keep running)
rem The services of a profile not given are stopped (e.g. start.cmd after start.cmd tls).
rem Uses docker from the Windows PATH, otherwise Docker inside WSL (default distribution) through start.sh:
rem then a minimized window keeps the WSL VM alive (it stops when idle, the containers with it);
rem stop.cmd closes it.
setlocal enabledelayedexpansion
where docker >nul 2>nul || goto :wsl
cd /d "%~dp0"

set "PROFILES="
set "TLS=0"
set "BROKERING=0"
set "LOGS=0"
:args
if "%~1"=="" goto :run
if /i "%~1"=="brokering" (
  set "PROFILES=!PROFILES! --profile brokering"
  set "BROKERING=1"
) else if /i "%~1"=="tls" (
  set "PROFILES=!PROFILES! --profile tls"
  set "TLS=1"
) else if /i "%~1"=="logs" (
  set "LOGS=1"
) else (
  echo Usage: %~nx0 [brokering] [tls] [logs] 1>&2
  exit /b 2
)
shift
goto :args

:run
rem Explicit path: with NoDefaultCurrentDirectoryInExePath cmd does not search the current folder
call .\setup-secrets.cmd || exit /b 1

rem Settings used here too (Compose reads .env by itself)
if exist .env for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do set "%%A=%%B"
if "%KC_PORT%"=="" set "KC_PORT=18180"
if "%IAM_ADMIN_USER%"=="" set "IAM_ADMIN_USER=admin"
if "%SPID_CHECK_PORT%"=="" set "SPID_CHECK_PORT=18443"
if "%CIE_CHECK_PORT%"=="" set "CIE_CHECK_PORT=18444"
if "%DOMAIN_NAME%"=="" set "DOMAIN_NAME=localhost"
if "%GATEWAY_PORT%"=="" set "GATEWAY_PORT=24443"
set "IAM_PUBLIC_URL="
if "%TLS%"=="1" set "IAM_PUBLIC_URL=https://%DOMAIN_NAME%:%GATEWAY_PORT%/auth"
set "URL=http://localhost:%KC_PORT%/auth"
if "%TLS%"=="1" set "URL=%IAM_PUBLIC_URL%"

rem Services of the profiles not given: the gateway would front a Keycloak with another URL
set "REMOVE="
if not "%BROKERING%"=="1" set "REMOVE=spid-saml-check cie-simulator"
if not "%TLS%"=="1" set "REMOVE=%REMOVE% gateway"
if not "%REMOVE%"=="" docker compose --profile brokering --profile tls rm --stop --force %REMOVE% >nul 2>nul

echo --- Starting (first time: images are downloaded and built, a few minutes)
docker compose %PROFILES% up -d --build --wait || exit /b 1

echo.
echo Keycloak ready: %URL% (admin: %IAM_ADMIN_USER%, password in secrets\kc_admin_password.txt)
echo Realm iamclient4d: %URL%/realms/iamclient4d
echo   users: demo / demo (realm-admin), student / Student#2026, scientist / Scientist#2026
if "%BROKERING%"=="1" echo SPID demo identity provider: http://localhost:%SPID_CHECK_PORT%/demo (users: /demo/users, e.g. ada / password123)
if "%BROKERING%"=="1" echo CIE simulator: http://localhost:%CIE_CHECK_PORT%/demo (metadata for Keycloak: http://cie-simulator:%CIE_CHECK_PORT%/demo/metadata.xml)
if "%TLS%"=="1" echo Self-signed certificate: config\nginx\ssl\certs\certificate.crt

if "%LOGS%"=="1" docker compose %PROFILES% logs -f
exit /b 0

:wsl
rem The wsl.exe that keeps WSL alive is recognized by the marker in its command line. Started by
rem Start-Process, which passes no handle: with start the window would inherit the output of this
rem script and keep a pipe reading it open (CI, a calling script).
powershell.exe -NoProfile -Command "if (-not (Get-CimInstance Win32_Process -Filter \"Name='wsl.exe'\" | Where-Object { $_.CommandLine -like '*iam4d-keepalive*' })) { Start-Process cmd.exe -WindowStyle Minimized -ArgumentList '/c title IAMClient4D WSL keep-alive & wsl.exe -- bash -c ''exec sleep infinity'' iam4d-keepalive' }"
wsl.exe --cd "%~dp0" -- bash ./start.sh %*
if errorlevel 1 exit /b 1
echo Keep the "IAMClient4D WSL keep-alive" window open while using the samples: closing it lets WSL stop the containers.
exit /b 0
