@echo off
rem Builds and starts the test Keycloak, spid-saml-check and the CIE simulator, and waits until they are ready.
rem Uses docker from the Windows PATH, otherwise Docker inside WSL (default distribution).
rem Optional variables: KC_VERSION, SPID_VERSION, CIE_VERSION, SPID_SHA256, CIE_SHA256, KC_PORT,
rem SPID_CHECK_VERSION, SPID_CHECK_PORT, CIE_CHECK_PORT (see docker-compose.yml).
setlocal
rem Only the defined ones: WSL passes a variable listed in WSLENV but not defined as an empty one,
rem which hides the defaults (e.g. SPID_SHA256 of the Dockerfile)
for %%V in (KC_VERSION SPID_VERSION CIE_VERSION SPID_SHA256 CIE_SHA256 KC_PORT SPID_CHECK_VERSION SPID_CHECK_PORT CIE_CHECK_PORT) do (
  if defined %%V call set "WSLENV=%%V/u:%%WSLENV%%"
)
where docker >nul 2>nul
if errorlevel 1 (
  wsl.exe --cd "%~dp0" -- docker compose up -d --build --wait
) else (
  docker compose -f "%~dp0docker-compose.yml" up -d --build --wait
)
if errorlevel 1 exit /b 1
if "%KC_PORT%"=="" set "KC_PORT=18080"
if "%SPID_CHECK_PORT%"=="" set "SPID_CHECK_PORT=8443"
if "%CIE_CHECK_PORT%"=="" set "CIE_CHECK_PORT=8444"
echo Keycloak ready: http://localhost:%KC_PORT% (admin/admin)
echo SPID demo identity provider: http://localhost:%SPID_CHECK_PORT%/demo (users: /demo/users)
echo CIE simulator: http://localhost:%CIE_CHECK_PORT%/demo, metadata for Keycloak: http://cie-simulator:%CIE_CHECK_PORT%/demo/metadata.xml
