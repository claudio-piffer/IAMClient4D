@echo off
rem  ---------------------------------------------------------------------------
rem  Keycloak of the IdentityBrokering mobile sample, for a physical phone.
rem  start: the sample environment of Docker\ with the profile brokering (Keycloak
rem  on http://localhost:18180/auth, realm iamclient4d, SPID demo identity provider
rem  on 18443, CIE simulator on 18444), then "adb reverse" of the three ports: on
rem  the phone localhost is the phone, the USB cable brings it to this PC.
rem  Usage: keycloak.cmd [start|reverse|logs|stop]
rem    start    start the environment (built the first time), forward the ports to the phone
rem    reverse  forward the ports again (needed after reconnecting the phone)
rem    logs     follow the Keycloak log, Ctrl+C to leave
rem    stop     remove the forwards, stop the environment (data kept: see Docker\delete-volumes.cmd)
rem  Ports from Docker\.env (KC_PORT, SPID_CHECK_PORT, CIE_CHECK_PORT).
rem  Optional variables: ADB (adb.exe), ANDROID_SERIAL (with more than one device).
rem  ---------------------------------------------------------------------------
setlocal
rem adb: the RAD Studio 37 Android SDK (PlatformSDKs, then the GetIt one), otherwise adb from the PATH
if not defined ADB for %%A in (
  "C:\Users\Public\Documents\Embarcadero\Studio\37.0\PlatformSDKs\android-sdk-windows\platform-tools\adb.exe"
  "C:\Users\Public\Documents\Embarcadero\Studio\37.0\CatalogRepository\AndroidSDK-37.0.60952.8797\platform-tools\Adb.exe"
) do if not defined ADB if exist %%A set "ADB=%%~A"
if not defined ADB for %%A in (adb.exe) do if not "%%~$PATH:A"=="" set "ADB=%%~$PATH:A"
for %%I in ("%~dp0..\..\..\Docker") do set "ENV_DIR=%%~fI"
if exist "%ENV_DIR%\.env" for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ENV_DIR%\.env") do set "%%A=%%B"
if not defined KC_PORT set "KC_PORT=18180"
if not defined SPID_CHECK_PORT set "SPID_CHECK_PORT=18443"
if not defined CIE_CHECK_PORT set "CIE_CHECK_PORT=18444"

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=start"
if /i "%ACTION%"=="start" goto :start
if /i "%ACTION%"=="reverse" goto :reverse_only
if /i "%ACTION%"=="logs" goto :logs
if /i "%ACTION%"=="stop" goto :stop
echo Usage: keycloak.cmd [start^|reverse^|logs^|stop]
exit /b 1

:start
call "%ENV_DIR%\start.cmd" brokering
if errorlevel 1 exit /b 1
call :reverse
echo.
echo App, Connection card: base URL http://localhost:%KC_PORT%/auth, realm iamclient4d, client iam4d-sample-app
echo Users: demo / demo (Keycloak, realm-admin), ada / password123 (SPID spid-test), marcopolo / password123 (CIE)
exit /b 0

:reverse_only
call :reverse
exit /b %errorlevel%

:reverse
if not exist "%ADB%" (
  echo [WARNING] adb not found: %ADB%  ^(set ADB^)
  exit /b 1
)
"%ADB%" start-server >nul 2>nul
"%ADB%" devices | findstr /e /c:"device" >nul
if errorlevel 1 (
  echo [WARNING] No phone connected: plug it in with USB debugging on, authorize this PC, then: keycloak.cmd reverse
  exit /b 1
)
for %%P in (%KC_PORT% %SPID_CHECK_PORT% %CIE_CHECK_PORT%) do (
  "%ADB%" reverse tcp:%%P tcp:%%P >nul
  if errorlevel 1 (
    echo [ERROR] adb reverse tcp:%%P failed ^(more than one device? set ANDROID_SERIAL^)
    exit /b 1
  )
)
echo --- Phone: localhost:%KC_PORT%, :%SPID_CHECK_PORT% and :%CIE_CHECK_PORT% forwarded to this PC
"%ADB%" reverse --list
exit /b 0

:logs
call "%ENV_DIR%\logs.cmd" keycloak
exit /b %errorlevel%

:stop
if exist "%ADB%" (
  for %%P in (%KC_PORT% %SPID_CHECK_PORT% %CIE_CHECK_PORT%) do "%ADB%" reverse --remove tcp:%%P >nul 2>nul
)
call "%ENV_DIR%\stop.cmd"
exit /b %errorlevel%
