@echo off
rem Builds and runs the IAMClient4D identity brokering test.
rem Usage: run_tests.bat [Win32^|Win64^|Linux64]   (default Win64)
rem Integration checks need a Keycloak 26+ reachable at KEYCLOAK_URL (default http://localhost:18080,
rem the one started by docker\up.cmd) with a master realm admin (KEYCLOAK_ADMIN /
rem KEYCLOAK_ADMIN_PASSWORD, default admin/admin); without it the test fails, unless IAM4D_ALLOW_SKIP=1
rem (integration skipped). Checks that need the Internet or an optional extension are counted as skipped.
rem The test creates and deletes the realm iam4d-idp-test.
rem Linux64 runs the test through WSL (default distribution); without WSL it only builds.
rem Set RSVARS to the rsvars.bat of a different RAD Studio installation.
setlocal
set "TEST_PLATFORM=%~1"
if "%TEST_PLATFORM%"=="" set "TEST_PLATFORM=Win64"
if "%RSVARS%"=="" set "RSVARS=C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat"
if "%KEYCLOAK_URL%"=="" set "KEYCLOAK_URL=http://localhost:18080"
if "%KEYCLOAK_ADMIN%"=="" set "KEYCLOAK_ADMIN=admin"
if "%KEYCLOAK_ADMIN_PASSWORD%"=="" set "KEYCLOAK_ADMIN_PASSWORD=admin"

call "%RSVARS%"
if errorlevel 1 exit /b 1
cd /d "%~dp0"

msbuild IAM4DIdentityProviderTest.dproj /t:Build /p:Config=Debug /p:Platform=%TEST_PLATFORM% /v:minimal /nologo
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)

set "TEST_BIN=%~dp0..\bin\IdentityProvider\%TEST_PLATFORM%\Debug"
set TEST_FAILED=0
set "RUN_CHECKED=%~dp0..\run_checked.bat"
if /i "%TEST_PLATFORM%"=="Linux64" goto :linux

call "%RUN_CHECKED%" "%TEST_BIN%\IAM4DIdentityProviderTest.exe" "%KEYCLOAK_URL%" "%KEYCLOAK_ADMIN%" "%KEYCLOAK_ADMIN_PASSWORD%"
if errorlevel 1 set TEST_FAILED=1
goto :summary

:linux
where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo WSL not available: Linux64 build succeeded, tests not run
  exit /b 0
)
pushd "%TEST_BIN%"
wsl.exe -- ./IAM4DIdentityProviderTest "%KEYCLOAK_URL%" "%KEYCLOAK_ADMIN%" "%KEYCLOAK_ADMIN_PASSWORD%"
if errorlevel 1 set TEST_FAILED=1
popd

:summary
echo.
if "%TEST_FAILED%"=="1" (
  echo IDENTITY PROVIDER TEST FAILED
) else (
  echo IDENTITY PROVIDER TEST PASSED
)
exit /b %TEST_FAILED%
