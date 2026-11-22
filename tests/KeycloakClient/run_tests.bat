@echo off
rem Builds and runs the Keycloak client login flow test (fake identity provider, no browser).
rem Usage: run_tests.bat [Win32^|Win64^|Linux64]   (default Win64)
rem Linux64 runs the test through WSL (default distribution); without WSL it only builds.
rem Set RSVARS to the rsvars.bat of a different RAD Studio installation.
setlocal
set "TEST_PLATFORM=%~1"
if "%TEST_PLATFORM%"=="" set "TEST_PLATFORM=Win64"
if "%RSVARS%"=="" set "RSVARS=C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat"

call "%RSVARS%"
if errorlevel 1 exit /b 1
cd /d "%~dp0"

msbuild IAM4DKeycloakClientTest.dproj /t:Build /p:Config=Debug /p:Platform=%TEST_PLATFORM% /v:minimal /nologo
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)

set "TEST_BIN=%~dp0..\bin\KeycloakClient\%TEST_PLATFORM%\Debug"
set TEST_FAILED=0
set "RUN_CHECKED=%~dp0..\run_checked.bat"
if /i "%TEST_PLATFORM%"=="Linux64" goto :linux

call "%RUN_CHECKED%" "%TEST_BIN%\IAM4DKeycloakClientTest.exe"
if errorlevel 1 set TEST_FAILED=1
goto :summary

:linux
where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo WSL not available: Linux64 build succeeded, tests not run
  exit /b 0
)
pushd "%TEST_BIN%"
wsl.exe -- ./IAM4DKeycloakClientTest
if errorlevel 1 set TEST_FAILED=1
popd

:summary
echo.
if "%TEST_FAILED%"=="1" (
  echo KEYCLOAK CLIENT TEST FAILED
) else (
  echo KEYCLOAK CLIENT TEST PASSED
)
exit /b %TEST_FAILED%
