@echo off
rem Builds and runs the HTTP timeout test (slow local HTTP server, no Keycloak).
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

msbuild IAM4DHTTPTimeoutTest.dproj /t:Build /p:Config=Debug /p:Platform=%TEST_PLATFORM% /v:minimal /nologo
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)

set "TEST_BIN=%~dp0..\bin\HTTPTimeout\%TEST_PLATFORM%\Debug"
set TEST_FAILED=0
set "RUN_CHECKED=%~dp0..\run_checked.bat"
if /i "%TEST_PLATFORM%"=="Linux64" goto :linux

call "%RUN_CHECKED%" "%TEST_BIN%\IAM4DHTTPTimeoutTest.exe"
if errorlevel 1 set TEST_FAILED=1
goto :summary

:linux
where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo WSL not available: Linux64 build succeeded, tests not run
  exit /b 0
)
pushd "%TEST_BIN%"
wsl.exe -- ./IAM4DHTTPTimeoutTest
if errorlevel 1 set TEST_FAILED=1
popd

:summary
echo.
if "%TEST_FAILED%"=="1" (
  echo HTTP TIMEOUT TEST FAILED
) else (
  echo HTTP TIMEOUT TEST PASSED
)
exit /b %TEST_FAILED%
