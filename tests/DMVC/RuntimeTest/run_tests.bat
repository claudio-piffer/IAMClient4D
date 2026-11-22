@echo off
rem Builds and runs the IAMClient4D DMVC runtime test on Indy Direct and WebBroker,
rem with the deprecated middleware and with the filter bundle.
rem Usage: run_tests.bat [Win32^|Win64^|Linux64]   (default Win64)
rem Linux64 runs the tests through WSL (default distribution); without WSL it only builds.
rem Set RSVARS to the rsvars.bat of a different RAD Studio installation.
setlocal
set "TEST_PLATFORM=%~1"
if "%TEST_PLATFORM%"=="" set "TEST_PLATFORM=Win64"
if "%RSVARS%"=="" set "RSVARS=C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat"

call "%RSVARS%"
if errorlevel 1 exit /b 1
cd /d "%~dp0"

msbuild IAM4DDMVCRuntimeTest.dproj /t:Build /p:Config=Debug /p:Platform=%TEST_PLATFORM% /v:minimal /nologo
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)

set "TEST_BIN=%~dp0..\..\bin\DMVC\%TEST_PLATFORM%\Debug"
set TEST_FAILED=0
set "RUN_CHECKED=%~dp0..\..\run_checked.bat"
if /i "%TEST_PLATFORM%"=="Linux64" goto :linux

for %%M in (middleware bundle) do (
  call "%RUN_CHECKED%" "%TEST_BIN%\IAM4DDMVCRuntimeTest.exe" indy 18765 %%M
  if errorlevel 1 set TEST_FAILED=1
  echo.
  call "%RUN_CHECKED%" "%TEST_BIN%\IAM4DDMVCRuntimeTest.exe" webbroker 18766 %%M
  if errorlevel 1 set TEST_FAILED=1
  echo.
)
goto :summary

:linux
where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo WSL not available: Linux64 build succeeded, tests not run
  exit /b 0
)
pushd "%TEST_BIN%"
for %%M in (middleware bundle) do (
  wsl.exe -- ./IAM4DDMVCRuntimeTest indy 18765 %%M
  if errorlevel 1 set TEST_FAILED=1
  echo.
  wsl.exe -- ./IAM4DDMVCRuntimeTest webbroker 18766 %%M
  if errorlevel 1 set TEST_FAILED=1
  echo.
)
popd

:summary
if "%TEST_FAILED%"=="1" (
  echo RUNTIME TEST FAILED
) else (
  echo RUNTIME TEST PASSED
)
exit /b %TEST_FAILED%
