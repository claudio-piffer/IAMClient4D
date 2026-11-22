@echo off
rem Builds and runs the TLS test: certificate validation and public key pinning over real
rem handshakes with local HTTPS servers (Indy + TaurusTLS), no Keycloak.
rem Usage: run_tests.bat [Win32^|Win64^|Linux64]   (default Win64)
rem Windows: OpenSSL from OPENSSL_DIR (default C:\OpenSSL4-<platform>, then C:\OpenSSL3-<platform>).
rem Linux64 runs through WSL with the distribution OpenSSL; without WSL it only builds.
rem Set RSVARS to the rsvars.bat of a different RAD Studio installation.
rem Set TAURUSTLS_SOURCE when TaurusTLS\Source is not under src\Lib (e.g. git worktrees).
setlocal
set "TEST_PLATFORM=%~1"
if "%TEST_PLATFORM%"=="" set "TEST_PLATFORM=Win64"
if "%RSVARS%"=="" set "RSVARS=C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat"
if "%OPENSSL_DIR%"=="" if exist "C:\OpenSSL4-%TEST_PLATFORM%\bin\" set "OPENSSL_DIR=C:\OpenSSL4-%TEST_PLATFORM%\bin"
if "%OPENSSL_DIR%"=="" if exist "C:\OpenSSL3-%TEST_PLATFORM%\bin\" set "OPENSSL_DIR=C:\OpenSSL3-%TEST_PLATFORM%\bin"

call "%RSVARS%"
if errorlevel 1 exit /b 1
cd /d "%~dp0"

if "%TAURUSTLS_SOURCE%"=="" (
  msbuild IAM4DTLSTest.dproj /t:Build /p:Config=Debug /p:Platform=%TEST_PLATFORM% /v:minimal /nologo
) else (
  msbuild IAM4DTLSTest.dproj /t:Build /p:Config=Debug /p:Platform=%TEST_PLATFORM% "/p:TaurusTLSSource=%TAURUSTLS_SOURCE%" /v:minimal /nologo
)
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)

set "TEST_BIN=%~dp0..\bin\TLS\%TEST_PLATFORM%\Debug"
set TEST_FAILED=0
set "RUN_CHECKED=%~dp0..\run_checked.bat"
if /i "%TEST_PLATFORM%"=="Linux64" goto :linux

call "%RUN_CHECKED%" "%TEST_BIN%\IAM4DTLSTest.exe" "%OPENSSL_DIR%"
if errorlevel 1 set TEST_FAILED=1
goto :summary

:linux
where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo WSL not available: Linux64 build succeeded, tests not run
  exit /b 0
)
pushd "%TEST_BIN%"
wsl.exe -- ./IAM4DTLSTest
if errorlevel 1 set TEST_FAILED=1
popd

:summary
echo.
if "%TEST_FAILED%"=="1" (
  echo TLS TEST FAILED
) else (
  echo TLS TEST PASSED
)
exit /b %TEST_FAILED%
