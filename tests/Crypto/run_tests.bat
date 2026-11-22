@echo off
rem Builds and runs the IAMClient4D crypto test for the LockBox3, TMS and TaurusTLS providers.
rem Usage: run_tests.bat [Win32^|Win64^|Linux64]   (default Win64)
rem TaurusTLS runs once per folder in OPENSSL_DIRS (";" separated).
rem   Default: the folders among C:\OpenSSL3-<platform> and C:\OpenSSL4-<platform> that exist
rem   (TaurusTLS run skipped when none does). A folder set in OPENSSL_DIRS must exist.
rem Linux64 runs through WSL with the distribution OpenSSL; without WSL it only builds.
rem Set RSVARS to the rsvars.bat of a different RAD Studio installation.
rem Set TAURUSTLS_SOURCE when TaurusTLS\Source is not under src\Lib (e.g. git worktrees).
setlocal
set "TEST_PLATFORM=%~1"
if "%TEST_PLATFORM%"=="" set "TEST_PLATFORM=Win64"
if "%RSVARS%"=="" set "RSVARS=C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat"
if "%OPENSSL_DIRS%"=="" if /i not "%TEST_PLATFORM%"=="Linux64" (
  for %%D in ("C:\OpenSSL3-%TEST_PLATFORM%" "C:\OpenSSL4-%TEST_PLATFORM%") do if exist "%%~D\" call :add_openssl_dir "%%~D"
)

call "%RSVARS%"
if errorlevel 1 exit /b 1
cd /d "%~dp0"

for %%P in (LockBox3 TMS TaurusTLS) do (
  echo === Build %%P %TEST_PLATFORM%
  if "%TAURUSTLS_SOURCE%"=="" (
    msbuild IAM4DCryptoTest.dproj /t:Build /p:Config=Debug /p:Platform=%TEST_PLATFORM% /p:Provider=%%P /v:minimal /nologo
  ) else (
    msbuild IAM4DCryptoTest.dproj /t:Build /p:Config=Debug /p:Platform=%TEST_PLATFORM% /p:Provider=%%P "/p:TaurusTLSSource=%TAURUSTLS_SOURCE%" /v:minimal /nologo
  )
  if errorlevel 1 (
    echo BUILD FAILED: %%P
    exit /b 1
  )
)

set "TEST_BIN=%~dp0..\bin\Crypto"
set TEST_FAILED=0
set "RUN_CHECKED=%~dp0..\run_checked.bat"
if /i "%TEST_PLATFORM%"=="Linux64" goto :linux

call :run "%TEST_BIN%\LockBox3\%TEST_PLATFORM%\Debug\IAM4DCryptoTest.exe"
call :run "%TEST_BIN%\TMS\%TEST_PLATFORM%\Debug\IAM4DCryptoTest.exe"
if "%OPENSSL_DIRS%"=="" (
  echo.
  echo TaurusTLS %TEST_PLATFORM%: no OpenSSL folder found ^(set OPENSSL_DIRS^), run skipped
  goto :summary
)
for %%D in ("%OPENSSL_DIRS:;=" "%") do call :run "%TEST_BIN%\TaurusTLS\%TEST_PLATFORM%\Debug\IAM4DCryptoTest.exe" "%%~D"
goto :summary

:linux
where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo WSL not available: Linux64 build succeeded, tests not run
  exit /b 0
)
for %%P in (LockBox3 TMS TaurusTLS) do (
  echo.
  echo --- %%P Linux64
  pushd "%TEST_BIN%\%%P\Linux64\Debug"
  wsl.exe -- ./IAM4DCryptoTest
  if errorlevel 1 set TEST_FAILED=1
  popd
)
goto :summary

:add_openssl_dir
if "%OPENSSL_DIRS%"=="" (set "OPENSSL_DIRS=%~1") else set "OPENSSL_DIRS=%OPENSSL_DIRS%;%~1"
exit /b 0

:run
echo.
echo --- %~1 %~2
call "%RUN_CHECKED%" "%~1" %2
if errorlevel 1 set TEST_FAILED=1
exit /b 0

:summary
echo.
if "%TEST_FAILED%"=="1" (
  echo CRYPTO TEST FAILED
) else (
  echo CRYPTO TEST PASSED
)
exit /b %TEST_FAILED%
