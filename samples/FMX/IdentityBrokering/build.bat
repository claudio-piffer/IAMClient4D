@echo off
rem Builds the FMX sample IdentityBrokeringMobile.
rem Usage: build.bat [Android64^|Android^|Win64^|Win32] [install]   (default Android64)
rem Android: builds and packages the APK (Build;Deploy); "install" then installs it with adb
rem (phone connected with USB debugging). Win32 and Win64: build only.
rem Set RSVARS to the rsvars.bat of a different RAD Studio installation, ADB to the adb.exe to use.
setlocal
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=Android64"
if "%RSVARS%"=="" set "RSVARS=C:\Program Files (x86)\Embarcadero\Studio\37.0\bin\rsvars.bat"
rem adb: the RAD Studio 37 Android SDK (PlatformSDKs, then the GetIt one), otherwise adb from the PATH
if "%ADB%"=="" for %%A in (
  "C:\Users\Public\Documents\Embarcadero\Studio\37.0\PlatformSDKs\android-sdk-windows\platform-tools\adb.exe"
  "C:\Users\Public\Documents\Embarcadero\Studio\37.0\CatalogRepository\AndroidSDK-37.0.60952.8797\platform-tools\Adb.exe"
) do if not defined ADB if exist %%A set "ADB=%%~A"
if "%ADB%"=="" for %%A in (adb.exe) do if not "%%~$PATH:A"=="" set "ADB=%%~$PATH:A"

call "%RSVARS%"
if errorlevel 1 exit /b 1
cd /d "%~dp0"

set "MSBUILD_TARGETS=Build"
if /i "%TARGET%"=="Android64" set "MSBUILD_TARGETS=Build;Deploy"
if /i "%TARGET%"=="Android" set "MSBUILD_TARGETS=Build;Deploy"

msbuild IdentityBrokeringMobile.dproj /t:%MSBUILD_TARGETS% /p:Config=Debug /p:Platform=%TARGET% /v:minimal /nologo
if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)

set "OUT=%~dp0..\..\bin\FMX\%TARGET%\Debug"
if /i "%~2"=="install" (
  "%ADB%" install -r "%OUT%\IdentityBrokeringMobile\bin\IdentityBrokeringMobile.apk"
  if errorlevel 1 exit /b 1
  echo Installed. Forward the Keycloak ports with keycloak.cmd reverse, see README.md
)
echo Output: %OUT%
