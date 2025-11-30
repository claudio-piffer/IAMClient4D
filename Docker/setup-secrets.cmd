@echo off
setlocal enabledelayedexpansion

set "SECRETS_DIR=.\secrets"

echo.
echo ====================================================
echo   Checking and generating secret files...
echo ====================================================
echo.

if not exist "%SECRETS_DIR%" (
    echo [INFO] Secrets directory not found, creating it...
    mkdir "%SECRETS_DIR%"
)

call :ProcessSecret pg_admin_password
call :ProcessSecret pg_keycloak_password

echo.
echo ====================================================
echo   Secret setup check complete.
echo ====================================================
echo.

goto :eof

:ProcessSecret
set "SECRET_NAME=%1"
set "TARGET_FILE=%SECRET_NAME%.txt"
set "TARGET_PATH=%SECRETS_DIR%\%TARGET_FILE%"

echo --- Checking for %TARGET_FILE%...

set "NEEDS_GENERATION=0"
if not exist "%TARGET_PATH%" (
    echo   [INFO] %TARGET_FILE% not found. Will generate a new password.
    set "NEEDS_GENERATION=1"
) else (
    for %%F in ("%TARGET_PATH%") do (
        if %%~zF gtr 0 (
            echo   [OK] %TARGET_FILE% already exists and is not empty. Skipping.
        ) else (
            echo   [INFO] %TARGET_FILE% exists but is empty. Will generate a new password.
            set "NEEDS_GENERATION=1"
        )
    )
)

if !NEEDS_GENERATION! equ 1 (
    echo   Generating an ultra script-safe password...

    for /f "usebackq delims=" %%P in (`
		powershell -NoProfile -Command "$chars = ([char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'); -join (1..24 | ForEach-Object { $chars | Get-Random })"
    `) do set "GENERATED_PASS=%%P"

    if not "!GENERATED_PASS!"=="" (
        <NUL set /p ".=!GENERATED_PASS!" > "%TARGET_PATH%"
        echo   [SET] New password saved in %TARGET_FILE%.
    ) else (
        echo   [ERROR] Failed to generate password for %TARGET_FILE%.
    )
)
echo.
goto :eof