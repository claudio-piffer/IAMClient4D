@echo off
setlocal enabledelayedexpansion

set "TEMPLATE_FILE=.env.template"
set "ENV_FILE=.env"
set "SECRETS_DIR=secrets"
set "KEYCLOAK_SECRET_FILE=%SECRETS_DIR%\pg_keycloak_password.txt"
set "SELF_SIGNED=0"
set "DOMAIN_NAME="

echo ====================================================
echo  IAM Cient 4D - First Time Setup (Windows)
echo ====================================================
echo.

rem ====================================================
rem  PARSE COMMAND LINE ARGUMENTS
rem ====================================================
:parse_args
if "%~1"=="" goto after_args
if /i "%~1"=="-self-signed" (
    set "SELF_SIGNED=1"
)
shift
goto parse_args
:after_args

rem ====================================================
rem  STEP 1: Check/Create secret files
rem ====================================================
echo --- [1/4] Checking/Creating secrets using setup-secrets.cmd...

if not exist "setup-secrets.cmd" (
    echo [ERROR] 'setup-secrets.cmd' is missing! Cannot generate passwords.
    exit /b 1
)
call setup-secrets.cmd
echo   [OK] Secret management process complete.
echo.

rem ====================================================
rem  STEP 2: Generate .env from template
rem ====================================================
echo --- [2/4] Generating '%ENV_FILE%' from '%TEMPLATE_FILE%' (preserving comments)...

if not exist "%TEMPLATE_FILE%" (
    echo [ERROR] Template file '%TEMPLATE_FILE%' not found!
    exit /b 1
)

set "VARS_TO_EXPAND="

for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%TEMPLATE_FILE%") do (
    set "%%A=%%B"
    set "VARS_TO_EXPAND=!VARS_TO_EXPAND! %%A"
)

if not exist "%KEYCLOAK_SECRET_FILE%" (
    echo [ERROR] Secret file '%KEYCLOAK_SECRET_FILE%' was not created. Aborting.
    exit /b 1
)
for /f "usebackq delims=" %%P in ("%KEYCLOAK_SECRET_FILE%") do set "IAM_DB_PASS=%%P"

(
    for /f "usebackq tokens=*" %%L in ("%TEMPLATE_FILE%") do (
        set "line=%%L"
        set "first_char=!line:~0,1!"

        if "!first_char!"=="" (
            echo.
        ) else if "!first_char!"=="#" (
            echo !line!
        ) else (
            for /f "tokens=1,* delims==" %%K in ("!line!") do (
                set "key=%%K"
                set "value=%%L"

                for %%V in (!VARS_TO_EXPAND!) do (
                   call set "value=%%value:${%%V}=!%%V!%%"
                )

                if /i "!key!"=="DOMAIN_NAME" (
                    set "DOMAIN_NAME=!value:${DOMAIN_NAME}=!"
                )

                echo !key!=!value!
            )
        )
    )

    echo.
    echo IAM_DB_PASS=!IAM_DB_PASS!

) > "%ENV_FILE%"

echo   [OK] '%ENV_FILE%' created successfully with resolved values and comments.
echo.

rem ====================================================
rem  STEP 3: Check/Create required docker volumes
rem ====================================================
echo --- [3/4] Checking for required Docker volumes...

for /f "usebackq tokens=1,* delims==" %%A in ("%ENV_FILE%") do (
    set "%%A=%%B"
)

set "NEEDS_VOLUME_CREATION=0"
docker volume inspect %IAM_DB_VOLUME_NAME% >nul 2>&1
if errorlevel 1 (
    echo [INFO] Volume "%IAM_DB_VOLUME_NAME%" is missing.
    set "NEEDS_VOLUME_CREATION=1"
) else (
    echo   [OK] Volume "%IAM_DB_VOLUME_NAME%" exists.
)

docker volume inspect %IAM_DB_LARC_VOLUME_NAME% >nul 2>&1
if errorlevel 1 (
    echo [INFO] Volume "%IAM_DB_LARC_VOLUME_NAME%" is missing.
    set "NEEDS_VOLUME_CREATION=1"
) else (
    echo   [OK] Volume "%IAM_DB_LARC_VOLUME_NAME%" exists.
)

if !NEEDS_VOLUME_CREATION! equ 1 (
    echo [ACTION] One or more volumes are missing. Running create-volumes.cmd...
    if exist "create-volumes.cmd" (
        call create-volumes.cmd
    ) else (
        echo [ERROR] 'create-volumes.cmd' script not found! Cannot create volumes.
        exit /b 1
    )
)
echo.

rem ====================================================
rem  STEP 3.5: Generate Self-Signed Certificate (optional)
rem ====================================================
if "%SELF_SIGNED%"=="1" (
    echo --- [3.5/4] Generating self-signed certificate for domain: !DOMAIN_NAME! ...
    if exist "config\nginx\ssl\generate-cert.cmd" (
        call config\nginx\ssl\generate-cert.cmd !DOMAIN_NAME!
    ) else (
        echo [ERROR] SSL certificate script 'generate-cert.cmd' not found!
        exit /b 1
    )
    echo   [OK] Self-signed certificate generated.
    echo.
)

rem ====================================================
rem  STEP 4: Final instructions
rem ====================================================
echo --- [4/4] Setup complete!
echo.
echo You can now start the services by running:
echo   start.cmd      (or)     start.cmd -logs
echo.

endlocal
goto :eof