@echo off
setlocal

set "ENV_FILE=.env"

for /f "usebackq tokens=*" %%a in (`findstr /v /r "^#" "%ENV_FILE%"`) do (
    for /f "tokens=1* delims==" %%i in ("%%a") do (
        set "%%i=%%j"
    )
)

set "CONTAINER_DB_VOLUME_NAME=%IAM_DB_VOLUME_NAME%"
set "CONTAINER_DB_LOG_ARCH_VOLUME_NAME=%IAM_DB_LARC_VOLUME_NAME%"
set "CONTAINER_DB_VOLUME_DEVICE=%CD%\db\keycloak\data"
set "CONTAINER_DB_LARC_VOLUME_DEVICE=%CD%\db\keycloak\pg_log_archive"

echo Ensuring local directories exist...
if not exist "%CONTAINER_DB_VOLUME_DEVICE%" mkdir "%CONTAINER_DB_VOLUME_DEVICE%"
if not exist "%CONTAINER_DB_LARC_VOLUME_DEVICE%" mkdir "%CONTAINER_DB_LARC_VOLUME_DEVICE%"

set "POSIX_CONTAINER_DB_VOLUME_DEVICE=/%CONTAINER_DB_VOLUME_DEVICE%"
set "POSIX_CONTAINER_DB_VOLUME_DEVICE=%POSIX_CONTAINER_DB_VOLUME_DEVICE:\=/%"
set "POSIX_CONTAINER_DB_VOLUME_DEVICE=%POSIX_CONTAINER_DB_VOLUME_DEVICE::/=/%"

set "POSIX_CONTAINER_DB_LARC_VOLUME_DEVICE=/%CONTAINER_DB_LARC_VOLUME_DEVICE%"
set "POSIX_CONTAINER_DB_LARC_VOLUME_DEVICE=%POSIX_CONTAINER_DB_LARC_VOLUME_DEVICE:\=/%"
set "POSIX_CONTAINER_DB_LARC_VOLUME_DEVICE=%POSIX_CONTAINER_DB_LARC_VOLUME_DEVICE::/=/%"

echo Creating database data volume: %CONTAINER_DB_VOLUME_NAME%
docker volume create --driver local --opt type=none --opt device="%POSIX_CONTAINER_DB_VOLUME_DEVICE%" --opt o=bind "%CONTAINER_DB_VOLUME_NAME%"

echo Creating log archive volume: %CONTAINER_DB_LOG_ARCH_VOLUME_NAME%
docker volume create --driver local --opt type=none --opt device="%POSIX_CONTAINER_DB_LARC_VOLUME_DEVICE%" --opt o=bind "%CONTAINER_DB_LOG_ARCH_VOLUME_NAME%"

echo Volumes created successfully.

endlocal