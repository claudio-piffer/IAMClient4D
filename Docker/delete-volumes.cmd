@echo off
setlocal

set ENV_FILE=.env

for /f "usebackq tokens=*" %%a in (`findstr /v /r "^#" "%ENV_FILE%"`) do (
    for /f "tokens=1* delims==" %%i in ("%%a") do (
        set "%%i=%%j"
    )
)

echo Attempting to remove Docker volumes: %IAM_DB_VOLUME_NAME%, %IAM_DB_LARC_VOLUME_NAME%
docker volume rm -f "%IAM_DB_VOLUME_NAME%" "%IAM_DB_LARC_VOLUME_NAME%" 2>NUL || (call;)
echo Volume removal process finished.

endlocal