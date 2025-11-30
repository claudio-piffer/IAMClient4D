@echo off
setlocal

if not exist ".env" (
    echo [ERROR] Configuration file '.env' not found.
    echo Please run 'first-setup.cmd' first to generate it.
    exit /b 1
)

echo --- Starting Docker Compose services in detached mode...
docker-compose up -d

echo.
echo --- Services started. ---
echo.

if /i "%~1"=="-logs" goto :show_logs
goto :eof

:show_logs
echo --- Showing real-time logs (press Ctrl+C to stop)...
docker-compose logs -f
goto :eof

endlocal