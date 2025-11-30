@echo off
setlocal

echo Stopping, removing containers, network and volumes...
docker-compose down

echo Shutdown complete.

endlocal