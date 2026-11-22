@echo off
rem Generates the passwords of the sample environment in secrets\ (24 letters and digits):
rem Keycloak admin, PostgreSQL admin, PostgreSQL user keycloak. An existing, non-empty file is kept.
rem Called by start.cmd; delete-volumes.cmd does not touch them.
setlocal
cd /d "%~dp0"
if not exist secrets mkdir secrets
for %%S in (kc_admin_password pg_admin_password pg_keycloak_password) do (
  call :secret %%S || exit /b 1
)
exit /b 0

:secret
set "FILE=secrets\%~1.txt"
if exist "%FILE%" for %%F in ("%FILE%") do if %%~zF gtr 0 exit /b 0
powershell -NoProfile -Command "$c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; $p = ''; $r = [Security.Cryptography.RandomNumberGenerator]::Create(); $b = New-Object byte[] 1; while ($p.Length -lt 24) { $r.GetBytes($b); if ($b[0] -lt 248) { $p += $c[$b[0] %% 62] } }; [IO.File]::WriteAllText((Join-Path (Get-Location) '%FILE%'), $p)" || exit /b 1
echo [OK] Generated %FILE%
exit /b 0
