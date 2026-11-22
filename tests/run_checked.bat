@echo off
rem Runs a Windows test executable: fails (exit code <> 0) when the test fails or when the memory
rem manager reported a leak on stderr ("Unexpected Memory Leak", ReportMemoryLeaksOnShutdown).
rem The exit code of the test alone misses it: the report comes after the program sets it.
rem Usage: call run_checked.bat <exe> [arguments]   (stderr of the test is echoed after it ends)
setlocal
set "LEAK_LOG=%TEMP%\iam4d_test_%RANDOM%%RANDOM%.err"
"%~1" %2 %3 %4 %5 %6 %7 %8 %9 2> "%LEAK_LOG%"
set "TEST_RC=%ERRORLEVEL%"
type "%LEAK_LOG%" 1>&2
findstr /c:"Unexpected Memory Leak" "%LEAK_LOG%" >nul
if not errorlevel 1 (
  echo MEMORY LEAK REPORTED: %~nx1
  if "%TEST_RC%"=="0" set "TEST_RC=1"
)
del "%LEAK_LOG%" >nul 2>nul
exit /b %TEST_RC%
