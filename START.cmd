@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem ============================================================================
rem WireSploit Launcher - Checks for executable first, falls back to Python
rem ============================================================================

rem Check if pre-built executable exists
if exist "dist\WireSploit.exe" (
    echo Found WireSploit executable. Starting...
    set "EXE_PATH=%~dp0dist\WireSploit.exe"
    set "WORKDIR=%~dp0"
    set "PID_FILE=%~dp0wiresploit.pid"

    rem Check for stale PID file
    if exist "%PID_FILE%" (
        set /p OLD_PID=<%PID_FILE%
        powershell -NoProfile -Command ^
            "$p = Get-Process -Id %OLD_PID% -ErrorAction SilentlyContinue; ^
            if ($p -and $p.Path -like '*WireSploit*') { exit 1 } else { exit 0 }"
        if errorlevel 1 (
            echo Warning: Stale WireSploit process found (PID: %OLD_PID%). Stopping it...
            taskkill /f /pid %OLD_PID% >nul 2>&1
        )
        del "%PID_FILE%" 2>nul
    )

    rem Start executable and capture PID
    echo Starting WireSploit server...
    for /f "tokens=*" %%A in ('powershell -NoProfile -Command ^
        "$proc = Start-Process -FilePath '%EXE_PATH%' -WorkingDirectory '%WORKDIR%' -PassThru; ^
        Write-Output $proc.Id"') do set SERVER_PID=%%A

    if not defined SERVER_PID (
        echo Error: Failed to start WireSploit executable.
        pause
        exit /b 1
    )
    echo Server started with PID: %SERVER_PID%
    echo %SERVER_PID% > "%PID_FILE%"

    rem Wait for server to be ready
    set "HOST=127.0.0.1"
    set "PORT=8765"
    set "HEALTH_CHECK_TIMEOUT=30"
    set "HEALTH_CHECK_INTERVAL=1"
    set "HEALTH_CHECK_MAX_RETRIES=30"
    set /a tries=0
    :waithealth
    set /a tries+=1
    if %tries% GEQ %HEALTH_CHECK_MAX_RETRIES% (
        echo Error: WireSploit did not become ready within %HEALTH_CHECK_TIMEOUT% seconds.
        echo Stopping server (PID: %SERVER_PID%)...
        taskkill /f /pid %SERVER_PID% >nul 2>&1
        del "%PID_FILE%" 2>nul
        pause
        exit /b 1
    )
    curl -s -o nul -w "%%{http_code}" http://%HOST%:%PORT%/api/health | findstr "200" >nul
    if errorlevel 1 (
        timeout /t %HEALTH_CHECK_INTERVAL% >nul
        goto waithealth
    )

    rem Server is ready, open browser
    echo WireSploit is ready at http://%HOST%:%PORT%/
    start "" http://%HOST%:%PORT%/
    echo Press Ctrl+C to stop the server...
    pause

    rem Cleanup on exit
    echo Stopping WireSploit server (PID: %SERVER_PID%)...
    taskkill /f /pid %SERVER_PID% >nul 2>&1
    del "%PID_FILE%" 2>nul
    echo WireSploit stopped.
    endlocal
    exit /b 0
)

rem ============================================================================
rem Fall back to Python/virtual environment
rem ============================================================================

rem Check for Python
where python >nul 2>nul
if errorlevel 1 (
    echo Error: Python 3 is required but not found in PATH.
    echo Please install Python 3.13 or later from https://www.python.org/
    pause
    exit /b 1
)

rem Check if virtual environment exists, if not create it
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Error: Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo Installing dependencies...
    .venv\Scripts\python.exe -m pip install -r requirements.txt
    if errorlevel 1 (
        echo Error: Failed to install dependencies.
        pause
        exit /b 1
    )
)

rem Set up environment variables for configuration
set "HOST=127.0.0.1"
set "PORT=8765"
rem Health check parameters (can be overridden by environment)
set "HEALTH_CHECK_TIMEOUT=30"
set "HEALTH_CHECK_INTERVAL=1"
set "HEALTH_CHECK_MAX_RETRIES=30"

rem PID file path for persistent tracking
set "PID_FILE=%~dp0wiresploit.pid"

rem Check for stale PID file and verify ownership
if exist "%PID_FILE%" (
    set /p OLD_PID=<%PID_FILE%
    rem Verify the process still exists and is our uvicorn process
    powershell -NoProfile -Command ^
        "$p = Get-Process -Id %OLD_PID% -ErrorAction SilentlyContinue; ^
        if ($p -and $p.Path -like '*uvicorn*') { exit 1 } else { exit 0 }"
    if errorlevel 1 (
        echo Warning: Stale WireSploit process found (PID: %OLD_PID%). Stopping it...
        taskkill /f /pid %OLD_PID% >nul 2>&1
    )
    del "%PID_FILE%" 2>nul
)

rem Start the server using PowerShell to capture PID
echo Starting WireSploit server...
set "PY_PATH=%~dp0.venv\Scripts\python.exe"
set "ARGS=-m uvicorn main:app --host %HOST% --port %PORT%"
set "WORKDIR=%~dp0"

for /f "tokens=*" %%A in ('powershell -NoProfile -Command ^
    "$proc = Start-Process -FilePath '%PY_PATH%' -ArgumentList '%ARGS%' -WorkingDirectory '%WORKDIR%' -PassThru; ^
    Write-Output $proc.Id"') do set SERVER_PID=%%A

if not defined SERVER_PID (
    echo Error: Failed to start WireSploit server.
    pause
    exit /b 1
)
echo Server started with PID: %SERVER_PID%

rem Save PID to file for persistent tracking
echo %SERVER_PID% > "%PID_FILE%"

rem Wait for server to be ready
set /a tries=0
:waithealth
set /a tries+=1
if %tries% GEQ %HEALTH_CHECK_MAX_RETRIES% (
    echo Error: WireSploit did not become ready within %HEALTH_CHECK_TIMEOUT% seconds.
    echo Stopping server (PID: %SERVER_PID%)...
    taskkill /f /pid %SERVER_PID% >nul 2>&1
    del "%PID_FILE%" 2>nul
    pause
    exit /b 1
)
curl -s -o nul -w "%%{http_code}" http://%HOST%:%PORT%/api/health | findstr "200" >nul
if errorlevel 1 (
    timeout /t %HEALTH_CHECK_INTERVAL% >nul
    goto waithealth
)

rem Server is ready, open browser
echo WireSploit is ready at http://%HOST%:%PORT%/
start "" http://%HOST%:%PORT%/

rem Trap Ctrl+C for clean shutdown
rem Note: batch files don't have proper signal handling, but we can use a wrapper
echo Press Ctrl+C to stop the server...
pause

rem Cleanup on exit
echo Stopping WireSploit server (PID: %SERVER_PID%)...
taskkill /f /pid %SERVER_PID% >nul 2>&1
del "%PID_FILE%" 2>nul
echo WireSploit stopped.

endlocal