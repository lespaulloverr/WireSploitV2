$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

# =============================================================================
# WireSploit Launcher - Checks for executable first, falls back to Python
# =============================================================================

# Check if pre-built executable exists
$exePath = Join-Path $PSScriptRoot 'dist\WireSploit.exe'
if (Test-Path -LiteralPath $exePath) {
    Write-Host "Found WireSploit executable. Starting..." -ForegroundColor Green

    $pidFile = Join-Path $PSScriptRoot 'wiresploit.pid'
    $host = '127.0.0.1'
    $port = 8765
    $timeout = 30
    $interval = 1
    $maxRetries = 30

    # Check for stale PID file
    if (Test-Path -LiteralPath $pidFile) {
        $oldPid = Get-Content -LiteralPath $pidFile
        $proc = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
        if ($proc -and $proc.Path -like '*WireSploit*') {
            Write-Host "Warning: Stale WireSploit process found (PID: $oldPid). Stopping it..." -ForegroundColor Yellow
            Stop-Process -Id $oldPid -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    }

    # Start executable and capture PID
    Write-Host "Starting WireSploit server..." -ForegroundColor Green
    $proc = Start-Process -FilePath $exePath -WorkingDirectory $PSScriptRoot -PassThru

    if (-not $proc) {
        Write-Host "Error: Failed to start WireSploit executable." -ForegroundColor Red
        exit 1
    }
    Write-Host "Server started with PID: $($proc.Id)" -ForegroundColor Cyan
    $proc.Id | Set-Content -LiteralPath $pidFile -Force

    # Wait for server to be ready
    $ready = $false
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not $ready) {
        if ($proc.HasExited) {
            throw "WireSploit server exited with code $($proc.ExitCode)."
        }
        if ($stopwatch.Elapsed.TotalSeconds -ge $timeout) {
            throw "WireSploit did not become ready within $timeout seconds."
        }
        try {
            $response = Invoke-WebRequest -Uri "http://$host:$port/api/health" -UseBasicParsing -TimeoutSec 1
            if ($response.StatusCode -eq 200) {
                $ready = $true
            }
        } catch {
            Start-Sleep -Milliseconds ($interval * 1000)
        }
    }

    # Server is ready
    Write-Host "WireSploit is ready at http://$host:$port/" -ForegroundColor Green
    Start-Process "http://$host:$port/"

    # Wait for the server process to exit
    Wait-Process -Id $proc.Id

    # Cleanup
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    exit 0
}

# =============================================================================
# Fall back to Python/virtual environment
# =============================================================================

# Check for Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host 'Error: Python 3 is required but not found in PATH.' -ForegroundColor Red
    Write-Host 'Please install Python 3.13 or later from https://www.python.org/' -ForegroundColor Yellow
    exit 1
}

# Check if virtual environment exists, if not create it
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    Write-Host 'Creating virtual environment...' -ForegroundColor Yellow
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not create the Python virtual environment.'
    }
    Write-Host 'Installing dependencies...' -ForegroundColor Yellow
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        throw 'Dependency installation failed.'
    }
}

# Load configuration from environment or .env file with defaults
$config = @{
    HOST = '127.0.0.1'
    PORT = 8765
    HEALTH_CHECK_TIMEOUT = 30
    HEALTH_CHECK_INTERVAL = 1
    HEALTH_CHECK_MAX_RETRIES = 30
}

# Override with environment variables
foreach ($key in $config.Keys) {
    if (Test-Path "env:$key") {
        $value = Get-Content "env:$key"
        if ($config[$key] -is [bool]) {
            $config[$key] = $value -in @('true', '1', 'yes', 'on')
        } elseif ($config[$key] -is [int]) {
            $config[$key] = [int]::Parse($value)
        } elseif ($config[$key] -is [float]) {
            $config[$key] = [float]::Parse($value)
        } else {
            $config[$key] = $value
        }
    }
}

# Extract values for convenience
$host = $config.HOST
$port = $config.PORT
$timeout = $config.HEALTH_CHECK_TIMEOUT
$interval = $config.HEALTH_CHECK_INTERVAL
$maxRetries = $config.HEALTH_CHECK_MAX_RETRIES

# Start the server
Write-Host "Starting WireSploit server..." -ForegroundColor Green
$py = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
$argList = @('-m', 'uvicorn', 'main:app', '--host', $host, '--port', $port)
$proc = Start-Process -FilePath $py -ArgumentList $argList -WorkingDirectory $PSScriptRoot -PassThru

# Wait for server to be ready
$ready = $false
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
while (-not $ready) {
    # Check if process has exited
    if ($proc.HasExited) {
        throw "WireSploit server exited with code $($proc.ExitCode)."
    }

    # Check timeout
    if ($stopwatch.Elapsed.TotalSeconds -ge $timeout) {
        throw "WireSploit did not become ready within $timeout seconds."
    }

    try {
        $response = Invoke-WebRequest -Uri "http://$host:$port/api/health" -UseBasicParsing -TimeoutSec 1
        if ($response.StatusCode -eq 200) {
            $ready = $true
        }
    } catch {
        Start-Sleep -Milliseconds ($interval * 1000)
    }
}

# Server is ready
Write-Host "WireSploit is ready at http://$host:$port/" -ForegroundColor Green
Start-Process "http://$host:$port/"

# Wait for the server process to exit (when user closes the browser or stops the app)
Wait-Process -Id $proc.Id