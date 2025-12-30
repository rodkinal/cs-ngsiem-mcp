
# NGSIEM MCP HTTP Server Startup Script (Windows PowerShell)
# Safely restarts the HTTP server by killing any existing instances
#

$ErrorActionPreference = "Stop"

# Colors for output
$RED = "Red"
$GREEN = "Green"
$YELLOW = "Yellow"

Write-Host "==========================================" -ForegroundColor $GREEN
Write-Host "NGSIEM MCP HTTP Server Startup" -ForegroundColor $GREEN
Write-Host "==========================================" -ForegroundColor $GREEN

# Load .env file
if (Test-Path ".env") {
    Write-Host "✓ Loading environment variables from .env" -ForegroundColor $GREEN
    Get-Content ".env" | ForEach-Object {
        if ($_ -match '^([^#=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            # Remove quotes if present
            $value = $value.Trim('"').Trim("'")
            [Environment]::SetEnvironmentVariable($key, $value, "Process")
        }
    }
} else {
    Write-Host "✗ .env file not found!" -ForegroundColor $RED
    Write-Host "Please create .env from .env.example" -ForegroundColor $RED
    exit 1
}

# Check for required variables
if (-not $env:MCP_API_KEY) {
    Write-Host "✗ MCP_API_KEY not set in .env!" -ForegroundColor $RED
    Write-Host "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'" -ForegroundColor $YELLOW
    exit 1
}

# Kill any existing processes
Write-Host ""
Write-Host "Checking for existing processes..."

$SLEEP_NEEDED = $false

# Strategy 1: Kill by process name
$uvicornProcesses = Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*python*" -and $_.CommandLine -like "*uvicorn*ngsiem_mcp_http*" } -ErrorAction SilentlyContinue
if ($uvicornProcesses) {
    Write-Host "WARNING: Found existing uvicorn processes, killing..." -ForegroundColor $YELLOW
    $uvicornProcesses | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $SLEEP_NEEDED = $true
}

$pythonProcesses = Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*python*" -and $_.CommandLine -like "*ngsiem_mcp_http.py*" } -ErrorAction SilentlyContinue
if ($pythonProcesses) {
    Write-Host "WARNING: Found existing python processes, killing..." -ForegroundColor $YELLOW
    $pythonProcesses | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $SLEEP_NEEDED = $true
}

# Strategy 2: Kill by port
$PORT = if ($env:MCP_HTTP_PORT) { $env:MCP_HTTP_PORT } else { 8080 }
$connections = Get-NetTCPConnection -LocalPort $PORT -ErrorAction SilentlyContinue
if ($connections) {
    Write-Host "WARNING: Port $PORT is in use, killing process..." -ForegroundColor $YELLOW
    $connections | ForEach-Object {
        $processId = $_.OwningProcess
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
    $SLEEP_NEEDED = $true
}

if ($SLEEP_NEEDED) {
    Start-Sleep -Seconds 2
    Write-Host "✓ Old processes terminated" -ForegroundColor $GREEN
} else {
    Write-Host "✓ System clean" -ForegroundColor $GREEN
}

# Activate virtual environment
if (Test-Path ".venv") {
    Write-Host "✓ Activating virtual environment" -ForegroundColor $GREEN
    . ".\.venv\Scripts\Activate.ps1"
} else {
    Write-Host "WARNING: No .venv found, using system Python" -ForegroundColor $YELLOW
}

# Get configuration
$SERVER_HOST = if ($env:MCP_HTTP_HOST) { $env:MCP_HTTP_HOST } else { "0.0.0.0" }
$PORT = if ($env:MCP_HTTP_PORT) { [int]$env:MCP_HTTP_PORT } else { 8080 }
$ACCESS_LOG = if ($env:MCP_HTTP_ACCESS_LOG) { $env:MCP_HTTP_ACCESS_LOG } else { "ngsiem-mcp-http.log" }
$APP_LOG = if ($env:MCP_HTTP_APP_LOG) { $env:MCP_HTTP_APP_LOG } else { "ngsiem_http_app.log" }

Write-Host ""
Write-Host "Server Configuration:"
Write-Host "  Host:        $SERVER_HOST"
Write-Host "  Port:        $PORT"
Write-Host "  Access Log:  $ACCESS_LOG"
Write-Host "  App Log:     $APP_LOG"
Write-Host ""

# Start server
Write-Host "▶  Starting NGSIEM MCP HTTP Server..." -ForegroundColor $GREEN
Write-Host "==========================================" -ForegroundColor $GREEN
Write-Host ""

# Start server via Python to run custom Uvicorn logging configuration in __main__
& python ngsiem_mcp_http.py

# Note: Server runs in foreground. Use Ctrl+C to stop.