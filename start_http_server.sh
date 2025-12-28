#!/bin/bash
#
# NGSIEM MCP HTTP Server Startup Script
# Safely restarts the HTTP server by killing any existing instances
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "NGSIEM MCP HTTP Server Startup"
echo "=========================================="

# Load .env file
if [ -f .env ]; then
    echo -e "${GREEN}✓${NC} Loading environment variables from .env"
    export $(grep -v '^#' .env | sed 's/#.*//g' | xargs)
else
    echo -e "${RED}✗${NC} .env file not found!"
    echo "Please create .env from .env.example"
    exit 1
fi

# Check for required variables
if [ -z "$MCP_API_KEY" ]; then
    echo -e "${RED}✗${NC} MCP_API_KEY not set in .env!"
    echo "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
    exit 1
fi

# Kill any existing uvicorn processes
echo ""
# Kill any existing uvicorn processes or port blockers
echo ""
echo "Checking for existing processes..."

# Strategy 1: Kill by name
if pgrep -f "uvicorn ngsiem_mcp_http" > /dev/null; then
    echo -e "${YELLOW}⚠${NC}  Found existing uvicorn process(es), killing..."
    pkill -9 -f "uvicorn ngsiem_mcp_http" || true
    SLEEP_NEEDED=true
fi
if pgrep -f "python ngsiem_mcp_http.py" > /dev/null; then
    echo -e "${YELLOW}⚠${NC}  Found existing python process(es), killing..."
    pkill -9 -f "python ngsiem_mcp_http.py" || true
    SLEEP_NEEDED=true
fi

# Strategy 2: Kill by port (requires lsof)
PORT=${MCP_HTTP_PORT:-8080}
if lsof -i :$PORT > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠${NC}  Port $PORT is in use, killing process..."
    lsof -ti :$PORT | xargs kill -9 || true
    SLEEP_NEEDED=true
fi

if [ "$SLEEP_NEEDED" = true ]; then
    sleep 2
    echo -e "${GREEN}✓${NC} Old processes terminated"
else
    echo -e "${GREEN}✓${NC} System clean"
fi

# Activate virtual environment
if [ -d ".venv" ]; then
    echo -e "${GREEN}✓${NC} Activating virtual environment"
    source .venv/bin/activate
else
    echo -e "${YELLOW}⚠${NC}  No .venv found, using system Python"
fi

# Get configuration
HOST=${MCP_HTTP_HOST:-0.0.0.0}
PORT=${MCP_HTTP_PORT:-8080}
ACCESS_LOG=${MCP_HTTP_ACCESS_LOG:-ngsiem-mcp-http.log}
APP_LOG=${MCP_HTTP_APP_LOG:-ngsiem_http_app.log}

echo ""
echo "Server Configuration:"
echo "  Host:        $HOST"
echo "  Port:        $PORT"
echo "  Access Log:  $ACCESS_LOG"
echo "  App Log:     $APP_LOG"
echo ""

# Start server
echo -e "${GREEN}▶${NC}  Starting NGSIEM MCP HTTP Server..."
echo "=========================================="
echo ""

# Start server via Python to run custom Uvicorn logging configuration in __main__
python ngsiem_mcp_http.py

# Note: Server runs in foreground. Use Ctrl+C to stop.
