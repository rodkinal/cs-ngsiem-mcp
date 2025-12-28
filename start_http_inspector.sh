#!/bin/bash
#
# NGSIEM MCP Inspector Startup Script (HTTP Mode)
# Launches the MCP Inspector configured for Streamable HTTP transport
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo "Starting MCP Inspector (HTTP Mode)"
echo "=========================================="

# Load .env variables
if [ -f .env ]; then
    export $(grep -v '^#' .env | sed 's/#.*//g' | xargs)
else
    echo -e "${RED}Error: .env file not found${NC}"
    exit 1
fi

if [ -z "$MCP_API_KEY" ]; then
    echo -e "${RED}Error: MCP_API_KEY not set in .env${NC}"
    exit 1
fi

HOST=${MCP_HTTP_HOST:-0.0.0.0}
PORT=${MCP_HTTP_PORT:-8080}
SERVER_URL="http://localhost:$PORT/mcp"

echo -e "Target Server: ${BLUE}$SERVER_URL${NC}"
echo -e "Transport:     ${BLUE}Streamable HTTP (2025-11-25)${NC}"
echo ""

# Cleanup stale inspector processes
# Default Inspector ports: 6277 (Proxy), 6274 (Client)
echo "Checking for existing inspector processes..."
KILLED=false

# Kill by port
for P in 6277 6274; do
    if lsof -i :$P > /dev/null 2>&1; then
        echo -e "${RED}⚠ Found process on port $P, killing...${NC}"
        lsof -ti :$P | xargs kill -9 || true
        KILLED=true
    fi
done

if [ "$KILLED" = true ]; then
    sleep 1
    echo -e "${GREEN}✓ Cleanup complete${NC}"
else
    echo -e "${GREEN}✓ No conflicts found${NC}"
fi
echo ""

# Launch Inspector
npx @modelcontextprotocol/inspector \
  --transport http \
  --server-url "$SERVER_URL" \
  --header "Authorization: Bearer $MCP_API_KEY" \
  --header "MCP-Protocol-Version: 2025-11-25"
