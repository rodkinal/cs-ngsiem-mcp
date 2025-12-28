#!/bin/bash
cd /Users/rod/cs-ngsiem-mcp
source .venv/bin/activate
exec npx @modelcontextprotocol/inspector .venv/bin/python ngsiem_mcp_stdio.py
