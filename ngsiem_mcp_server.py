#!/usr/bin/env python3
"""
CrowdStrike NGSIEM MCP Server
Exposes NGSIEM search capabilities via Model Context Protocol.
"""
import asyncio
import json
import logging
from typing import Any, Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field

from config import CONFIG, load_config
from ngsiem_tools import create_ngsiem_client, NGSIEMSearchTools


# Configure logging
logging.basicConfig(
    level=getattr(logging, CONFIG.log_level if CONFIG else "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(CONFIG.log_file if CONFIG else "ngsiem_mcp.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Initialize MCP server
app = Server("ngsiem-server")


# Global NGSIEM client instance
ngsiem_client: NGSIEMSearchTools = None


# Tool argument schemas
class StartSearchArgs(BaseModel):
    """Arguments for starting a NGSIEM search."""
    repository: Optional[str] = Field(
        default=None,
        description="NGSIEM repository name (uses default from config if not specified)"
    )
    query_string: str = Field(
        description="NGSIEM search query (e.g., '#event_simpleName=ProcessRollup2')"
    )
    start: str = Field(
        default="1d",
        description="Time range start (e.g., '1d', '24h', '2025-01-01T00:00:00Z')"
    )
    is_live: bool = Field(
        default=False,
        description="Enable live/streaming search mode"
    )


class GetSearchStatusArgs(BaseModel):
    """Arguments for getting NGSIEM search status."""
    repository: Optional[str] = Field(
        default=None,
        description="NGSIEM repository name (uses default from config if not specified)"
    )
    search_id: str = Field(..., description="Search job ID from start_search")


class SearchAndWaitArgs(BaseModel):
    """Arguments for search_and_wait (blocking search with auto-polling)."""
    repository: Optional[str] = Field(
        default=None,
        description="NGSIEM repository name (uses default from config if not specified)"
    )
    query_string: str = Field(..., description="NGSIEM search query")
    start: str = Field(default="1d", description="Time range (e.g., '1d', '24h')")
    is_live: bool = Field(default=False, description="Live/streaming search mode")
    max_wait_seconds: int = Field(
        default=300,
        description="Maximum time to wait for results (1-3600 seconds)"
    )
    poll_interval: int = Field(
        default=2,
        description="Seconds between status checks (1-60 seconds)"
    )


class StopSearchArgs(BaseModel):
    """Arguments for stop_search tool."""
    repository: Optional[str] = Field(
        default=None,
        description="NGSIEM repository name (uses default from config if not specified)"
    )
    search_id: str = Field(
        description="Search job ID to cancel"
    )


@app.list_tools()
async def list_tools() -> list[Tool]:
    """
    List available NGSIEM tools.
    
    Returns:
        List of MCP Tool definitions
    """
    return [
        Tool(
            name="start_search",
            description=(
                "Initiate a NGSIEM search in CrowdStrike. "
                "Returns a search job ID that can be used to check status and retrieve results. "
                "Use NGSIEM query language syntax (e.g., '#event_simpleName=ProcessRollup2 | ComputerName=*'). "
                "For time ranges, use relative (1d, 24h) or absolute timestamps."
            ),
            inputSchema=StartSearchArgs.model_json_schema()
        ),
        Tool(
            name="get_search_status",
            description=(
                "Check the status of a running NGSIEM search and retrieve results if complete. "
                "Returns search status (RUNNING/DONE), event count, and events if the search has finished. "
                "Poll this endpoint periodically for long-running searches."
            ),
            inputSchema=GetSearchStatusArgs.model_json_schema()
        ),
        Tool(
            name="stop_search",
            description=(
                "Cancel a running NGSIEM search. "
                "Useful for stopping long-running or resource-intensive searches. "
                "Returns confirmation of cancellation."
            ),
            inputSchema=StopSearchArgs.model_json_schema()
        ),
        Tool(
            name="search_and_wait",
            description=(
                "Execute a NGSIEM search and automatically wait for results (blocking). "
                "This combines start_search and get_search_status into one operation. "
                "The server will poll the API until results are ready or timeout occurs. "
                "Default timeout: 5 minutes. Use this for quick searches where you want "
                "immediate results. For long-running searches, use start_search + get_search_status "
                "to allow progress monitoring and avoid timeouts."
            ),
            inputSchema=SearchAndWaitArgs.model_json_schema()
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """
    Execute NGSIEM tool calls.
    
    Args:
        name: Tool name (start_search, get_search_status, stop_search)
        arguments: Tool-specific arguments
        
    Returns:
        List of TextContent with results
        
    Raises:
        ValueError: If tool name is unknown or arguments are invalid
        RuntimeError: If API call fails
    """
    global ngsiem_client
    
    # Ensure client is initialized
    if ngsiem_client is None:
        try:
            ngsiem_client = create_ngsiem_client()
        except Exception as e:
            logger.error(f"Failed to initialize NGSIEM client: {e}")
            return [TextContent(
                type="text",
                text=f"❌ Configuration error: {e}\n\n"
                     f"Please ensure .env file exists with valid CrowdStrike credentials."
            )]
    
    try:
        # Route to appropriate tool handler
        if name == "start_search":
            args = StartSearchArgs(**arguments)
            
            # Use default repository if not specified
            repository = args.repository or CONFIG.default_repository
            
            result = ngsiem_client.start_search(
                repository=repository,
                query_string=args.query_string,
                start=args.start,
                is_live=args.is_live
            )
            
            return [TextContent(
                type="text",
                text=(
                    f"✅ Search started successfully!\n\n"
                    f"**Search ID:** `{result['id']}`\n"
                    f"**Repository:** {result['repository']}\n"
                    f"**Query:** {result['query']}\n"
                    f"**Time Range:** {result['start']}\n"
                    f"**Live Search:** {result['is_live']}\n\n"
                    f"Use `get_search_status` with this search ID to check progress and retrieve results."
                )
            )]
        
        elif name == "get_search_status":
            args = GetSearchStatusArgs(**arguments)
            
            # Use default repository if not specified
            repository = args.repository or CONFIG.default_repository
            
            result = ngsiem_client.get_search_status(
                repository=repository,
                search_id=args.search_id
            )
            
            status_emoji = "✅" if result['done'] else "⏳"
            
            response_text = (
                f"{status_emoji} **Search Status**\n\n"
                f"**Search ID:** `{result['id']}`\n"
                f"**Repository:** {result['repository']}\n"
                f"**Status:** {result['status']}\n"
                f"**Event Count:** {result['event_count']}\n"
            )
            
            if result['done'] and result['event_count'] > 0:
                response_text += f"\n**Results:**\n```json\n{result['events'][:5]}\n```\n"
                if result['event_count'] > 5:
                    response_text += f"\n_(Showing first 5 of {result['event_count']} events)_"
            elif result['done']:
                response_text += "\n_No events found matching the query._"
            else:
                response_text += "\n_Search still running. Check again in a few seconds._"
            
            return [TextContent(type="text", text=response_text)]
        
        elif name == "stop_search":
            args = StopSearchArgs(**arguments)
            
            # Use default repository if not specified
            repository = args.repository or CONFIG.default_repository
            
            result = ngsiem_client.stop_search(
                repository=repository,
                search_id=args.search_id
            )
            response_text = (
                f"✅ **Search Cancelled**\n\n"
                f"- **Search ID**: `{result['id']}`\n"
                f"- **Repository**: `{result['repository']}`\n"
                f"- **Status**: {result['status']}\n"
                f"- **Stopped at**: {result['stopped_at']}\n"
            )
        
        elif name == "search_and_wait":
            args = SearchAndWaitArgs(**arguments)
            
            # Use default repository if not specified
            repository = args.repository or CONFIG.default_repository
            
            response_text = (
                f"🔍 **Starting Search** (will wait for results)...\n\n"
                f"- **Repository**: `{repository}`\n"
                f"- **Query**: `{args.query_string}`\n"
                f"- **Time Range**: {args.start}\n"
                f"- **Max Wait**: {args.max_wait_seconds}s\n"
                f"- **Poll Interval**: {args.poll_interval}s\n\n"
                f"⏳ Waiting for results...\n\n"
            )
            
            try:
                result = ngsiem_client.search_and_wait(
                    repository=repository,
                    query_string=args.query_string,
                    start=args.start,
                    is_live=args.is_live,
                    max_wait_seconds=args.max_wait_seconds,
                    poll_interval=args.poll_interval
                )
                
                response_text += (
                    f"✅ **Search Complete**\n\n"
                    f"- **Search ID**: `{result['search_id']}`\n"
                    f"- **Status**: {result['status']}\n"
                    f"- **Events Found**: {result['event_count']}\n"
                    f"- **Time Taken**: {result['elapsed_time']:.1f}s\n"
                    f"- **Polls**: {result['poll_count']}\n\n"
                )
                
                if result['event_count'] > 0:
                    # Show sample results
                    sample_count = min(5, result['event_count'])
                    response_text += f"**First {sample_count} Results:**\n```json\n"
                    response_text += json.dumps(result['events'][:sample_count], indent=2)
                    response_text += "\n```\n\n"
                    
                    if result['event_count'] > sample_count:
                        response_text += f"*({result['event_count'] - sample_count} more events in full result)*\n"
                else:
                    response_text += "No events found matching the query.\n"
                    
            except TimeoutError as e:
                response_text += (
                    f"⏱️ **Search Timeout**\n\n"
                    f"{str(e)}\n\n"
                    f"The search is still running in the background. "
                    f"You can check results later using `get_search_status`.\n"
                )
        
        else:
            raise ValueError(f"Unknown tool: {name}")
        
        return [TextContent(type="text", text=response_text)] # Moved common return here
    
    except ValueError as e:
        logger.error(f"Validation error in {name}: {e}")
        return [TextContent(
            type="text",
            text=f"❌ **Validation Error**\n\n{str(e)}"
        )]
    
    except RuntimeError as e:
        logger.error(f"Runtime error in {name}: {e}")
        return [TextContent(
            type="text",
            text=f"❌ **API Error**\n\n{str(e)}"
        )]
    
    except Exception as e:
        logger.error(f"Unexpected error in {name}: {e}", exc_info=True)
        return [TextContent(
            type="text",
            text=f"❌ **Unexpected Error**\n\n{str(e)}\n\nCheck logs for details."
        )]


async def main():
    """Main entry point for the MCP server."""
    logger.info("Starting NGSIEM MCP Server...")
    
    # Validate configuration on startup
    try:
        config = load_config()
        logger.info(f"Configuration loaded successfully")
        logger.info(f"Base URL: {config.base_url}")
        logger.info(f"Default Repository: {config.default_repository or 'Not set'}")
    except Exception as e:
        logger.error(f"Configuration error: {e}")
        logger.error("Server will start but tools will fail until configuration is fixed")
    
    # Run MCP server
    async with stdio_server() as (read_stream, write_stream):
        logger.info("MCP Server running on stdio")
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
