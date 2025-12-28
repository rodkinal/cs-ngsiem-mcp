"""
NGSIEM MCP HTTP Server - Streamable HTTP Transport (MCP 2025-11-25)

FastAPI server implementing the official MCP Streamable HTTP specification.

Architecture:
- POST /mcp - Unified endpoint for all JSON-RPC messages
- GET /mcp - Optional SSE stream for server notifications
- GET /health - Health check (no auth)

Security:
- Bearer token authentication (constant-time comparison)
- MCP-Protocol-Version header validation
- Pydantic input validation

Specification: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime
from typing import Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sse_starlette.sse import EventSourceResponse

# Local imports
from auth import RequireAuth, generate_secure_token
from config import load_config
from ngsiem_tools import NGSIEMSearchTools, create_ngsiem_client
from ngsiem_query_catalog import get_catalog
from ngsiem_query_validator import get_validator

# Configure logging
app_log_file = os.environ.get("MCP_HTTP_APP_LOG", "ngsiem_http_app.log")
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(app_log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Supported MCP protocol versions
SUPPORTED_VERSIONS = ["2025-11-25", "2025-03-26"]
DEFAULT_VERSION = "2025-03-26"  # Fallback if header missing


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class JsonRpcRequest(BaseModel):
    """JSON-RPC 2.0 request model."""
    jsonrpc: str = Field(default="2.0", pattern=r"^2\.0$")
    id: int | str | None = Field(default=None)
    method: str = Field(..., min_length=1, max_length=100)
    params: dict[str, Any] = Field(default_factory=dict)
    
    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        """Validate method name format."""
        allowed_prefixes = ("tools/", "resources/", "prompts/", "ping", "initialize", "notifications/")
        if not any(v.startswith(p) for p in allowed_prefixes):
            raise ValueError(f"Invalid method: {v}")
        return v


class JsonRpcResponse(BaseModel):
    """
    JSON-RPC 2.0 response model.
    
    Per spec: A response MUST contain either 'result' OR 'error', never both.
    """
    jsonrpc: str = "2.0"
    id: int | str | None = None
    result: Any = None
    error: Optional[dict[str, Any]] = None
    
    def dict(self, **kwargs):
        """Override dict to ensure only result OR error is present."""
        d = super().dict(**kwargs)
        # JSON-RPC spec: only one of result/error should be present
        if d.get('error') is None and 'result' in d:
            d.pop('error', None)
        elif d.get('result') is None and 'error' in d:
            d.pop('result', None)
        # Force id to be present even if None (required for Response)
        if 'id' not in d:
             d['id'] = self.id
        return d


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    timestamp: str
    version: str = "1.0.0"
    mcp_version: str = "2025-11-25"


# =============================================================================
# APPLICATION LIFESPAN
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    logger.info("Starting NGSIEM MCP Server (Streamable HTTP/2025-11-25)...")
    
    try:
        config = load_config()
        logger.info(f"Configuration loaded: {config.base_url}")
        
        catalog = get_catalog()
        logger.info("Query catalog loaded")
        
        # Store in app state
        app.state.config = config
        app.state.catalog = catalog
        app.state.active_sse_streams = set()
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise
    
    logger.info("Server ready - MCP 2025-11-25 Streamable HTTP transport")
    
    yield  # Server running
    
    # Shutdown
    logger.info("Shutting down...")
    for stream in app.state.active_sse_streams:
        stream.cancel()
    logger.info("Shutdown complete")


# =============================================================================
# FASTAPI APPLICATION
# =============================================================================

app = FastAPI(
    title="NGSIEM MCP Server",
    description="MCP 2025-11-25 Streamable HTTP transport for NGSIEM",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
cors_origins = os.environ.get("MCP_CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# =============================================================================
# PROTOCOL VERSION VALIDATION
# =============================================================================

def validate_protocol_version(version: Optional[str]) -> str:
    """
    Validate MCP-Protocol-Version header.
    
    Args:
        version: Protocol version from header (or None).
        
    Returns:
        str: Validated version string.
        
    Raises:
        HTTPException: 400 if version is invalid.
    """
    if version is None:
        logger.warning(f"Missing MCP-Protocol-Version header, defaulting to {DEFAULT_VERSION}")
        return DEFAULT_VERSION
    
    if version not in SUPPORTED_VERSIONS:
        logger.error(f"Unsupported protocol version: {version}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported MCP-Protocol-Version: {version}. Supported: {SUPPORTED_VERSIONS}"
        )
    
    return version


# =============================================================================
# ENDPOINTS
# =============================================================================

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """
    Health check endpoint (no authentication required).
    
    Returns:
        HealthResponse: Server status.
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow().isoformat(),
        version="2.0.0",
        mcp_version="2025-11-25"
    )


@app.get("/mcp", tags=["MCP"])
async def mcp_get_stream(
    request: Request,
    token: RequireAuth,
    mcp_protocol_version: Optional[str] = Header(None, alias="MCP-Protocol-Version")
):
    """
    Optional SSE stream for server-initiated messages.
    
    Per MCP 2025-11-25 spec, this provides a long-lived connection for
    server notifications, progress updates, and keepalive pings.
    
    Args:
        request: FastAPI request.
        token: Validated Bearer token.
        mcp_protocol_version: Protocol version header.
        
    Returns:
        EventSourceResponse: SSE stream.
    """
    version = validate_protocol_version(mcp_protocol_version)
    logger.info(f"GET /mcp - SSE stream established (protocol {version})")
    
    async def event_generator():
        """Generate SSE events."""
        try:
            # Send initial connected event
            yield {
                "event": "connected",
                "id": "0",
                "data": json.dumps({
                    "message": "MCP SSE stream established",
                    "protocol_version": version,
                    "timestamp": datetime.utcnow().isoformat()
                })
            }
            
            # Keepalive pings
            ping_count = 1
            while True:
                if await request.is_disconnected():
                    logger.info("SSE client disconnected")
                    break
                
                yield {
                    "event": "ping",
                    "id": str(ping_count),
                    "retry": 30000,  # Suggest 30s reconnection
                    "data": json.dumps({"timestamp": datetime.utcnow().isoformat()})
                }
                
                ping_count += 1
                await asyncio.sleep(30)
                
        except asyncio.CancelledError:
            logger.info("SSE stream cancelled")
        except Exception as e:
            logger.error(f"SSE error: {e}")
    
    return EventSourceResponse(event_generator())


@app.post("/mcp", tags=["MCP"])
async def mcp_post_message(
    request: Request,
    message: JsonRpcRequest,
    token: RequireAuth,
    mcp_protocol_version: Optional[str] = Header(None, alias="MCP-Protocol-Version"),
    accept: str = Header("application/json")
):
    """
    Unified endpoint for all JSON-RPC messages.
    
    Per MCP 2025-11-25 spec, this endpoint:
    - Accepts JSON-RPC requests, responses, and notifications
    - Returns 202 Accepted for notifications/responses
    - Returns SSE stream for long-running requests (if Accept: text/event-stream)
    - Returns direct JSON for quick requests
    
    Args:
        request: FastAPI request.
        message: JSON-RPC message.
        token: Validated Bearer token.
        mcp_protocol_version: Protocol version header.
        accept: Accept header (application/json or text/event-stream).
        
    Returns:
        JSONResponse, StreamingResponse, or 202 Accepted.
    """
    version = validate_protocol_version(mcp_protocol_version)
    logger.info(f"POST /mcp - method={message.method}, id={message.id}, protocol={version}")
    
    try:
        # Route based on message type
        if message.id is None:
            # Notification - return 202 Accepted
            logger.info(f"Received notification: {message.method}")
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={}
            )
        
        # Request - process and return result
        result = await process_mcp_request(message, version)
        
        # Always return direct JSON response (simpler, more compatible)
        response = JsonRpcResponse(
            id=message.id,
            result=result
        )
        return JSONResponse(content=response.dict())
        
    except HTTPException:
        raise
    except ValueError as e:
        logger.warning(f"Validation error: {e}")
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=JsonRpcResponse(
                id=message.id,
                error={
                    "code": -32602,
                    "message": "Invalid params",
                    "data": str(e)
                }
            ).dict()
        )
    except Exception as e:
        logger.error(f"Request processing error: {e}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=JsonRpcResponse(
                id=message.id,
                error={
                    "code": -32603,
                    "message": "Internal error",
                    "data": "An unexpected error occurred"
                }
            ).dict()
        )


# =============================================================================
# MCP REQUEST PROCESSING
# =============================================================================

async def process_mcp_request(request: JsonRpcRequest, protocol_version: str) -> Any:
    """
    Route MCP request to appropriate handler.
    
    Args:
        request: Validated JSON-RPC request.
        protocol_version: Negotiated protocol version.
        
    Returns:
        Any: Result from handler.
    """
    method = request.method
    params = request.params
    
    # Route to handlers
    if method == "initialize":
        return await handle_initialize(params, protocol_version)
    
    elif method == "ping":
        return {}  # Empty object per spec
    
    elif method == "tools/list":
        return await handle_list_tools()
    
    elif method == "tools/call":
        return await handle_tool_call(params)
    
    elif method == "resources/list":
        return await handle_list_resources()
    
    elif method == "resources/read":
        return await handle_read_resource(params)
    
    else:
        raise ValueError(f"Unknown method: {method}")


async def handle_initialize(params: dict, protocol_version: str) -> dict:
    """Handle MCP initialize request."""
    return {
        "protocolVersion": protocol_version,
        "capabilities": {
            "tools": {},
            "resources": {}
        },
        "serverInfo": {
            "name": "ngsiem-mcp-server",
            "version": "2.0.0"
        }
    }


async def handle_list_tools() -> dict:
    """List available MCP tools."""
    from ngsiem_mcp_stdio import list_tools
    result = await list_tools()
   # The MCP server returns a ListToolsResult object
    tools_list = result.tools if hasattr(result, 'tools') else result
    return {
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.inputSchema
            }
            for t in tools_list
        ]
    }


async def handle_tool_call(params: dict) -> dict:
    """Execute an MCP tool."""
    tool_name = params.get("name")
    arguments = params.get("arguments", {})
    
    if not tool_name:
        raise ValueError("Tool name is required")
    
    from ngsiem_mcp_stdio import call_tool
    from mcp.types import CallToolRequest
    
    # Create proper CallToolRequest
    result = await call_tool(tool_name, arguments)
    
    return {
        "content": result.content if hasattr(result, 'content') else [{"type": "text", "text": str(result)}],
        "isError": False
    }


async def handle_list_resources() -> dict:
    """List available MCP resources."""
    from ngsiem_mcp_stdio import list_resources
    resources = await list_resources()
    return {
        "resources": [
            {
                "uri": r.uri,
                "name": r.name,
                "description": r.description,
                "mimeType": r.mimeType
            }
            for r in resources.resources
        ]
    }


async def handle_read_resource(params: dict) -> dict:
    """Read an MCP resource."""
    uri = params.get("uri")
    if not uri:
        raise ValueError("Resource URI is required")
    
    from ngsiem_mcp_stdio import read_resource
    from mcp.types import ReadResourceRequest
    
    resource_request = ReadResourceRequest(
        method="resources/read",
        params={"uri": uri}
    )
    
    content = await read_resource(resource_request)
    
    return {
        "contents": content.contents if hasattr(content, 'contents') else []
    }


async def stream_tool_execution(request: JsonRpcRequest, result: Any) -> StreamingResponse:
    """
    Stream tool execution with SSE for progress updates.
    
    Args:
        request: Original JSON-RPC request.
        result: Tool execution result.
        
    Returns:
        StreamingResponse: SSE stream.
    """
    async def event_generator():
        """Generate SSE events for tool execution."""
        try:
            # Send initial event with event-id
            yield f"id: 0\ndata: \n\n"
            
            # Send progress notification (optional)
            yield f'id: 1\nevent: progress\ndata: {json.dumps({"status": "executing"})}\n\n'
            
            # Send final result
            response = JsonRpcResponse(
                id=request.id,
                result=result
            )
            yield f'id: 2\nevent: result\ndata: {json.dumps(response.dict())}\n\n'
            
            # Stream termination (per spec)
            logger.info("SSE stream terminated after result delivery")
            
        except Exception as e:
            logger.error(f"SSE streaming error: {e}")
            error_response = JsonRpcResponse(
                id=request.id,
                error={
                    "code": -32603,
                    "message": "Streaming error",
                    "data": str(e)
                }
            )
            yield f'event: error\ndata: {json.dumps(error_response.dict())}\n\n'
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
        }
    )


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with JSON-RPC error format."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32000 - exc.status_code,
                "message": exc.detail
            }
        }
    )


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # Check for API key
    if not os.environ.get("MCP_API_KEY"):
        print("\n" + "=" * 60)
        print("ERROR: MCP_API_KEY environment variable is not set!")
        print("=" * 60)
        print("\nGenerate a secure token and add it to your .env file:")
        print(f"\n    MCP_API_KEY={generate_secure_token()}\n")
        print("=" * 60 + "\n")
        sys.exit(1)
    
    host = os.environ.get("MCP_HTTP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_HTTP_PORT", "8080"))
    access_log_file = os.environ.get("MCP_HTTP_ACCESS_LOG", "ngsiem-mcp-http.log")
    
    logger.info(f"Starting MCP 2025-11-25 server on {host}:{port}")
    logger.info(f"Access logs: {access_log_file}")
    logger.info(f"Application logs: {app_log_file}")
    
    # Configure Uvicorn logging by extending the default config
    from uvicorn.config import LOGGING_CONFIG
    import copy

    log_config = copy.deepcopy(LOGGING_CONFIG)
    
    # Add our file handler for access logs
    log_config['handlers']['access_file'] = {
        "class": "logging.FileHandler",
        "filename": access_log_file,
        "formatter": "access",
        "mode": "a"
    }
    
    # Update uvicorn.access logger to use our file handler INSTEAD of default console
    # Or start with [access_file] if we want ONLY file, or ["access", "access_file"] for BOTH.
    log_config['loggers']['uvicorn.access']['handlers'] = ["access_file"]
    log_config['loggers']['uvicorn.access']['propagate'] = False

    uvicorn.run(
        "ngsiem_mcp_http:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
        log_config=log_config
    )
