"""
Authentication Module for NGSIEM HTTP Server

Provides Bearer token authentication for FastAPI endpoints.

Security Notes:
- Uses constant-time comparison to prevent timing attacks
- Token loaded from environment variable (never hardcoded)
- Returns structured 401 responses on auth failure
"""
import os
import secrets
import logging
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger(__name__)

# Check for development skip-auth mode
# WARNING: Only use for development with MCP Inspector (known header forwarding bug)
SKIP_AUTH = os.environ.get("MCP_SKIP_AUTH", "").lower() in ("true", "1", "yes")
if SKIP_AUTH:
    logger.warning("⚠️  MCP_SKIP_AUTH is enabled - authentication is DISABLED. DO NOT USE IN PRODUCTION!")

# Security scheme for OpenAPI documentation
security_scheme = HTTPBearer(
    scheme_name="Bearer Token",
    description="API key for authentication. Set via MCP_API_KEY environment variable.",
    auto_error=not SKIP_AUTH  # Don't auto-error if skip mode is enabled
)


def get_api_key() -> str:
    """
    Retrieve API key from environment.
    
    Returns:
        str: The configured API key.
        
    Raises:
        RuntimeError: If MCP_API_KEY is not configured.
        
    Security:
        Key is loaded once per request, not cached globally.
    """
    api_key = os.environ.get("MCP_API_KEY", "").strip()
    
    if not api_key:
        logger.error("MCP_API_KEY environment variable is not set")
        raise RuntimeError(
            "Server misconfiguration: MCP_API_KEY not set. "
            "Set this environment variable before starting the server."
        )
    
    return api_key


async def verify_bearer_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security_scheme)] = None
) -> str:
    """
    Validate Bearer token from Authorization header.
    
    This is a FastAPI dependency that should be injected into protected routes.
    
    Args:
        credentials: HTTP Authorization credentials extracted by FastAPI.
        
    Returns:
        str: The validated token (for logging/audit purposes).
        
    Raises:
        HTTPException: 401 if token is missing, invalid, or doesn't match.
        
    Security:
        - Uses secrets.compare_digest() for constant-time comparison
        - Prevents timing attacks that could leak token information
        - Logs failed attempts without exposing token details
        
    Example:
        @app.get("/protected")
        async def protected_route(token: str = Depends(verify_bearer_token)):
            return {"status": "authenticated"}
    """
    # Development mode: skip authentication (for MCP Inspector testing)
    if SKIP_AUTH:
        logger.debug("SKIP_AUTH enabled - bypassing authentication")
        return "skip-auth-development-token"
    
    # No credentials provided and not in skip mode
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    try:
        expected_token = get_api_key()
    except RuntimeError as e:
        logger.error(f"Authentication system error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication system unavailable"
        )
    
    provided_token = credentials.credentials
    
    # Constant-time comparison prevents timing attacks
    # Even if tokens differ in length, comparison takes same time
    is_valid = secrets.compare_digest(
        provided_token.encode("utf-8"),
        expected_token.encode("utf-8")
    )
    
    if not is_valid:
        logger.warning(
            f"Authentication failed: invalid token "
            f"(provided length: {len(provided_token)})"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    logger.debug("Authentication successful")
    return provided_token


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Utility function for generating new API keys.
    
    Args:
        length: Number of bytes for token (default 32 = 256 bits).
        
    Returns:
        str: Hexadecimal token string (length * 2 characters).
        
    Example:
        >>> generate_secure_token()
        'a1b2c3d4e5f6...'  # 64 character hex string
    """
    return secrets.token_hex(length)


# Convenience alias for route dependencies
RequireAuth = Annotated[str, Depends(verify_bearer_token)]
