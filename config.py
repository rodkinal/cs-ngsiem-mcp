"""
Configuration management for NGSIEM MCP Server.
Loads credentials and settings from environment variables.
"""
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator


# Load environment variables from .env file
load_dotenv()


class NGSIEMConfig(BaseModel):
    """Configuration for CrowdStrike NGSIEM API integration."""
    
    # CrowdStrike API Credentials
    client_id: str = Field(..., description="CrowdStrike API Client ID")
    client_secret: str = Field(..., description="CrowdStrike API Client Secret")
    base_url: str = Field(
        default="https://api.crowdstrike.com",
        description="CrowdStrike API base URL"
    )
    
    # NGSIEM Configuration
    default_repository: Optional[str] = Field(
        default=None,
        description="Default NGSIEM repository name"
    )
    
    # Logging Configuration
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: str = Field(default="ngsiem_mcp.log", description="Log file path")
    
    @field_validator("client_id", "client_secret")
    @classmethod
    def validate_credentials(cls, v: str) -> str:
        """Ensure credentials are not placeholder values."""
        if not v or v.startswith("your_"):
            raise ValueError(
                "Credentials must be set in .env file. "
                "Copy .env.example to .env and configure your CrowdStrike credentials."
            )
        return v
    
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is a valid Python logging level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"log_level must be one of: {', '.join(valid_levels)}")
        return v_upper
    
    model_config = {
        "env_prefix": "CROWDSTRIKE_",
        "case_sensitive": False
    }


def load_config() -> NGSIEMConfig:
    """
    Load configuration from environment variables.
    
    Returns:
        NGSIEMConfig: Validated configuration object
        
    Raises:
        ValueError: If required credentials are missing or invalid
    """
    try:
        config = NGSIEMConfig(
            client_id=os.getenv("CROWDSTRIKE_CLIENT_ID", ""),
            client_secret=os.getenv("CROWDSTRIKE_CLIENT_SECRET", ""),
            base_url=os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com"),
            default_repository=os.getenv("NGSIEM_DEFAULT_REPOSITORY"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE", "ngsiem_mcp.log"),
        )
        return config
    except Exception as e:
        raise ValueError(
            f"Configuration error: {e}\n"
            f"Please ensure .env file exists and contains valid credentials.\n"
            f"Copy .env.example to .env and configure your CrowdStrike credentials."
        ) from e


# Global configuration instance
try:
    CONFIG = load_config()
except ValueError as e:
    # Allow import to succeed but warn about configuration
    print(f"⚠️  WARNING: {e}")
    CONFIG = None
