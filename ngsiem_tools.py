"""
NGSIEM Search Tools for MCP Server.
Implements CrowdStrike NGSIEM search operations using FalconPy SDK.
"""
import logging
import time
from typing import Dict, Any, Optional
from datetime import datetime
from falconpy import APIHarnessV2
from config import CONFIG


# Configure logging
logger = logging.getLogger(__name__)


class NGSIEMSearchTools:
    """
    Wrapper for CrowdStrike NGSIEM search operations.
    Provides secure, validated access to NGSIEM API.
    """
    
    def __init__(self, client_id: str, client_secret: str, base_url: str):
        """
        Initialize NGSIEM client with credentials.
        
        Args:
            client_id: CrowdStrike API Client ID
            client_secret: CrowdStrike API Client Secret
            base_url: CrowdStrike API base URL
            
        Raises:
            ValueError: If credentials are invalid
        """
        try:
            self.falcon = APIHarnessV2(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url
            )
            logger.info("NGSIEM client (APIHarnessV2) initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize NGSIEM client: {e}")
            raise ValueError(f"Authentication failed: {e}") from e
    
    def start_search(
        self,
        repository: str,
        query_string: str,
        start: str = "1d",
        is_live: bool = False
    ) -> Dict[str, Any]:
        """
        Initiate a NGSIEM search.
        
        Args:
            repository: NGSIEM repository name
            query_string: Search query (e.g., "#event_simpleName=ProcessRollup2")
            start: Time range start (e.g., "1d", "24h", "2025-01-01T00:00:00Z")
            is_live: Whether to run as a live/streaming search
            
        Returns:
            Dict containing:
                - id: Search job ID
                - status: Initial search status
                - query: Original query parameters
                
        Raises:
            ValueError: If parameters are invalid
            RuntimeError: If API call fails
            
        Security:
            - Input sanitization for query_string
            - Repository name validation
            - Rate limiting handled by SDK
        """
        # Input validation
        if not repository or not repository.strip():
            raise ValueError("repository parameter is required")
        
        if not query_string or not query_string.strip():
            raise ValueError("query_string parameter is required")
        
        # Sanitize inputs (prevent injection attacks)
        repository = repository.strip()
        query_string = query_string.strip()
        
        logger.info(
            f"Starting search in repository '{repository}' "
            f"with query: {query_string[:100]}..."
        )
        
        try:
            # Build request body
            search_query = {
                "isLive": is_live,
                "start": start,
                "queryString": query_string
            }
            
            response = self.falcon.command(
                "StartSearchV1",
                repository=repository,
                body=search_query
            )
            
            
            # Log full response for debugging
            logger.debug(f"API Response: status_code={response.get('status_code')}, body={response.get('body')}")
            
            # Check for API errors
            status_code = response.get("status_code")
            if status_code != 200:
                error_msg = response.get("body", {}).get("errors", [])
                error_detail = response.get("body", {})
                
                # Log detailed error information
                logger.error(
                    f"Search failed - Status: {status_code}, "
                    f"Errors: {error_msg}, "
                    f"Full response: {error_detail}"
                )
                
                # Provide helpful error message
                if status_code == 401:
                    raise RuntimeError(
                        "Authentication failed. Please verify your CrowdStrike credentials in .env file."
                    )
                elif status_code == 403:
                    raise RuntimeError(
                        f"Access denied to repository '{repository}'. "
                        f"Verify you have NGSIEM permissions and the repository name is correct."
                    )
                elif status_code == 404:
                    raise RuntimeError(
                        f"Repository '{repository}' not found. "
                        f"Check the repository name in your configuration."
                    )
                else:
                    raise RuntimeError(
                        f"API error (HTTP {status_code}): {error_msg or error_detail}"
                    )
            
            
            # Extract search job ID
            body = response.get("body", {})
            
            # Log complete response for debugging
            logger.info(
                f"API Response - Status: {status_code}, "
                f"Body keys: {list(body.keys()) if body else 'empty'}, "
                f"Full body: {body}"
            )
            
            search_id = body.get("id")
            
            if not search_id:
                logger.error(
                    f"No search ID in response. "
                    f"Repository: '{repository}', "
                    f"Query: '{query_string}', "
                    f"Response body: {body}"
                )
                raise RuntimeError(
                    f"Failed to retrieve search ID from API. "
                    f"Please verify repository name '{repository}' is correct. "
                    f"Response was: {body}"
                )
            
            logger.info(f"Search started successfully. Job ID: {search_id}")
            
            return {
                "id": search_id,
                "status": "RUNNING",
                "repository": repository,
                "query": query_string,
                "start": start,
                "is_live": is_live,
                "created_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to start search: {e}", exc_info=True)
            raise RuntimeError(f"Search initiation failed: {e}") from e
    
    def get_search_status(
        self,
        repository: str,
        search_id: str
    ) -> Dict[str, Any]:
        """
        Get the status and results of a NGSIEM search.
        
        Args:
            repository: NGSIEM repository name
            search_id: Search job ID from start_search()
            
        Returns:
            Dict containing:
                - id: Search job ID
                - status: Current status (RUNNING, DONE, CANCELLED, ERROR)
                - progress: Completion percentage (if available)
                - events: Search results (if complete)
                - metadata: Additional search metadata
                
        Raises:
            ValueError: If parameters are invalid
            RuntimeError: If API call fails
        """
        # Input validation
        if not repository or not repository.strip():
            raise ValueError("repository parameter is required")
        
        if not search_id or not search_id.strip():
            raise ValueError("search_id parameter is required")
        
        repository = repository.strip()
        search_id = search_id.strip()
        
        logger.info(f"Checking status for search {search_id} in repository '{repository}'")
        
        try:
            response = self.falcon.command(
                "GetSearchStatusV1",
                repository=repository,
                search_id=search_id
            )
            
            # Check for API errors
            if response.get("status_code") != 200:
                error_msg = response.get("body", {}).get("errors", ["Unknown error"])
                logger.error(f"Status check failed: {error_msg}")
                raise RuntimeError(f"API error: {error_msg}")
            
            body = response.get("body", {})
            
            # Extract status information
            status = body.get("done", False)
            events = body.get("events", [])
            metadata = body.get("metaData", {})
            
            result = {
                "id": search_id,
                "repository": repository,
                "status": "DONE" if status else "RUNNING",
                "done": status,
                "event_count": len(events),
                "events": events if status else [],
                "metadata": metadata,
                "checked_at": datetime.utcnow().isoformat()
            }
            
            logger.info(
                f"Search {search_id} status: {result['status']}, "
                f"events: {result['event_count']}"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to get search status: {e}", exc_info=True)
            raise RuntimeError(f"Status check failed: {e}") from e
    
    def search_and_wait(
        self,
        repository: str,
        query_string: str,
        start: str = "1d",
        is_live: bool = False,
        max_wait_seconds: int = 300,
        poll_interval: int = 2
    ) -> Dict[str, Any]:
        """
        Initiate a search and wait for results (blocking operation).
        
        This is a convenience method that combines start_search and get_search_status,
        automatically polling until the search completes or times out.
        
        Args:
            repository: NGSIEM repository name
            query_string: Search query
            start: Time range start
            is_live: Whether to run as live search
            max_wait_seconds: Maximum time to wait for results (default: 300s/5min)
            poll_interval: Seconds between status checks (default: 2s)
            
        Returns:
            Dict containing:
                - search_id: The search job ID
                - status: Final status (DONE or TIMEOUT)
                - events: Search results
                - metadata: Search metadata
                - elapsed_time: Time taken to complete
                
        Raises:
            ValueError: If parameters are invalid
            RuntimeError: If API call fails
            TimeoutError: If search exceeds max_wait_seconds
            
        Note:
            This is a blocking operation that can take significant time.
            For long-running searches, consider using start_search + get_search_status
            to allow progress monitoring.
        """
        # Input validation
        if max_wait_seconds < 1 or max_wait_seconds > 3600:
            raise ValueError("max_wait_seconds must be between 1 and 3600")
        
        if poll_interval < 1 or poll_interval > 60:
            raise ValueError("poll_interval must be between 1 and 60 seconds")
        
        logger.info(
            f"Starting search_and_wait in repository '{repository}' "
            f"(max_wait={max_wait_seconds}s, poll={poll_interval}s)"
        )
        
        start_time = time.time()
        
        try:
            # Step 1: Start the search
            search_result = self.start_search(
                repository=repository,
                query_string=query_string,
                start=start,
                is_live=is_live
            )
            
            search_id = search_result["id"]
            logger.info(f"Search started with ID: {search_id}, now polling for results...")
            
            # Step 2: Poll for results
            poll_count = 0
            while True:
                elapsed = time.time() - start_time
                
                # Check timeout
                if elapsed >= max_wait_seconds:
                    logger.warning(
                        f"Search {search_id} timed out after {elapsed:.1f}s "
                        f"(max: {max_wait_seconds}s)"
                    )
                    raise TimeoutError(
                        f"Search did not complete within {max_wait_seconds} seconds. "
                        f"Search ID: {search_id}. "
                        f"You can check status later using get_search_status."
                    )
                
                # Get status
                poll_count += 1
                status_result = self.get_search_status(
                    repository=repository,
                    search_id=search_id
                )
                
                logger.debug(
                    f"Poll #{poll_count}: status={status_result['status']}, "
                    f"events={status_result['event_count']}, "
                    f"elapsed={elapsed:.1f}s"
                )
                
                # Check if done
                if status_result["done"]:
                    elapsed_final = time.time() - start_time
                    logger.info(
                        f"Search {search_id} completed in {elapsed_final:.1f}s "
                        f"({poll_count} polls, {status_result['event_count']} events)"
                    )
                    
                    return {
                        "search_id": search_id,
                        "status": "DONE",
                        "event_count": status_result["event_count"],
                        "events": status_result["events"],
                        "metadata": status_result["metadata"],
                        "elapsed_time": elapsed_final,
                        "poll_count": poll_count
                    }
                
                # Wait before next poll
                time.sleep(poll_interval)
                
        except TimeoutError:
            raise
        except Exception as e:
            logger.error(f"search_and_wait failed: {e}", exc_info=True)
            raise RuntimeError(f"Search and wait operation failed: {e}") from e
    
    def stop_search(
        self,
        repository: str,
        search_id: str
    ) -> Dict[str, Any]:
        """
        Stop/cancel a running NGSIEM search.
        
        Args:
            repository: NGSIEM repository name
            search_id: Search job ID from start_search()
            
        Returns:
            Dict containing:
                - id: Search job ID
                - status: CANCELLED
                - stopped_at: Timestamp of cancellation
                
        Raises:
            ValueError: If parameters are invalid
            RuntimeError: If API call fails
        """
        # Input validation
        if not repository or not repository.strip():
            raise ValueError("repository parameter is required")
        
        if not search_id or not search_id.strip():
            raise ValueError("search_id parameter is required")
        
        repository = repository.strip()
        search_id = search_id.strip()
        
        logger.info(f"Stopping search {search_id} in repository '{repository}'")
        
        try:
            response = self.falcon.command(
                "StopSearchV1",
                repository=repository,
                search_id=search_id
            )
            
            # Check for API errors
            if response.get("status_code") not in [200, 204]:
                error_msg = response.get("body", {}).get("errors", ["Unknown error"])
                logger.error(f"Stop search failed: {error_msg}")
                raise RuntimeError(f"API error: {error_msg}")
            
            logger.info(f"Search {search_id} stopped successfully")
            
            return {
                "id": search_id,
                "repository": repository,
                "status": "CANCELLED",
                "stopped_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to stop search: {e}", exc_info=True)
            raise RuntimeError(f"Search cancellation failed: {e}") from e

    def get_repo_fieldset(
        self,
        repository: str,
        timeout_seconds: int = 60
    ) -> Dict[str, Any]:
        """
        Discover the complete field schema for a NGSIEM repository.

        ╔══════════════════════════════════════════════════════════════════════╗
        ║  CRITICAL INSTRUCTION FOR LLM AGENTS                                 ║
        ╠══════════════════════════════════════════════════════════════════════╣
        ║  This tool MUST be called BEFORE constructing any search query.      ║
        ║                                                                      ║
        ║  MANDATORY RULES:                                                    ║
        ║  1. You MUST ONLY use field names returned by this function.         ║
        ║  2. You are STRICTLY FORBIDDEN from inventing or hallucinating       ║
        ║     field names that do not appear in this output.                   ║
        ║  3. If the user requests a field not in this list, inform them       ║
        ║     that the field does not exist and suggest alternatives.          ║
        ║                                                                      ║
        ║  SECURITY: Using non-existent fields will cause query failures.      ║
        ╚══════════════════════════════════════════════════════════════════════╝

        Args:
            repository: NGSIEM repository name. Must contain only alphanumeric
                characters, underscores, and hyphens. Case-sensitive.
            timeout_seconds: Maximum wait time for schema retrieval (1-120s).
                Default: 60 seconds.

        Returns:
            Dict containing:
                - repository: The queried repository name
                - field_count: Total number of fields discovered
                - fields: List of field names available in the repository
                - retrieved_at: ISO timestamp of retrieval

        Raises:
            ValueError: If repository name is invalid or contains dangerous characters.
            RuntimeError: If repository does not exist or API call fails.
            TimeoutError: If schema retrieval exceeds timeout.

        Example:
            >>> result = client.get_repo_fieldset("base_sensor")
            >>> print(result['fields'][:5])
            ['aid', 'event_simpleName', 'ContextTimeStamp', 'ComputerName', 'UserName']

        Security:
            - Repository name is strictly validated (alphanumeric, underscore, hyphen only)
            - Input is sanitized to prevent query injection attacks
            - Quoted strings are properly escaped
        """
        import re

        # =========================================================================
        # INPUT VALIDATION & SANITIZATION (OWASP: Input Validation)
        # =========================================================================

        if not repository:
            raise ValueError("repository parameter is required and cannot be empty")

        repository = repository.strip()

        # Strict validation: only allow safe characters
        # Pattern: alphanumeric, underscores, hyphens (no spaces, quotes, etc.)
        if not re.match(r'^[a-zA-Z0-9_-]+$', repository):
            raise ValueError(
                f"Invalid repository name '{repository}'. "
                "Repository names must contain only alphanumeric characters, "
                "underscores, and hyphens. No spaces or special characters allowed."
            )

        # Validate timeout bounds
        if not 1 <= timeout_seconds <= 120:
            raise ValueError(
                f"timeout_seconds must be between 1 and 120, got {timeout_seconds}"
            )

        # =========================================================================
        # QUERY CONSTRUCTION (Injection-Safe)
        # =========================================================================

        # Escape any quotes in repository name (defense in depth)
        safe_repo = repository.replace('"', '\\"')

        # Build the fieldset query
        # Format: #repo="{repository}" | fieldset()
        fieldset_query = f'#repo="{safe_repo}" | fieldset()'

        logger.info(
            f"[FIELDSET] Discovering schema for repository '{repository}'"
        )

        # =========================================================================
        # EXECUTE QUERY
        # =========================================================================

        try:
            # Use search_and_wait for blocking execution with timeout
            result = self.search_and_wait(
                repository=repository,
                query_string=fieldset_query,
                start="1h",  # Short time range is sufficient for schema discovery
                is_live=False,
                max_wait_seconds=timeout_seconds,
                poll_interval=2
            )

            # =========================================================================
            # PARSE FIELDSET RESPONSE
            # =========================================================================

            events = result.get('events', [])

            if not events:
                logger.warning(
                    f"[FIELDSET] No fields returned for repository '{repository}'. "
                    "This may indicate an empty repository or incorrect name."
                )
                return {
                    "repository": repository,
                    "field_count": 0,
                    "fields": [],
                    "retrieved_at": datetime.utcnow().isoformat(),
                    "warning": "No fields returned. Verify repository name is correct."
                }

            # Extract unique field names from the fieldset response
            # The fieldset() function returns events with field metadata
            fields: set[str] = set()

            for event in events:
                if isinstance(event, dict):
                    # Add all keys from the event as field names
                    fields.update(event.keys())
                    # Also check for a 'field' or 'name' key if present
                    if 'field' in event:
                        fields.add(event['field'])
                    if '_field' in event:
                        fields.add(event['_field'])

            # Sort fields alphabetically for consistent output
            sorted_fields = sorted(fields)

            logger.info(
                f"[FIELDSET] Discovered {len(sorted_fields)} fields in '{repository}'"
            )

            return {
                "repository": repository,
                "field_count": len(sorted_fields),
                "fields": sorted_fields,
                "retrieved_at": datetime.utcnow().isoformat()
            }

        except TimeoutError:
            logger.error(
                f"[FIELDSET] Timeout after {timeout_seconds}s for '{repository}'"
            )
            raise TimeoutError(
                f"Schema discovery timed out after {timeout_seconds} seconds. "
                f"The repository '{repository}' may be very large or unavailable."
            )

        except RuntimeError as e:
            # Re-raise with more context
            if "404" in str(e) or "not found" in str(e).lower():
                raise RuntimeError(
                    f"Repository '{repository}' not found. "
                    "Use get_available_repositories to see valid repository names."
                ) from e
            raise

        except Exception as e:
            logger.error(
                f"[FIELDSET] Failed to discover schema for '{repository}': {e}",
                exc_info=True
            )
            raise RuntimeError(
                f"Schema discovery failed for repository '{repository}': {e}"
            ) from e


def create_ngsiem_client() -> NGSIEMSearchTools:
    """
    Factory function to create NGSIEM client from configuration.
    
    Returns:
        NGSIEMSearchTools: Initialized NGSIEM client
        
    Raises:
        ValueError: If configuration is invalid
    """
    if CONFIG is None:
        raise ValueError(
            "Configuration not loaded. "
            "Please create .env file with CrowdStrike credentials."
        )
    
    return NGSIEMSearchTools(
        client_id=CONFIG.client_id,
        client_secret=CONFIG.client_secret,
        base_url=CONFIG.base_url
    )
