"""
Synchronous NGSIEM operations for thread pool execution.

These functions are designed to be called via asyncio.to_thread() or
run_blocking() from the async executor. Each function uses a thread-local
NGSIEM client for thread safety.

All functions are pure synchronous wrappers that:
1. Obtain a thread-local client via get_thread_client()
2. Call the corresponding NGSIEMSearchTools method
3. Return the result (or raise exceptions)

Security Notes:
    - Input validation is performed by NGSIEMSearchTools methods
    - No credentials are logged or exposed
    - Thread isolation prevents cross-request data leakage
"""
from typing import Any

from ngsiem_async_executor import get_thread_client


def execute_search_and_wait(
    repository: str,
    query_string: str,
    start: str = "1d",
    is_live: bool = False,
    max_wait_seconds: int = 300,
    poll_interval: int = 2
) -> dict[str, Any]:
    """
    Execute search_and_wait in thread context.
    
    This is the primary search method that initiates a search and waits
    for completion, polling the API until results are available.
    
    Args:
        repository: NGSIEM repository name.
        query_string: Search query string.
        start: Time range start (e.g., "1d", "24h").
        is_live: Whether to run as a live/streaming search.
        max_wait_seconds: Maximum time to wait for results.
        poll_interval: Seconds between status polls.
        
    Returns:
        dict: Search results with events.
        
    Raises:
        ValueError: If parameters are invalid.
        RuntimeError: If API call fails.
        TimeoutError: If search exceeds max_wait_seconds.
    """
    client = get_thread_client()
    return client.search_and_wait(
        repository=repository,
        query_string=query_string,
        start=start,
        is_live=is_live,
        max_wait_seconds=max_wait_seconds,
        poll_interval=poll_interval
    )


def execute_start_search(
    repository: str,
    query_string: str,
    start: str = "1d",
    is_live: bool = False
) -> dict[str, Any]:
    """
    Execute start_search in thread context.
    
    Initiates a search job without waiting for completion.
    Use get_search_status to poll for results.
    
    Args:
        repository: NGSIEM repository name.
        query_string: Search query string.
        start: Time range start.
        is_live: Whether to run as a live search.
        
    Returns:
        dict: Search job metadata including job ID.
        
    Raises:
        ValueError: If parameters are invalid.
        RuntimeError: If API call fails.
    """
    client = get_thread_client()
    return client.start_search(
        repository=repository,
        query_string=query_string,
        start=start,
        is_live=is_live
    )


def execute_get_search_status(
    repository: str,
    search_id: str
) -> dict[str, Any]:
    """
    Execute get_search_status in thread context.
    
    Retrieves the current status and results of a search job.
    
    Args:
        repository: NGSIEM repository name.
        search_id: Search job ID from start_search.
        
    Returns:
        dict: Search status and events (if complete).
        
    Raises:
        ValueError: If parameters are invalid.
        RuntimeError: If API call fails.
    """
    client = get_thread_client()
    return client.get_search_status(
        repository=repository,
        search_id=search_id
    )


def execute_stop_search(
    repository: str,
    search_id: str
) -> dict[str, Any]:
    """
    Execute stop_search in thread context.
    
    Cancels a running search job.
    
    Args:
        repository: NGSIEM repository name.
        search_id: Search job ID to cancel.
        
    Returns:
        dict: Cancellation confirmation.
        
    Raises:
        ValueError: If parameters are invalid.
        RuntimeError: If API call fails.
    """
    client = get_thread_client()
    return client.stop_search(
        repository=repository,
        search_id=search_id
    )


def execute_get_repo_fieldset(
    repository: str,
    timeout_seconds: int = 60
) -> dict[str, Any]:
    """
    Execute get_repo_fieldset in thread context.
    
    Discovers the complete field schema for a repository.
    This is a mandatory pre-search step to prevent field hallucination.
    
    Args:
        repository: NGSIEM repository name.
        timeout_seconds: Maximum time to wait for schema.
        
    Returns:
        dict: Repository field schema.
        
    Raises:
        ValueError: If repository name is invalid.
        RuntimeError: If API call fails.
        TimeoutError: If schema retrieval times out.
    """
    client = get_thread_client()
    return client.get_repo_fieldset(
        repository=repository,
        timeout_seconds=timeout_seconds
    )
