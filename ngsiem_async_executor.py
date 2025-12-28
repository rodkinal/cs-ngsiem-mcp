"""
Async Executor for NGSIEM blocking operations.

Provides thread-safe execution of FalconPy SDK calls using asyncio.to_thread().
Each thread maintains its own NGSIEM client instance to ensure thread safety,
as FalconPy's APIHarnessV2 is not guaranteed to be thread-safe.

Security Notes:
    - Thread-local storage prevents credential leakage between requests
    - No shared state between threads except read-only configuration
    - Logging excludes sensitive data (credentials, tokens)

Example:
    >>> from ngsiem_async_executor import run_blocking, get_thread_client
    >>> 
    >>> async def search():
    ...     result = await run_blocking(
    ...         lambda: get_thread_client().start_search("repo", "query")
    ...     )
    ...     return result
"""
import asyncio
import threading
import logging
import os
from typing import Any, TypeVar, Callable
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Thread-local storage for NGSIEM clients
_thread_local = threading.local()

# Configurable thread pool executor
_executor: ThreadPoolExecutor | None = None


def _get_executor() -> ThreadPoolExecutor | None:
    """
    Get or create the thread pool executor.
    
    Uses NGSIEM_THREAD_POOL_SIZE env var if set, otherwise returns None
    to use Python's default executor (min(32, cpu_count + 4) workers).
    
    Returns:
        ThreadPoolExecutor or None for default behavior.
    """
    global _executor
    
    pool_size_str = os.environ.get("NGSIEM_THREAD_POOL_SIZE")
    if pool_size_str is None:
        return None  # Use default executor
    
    if _executor is None:
        try:
            pool_size = int(pool_size_str)
            _executor = ThreadPoolExecutor(
                max_workers=pool_size,
                thread_name_prefix="ngsiem-worker"
            )
            logger.info(f"Created thread pool with {pool_size} workers")
        except ValueError:
            logger.warning(
                f"Invalid NGSIEM_THREAD_POOL_SIZE: {pool_size_str}, using default"
            )
            return None
    
    return _executor


def get_thread_client():
    """
    Get or create a thread-local NGSIEM client.
    
    Each thread gets its own client instance to ensure thread safety,
    as FalconPy's APIHarnessV2 is not guaranteed to be thread-safe.
    
    Returns:
        NGSIEMSearchTools: Thread-local client instance.
        
    Raises:
        ValueError: If configuration is invalid.
    """
    # Import here to avoid circular imports
    from ngsiem_tools import create_ngsiem_client
    
    if not hasattr(_thread_local, "client"):
        thread_name = threading.current_thread().name
        logger.debug(f"Creating new NGSIEM client for thread: {thread_name}")
        _thread_local.client = create_ngsiem_client()
    
    return _thread_local.client


async def run_blocking(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """
    Execute a blocking function in a thread pool.
    
    This function wraps synchronous, blocking I/O operations (like FalconPy
    API calls) and executes them in a separate thread to prevent blocking
    the asyncio event loop.
    
    Args:
        func: Blocking function to execute.
        *args: Positional arguments for func.
        **kwargs: Keyword arguments for func.
        
    Returns:
        T: Result from the blocking function.
        
    Raises:
        Exception: Any exception raised by func is propagated.
        
    Example:
        >>> result = await run_blocking(
        ...     some_sync_function, 
        ...     arg1, 
        ...     arg2, 
        ...     kwarg1=value
        ... )
    """
    loop = asyncio.get_running_loop()
    executor = _get_executor()
    
    # Wrap with kwargs support
    def _wrapper() -> T:
        return func(*args, **kwargs)
    
    return await loop.run_in_executor(executor, _wrapper)


def cleanup_executor() -> None:
    """
    Shutdown the thread pool executor gracefully.
    
    Call this during application shutdown to ensure all threads
    complete their work before the process exits.
    """
    global _executor
    
    if _executor is not None:
        logger.info("Shutting down thread pool executor...")
        _executor.shutdown(wait=True)
        _executor = None
        logger.info("Thread pool executor shutdown complete")
