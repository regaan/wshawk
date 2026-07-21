#!/usr/bin/env python3
from __future__ import annotations

"""
WSHawk HTTP Resilience Layer
Retry with exponential backoff, circuit breaker, and rate-limit handling

Author: Regaan (@regaan)
"""

import asyncio
import time
import logging
from enum import Enum
from functools import wraps
from typing import TYPE_CHECKING, Optional, Set

if TYPE_CHECKING:
    import aiohttp

logger = logging.getLogger('wshawk.resilience')


# ─── Retry with Exponential Backoff ────────────────────────────

class RetryConfig:
    """Configuration for retry behavior."""
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        retry_on_status: Optional[Set[int]] = None,
        retry_on_exceptions: Optional[tuple] = None,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.retry_on_status = retry_on_status or {429, 500, 502, 503, 504}
        self.retry_on_exceptions = retry_on_exceptions or (
            ConnectionError, TimeoutError, OSError,
        )


def retry_async(config: RetryConfig = None):
    """
    Decorator for async functions with exponential backoff retry.
    
    Handles:
    - HTTP 429 (Too Many Requests) with Retry-After header
    - 5xx server errors
    - Connection errors and timeouts
    
    Usage:
        @retry_async(RetryConfig(max_retries=3))
        async def call_api(self, data):
            ...
    """
    if config is None:
        config = RetryConfig()
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(config.max_retries + 1):
                try:
                    result = await func(*args, **kwargs)
                    
                    # If result is an aiohttp response, check status
                    if hasattr(result, 'status'):
                        if result.status == 429:
                            # Rate limited — respect Retry-After
                            retry_after = result.headers.get('Retry-After', '')
                            try:
                                delay = float(retry_after)
                            except (ValueError, TypeError):
                                delay = config.base_delay * (config.exponential_base ** attempt)
                            
                            delay = min(delay, config.max_delay)
                            logger.warning(
                                f"Rate limited (429). Retry {attempt+1}/{config.max_retries} "
                                f"after {delay:.1f}s"
                            )
                            await asyncio.sleep(delay)
                            continue
                        
                        if result.status in config.retry_on_status and attempt < config.max_retries:
                            delay = config.base_delay * (config.exponential_base ** attempt)
                            delay = min(delay, config.max_delay)
                            logger.warning(
                                f"HTTP {result.status}. Retry {attempt+1}/{config.max_retries} "
                                f"after {delay:.1f}s"
                            )
                            await asyncio.sleep(delay)
                            continue
                    
                    return result
                
                except config.retry_on_exceptions as e:
                    last_exception = e
                    if attempt < config.max_retries:
                        delay = config.base_delay * (config.exponential_base ** attempt)
                        delay = min(delay, config.max_delay)
                        logger.warning(
                            f"{type(e).__name__}: {e}. Retry {attempt+1}/{config.max_retries} "
                            f"after {delay:.1f}s"
                        )
                        await asyncio.sleep(delay)
                    else:
                        raise
            
            if last_exception:
                raise last_exception
            return result
        
        return wrapper
    return decorator


# ─── Circuit Breaker ───────────────────────────────────────────

class CircuitState(Enum):
    CLOSED = 'closed'       # Normal operation
    OPEN = 'open'           # Failing, reject immediately
    HALF_OPEN = 'half_open' # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker pattern for external service calls.
    
    Prevents cascading failures by stopping calls to a failing service
    after a threshold of consecutive failures.
    
    States:
    - CLOSED:    Normal. Track failures.
    - OPEN:      Too many failures. Reject all calls for `reset_timeout` seconds.
    - HALF_OPEN: After timeout, allow one test call. If success → CLOSED, else → OPEN.
    
    Usage:
        breaker = CircuitBreaker(name='defectdojo', failure_threshold=5)
        
        if breaker.can_execute():
            try:
                result = await call_api()
                breaker.record_success()
            except Exception as e:
                breaker.record_failure()
    """
    
    def __init__(
        self,
        name: str = 'default',
        failure_threshold: int = 5,
        reset_timeout: float = 60.0,
        half_open_max_calls: int = 1,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max_calls = half_open_max_calls
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float = 0
        self._half_open_calls = 0
    
    @property
    def state(self) -> CircuitState:
        """Get current state, with automatic OPEN → HALF_OPEN transition."""
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self.reset_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                logger.info(f"Circuit '{self.name}' → HALF_OPEN (testing recovery)")
        return self._state
    
    def can_execute(self) -> bool:
        """Check if a call should be allowed."""
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            return self._half_open_calls < self.half_open_max_calls
        return False  # OPEN
    
    def record_success(self):
        """Record a successful call."""
        self._failure_count = 0
        
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            self._state = CircuitState.CLOSED
            logger.info(f"Circuit '{self.name}' → CLOSED (service recovered)")
        
        self._state = CircuitState.CLOSED
    
    def record_failure(self):
        """Record a failed call."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            logger.warning(f"Circuit '{self.name}' → OPEN (still failing)")
        elif self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(
                f"Circuit '{self.name}' → OPEN ({self._failure_count} consecutive failures)"
            )
    
    def get_stats(self) -> dict:
        """Get circuit breaker statistics."""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': self._failure_count,
            'success_count': self._success_count,
            'failure_threshold': self.failure_threshold,
            'reset_timeout': self.reset_timeout,
        }


# ─── Resilient HTTP Session ────────────────────────────────────

class ResilientSession:
    """
    Wrapper around aiohttp.ClientSession with built-in resilience.
    
    Features:
    - Automatic retry with exponential backoff
    - Circuit breaker per base URL
    - Timeout enforcement
    - Request/response logging
    
    Usage:
        async with ResilientSession(timeout=30) as session:
            resp = await session.post(url, json=data)
    """
    
    def __init__(
        self,
        timeout: float = 30.0,
        retry_config: RetryConfig = None,
        circuit_breaker: CircuitBreaker = None,
        headers: Optional[dict] = None,
        ssl_context: Optional[any] = None,
    ):
        self.timeout = timeout
        self.retry_config = retry_config or RetryConfig()
        self.circuit_breaker = circuit_breaker
        self.headers = headers
        self.ssl_context = ssl_context
        self._session = None
        self._request_count = 0
        self._error_count = 0
    
    async def __aenter__(self):
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = None
            if self.ssl_context:
                connector = aiohttp.TCPConnector(ssl=self.ssl_context)
            
            self._session = aiohttp.ClientSession(
                timeout=timeout, 
                headers=self.headers,
                connector=connector
            )
        except ImportError:
            raise ImportError("aiohttp required. Install: pip install aiohttp")
        return self
    
    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()
    
    async def request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make a resilient HTTP request."""
        if self.circuit_breaker and not self.circuit_breaker.can_execute():
            raise ConnectionError(
                f"Circuit breaker '{self.circuit_breaker.name}' is OPEN. "
                f"Service unavailable."
            )
        
        last_error = None
        for attempt in range(self.retry_config.max_retries + 1):
            try:
                self._request_count += 1
                resp = await self._session.request(method, url, **kwargs)
                
                # Handle rate limiting
                if resp.status == 429:
                    retry_after = resp.headers.get('Retry-After', '')
                    try:
                        delay = float(retry_after)
                    except (ValueError, TypeError):
                        delay = self.retry_config.base_delay * (
                            self.retry_config.exponential_base ** attempt
                        )
                    delay = min(delay, self.retry_config.max_delay)
                    logger.warning(f"Rate limited (429). Waiting {delay:.1f}s...")
                    await asyncio.sleep(delay)
                    continue
                
                # Retry on server errors
                if resp.status in self.retry_config.retry_on_status and attempt < self.retry_config.max_retries:
                    delay = self.retry_config.base_delay * (
                        self.retry_config.exponential_base ** attempt
                    )
                    delay = min(delay, self.retry_config.max_delay)
                    logger.warning(f"HTTP {resp.status}. Retry {attempt+1} after {delay:.1f}s")
                    await asyncio.sleep(delay)
                    continue
                
                # Success
                if self.circuit_breaker:
                    self.circuit_breaker.record_success()
                
                return resp
            
            except self.retry_config.retry_on_exceptions as e:
                last_error = e
                self._error_count += 1
                
                if self.circuit_breaker:
                    self.circuit_breaker.record_failure()
                
                if attempt < self.retry_config.max_retries:
                    delay = self.retry_config.base_delay * (
                        self.retry_config.exponential_base ** attempt
                    )
                    delay = min(delay, self.retry_config.max_delay)
                    logger.warning(f"{type(e).__name__}. Retry {attempt+1} after {delay:.1f}s")
                    await asyncio.sleep(delay)
        
        if last_error:
            raise last_error
        raise ConnectionError(f"Request to {url} failed after {self.retry_config.max_retries} retries")
    
    async def get(self, url: str, **kwargs):
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs):
        return await self.request('POST', url, **kwargs)
    
    async def put(self, url: str, **kwargs):
        return await self.request('PUT', url, **kwargs)
    
    async def delete(self, url: str, **kwargs):
        return await self.request('DELETE', url, **kwargs)
    
    def get_stats(self) -> dict:
        return {
            'total_requests': self._request_count,
            'total_errors': self._error_count,
            'circuit_breaker': self.circuit_breaker.get_stats() if self.circuit_breaker else None,
        }
