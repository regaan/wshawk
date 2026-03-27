#!/usr/bin/env python3
"""
WSHawk WebSocket Endpoint Discovery Module
Auto-detect WebSocket endpoints from HTTP targets

Author: Regaan (@regaan)
"""

import asyncio
import re
import ssl
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    from .__main__ import Logger, Colors
except ImportError:
    from __main__ import Logger, Colors


class WSEndpointDiscovery:
    """
    Discover WebSocket endpoints from HTTP targets.

    Techniques:
    1. HTTP Upgrade probe on common paths
    2. HTML/JS parsing for ws:// and wss:// URLs
    3. JavaScript source analysis for WebSocket constructors
    4. Common path brute-force (/ws, /socket, /websocket, etc.)
    5. Response header analysis (Upgrade, Sec-WebSocket-*)
    """

    # Common WebSocket endpoint paths found across web applications
    COMMON_WS_PATHS = [
        '/ws',
        '/wss',
        '/websocket',
        '/socket',
        '/socket.io/',
        '/sockjs/',
        '/signalr/',
        '/cable',
        '/live',
        '/realtime',
        '/stream',
        '/events',
        '/feed',
        '/push',
        '/notifications',
        '/chat',
        '/api/ws',
        '/api/websocket',
        '/api/v1/ws',
        '/api/v2/ws',
        '/api/stream',
        '/graphql',
        '/subscriptions',
        '/hub',
        '/connect',
        '/channel',
        '/mqtt',
        '/stomp',
    ]

    def __init__(self,
                 target: str,
                 timeout: int = 10,
                 max_depth: int = 2,
                 headers: Optional[Dict] = None,
                 verify_ssl: bool = True):
        """
        Args:
            target: Base HTTP(S) URL to scan (e.g., https://example.com)
            timeout: Request timeout in seconds
            max_depth: How many link levels to follow for JS analysis
            headers: Custom HTTP headers
            verify_ssl: Whether to verify SSL certificates
        """
        parsed = urlparse(target)
        if parsed.scheme not in ('http', 'https'):
            # Accept ws:// and wss:// too — convert to http(s)
            if parsed.scheme == 'ws':
                target = 'http://' + target[5:]
            elif parsed.scheme == 'wss':
                target = 'https://' + target[6:]
            else:
                target = 'https://' + target

        self.target = target.rstrip('/')
        self.parsed = urlparse(self.target)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.timeout = timeout
        self.max_depth = max_depth
        self.headers = headers or {}
        self.verify_ssl = verify_ssl

        # Results
        self.discovered_endpoints: List[Dict] = []
        self.visited_urls: Set[str] = set()
        self.js_urls_analyzed: Set[str] = set()

    async def discover(self) -> List[Dict]:
        """
        Run full discovery process.

        Returns:
            List of discovered WebSocket endpoints with metadata:
            [
                {
                    'url': 'ws://example.com/ws',
                    'source': 'upgrade_probe',
                    'confidence': 'HIGH',
                    'details': '...'
                },
                ...
            ]
        """
        if not aiohttp:
            Logger.error("aiohttp required for WS discovery. Install: pip install aiohttp")
            return []

        Logger.info("=" * 50)
        Logger.info("WebSocket Endpoint Discovery")
        Logger.info("=" * 50)
        Logger.info(f"Target: {self.target}")
        print()

        ssl_ctx = None
        if not self.verify_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        # Use resilient session when available
        try:
            from .resilience import ResilientSession, RetryConfig, CircuitBreaker
            
            breaker = CircuitBreaker(name='discovery', failure_threshold=10, reset_timeout=30.0)
            retry = RetryConfig(max_retries=2, base_delay=1.0)
            
            async with ResilientSession(
                timeout=self.timeout, retry_config=retry, circuit_breaker=breaker, ssl_context=ssl_ctx, headers=self.headers
            ) as resilient:
                session = resilient._session
                # Phase 1: Probe common paths with HTTP Upgrade
                Logger.info("[Phase 1] Probing common WebSocket paths...")
                await self._probe_common_paths(session)
    
                # Phase 2: Fetch and parse HTML for ws:// URLs
                Logger.info("[Phase 2] Analyzing HTML for WebSocket URLs...")
                await self._analyze_html(session, self.target, depth=0)
    
                # Phase 3: Analyze linked JavaScript files
                Logger.info("[Phase 3] Scanning JavaScript sources...")
                await self._analyze_javascript_files(session)
        except ImportError:
            # Fallback: raw aiohttp without resilience
            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers=self.headers
            ) as session:
                # Phase 1: Probe common paths with HTTP Upgrade
                Logger.info("[Phase 1] Probing common WebSocket paths...")
                await self._probe_common_paths(session)
    
                # Phase 2: Fetch and parse HTML for ws:// URLs
                Logger.info("[Phase 2] Analyzing HTML for WebSocket URLs...")
                await self._analyze_html(session, self.target, depth=0)
    
                # Phase 3: Analyze linked JavaScript files
                Logger.info("[Phase 3] Scanning JavaScript sources...")
                await self._analyze_javascript_files(session)

        # Deduplicate results
        self._deduplicate()

        # Summary
        print()
        Logger.info("=" * 50)
        Logger.info("Discovery Results")
        Logger.info("=" * 50)

        if self.discovered_endpoints:
            for ep in self.discovered_endpoints:
                confidence_color = {
                    'CONFIRMED': Colors.GREEN,
                    'HIGH': Colors.CYAN,
                    'MEDIUM': Colors.YELLOW,
                    'LOW': Colors.RED
                }.get(ep['confidence'], Colors.YELLOW)

                Logger.success(
                    f"{confidence_color}[{ep['confidence']}]{Colors.END} "
                    f"{ep['url']} "
                    f"(via {ep['source']})"
                )
                if ep.get('details'):
                    print(f"    └─ {ep['details']}")
        else:
            Logger.warning("No WebSocket endpoints discovered.")
            Logger.info("Tips: Try providing authenticated headers or specific paths.")

        return self.discovered_endpoints

    # ─── Phase 1: HTTP Upgrade Probing ──────────────────────────────

    async def _probe_common_paths(self, session: aiohttp.ClientSession):
        """Probe common paths with WebSocket upgrade headers."""
        tasks = []
        for path in self.COMMON_WS_PATHS:
            url = self.base_url + path
            tasks.append(self._probe_single_path(session, url, path))

        # Also probe the target URL itself
        tasks.append(self._probe_single_path(session, self.target, self.parsed.path or '/'))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = sum(1 for r in results if r is True)
        Logger.info(f"  Probed {len(tasks)} paths, {found} potential endpoints found")

    async def _probe_single_path(self, session: aiohttp.ClientSession, url: str, path: str) -> bool:
        """Send an HTTP request with Upgrade headers to detect WS support."""
        try:
            upgrade_headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13',
            }
            upgrade_headers.update(self.headers)

            async with session.get(url, headers=upgrade_headers, allow_redirects=False) as resp:
                # 101 Switching Protocols = confirmed WebSocket
                if resp.status == 101:
                    ws_url = self._to_ws_url(url)
                    self._add_endpoint(ws_url, 'upgrade_probe', 'CONFIRMED',
                                       f"HTTP 101 Switching Protocols on {path}")
                    return True

                # Check for WebSocket-related headers even on non-101
                upgrade_header = resp.headers.get('Upgrade', '').lower()
                ws_accept = resp.headers.get('Sec-WebSocket-Accept', '')

                if upgrade_header == 'websocket' or ws_accept:
                    ws_url = self._to_ws_url(url)
                    self._add_endpoint(ws_url, 'upgrade_header', 'HIGH',
                                       f"WebSocket headers detected (HTTP {resp.status})")
                    return True

                # 400 with specific WebSocket error messages
                if resp.status == 400:
                    body = await resp.text()
                    ws_indicators = [
                        'websocket', 'upgrade required', 'sec-websocket',
                        'missing upgrade', 'not a websocket'
                    ]
                    if any(ind in body.lower() for ind in ws_indicators):
                        ws_url = self._to_ws_url(url)
                        self._add_endpoint(ws_url, 'error_analysis', 'MEDIUM',
                                           f"WebSocket error message on {path}")
                        return True

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

        return False

    # ─── Phase 2: HTML Analysis ─────────────────────────────────────

    async def _analyze_html(self, session: aiohttp.ClientSession, url: str, depth: int):
        """Fetch HTML page and extract WebSocket URLs from content and scripts."""
        if url in self.visited_urls or depth > self.max_depth:
            return
        self.visited_urls.add(url)

        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return

                content_type = resp.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    return

                body = await resp.text()

                # Extract ws:// and wss:// URLs from HTML
                ws_pattern = re.compile(r'''(?:["'`])(wss?://[^\s"'`<>]+)(?:["'`])''', re.IGNORECASE)
                for match in ws_pattern.finditer(body):
                    ws_url = match.group(1)
                    # Resolve relative-looking URLs
                    if self.parsed.netloc in ws_url or 'localhost' in ws_url:
                        self._add_endpoint(ws_url, 'html_content', 'HIGH',
                                           f"Found in HTML source at {url}")

                # Extract WebSocket constructor patterns from inline scripts
                self._extract_ws_from_js(body, url)

                # Find JavaScript file URLs to analyze
                script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
                for match in script_pattern.finditer(body):
                    js_url = match.group(1)
                    if not js_url.startswith(('http://', 'https://')):
                        js_url = urljoin(url, js_url)
                    self.js_urls_analyzed.add(js_url)

                # Find linked pages (depth crawl)
                if depth < self.max_depth:
                    link_pattern = re.compile(r'<a[^>]+href=["\']([^"\'#]+)["\']', re.IGNORECASE)
                    for match in link_pattern.finditer(body):
                        link = match.group(1)
                        if not link.startswith(('http://', 'https://')):
                            link = urljoin(url, link)
                        # Only follow same-domain links
                        if urlparse(link).netloc == self.parsed.netloc:
                            await self._analyze_html(session, link, depth + 1)

        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

    # ─── Phase 3: JavaScript File Analysis ──────────────────────────

    async def _analyze_javascript_files(self, session: aiohttp.ClientSession):
        """Analyze JavaScript files for WebSocket usage patterns."""
        tasks = [
            self._analyze_single_js(session, js_url)
            for js_url in self.js_urls_analyzed
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            Logger.info(f"  Analyzed {len(tasks)} JavaScript files")
        else:
            Logger.info("  No JavaScript files to analyze")

    async def _analyze_single_js(self, session: aiohttp.ClientSession, url: str):
        """Download and analyze a single JavaScript file."""
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return

                body = await resp.text()
                self._extract_ws_from_js(body, url)

        except Exception:
            pass

    def _extract_ws_from_js(self, js_content: str, source_url: str):
        """Extract WebSocket URLs from JavaScript content."""

        # Pattern 1: new WebSocket("ws://...")
        ws_constructor = re.compile(
            r'new\s+WebSocket\s*\(\s*["\']?(wss?://[^\s"\'`)<>]+)',
            re.IGNORECASE
        )
        for match in ws_constructor.finditer(js_content):
            ws_url = match.group(1).rstrip("'\"`)>;,")
            self._add_endpoint(ws_url, 'js_constructor', 'HIGH',
                               f"WebSocket constructor in {source_url}")

        # Pattern 2: WebSocket URL in string concatenation
        # e.g., "ws://" + host + "/socket"
        ws_concat = re.compile(
            r'["\']wss?://["\']?\s*\+',
            re.IGNORECASE
        )
        if ws_concat.search(js_content):
            # Try to extract the path component
            path_after = re.compile(r'\+\s*["\']([/\w\-]+)["\']', re.IGNORECASE)
            for match in path_after.finditer(js_content):
                path = match.group(1)
                if path.startswith('/'):
                    constructed_url = self._to_ws_url(self.base_url + path)
                    self._add_endpoint(constructed_url, 'js_concatenation', 'MEDIUM',
                                       f"Dynamic WS URL construction in {source_url}")

        # Pattern 3: Socket.IO detection
        if 'socket.io' in js_content.lower() or 'io.connect' in js_content.lower():
            socketio_url = self._to_ws_url(self.base_url + '/socket.io/')
            self._add_endpoint(socketio_url, 'socketio_detection', 'HIGH',
                               f"Socket.IO library detected in {source_url}")

        # Pattern 4: SockJS detection
        if 'sockjs' in js_content.lower():
            sockjs_url = self._to_ws_url(self.base_url + '/sockjs/')
            self._add_endpoint(sockjs_url, 'sockjs_detection', 'HIGH',
                               f"SockJS library detected in {source_url}")

        # Pattern 5: SignalR detection
        if 'signalr' in js_content.lower() or 'hubconnection' in js_content.lower():
            signalr_url = self._to_ws_url(self.base_url + '/signalr/')
            self._add_endpoint(signalr_url, 'signalr_detection', 'HIGH',
                               f"SignalR library detected in {source_url}")

        # Pattern 6: GraphQL subscriptions
        if 'subscriptions' in js_content.lower() and 'graphql' in js_content.lower():
            gql_url = self._to_ws_url(self.base_url + '/graphql')
            self._add_endpoint(gql_url, 'graphql_subscriptions', 'MEDIUM',
                               f"GraphQL subscription endpoint detected in {source_url}")

    # ─── Helpers ────────────────────────────────────────────────────

    def _to_ws_url(self, http_url: str) -> str:
        """Convert HTTP(S) URL to WS(S) URL."""
        if http_url.startswith('https://'):
            return 'wss://' + http_url[8:]
        elif http_url.startswith('http://'):
            return 'ws://' + http_url[7:]
        return http_url

    def _add_endpoint(self, url: str, source: str, confidence: str, details: str = ''):
        """Add a discovered endpoint to results."""
        # Clean URL
        url = url.rstrip('/')

        # Check for duplicates
        for ep in self.discovered_endpoints:
            if ep['url'] == url:
                # Upgrade confidence if higher
                confidence_order = ['LOW', 'MEDIUM', 'HIGH', 'CONFIRMED']
                if confidence_order.index(confidence) > confidence_order.index(ep['confidence']):
                    ep['confidence'] = confidence
                    ep['source'] = source
                    ep['details'] = details
                return

        self.discovered_endpoints.append({
            'url': url,
            'source': source,
            'confidence': confidence,
            'details': details,
            'discovered_at': datetime.now().isoformat(),
        })

    def _deduplicate(self):
        """Remove duplicate endpoints, keeping highest confidence."""
        seen = {}
        for ep in self.discovered_endpoints:
            url = ep['url']
            if url not in seen:
                seen[url] = ep
            else:
                confidence_order = ['LOW', 'MEDIUM', 'HIGH', 'CONFIRMED']
                if confidence_order.index(ep['confidence']) > confidence_order.index(seen[url]['confidence']):
                    seen[url] = ep

        self.discovered_endpoints = list(seen.values())

        # Sort by confidence (highest first)
        confidence_order = {'CONFIRMED': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        self.discovered_endpoints.sort(key=lambda x: confidence_order.get(x['confidence'], 99))


# ─── CLI Integration ─────────────────────────────────────────────

async def discover_endpoints(target: str, **kwargs) -> List[Dict]:
    """Convenience function for endpoint discovery."""
    discovery = WSEndpointDiscovery(target, **kwargs)
    return await discovery.discover()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m wshawk.ws_discovery <target_url>")
        print("Example: python -m wshawk.ws_discovery https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    endpoints = asyncio.run(discover_endpoints(target))

    if endpoints:
        print(f"\nDiscovered {len(endpoints)} WebSocket endpoint(s)")
        for ep in endpoints:
            print(f"  {ep['url']} [{ep['confidence']}]")
