"""
Hostname Resolution Module

This module provides IP address to hostname resolution with caching capabilities.
It demonstrates advanced programming concepts including thread safety, multiple 
fallback strategies, and external command execution.

Educational Concepts:
- Caching strategies for performance optimization
- Thread safety with locks
- Multiple fallback strategies
- System command execution
- Regular expressions for text parsing
- Time-based cache expiration
"""

import socket
import subprocess
import threading
import time
import re
from typing import Dict


class HostnameResolver:
    """
    Hostname Resolution with Caching

    This class resolves IP addresses to human-readable hostnames using multiple methods.
    It demonstrates advanced programming concepts:

    Educational Concepts:
    - Caching strategies for performance optimization
    - Thread safety with locks
    - Multiple fallback strategies
    - System command execution
    - Regular expressions for text parsing
    - Time-based cache expiration
    """

    def __init__(self, config):
        """
        Initialize the hostname resolver with configuration settings.

        Args:
            config (Config): Configuration object containing resolution settings

        Educational Note:
            We use dictionaries to create in-memory caches for performance.
            Threading locks ensure thread safety when multiple threads access the cache.
        """
        self.config = config
        # Cache to store IP -> hostname mappings for faster lookups
        self.hostname_cache: Dict[str, str] = {}
        # Track when each cache entry was created for expiration
        self.cache_timestamps: Dict[str, float] = {}
        # Thread lock to prevent race conditions in multi-threaded access
        self.lock = threading.Lock()

    def get_hostname(self, ip: str) -> str:
        """
        Resolve an IP address to a hostname using multiple fallback methods.

        This method demonstrates several important programming concepts:
        - Thread synchronization with locks
        - Cache implementation with expiration
        - Multiple fallback strategies
        - External command execution
        - Regular expression parsing
        - Error handling and graceful degradation

        Args:
            ip (str): IP address to resolve

        Returns:
            str: Resolved hostname or "Unknown" if resolution fails

        Educational Flow:
        1. Check if hostname resolution is enabled in config
        2. Acquire thread lock for safe cache access
        3. Check cache validity (not expired)
        4. Try multiple resolution methods in order
        5. Cache the result for future use
        6. Return the best result found
        """
        # Early return if hostname resolution is disabled
        if not self.config.get('hostname_resolution', 'enabled', default=True):
            return ip

        # Thread synchronization: Only one thread can modify cache at a time
        with self.lock:
            current_time = time.time()
            cache_timeout = self.config.get('hostname_resolution', 'cache_timeout', default=3600)

            # Cache hit: Return cached value if it's still valid
            if ip in self.hostname_cache:
                if current_time - self.cache_timestamps.get(ip, 0) < cache_timeout:
                    return self.hostname_cache[ip]

            # Cache miss or expired: Try to resolve the hostname
            hostname = "Unknown"
            methods = self.config.get('hostname_resolution', 'methods', default={})

            # Method 1: DNS reverse lookup (most reliable)
            if methods.get('dns', True):
                try:
                    # socket.gethostbyaddr() performs reverse DNS lookup
                    hostname = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror):
                    # These exceptions occur when DNS resolution fails
                    pass

            # Method 2: NetBIOS name resolution (Windows networks)
            if hostname == "Unknown" and methods.get('nbtscan', True):
                try:
                    # Execute external nbtscan command with timeout
                    result = subprocess.run(['nbtscan', '-q', ip],
                                            capture_output=True,  # Capture stdout/stderr
                                            text=True,           # Return strings, not bytes
                                            timeout=1)           # 1-second timeout

                    if result.stdout:
                        # Parse nbtscan output using regular expressions
                        match = re.search(r'\s(\S+)\s*$', result.stdout)
                        if match:
                            hostname = match.group(1)

                except (subprocess.TimeoutExpired, FileNotFoundError):
                    # TimeoutExpired: Command took too long
                    # FileNotFoundError: nbtscan command not found
                    pass

            # Method 3: Ping-based hostname detection (last resort)
            if hostname == "Unknown" and methods.get('ping', True):
                try:
                    result = subprocess.run(['ping', '-c', '1', ip],
                                            capture_output=True,
                                            text=True,
                                            timeout=1)

                    # Extract hostname from ping command output
                    match = re.search(r'ping\s+([^\s]+)\s+\(', result.stdout)
                    if match:
                        hostname = match.group(1)

                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

            # Update cache with the resolved hostname (even if "Unknown")
            self.hostname_cache[ip] = hostname
            self.cache_timestamps[ip] = current_time
            return hostname