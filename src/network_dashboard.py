#!/usr/bin/env python3
"""
Network Traffic Dashboard - A Real-time Network Monitoring Tool

This application captures and displays network traffic in a terminal-based dashboard,
showing packet information, hostnames, and payload content for educational purposes.

Author: Educational Project
Purpose: Teaching Python networking, threading, and system programming concepts

Dependencies:
    - scapy: Packet capture and analysis
    - yaml: Configuration file parsing
    - curses: Terminal UI
    - Standard library modules for networking and system operations
"""

# Import required modules with comments explaining their purpose
from scapy.all import *        # Packet capture and network protocol analysis
import curses                  # Terminal-based user interface
from collections import defaultdict  # Dictionary with default values
import threading              # Multi-threaded programming for concurrent operations
from datetime import datetime # Timestamp formatting
from queue import Queue       # Thread-safe data exchange between threads
import time                   # Sleep and timing functions
import argparse              # Command-line argument parsing
import socket                # Network hostname resolution
import subprocess           # External command execution
from typing import Dict     # Type hints for better code documentation
import re                  # Regular expressions for text parsing
import binascii           # Binary/ASCII data conversion
import os                # Operating system interface
import textwrap         # Text wrapping utilities
import yaml            # YAML configuration file parsing
from pathlib import Path  # Modern path handling


class Config:
    """
    Configuration Management Class

    This class handles loading and accessing configuration settings from a YAML file.
    It demonstrates:
    - File I/O operations with YAML
    - Error handling for missing files/keys
    - Nested dictionary access with safe fallbacks

    Educational Concepts:
    - Class design and encapsulation
    - File handling and parsing
    - Exception handling patterns
    """

    def __init__(self, config_path="config.yaml"):
        """
        Initialize the configuration manager.

        Args:
            config_path (str): Path to the YAML configuration file

        Educational Note:
            The __init__ method is called when creating a new instance of the class.
            It sets up the initial state of the object.
        """
        self.config_path = config_path
        self.reload()  # Load configuration immediately upon creation

    def reload(self):
        """
        Load or reload configuration from the YAML file.

        Educational Concepts:
        - File reading with context managers (with statement)
        - YAML parsing
        - Error handling for file operations

        Raises:
            FileNotFoundError: If the config file doesn't exist
            yaml.YAMLError: If the YAML syntax is invalid
        """
        with open(self.config_path, 'r') as f:
            # The 'with' statement ensures the file is properly closed
            # even if an error occurs during reading
            self.config = yaml.safe_load(f)

    def get(self, *keys, default=None):
        """
        Safely retrieve nested configuration values with fallback defaults.

        This method demonstrates advanced Python concepts:
        - *args parameter (variable number of arguments)
        - Nested dictionary traversal
        - Exception handling for missing keys
        - Default value patterns

        Args:
            *keys: Variable number of keys for nested dictionary access
            default: Value to return if the key path doesn't exist

        Returns:
            The configuration value or the default if not found

        Example:
            config.get('display', 'max_packets_per_ip', default=5)
            This would access config['display']['max_packets_per_ip']
        """
        value = self.config
        for key in keys:
            try:
                value = value[key]
            except (KeyError, TypeError):
                # KeyError: Key doesn't exist in dictionary
                # TypeError: Trying to access key on non-dict value
                return default
        return value


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

class PacketAnalyzer:
    """
    Packet Payload Analysis and Protocol Detection

    This class analyzes network packets to extract meaningful information from their payloads.
    It demonstrates several important programming concepts:

    Educational Concepts:
    - Protocol-specific parsing (HTTP, DNS, HTTPS)
    - Binary data handling and text encoding
    - Configuration-driven behavior
    - Error handling and graceful degradation
    - String manipulation and formatting
    - Environment variable usage
    """

    def __init__(self, config):
        """
        Initialize the packet analyzer with configuration settings.

        Args:
            config (Config): Configuration object containing analysis settings

        Educational Note:
            We check for SSL keylog files to potentially decrypt HTTPS traffic.
            Environment variables are accessed using os.getenv().
        """
        self.config = config
        # Check if SSL keylog file is available for HTTPS decryption
        self.keylog_file = os.getenv('SSLKEYLOGFILE')
        if self.keylog_file:
            print(f"Using SSL keylog file: {self.keylog_file}")

    def extract_payload(self, packet):
        """
        Extract and decode packet payload based on protocol and configuration.

        This method demonstrates advanced data processing concepts:
        - Protocol detection and specific handling
        - Text encoding and decoding (UTF-8, hex)
        - Binary data processing
        - Error handling for malformed data
        - Configuration-driven behavior
        - Text wrapping and formatting

        Args:
            packet: Scapy packet object containing network data

        Returns:
            tuple: (protocol_name, list_of_payload_lines)

        Educational Flow:
        1. Get display parameters from configuration
        2. Detect packet protocol (HTTP, HTTPS, DNS, etc.)
        3. Extract payload using protocol-specific methods
        4. Handle text encoding and formatting
        5. Apply line limits and formatting
        6. Return structured data for display
        """
        # Get configuration parameters for display formatting
        max_lines = self.config.get('display', 'max_payload_lines', default=3)
        line_length = self.config.get('display', 'line_length', default=80)
        protocols = self.config.get('analysis', 'protocols', default={})

        payload_lines = []
        protocol = "Unknown"

        try:
            # HTTP Traffic Analysis (Unencrypted web traffic)
            if (protocols.get('http', {}).get('enabled', True) and
                    TCP in packet and
                    (packet[TCP].dport in protocols.get('http', {}).get('ports', [80]) or
                     packet[TCP].sport in protocols.get('http', {}).get('ports', [80]))):

                protocol = "HTTP"
                if Raw in packet:  # Check if packet has payload data
                    raw_payload = packet[Raw].load
                    try:
                        # Decode binary data to text
                        decoded = raw_payload.decode('utf-8', errors='ignore')

                        # HTTP messages have headers and body separated by double CRLF
                        parts = decoded.split('\r\n\r\n', 1)
                        headers = parts[0].split('\r\n')

                        # Add HTTP headers to display (most important part)
                        payload_lines.extend(headers[:max_lines])

                        # Add HTTP body if present and we have space
                        if len(parts) > 1 and len(payload_lines) < max_lines:
                            remaining_lines = max_lines - len(payload_lines)
                            body_lines = parts[1].split('\n')
                            payload_lines.extend(body_lines[:remaining_lines])

                    except UnicodeDecodeError:
                        # Fallback to hex representation for binary HTTP data
                        payload_lines.append(raw_payload.hex())

            # DNS Traffic Analysis (Domain name lookups)
            elif protocols.get('dns', {}).get('enabled', True) and DNS in packet:
                protocol = "DNS"

                # DNS packets can be queries (qr=0) or responses (qr=1)
                if packet.qr == 0:  # DNS query
                    # Show what domain is being looked up
                    query_name = packet[DNSQR].qname.decode()
                    payload_lines.append(f"Query: {query_name}")
                else:  # DNS response
                    # Show the resolved addresses
                    if packet.an:  # If there are answers
                        for i, answer in enumerate(packet.an):
                            if i >= max_lines:
                                break
                            payload_lines.append(f"Answer {i+1}: {answer.rdata}")

            # HTTPS/TLS Traffic Analysis (Encrypted web traffic)
            elif (protocols.get('https', {}).get('enabled', True) and
                  TCP in packet and
                  (packet[TCP].dport in protocols.get('https', {}).get('ports', [443]) or
                   packet[TCP].sport in protocols.get('https', {}).get('ports', [443]))):

                protocol = "HTTPS"
                if Raw in packet:
                    # HTTPS traffic is encrypted, so we can't read the content
                    payload_lines.append("(Encrypted TLS traffic)")

                    # If SSL keylog file is available, mention decryption possibility
                    if self.keylog_file:
                        payload_lines.append(f"SSL keys available in: {self.keylog_file}")
                        payload_lines.append("Use Wireshark with SSLKEYLOGFILE to decrypt")

            # Raw Payload Analysis (Any other traffic with data)
            elif protocols.get('raw', {}).get('enabled', True) and Raw in packet:
                raw_data = packet[Raw].load

                try:
                    # Attempt UTF-8 decoding for text-based protocols
                    decoded = raw_data.decode('utf-8', errors='ignore')

                    # Process each line, keeping only printable characters
                    clean_lines = []
                    for line in decoded.split('\n'):
                        # Filter out non-printable characters (control chars, etc.)
                        clean_line = ''.join(char for char in line if char.isprintable())
                        if clean_line:  # Only keep non-empty lines
                            # Wrap long lines to fit display width
                            wrapped_lines = textwrap.wrap(clean_line, width=line_length)
                            clean_lines.extend(wrapped_lines)

                    payload_lines.extend(clean_lines[:max_lines])

                except UnicodeDecodeError:
                    # Fallback to hexadecimal representation for binary data
                    if protocols.get('raw', {}).get('show_hex', True):
                        hex_data = raw_data.hex()
                        # Wrap hex data into readable chunks
                        hex_lines = textwrap.wrap(hex_data, width=line_length)
                        payload_lines.extend(hex_lines[:max_lines])

            # Truncate if we have too many lines and add continuation indicator
            if len(payload_lines) > max_lines:
                payload_lines = payload_lines[:max_lines]
                payload_lines[-1] += " ..."

        except Exception as e:
            # Catch-all error handler for any unexpected issues
            payload_lines.append(f"(Decode error: {str(e)})")

        # Ensure no line exceeds the configured maximum length
        payload_lines = [line[:line_length] for line in payload_lines]

        return protocol, payload_lines


class PacketDashboard:
    """
    Terminal-Based Network Traffic Dashboard

    This is the main UI class that manages the terminal interface and coordinates
    all other components. It demonstrates advanced Python concepts:

    Educational Concepts:
    - Terminal programming with the curses library
    - Multi-threaded UI programming
    - Real-time data visualization
    - Thread-safe data sharing between capture and display threads
    - Event-driven programming (keyboard input)
    - Memory management (limiting stored packets)
    - Color-coded terminal output
    """

    def __init__(self, screen, config):
        """
        Initialize the dashboard with terminal screen and configuration.

        Args:
            screen: Curses screen object for terminal manipulation
            config (Config): Configuration object with display settings

        Educational Concepts:
        - Object composition (dashboard contains resolver, analyzer)
        - Terminal initialization and color setup
        - Data structure initialization (defaultdict, Queue)
        - Thread synchronization setup (locks)
        """
        self.screen = screen
        self.config = config

        # Get display configuration
        self.max_packets_per_ip = config.get('display', 'max_packets_per_ip', default=5)

        # Data structures for packet storage and processing
        # defaultdict creates missing keys automatically with empty lists
        self.ip_packets = defaultdict(list)

        # Thread-safe queue for communication between capture and display threads
        self.packet_queue = Queue()

        # Thread lock for safe access to shared data structures
        self.lock = threading.Lock()

        # Initialize component objects
        self.hostname_resolver = HostnameResolver(config)
        self.packet_analyzer = PacketAnalyzer(config)

        # Configure terminal colors and behavior
        curses.start_color()
        # Define color pairs: (pair_number, foreground, background)
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)    # IP headers
        curses.init_pair(2, curses.COLOR_CYAN, curses.COLOR_BLACK)     # Packet info
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)   # Separators
        curses.init_pair(4, curses.COLOR_MAGENTA, curses.COLOR_BLACK)  # Payload data

        # Enable non-blocking keyboard input
        self.screen.nodelay(1)

    def packet_callback(self, packet):
        """
        Process each captured network packet (called by Scapy in capture thread).

        This method runs in the packet capture thread and must be thread-safe.
        It demonstrates:
        - Network packet inspection
        - Protocol detection
        - Data extraction and transformation
        - Thread-safe data queuing

        Args:
            packet: Scapy packet object containing network data

        Educational Note:
            This method is called by Scapy's sniff() function for every captured packet.
            We need to be fast here to avoid dropping packets during high traffic.
        """
        # Only process IP packets (ignore ARP, etc.)
        if IP in packet:
            src_ip = packet[IP].src    # Source IP address
            dst_ip = packet[IP].dst    # Destination IP address

            # Filter for local network traffic based on configuration
            local_prefix = self.config.get('network', 'local_ip_prefix', default="192.168.")
            if src_ip.startswith(local_prefix) or dst_ip.startswith(local_prefix):

                # Create timestamp for this packet
                timestamp = datetime.now().strftime('%H:%M:%S')

                # Analyze packet payload and determine protocol
                protocol, payload_lines = self.packet_analyzer.extract_payload(packet)

                # Extract port information if available
                src_port = dst_port = None
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport

                # Create packet information dictionary for display
                packet_info = {
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'size': len(packet),
                    'payload_lines': payload_lines
                }

                # Queue packet for display thread (thread-safe operation)
                self.packet_queue.put(packet_info)

    def update_display(self):
        """
        Main display loop that updates the terminal interface.

        This method runs in the main thread and handles:
        - Processing queued packets from capture thread
        - Updating data structures with thread safety
        - Rendering the terminal interface
        - Handling user input (quit command)
        - Managing memory by limiting stored packets

        Educational Concepts:
        - Infinite loop for real-time updates
        - Thread-safe queue processing
        - Terminal rendering with curses
        - Memory management strategies
        - User input handling
        - Exception handling for terminal operations
        """
        # Get display configuration parameters
        screen_width = self.config.get('display', 'screen_width', default=120)
        refresh_rate = self.config.get('display', 'refresh_rate', default=0.1)

        while True:  # Main display loop
            try:
                # Process all pending packets from the capture thread
                while not self.packet_queue.empty():
                    packet_info = self.packet_queue.get_nowait()

                    # Thread-safe update of packet storage
                    with self.lock:
                        local_prefix = self.config.get('network', 'local_ip_prefix', default="192.168.")

                        # Store packet for source IP if it's local
                        if packet_info['src_ip'].startswith(local_prefix):
                            self.ip_packets[packet_info['src_ip']].append(packet_info)
                            # Limit memory usage by keeping only recent packets
                            if len(self.ip_packets[packet_info['src_ip']]) > self.max_packets_per_ip:
                                self.ip_packets[packet_info['src_ip']].pop(0)  # Remove oldest

                        # Store packet for destination IP if it's local
                        if packet_info['dst_ip'].startswith(local_prefix):
                            self.ip_packets[packet_info['dst_ip']].append(packet_info)
                            if len(self.ip_packets[packet_info['dst_ip']]) > self.max_packets_per_ip:
                                self.ip_packets[packet_info['dst_ip']].pop(0)

                # Clear screen and redraw everything
                self.screen.clear()

                # Draw header section
                self.screen.addstr(0, 0, "Network Traffic Dashboard (with Extended Payload)", curses.A_BOLD)
                self.screen.addstr(1, 0, f"Monitoring {len(self.ip_packets)} local IPs - Press 'q' to quit")
                self.screen.addstr(2, 0, "=" * screen_width)

                # Draw packet data for each IP address
                row = 3  # Start after header
                for ip, packets in sorted(self.ip_packets.items()):
                    # Check if we have room on screen
                    if row >= curses.LINES - 2:
                        break

                    # Resolve and display IP address with hostname
                    hostname = self.hostname_resolver.get_hostname(ip)
                    ip_header = f"IP: {ip} ({hostname})"
                    self.screen.addstr(row, 0, ip_header, curses.color_pair(1))
                    row += 1

                    # Display recent packets for this IP
                    for packet in packets[-self.max_packets_per_ip:]:
                        if row >= curses.LINES - 2:
                            break

                        # Determine traffic direction relative to this IP
                        direction = "→" if packet['src_ip'] == ip else "←"
                        other_ip = packet['dst_ip'] if packet['src_ip'] == ip else packet['src_ip']
                        other_hostname = self.hostname_resolver.get_hostname(other_ip)

                        # Format port information if available
                        ports = f":{packet['src_port']}->{packet['dst_port']}" if packet['src_port'] and packet['dst_port'] else ""

                        # Display connection information
                        packet_str = (f"  {packet['timestamp']} {direction} {other_ip} ({other_hostname}){ports} "
                                      f"[{packet['protocol']}] {packet['size']} bytes")
                        self.screen.addstr(row, 0, packet_str[:screen_width-1], curses.color_pair(2))
                        row += 1

                        # Display packet payload (multi-line, indented)
                        for i, payload_line in enumerate(packet['payload_lines']):
                            if row >= curses.LINES - 2:
                                break
                            # Use different prefix for first line vs. continuation lines
                            prefix = "    └─ " if i == 0 else "       "
                            payload_str = f"{prefix}{payload_line}"
                            self.screen.addstr(row, 0, payload_str[:screen_width-1], curses.color_pair(4))
                            row += 1

                    # Draw separator line between IP addresses
                    self.screen.addstr(row, 0, "-" * screen_width, curses.color_pair(3))
                    row += 1

                # Refresh screen to show updates
                self.screen.refresh()

                # Check for user input (non-blocking)
                c = self.screen.getch()
                if c == ord('q'):  # Quit if 'q' is pressed
                    return

            except curses.error:
                # Handle terminal-related errors (e.g., window too small)
                pass

            # Sleep briefly to control refresh rate and reduce CPU usage
            time.sleep(refresh_rate)


def start_dashboard(interface=None, config_path="config.yaml"):
    """
    Initialize and start the network traffic dashboard.

    This function demonstrates:
    - Configuration management and file handling
    - Multi-threaded application startup
    - Error handling for missing files
    - Integration of all application components

    Args:
        interface (str, optional): Network interface to monitor
        config_path (str): Path to YAML configuration file

    Educational Concepts:
    - Function composition and orchestration
    - Configuration override patterns
    - Thread management and daemon threads
    - Curses application wrapper
    """
    # Load configuration from YAML file
    config = Config(config_path)

    # Command line interface can override configuration file settings
    if interface:
        config.config['network']['interface'] = interface

    def main(stdscr):
        """
        Main curses application function.

        This nested function demonstrates:
        - Curses application structure
        - Multi-threaded application design
        - Clean separation of UI and business logic

        Args:
            stdscr: Curses standard screen object (provided by curses.wrapper)

        Educational Note:
            The curses.wrapper() function handles terminal initialization/cleanup
            and ensures the terminal is restored even if the program crashes.
        """
        # Create the main dashboard object
        dashboard = PacketDashboard(stdscr, config)

        # Create and start packet capture thread
        # Lambda function creates a simple anonymous function
        capture_thread = threading.Thread(target=lambda: sniff(
            iface=config.get('network', 'interface'),  # Network interface to monitor
            prn=dashboard.packet_callback,             # Callback for each packet
            store=0                                    # Don't store packets in memory
        ))

        # Daemon threads automatically terminate when main program exits
        capture_thread.daemon = True
        capture_thread.start()

        # Start the main display loop (runs in main thread)
        dashboard.update_display()

    # curses.wrapper handles terminal setup/teardown automatically
    curses.wrapper(main)


if __name__ == "__main__":
    """
    Main program entry point with command-line argument processing.
    
    This section demonstrates:
    - Command-line interface design with argparse
    - File existence checking and error handling
    - Default configuration creation
    - Program initialization and error handling
    
    Educational Concepts:
    - Script vs. module execution (__name__ == "__main__")
    - Command-line argument parsing
    - File system operations
    - YAML file creation and manipulation
    - Exception handling patterns
    """

    # Set up command-line argument parser
    parser = argparse.ArgumentParser(
        description='Network Traffic Dashboard - Educational Network Monitoring Tool',
        epilog='Example: sudo -E python network_dashboard.py -i eth0 -c custom_config.yaml'
    )

    # Define command-line arguments
    parser.add_argument('-i', '--interface',
                        help='Network interface to monitor (e.g., eth0, wlan0)')
    parser.add_argument('-c', '--config',
                        help='Path to YAML configuration file',
                        default='config.yaml')

    # Parse command-line arguments
    args = parser.parse_args()

    # Check if configuration file exists, create default if missing
    if not os.path.exists(args.config):
        print(f"Config file not found: {args.config}")
        print("Creating default configuration file...")

        # Define default configuration structure
        # This demonstrates nested dictionary creation and YAML structure
        default_config = {
            'display': {
                'max_packets_per_ip': 5,      # Limit packets shown per IP
                'max_payload_lines': 3,       # Lines of payload to display
                'line_length': 80,            # Character limit per line
                'refresh_rate': 0.1,          # UI update frequency (seconds)
                'screen_width': 120           # Terminal formatting width
            },
            'network': {
                'local_ip_prefix': "192.168.",  # Define "local" network range
                'interface': None               # Auto-detect interface
            },
            'analysis': {
                'protocols': {
                    # HTTP traffic analysis settings
                    'http': {
                        'enabled': True,
                        'ports': [80, 8080]
                    },
                    # HTTPS traffic analysis settings
                    'https': {
                        'enabled': True,
                        'ports': [443, 8443]
                    },
                    # DNS query/response analysis
                    'dns': {
                        'enabled': True
                    },
                    # Raw payload analysis for other protocols
                    'raw': {
                        'enabled': True,
                        'show_hex': True      # Show hex dump for binary data
                    }
                }
            },
            'hostname_resolution': {
                'enabled': True,              # Enable IP -> hostname lookups
                'cache_timeout': 3600,        # Cache entries for 1 hour
                'methods': {
                    'dns': True,              # Use DNS reverse lookups
                    'nbtscan': True,         # Use NetBIOS name resolution
                    'ping': True             # Use ping-based detection
                }
            }
        }

        # Write default configuration to file
        # default_flow_style=False creates readable multi-line YAML
        with open(args.config, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False, indent=2)

        print(f"Default configuration created at: {args.config}")
        print("You can edit this file to customize the dashboard behavior.")

    # Start the main application with error handling
    try:
        start_dashboard(args.interface, args.config)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\nShutting down gracefully...")
    except PermissionError:
        # Handle common permission issues
        print("\nError: This application requires root privileges for packet capture.")
        print("Please run with sudo: sudo -E python network_dashboard.py")
    except Exception as e:
        # Handle any other unexpected errors
        print(f"\nUnexpected error occurred: {str(e)}")
        print("Please check your configuration and try again.")