"""
Packet Dashboard Module

This module provides the terminal-based user interface for the network traffic dashboard.
It demonstrates advanced terminal programming with curses, multi-threaded UI programming,
and real-time data visualization.

Educational Concepts:
- Terminal programming with the curses library
- Multi-threaded UI programming
- Real-time data visualization
- Thread-safe data sharing between capture and display threads
- Event-driven programming (keyboard input)
- Memory management (limiting stored packets)
- Color-coded terminal output
"""

import curses
import threading
import time
from collections import defaultdict
from queue import Queue
from datetime import datetime
from scapy.all import IP, TCP, UDP, sniff

from .hostname_resolver import HostnameResolver
from .packet_analyzer import PacketAnalyzer


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

    def start_capture(self, interface=None):
        """
        Start packet capture in a separate thread.

        Args:
            interface (str, optional): Network interface to monitor

        Educational Concepts:
        - Thread creation and management
        - Lambda functions for simple anonymous functions
        - Daemon threads for automatic cleanup
        """
        # Create and start packet capture thread
        # Lambda function creates a simple anonymous function
        capture_thread = threading.Thread(target=lambda: sniff(
            iface=interface,                    # Network interface to monitor
            prn=self.packet_callback,          # Callback for each packet
            store=0                             # Don't store packets in memory
        ))

        # Daemon threads automatically terminate when main program exits
        capture_thread.daemon = True
        capture_thread.start()
        
        return capture_thread