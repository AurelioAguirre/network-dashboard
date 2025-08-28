"""
Packet Analysis Module

This module analyzes network packets to extract meaningful information from their payloads.
It demonstrates protocol-specific parsing, binary data handling, and configuration-driven behavior.

Educational Concepts:
- Protocol-specific parsing (HTTP, DNS, HTTPS)
- Binary data handling and text encoding
- Configuration-driven behavior
- Error handling and graceful degradation
- String manipulation and formatting
- Environment variable usage
"""

import os
import textwrap
import binascii
from scapy.all import TCP, UDP, DNS, DNSQR, Raw


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