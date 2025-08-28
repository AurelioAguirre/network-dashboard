"""
Network Dashboard Module

A real-time network monitoring tool built in Python for educational purposes.
This application demonstrates advanced Python programming concepts including
networking, threading, terminal interfaces, and system programming.

This module provides a clean, modular architecture with separate components
for configuration management, packet analysis, hostname resolution, and
terminal-based user interfaces.

Classes:
    Config: YAML configuration management
    HostnameResolver: IP-to-hostname resolution with caching
    PacketAnalyzer: Network packet payload analysis
    PacketDashboard: Terminal-based user interface

Educational Concepts Demonstrated:
- Network Programming: Packet capture and analysis using Scapy
- Threading: Concurrent packet processing and UI updates
- Terminal UI: Building interactive console applications with curses
- Configuration Management: YAML-based settings with validation
- System Programming: Integration with OS-level networking tools
- Object-Oriented Design: Well-structured classes with clear responsibilities
- Error Handling: Robust exception handling and graceful degradation
- Caching Strategies: Performance optimization through intelligent caching
"""

from .config import Config
from .hostname_resolver import HostnameResolver
from .packet_analyzer import PacketAnalyzer
from .packet_dashboard import PacketDashboard
from .main import main, start_dashboard, create_default_config

__version__ = "1.0.0"
__author__ = "Educational Project"
__email__ = "example@education.com"

__all__ = [
    'Config',
    'HostnameResolver', 
    'PacketAnalyzer',
    'PacketDashboard',
    'main',
    'start_dashboard',
    'create_default_config',
]