#!/usr/bin/env python3
"""
Network Traffic Dashboard - Main Application Entry Point

This is the main entry point for the Network Traffic Dashboard application.
It handles command-line argument processing, configuration management, and 
application startup with proper error handling.

Educational Concepts:
- Command-line interface design with argparse
- Configuration file management and default creation
- Application initialization and orchestration
- Error handling patterns for system-level issues
- Multi-threaded application startup
"""

import argparse
import os
import sys
import curses
import yaml

from .config import Config
from .packet_dashboard import PacketDashboard


def create_default_config(config_path):
    """
    Create a default configuration file with comprehensive settings.
    
    Args:
        config_path (str): Path where the configuration file should be created
        
    Educational Concepts:
    - YAML file creation and structure
    - Nested dictionary construction
    - Default value specification
    - File I/O operations
    """
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
    with open(config_path, 'w') as f:
        yaml.dump(default_config, f, default_flow_style=False, indent=2)

    print(f"Default configuration created at: {config_path}")
    print("You can edit this file to customize the dashboard behavior.")


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

        # Start packet capture in background thread
        interface_to_use = config.get('network', 'interface')
        dashboard.start_capture(interface_to_use)

        # Start the main display loop (runs in main thread)
        dashboard.update_display()

    # curses.wrapper handles terminal setup/teardown automatically
    curses.wrapper(main)


def main():
    """
    Main program entry point with command-line argument processing.

    This function demonstrates:
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
        epilog='Example: sudo -E python -m network_dashboard.main -i eth0 -c custom_config.yaml'
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
        create_default_config(args.config)

    # Start the main application with error handling
    try:
        start_dashboard(args.interface, args.config)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\nShutting down gracefully...")
    except PermissionError:
        # Handle common permission issues
        print("\nError: This application requires root privileges for packet capture.")
        print("Please run with sudo: sudo -E python -m network_dashboard.main")
    except Exception as e:
        # Handle any other unexpected errors
        print(f"\nUnexpected error occurred: {str(e)}")
        print("Please check your configuration and try again.")


if __name__ == "__main__":
    main()