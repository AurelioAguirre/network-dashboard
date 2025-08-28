#!/usr/bin/env python3
"""
Network Traffic Dashboard - Application Launcher

This is the main entry point for running the Network Traffic Dashboard.
It imports and runs the main function from the network_dashboard module.

Usage:
    python main.py [options]
    python -m network_dashboard.main [options]  # Alternative module execution
    
Examples:
    sudo python main.py
    sudo python main.py -i eth0
    sudo python main.py -c custom_config.yaml
"""

if __name__ == "__main__":
    from src.network_dashboard.main import main
    main()