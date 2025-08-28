# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Running the Application
```bash
# Using the smart launcher script (recommended - handles venv automatically)
sudo -E ./run.sh

# Specify network interface
sudo -E ./run.sh -i eth0

# Use custom config file  
sudo -E ./run.sh -c custom_config.yaml

# Manual alternatives (if run.sh not available):
sudo -E myenv/bin/python main.py          # Using virtual environment
sudo -E python main.py                    # Using system Python
sudo -E python -m src.network_dashboard.main -i eth0  # Module execution
```

### Smart Launcher Features
The `run.sh` script automatically:
- Detects virtual environments (myenv, venv, .venv, etc.)
- Finds the best Python version available
- Verifies required packages (scapy, pyyaml) are installed
- Falls back to system Python if no venv found
- Provides helpful error messages and setup instructions

### Dependencies
```bash
# Install dependencies
pip install -r requirements.txt

# Or manually install core dependencies
pip install scapy==2.6.1 PyYAML==6.0.2

# System dependencies (optional but recommended)
sudo apt-get install nbtscan lsof python3-dev libpcap-dev
```

### Virtual Environment Setup
```bash
# Create and activate virtual environment
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
```

## Architecture Overview

### Modular Structure
The application has been refactored into a clean, modular architecture with separate files for each component:

```
src/network_dashboard/
├── __init__.py           # Module exports and version info
├── config.py            # Config class - YAML configuration management
├── hostname_resolver.py  # HostnameResolver class - IP-to-hostname resolution
├── packet_analyzer.py   # PacketAnalyzer class - Protocol-specific payload analysis
├── packet_dashboard.py  # PacketDashboard class - Terminal UI with curses
├── main.py             # Main application entry point and CLI handling
main.py                  # Top-level application launcher
```

### Core Classes and Structure

**Config Class (src/network_dashboard/config.py)**
- Manages YAML configuration with nested dictionary traversal
- Handles file I/O with proper error handling
- Provides safe key access with defaults

**HostnameResolver Class (src/network_dashboard/hostname_resolver.py)**
- Multi-threaded caching system for IP-to-hostname resolution
- Uses multiple fallback methods: DNS, NetBIOS (nbtscan), ping
- Thread-safe with locks and time-based cache expiration
- Executes external commands with subprocess

**PacketAnalyzer Class (src/network_dashboard/packet_analyzer.py)**
- Protocol-specific payload extraction (HTTP, HTTPS, DNS, raw)
- Handles text encoding (UTF-8) and binary data (hex)
- Configuration-driven protocol analysis
- Supports SSL keylog file integration for HTTPS decryption

**PacketDashboard Class (src/network_dashboard/packet_dashboard.py)**
- Terminal-based UI using curses library
- Real-time packet display updates with color coding
- Thread-safe UI updates with proper synchronization
- Packet capture coordination and display management

### Threading Architecture
```
Main Thread (UI)
├── Packet Capture Thread (Scapy sniffing) 
├── Hostname Resolution (Background DNS lookups)
└── Display Update Loop (Terminal rendering)
```

### Configuration System
The application uses YAML configuration with these main sections:
- `display`: UI parameters (packet limits, payload lines, refresh rate)
- `network`: Interface selection and local IP prefix definition
- `analysis.protocols`: Protocol-specific analysis settings
- `hostname_resolution`: Caching and resolution method configuration

### Key Educational Concepts Demonstrated
- Multi-threaded programming with thread safety (locks)
- Network packet analysis using Scapy
- Configuration management with YAML
- Error handling and graceful degradation
- External command execution with subprocess
- Text encoding handling (UTF-8, hex)
- Caching strategies with expiration
- Protocol-specific data parsing
- Terminal UI programming (curses)

### Module Benefits
1. **Improved Maintainability**: Each class has its own file for easier development
2. **Clear Separation of Concerns**: Configuration, analysis, UI, and main logic are isolated
3. **Better Testability**: Individual components can be tested independently
4. **Enhanced Readability**: Smaller files are easier to understand and navigate
5. **Professional Structure**: Follows Python packaging best practices

### Development Notes
- Requires root privileges for packet capture
- Uses daemon threads for automatic cleanup
- Supports SSL keylog file integration via SSLKEYLOGFILE environment variable
- Configurable protocol analysis and payload extraction
- Multi-method hostname resolution with intelligent fallbacks
- Modular architecture allows easy extension and modification of individual components