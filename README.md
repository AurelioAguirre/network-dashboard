# Network Traffic Dashboard

A real-time network monitoring tool built in Python for educational purposes. This application demonstrates advanced Python programming concepts including networking, threading, terminal interfaces, and system programming.

## 🎓 Educational Purpose

This project is designed as a teaching tool for Python students at beginner-to-intermediate levels. It showcases:

- **Network Programming**: Packet capture and analysis using Scapy
- **Threading**: Concurrent packet processing and UI updates
- **Terminal UI**: Building interactive console applications with curses
- **Configuration Management**: YAML-based settings with validation
- **System Programming**: Integration with OS-level networking tools
- **Object-Oriented Design**: Well-structured classes with clear responsibilities
- **Error Handling**: Robust exception handling and graceful degradation
- **Caching Strategies**: Performance optimization through intelligent caching
- **Documentation**: Professional code documentation practices

## 🚀 Features

### Core Functionality
- **Real-time packet monitoring** on local network interfaces
- **Hostname resolution** using multiple methods (DNS, NetBIOS, ping)
- **Protocol analysis** with support for HTTP, HTTPS, DNS, and raw packets
- **Payload extraction** showing packet contents (up to 3 lines configurable)
- **Multi-threaded architecture** for responsive UI during heavy traffic
- **Configurable filtering** by IP ranges and protocols

### Educational Features
- **Comprehensive documentation** explaining every concept
- **Clear code structure** with educational comments
- **YAML configuration** demonstrating external config management
- **Thread safety examples** showing proper lock usage
- **Error handling patterns** throughout the codebase
- **Performance optimization** techniques (caching, efficient data structures)

## 📋 Prerequisites

### System Requirements
- Linux-based operating system (Ubuntu, Debian, CentOS, etc.)
- Python 3.7 or higher
- Root/administrator privileges (required for packet capture)

### Python Dependencies
```bash
pip install scapy pyyaml
```

### System Tools (Optional but Recommended)
```bash
# Ubuntu/Debian
sudo apt-get install nbtscan lsof python3-dev libpcap-dev

# CentOS/RHEL
sudo yum install nbtscan lsof python3-devel libpcap-devel
```

## 🛠️ Installation

### 1. Clone or Download the Project
```bash
# Create project directory
mkdir network-dashboard
cd network-dashboard

# Copy the Python files (network_dashboard.py and config.yaml)
```

### 2. Set Up Python Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install scapy pyyaml
```

### 3. Install System Dependencies
```bash
sudo apt-get install nbtscan lsof python3-dev libpcap-dev
```

## 🎮 Usage

### Basic Usage
```bash
# Using the smart launcher (automatically detects virtual environment)
sudo -E ./run.sh

# Specify network interface
sudo -E ./run.sh -i eth0

# Use custom configuration file
sudo -E ./run.sh -c custom_config.yaml

# Manual execution (if launcher not available)
sudo -E myenv/bin/python main.py
```

### Command Line Options
- `-i, --interface`: Network interface to monitor (e.g., eth0, wlan0)
- `-c, --config`: Path to YAML configuration file (default: config.yaml)

### Interactive Controls
- **q**: Quit the application
- **Terminal resize**: Automatically adjusts to terminal size

### HTTPS Traffic Decryption (Advanced)
To view HTTPS payload content from your browser:

```bash
# Set up SSL key logging (before starting browser)
export SSLKEYLOGFILE=/path/to/ssl-keys.log
chrome  # or firefox

# Then run the dashboard
sudo -E /path/to/your/venv/bin/python network_dashboard.py
```

## ⚙️ Configuration

The application uses a YAML configuration file that controls all aspects of behavior:

### Sample Configuration (config.yaml)
```yaml
# Dashboard Display Settings
display:
  max_packets_per_ip: 5        # Number of recent packets to show per IP
  max_payload_lines: 3         # Lines of payload content to display
  line_length: 80             # Maximum characters per payload line
  refresh_rate: 0.1           # UI update frequency (seconds)
  screen_width: 120           # Terminal width for formatting

# Network Settings
network:
  local_ip_prefix: "192.168."  # IP range to consider "local"
  interface: null              # Default interface (null = auto-detect)

# Packet Analysis Settings
analysis:
  protocols:
    http:
      enabled: true            # Enable HTTP analysis
      ports: [80, 8080]       # Ports to consider HTTP traffic
    https:
      enabled: true
      ports: [443, 8443]
    dns:
      enabled: true            # Enable DNS query/response analysis
    raw:
      enabled: true            # Enable raw payload analysis
      show_hex: true          # Show hex dump for binary data

# Hostname Resolution Settings
hostname_resolution:
  enabled: true               # Enable hostname lookups
  cache_timeout: 3600        # Cache entries expire after 1 hour
  methods:
    dns: true                # Use DNS reverse lookups
    nbtscan: true           # Use NetBIOS name resolution
    ping: true              # Use ping-based hostname detection
```

### Configuration Sections Explained

#### Display Settings
Controls how information is presented in the terminal interface:
- `max_packets_per_ip`: Limits memory usage and screen clutter
- `max_payload_lines`: Balances detail vs. readability
- `refresh_rate`: Affects CPU usage vs. responsiveness

#### Network Settings
Defines what traffic to monitor:
- `local_ip_prefix`: Typically "192.168." for home networks, "10." for corporate
- `interface`: Leave null for auto-detection, or specify like "eth0"

#### Protocol Analysis
Enables/disables specific protocol decoders:
- HTTP: Shows request/response headers and body
- HTTPS: Indicates encrypted traffic, shows SSL key info if available
- DNS: Shows domain queries and resolved addresses
- Raw: Attempts to decode any packet with readable content

#### Hostname Resolution
Controls device name lookup behavior:
- Caching improves performance by avoiding repeated lookups
- Multiple methods provide fallbacks when one method fails
- Can be disabled entirely for privacy or performance

## 🏗️ Architecture

### Class Structure

#### 1. Config Class
**Purpose**: Manages application configuration from YAML files
**Key Concepts**:
- File I/O with context managers
- Nested dictionary traversal
- Safe key access with defaults
- YAML parsing and error handling

#### 2. HostnameResolver Class
**Purpose**: Converts IP addresses to human-readable hostnames
**Key Concepts**:
- Multi-threaded caching with locks
- Multiple fallback resolution strategies
- External command execution
- Regular expression parsing
- Time-based cache expiration

#### 3. PacketAnalyzer Class
**Purpose**: Extracts and decodes packet payload content
**Key Concepts**:
- Protocol-specific parsing (HTTP, DNS, HTTPS)
- Text encoding handling (UTF-8, hex fallback)
- Binary data processing
- Configuration-driven behavior

#### 4. PacketDashboard Class
**Purpose**: Manages the terminal UI and packet display
**Key Concepts**:
- Terminal programming with curses
- Real-time data visualization
- Thread-safe UI updates
- Dynamic screen layout

### Threading Architecture

The application uses a multi-threaded design to ensure responsive UI:

```
Main Thread (UI)
├── Packet Capture Thread (Scapy sniffing)
├── Hostname Resolution Thread (Background DNS lookups)
└── Display Update Loop (Terminal rendering)
```

**Thread Safety**: All shared data structures use locks to prevent race conditions.

### Data Flow

1. **Packet Capture**: Scapy captures raw network packets
2. **Filtering**: Only local network traffic is processed
3. **Analysis**: Protocols are identified and payloads extracted
4. **Queuing**: Processed packets are queued for display
5. **Caching**: Hostnames are resolved and cached
6. **Display**: UI thread renders packets in real-time
7. **Cleanup**: Old packets are removed to manage memory

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Problem: Packet capture requires root privileges
# Solution: Use sudo with environment preservation
sudo -E /path/to/your/venv/bin/python network_dashboard.py
```

#### Module Not Found: scapy
```bash
# Problem: Scapy not installed in current environment
# Solution: Install in the correct environment
source venv/bin/activate
pip install scapy
```

#### No Packets Appearing
```bash
# Problem: Wrong interface or no traffic
# Solution: Check available interfaces
ip link show
# Then specify the correct interface
sudo -E python network_dashboard.py -i wlan0
```

#### Hostname Resolution Failing
```bash
# Problem: Missing system tools
# Solution: Install required tools
sudo apt-get install nbtscan lsof
```

### Debug Mode
For troubleshooting, you can modify the code to add debug output:

```python
# Add this to packet_callback method for debugging
print(f"Captured packet: {packet.summary()}")
```

## 📚 Learning Exercises

### Beginner Exercises
1. **Modify Display**: Change the number of packets shown per IP
2. **Add Timestamps**: Show full timestamps instead of just time
3. **Color Customization**: Modify the curses color schemes
4. **Filter by Protocol**: Add a config option to show only HTTP traffic

### Intermediate Exercises
1. **Add New Protocols**: Implement FTP or SMTP analysis
2. **Export Feature**: Save captured packets to a CSV file
3. **Statistics Dashboard**: Add a summary view showing traffic volume
4. **Performance Monitoring**: Track and display packets per second

### Advanced Exercises
1. **Database Integration**: Store packets in SQLite for historical analysis
2. **Web Interface**: Create a Flask web app displaying the same data
3. **Alerting System**: Send notifications for suspicious traffic patterns
4. **Distributed Monitoring**: Network multiple instances together

## 🔐 Security Considerations

### Privacy and Legal
- **Only monitor networks you own or have permission to monitor**
- **Be aware of local laws regarding network monitoring**
- **Consider privacy implications when logging traffic**
- **Secure any log files containing network data**

### Technical Security
- **Run with minimal necessary privileges**
- **Validate all configuration input**
- **Handle untrusted network data safely**
- **Keep dependencies updated**

## 🤝 Contributing

This project is designed for educational use. Students and instructors are encouraged to:

1. **Fork the project** for classroom use
2. **Submit improvements** to documentation or code clarity
3. **Add new protocol analyzers** for additional learning opportunities
4. **Create exercises** based on the codebase
5. **Report bugs** or unclear documentation

### Code Style Guidelines
- Follow PEP 8 Python style guidelines
- Add docstrings to all classes and methods
- Include educational comments explaining complex concepts
- Use type hints where helpful for learning
- Maintain thread safety in all shared data access

## 📖 Additional Resources

### Python Concepts Demonstrated
- **Object-Oriented Programming**: Classes, inheritance, encapsulation
- **Threading**: Race conditions, locks, thread-safe programming
- **Networking**: Sockets, protocols, packet analysis
- **File I/O**: Reading configuration, handling errors
- **Regular Expressions**: Text parsing and extraction
- **Exception Handling**: Graceful error recovery
- **Command Line Tools**: Argument parsing, user interfaces

### Recommended Reading
- [Python Threading Documentation](https://docs.python.org/3/library/threading.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Network Programming in Python](https://docs.python.org/3/howto/sockets.html)
- [YAML Format Specification](https://yaml.org/spec/)

### Related Projects
- **Wireshark**: Professional network protocol analyzer
- **tcpdump**: Command-line packet analyzer
- **netstat**: Network connection monitoring
- **iftop**: Bandwidth usage monitoring

## 📄 License

This educational project is released under the MIT License, making it free to use, modify, and distribute for educational purposes.

---

**Happy Learning!** 🐍📡

This project demonstrates real-world Python programming techniques while providing practical network monitoring capabilities. Use it to explore networking concepts, practice threading, and understand how professional network tools are built.