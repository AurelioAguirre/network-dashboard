#!/bin/bash
#
# Network Dashboard Launcher Script
#
# This script intelligently detects Python virtual environments and runs
# the network dashboard with the appropriate Python interpreter.
#
# Usage:
#   sudo -E ./run.sh [arguments...]
#   sudo -E ./run.sh -i eth0
#   sudo -E ./run.sh -c custom_config.yaml
#
# The script will:
# 1. Look for virtual environments in common locations
# 2. Use the latest Python version available in the venv
# 3. Fall back to system Python if no venv is found
# 4. Pass all arguments to the application
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_info "Network Dashboard Launcher"
print_info "Script directory: $SCRIPT_DIR"

# Check if main.py exists
if [[ ! -f "main.py" ]]; then
    print_error "main.py not found in $SCRIPT_DIR"
    print_error "Make sure you're running this script from the project root directory"
    exit 1
fi

# Function to find the best Python executable in a directory
find_best_python() {
    local bin_dir="$1"
    local python_exec=""
    
    # Look for Python executables in order of preference
    for py_name in python3.13 python3.12 python3.11 python3.10 python3.9 python3 python; do
        if [[ -x "$bin_dir/$py_name" ]]; then
            python_exec="$bin_dir/$py_name"
            break
        fi
    done
    
    echo "$python_exec"
}

# Function to verify Python and required packages
verify_python() {
    local python_path="$1"
    local env_name="$2"
    
    print_info "Verifying Python interpreter: $python_path"
    
    # Check if Python executable exists and is executable
    if [[ ! -x "$python_path" ]]; then
        print_error "Python executable not found or not executable: $python_path"
        return 1
    fi
    
    # Check Python version
    local python_version
    python_version=$("$python_path" --version 2>&1)
    print_info "Python version: $python_version"
    
    # Check for required packages
    print_info "Checking required packages..."
    
    if ! "$python_path" -c "import scapy" 2>/dev/null; then
        print_error "Scapy not found in $env_name"
        print_error "Install with: $python_path -m pip install scapy"
        return 1
    fi
    
    if ! "$python_path" -c "import yaml" 2>/dev/null; then
        print_error "PyYAML not found in $env_name"
        print_error "Install with: $python_path -m pip install pyyaml"
        return 1
    fi
    
    print_success "All required packages found in $env_name"
    return 0
}

# Look for virtual environments in common locations
PYTHON_EXEC=""
ENV_FOUND=""

# Common virtual environment directory names
VENV_DIRS=("myenv" "venv" ".venv" ".myenv" "env" ".env")

print_info "Searching for virtual environments..."

for venv_dir in "${VENV_DIRS[@]}"; do
    if [[ -d "$venv_dir" ]]; then
        bin_dir="$venv_dir/bin"
        if [[ -d "$bin_dir" ]]; then
            python_candidate=$(find_best_python "$bin_dir")
            if [[ -n "$python_candidate" ]]; then
                print_info "Found virtual environment: $venv_dir"
                if verify_python "$python_candidate" "$venv_dir"; then
                    PYTHON_EXEC="$python_candidate"
                    ENV_FOUND="$venv_dir"
                    break
                else
                    print_warning "Virtual environment $venv_dir has missing dependencies, continuing search..."
                fi
            fi
        fi
    fi
done

# If no suitable virtual environment found, try system Python
if [[ -z "$PYTHON_EXEC" ]]; then
    print_warning "No suitable virtual environment found, trying system Python"
    
    # Try to find system Python
    system_python=$(find_best_python "/usr/bin")
    if [[ -z "$system_python" ]]; then
        # Fallback to PATH lookup
        if command -v python3 >/dev/null 2>&1; then
            system_python="python3"
        elif command -v python >/dev/null 2>&1; then
            system_python="python"
        fi
    fi
    
    if [[ -n "$system_python" ]] && verify_python "$system_python" "system"; then
        PYTHON_EXEC="$system_python"
        ENV_FOUND="system"
    else
        print_error "No suitable Python interpreter found with required packages"
        print_error ""
        print_error "Please ensure you have either:"
        print_error "1. A virtual environment (venv, myenv, etc.) with scapy and pyyaml installed, or"
        print_error "2. System Python with scapy and pyyaml installed"
        print_error ""
        print_error "To create a virtual environment:"
        print_error "  python3 -m venv myenv"
        print_error "  source myenv/bin/activate"
        print_error "  pip install -r requirements.txt"
        exit 1
    fi
fi

# Check if we're running with appropriate privileges
if [[ $EUID -ne 0 ]]; then
    print_error "This application requires root privileges for packet capture"
    print_error "Please run with: sudo -E ./run.sh"
    exit 1
fi

# Show what we're about to run
print_success "Using Python: $PYTHON_EXEC ($ENV_FOUND)"
print_info "Starting Network Dashboard..."
print_info "Arguments: $*"
print_info ""

# Preserve environment and run the application
exec "$PYTHON_EXEC" main.py "$@"