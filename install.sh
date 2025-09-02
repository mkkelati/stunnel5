#!/bin/bash

#################################################################
# SSH-Stunnel Manager - One-Line Installer
# 
# Automatically downloads, installs dependencies, and sets up
# the SSH-Stunnel Manager with all required packages
#
# Usage: curl -fsSL https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh | sudo bash
#################################################################

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_URL="https://raw.githubusercontent.com/mkkelati/stunnel5/main/ssh-stunnel-manager.sh"
readonly SCRIPT_NAME="ssh-stunnel-manager.sh"
readonly INSTALL_DIR="/usr/local/bin"
readonly LOG_FILE="/var/log/ssh-stunnel-install.log"

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE" >/dev/null 2>&1 || true
    
    case "$level" in
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message"
            ;;
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This installer must be run as root. Please use 'sudo' or run as root user."
        exit 1
    fi
}

# Detect Linux distribution and version
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# Get Ubuntu version
get_ubuntu_version() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$VERSION_ID"
    else
        echo "unknown"
    fi
}

# Check if Ubuntu version is supported (20.04 to 24.04)
check_ubuntu_support() {
    local distro=$(detect_distro)
    if [[ "$distro" == "ubuntu" ]]; then
        local version=$(get_ubuntu_version)
        case "$version" in
            "20.04"|"22.04"|"24.04"|"20.10"|"21.04"|"21.10"|"23.04"|"23.10")
                log "INFO" "Ubuntu $version detected - supported version"
                return 0
                ;;
            *)
                log "WARNING" "Ubuntu $version detected - may work but not officially tested"
                log "INFO" "Officially supported: Ubuntu 20.04, 22.04, 24.04"
                return 0
                ;;
        esac
    fi
    return 0
}

# Update system packages
update_system() {
    local distro=$(detect_distro)
    
    log "INFO" "Updating system packages for distribution: $distro"
    
    case "$distro" in
        "ubuntu"|"debian")
            log "INFO" "Updating package lists..."
            apt-get update -qq || {
                log "ERROR" "Failed to update package lists"
                exit 1
            }
            
            log "INFO" "Upgrading existing packages..."
            DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || {
                log "WARNING" "Some packages failed to upgrade, continuing..."
            }
            
            log "INFO" "Installing essential packages..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                curl \
                wget \
                ca-certificates \
                gnupg \
                lsb-release \
                software-properties-common || {
                log "ERROR" "Failed to install essential packages"
                exit 1
            }
            ;;
        "centos"|"rhel")
            log "INFO" "Updating packages with yum..."
            yum update -y || {
                log "WARNING" "Some packages failed to update, continuing..."
            }
            
            log "INFO" "Installing essential packages..."
            yum install -y \
                curl \
                wget \
                ca-certificates \
                gnupg2 \
                epel-release || {
                log "ERROR" "Failed to install essential packages"
                exit 1
            }
            ;;
        "fedora")
            log "INFO" "Updating packages with dnf..."
            dnf update -y || {
                log "WARNING" "Some packages failed to update, continuing..."
            }
            
            log "INFO" "Installing essential packages..."
            dnf install -y \
                curl \
                wget \
                ca-certificates \
                gnupg2 || {
                log "ERROR" "Failed to install essential packages"
                exit 1
            }
            ;;
        *)
            log "ERROR" "Unsupported distribution: $distro"
            log "INFO" "Supported distributions: Ubuntu, Debian, CentOS, RHEL, Fedora"
            exit 1
            ;;
    esac
    
    log "INFO" "System update completed successfully"
}

# Install SSH-Stunnel Manager dependencies
install_dependencies() {
    local distro=$(detect_distro)
    local ubuntu_version=$(get_ubuntu_version)
    
    log "INFO" "Installing SSH-Stunnel Manager dependencies..."
    
    case "$distro" in
        "ubuntu")
            log "INFO" "Installing packages for Ubuntu $ubuntu_version..."
            
            # Update package lists first
            apt-get update -qq
            
            # Install dependencies with Ubuntu-specific handling
            local packages=(
                "stunnel4"
                "openssh-server" 
                "openssl"
                "net-tools"
                "systemd"
                "ca-certificates"
                "curl"
                "wget"
            )
            
            # Add netstat-nat if available (may not be in newer Ubuntu versions)
            if apt-cache show netstat-nat >/dev/null 2>&1; then
                packages+=("netstat-nat")
            fi
            
            # Install packages one by one for better error handling
            for package in "${packages[@]}"; do
                log "INFO" "Installing $package..."
                if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"; then
                    if [[ "$package" == "netstat-nat" ]]; then
                        log "WARNING" "netstat-nat not available, using net-tools instead"
                        continue
                    else
                        log "ERROR" "Failed to install $package"
                        exit 1
                    fi
                fi
            done
            
            # Verify stunnel installation
            if ! command -v stunnel4 >/dev/null 2>&1 && ! command -v stunnel >/dev/null 2>&1; then
                log "ERROR" "Stunnel installation failed"
                exit 1
            fi
            ;;
        "debian")
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                stunnel4 \
                openssh-server \
                openssl \
                net-tools \
                systemd \
                ca-certificates \
                curl \
                wget || {
                log "ERROR" "Failed to install dependencies"
                exit 1
            }
            ;;
        "centos"|"rhel")
            yum install -y \
                stunnel \
                openssh-server \
                openssl \
                net-tools \
                systemd \
                ca-certificates \
                curl \
                wget || {
                log "ERROR" "Failed to install dependencies"
                exit 1
            }
            ;;
        "fedora")
            dnf install -y \
                stunnel \
                openssh-server \
                openssl \
                net-tools \
                systemd \
                ca-certificates \
                curl \
                wget || {
                log "ERROR" "Failed to install dependencies"
                exit 1
            }
            ;;
    esac
    
    log "INFO" "Dependencies installed successfully"
}

# Download and install the main script
download_script() {
    log "INFO" "Downloading SSH-Stunnel Manager script..."
    
    # Create temporary directory
    local temp_dir=$(mktemp -d)
    local temp_script="$temp_dir/$SCRIPT_NAME"
    
    # Download the script
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$SCRIPT_URL" -o "$temp_script" || {
            log "ERROR" "Failed to download script with curl"
            exit 1
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$SCRIPT_URL" -O "$temp_script" || {
            log "ERROR" "Failed to download script with wget"
            exit 1
        }
    else
        log "ERROR" "Neither curl nor wget is available"
        exit 1
    fi
    
    # Verify download
    if [[ ! -f "$temp_script" ]]; then
        log "ERROR" "Script download failed - file not found"
        exit 1
    fi
    
    # Check if script is valid bash
    if ! bash -n "$temp_script"; then
        log "ERROR" "Downloaded script has syntax errors"
        exit 1
    fi
    
    # Install script to system location
    cp "$temp_script" "$INSTALL_DIR/$SCRIPT_NAME"
    chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    
    # Create symlink for easy access
    if [[ ! -L "/usr/local/bin/ssh-stunnel" ]]; then
        ln -sf "$INSTALL_DIR/$SCRIPT_NAME" "/usr/local/bin/ssh-stunnel"
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
    
    log "INFO" "Script installed to: $INSTALL_DIR/$SCRIPT_NAME"
    log "INFO" "Symlink created: /usr/local/bin/ssh-stunnel"
}

# Setup directories and permissions
setup_environment() {
    log "INFO" "Setting up environment..."
    
    # Create log directory
    local log_dir=$(dirname "$LOG_FILE")
    mkdir -p "$log_dir"
    chmod 755 "$log_dir"
    
    # Create stunnel directories
    mkdir -p /etc/stunnel
    mkdir -p /var/run/stunnel
    chmod 755 /etc/stunnel
    chmod 755 /var/run/stunnel
    
    # Ensure SSH service is enabled
    systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
    
    log "INFO" "Environment setup completed"
}

# Run the script's built-in installation
run_script_install() {
    log "INFO" "Running SSH-Stunnel Manager installation..."
    
    # Run the script's install command
    "$INSTALL_DIR/$SCRIPT_NAME" install || {
        log "ERROR" "SSH-Stunnel Manager installation failed"
        exit 1
    }
    
    log "INFO" "SSH-Stunnel Manager installation completed"
}

# Display installation summary
show_summary() {
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}              ${CYAN}SSH-Stunnel Manager Installation${NC}              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                     ${CYAN}COMPLETED SUCCESSFULLY${NC}                   ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${YELLOW}📁 Installation Details:${NC}"
    echo -e "   Script Location: ${CYAN}$INSTALL_DIR/$SCRIPT_NAME${NC}"
    echo -e "   Symlink: ${CYAN}/usr/local/bin/ssh-stunnel${NC}"
    echo -e "   Log File: ${CYAN}$LOG_FILE${NC}"
    echo
    echo -e "${YELLOW}🚀 Quick Start:${NC}"
    echo -e "   Interactive Menu: ${CYAN}ssh-stunnel menu${NC}"
    echo -e "   Or: ${CYAN}$SCRIPT_NAME menu${NC}"
    echo
    echo -e "${YELLOW}📋 Example Usage:${NC}"
    echo -e "   ${CYAN}ssh-stunnel start --host your-server.com --ssh-port 443 --local-port 8443${NC}"
    echo -e "   ${CYAN}ssh-stunnel status${NC}"
    echo -e "   ${CYAN}ssh-stunnel logs${NC}"
    echo
    echo -e "${YELLOW}🔐 For HTTP Injector:${NC}"
    echo -e "   1. Run: ${CYAN}ssh-stunnel menu${NC}"
    echo -e "   2. Configure your tunnel to port 443"
    echo -e "   3. Use localhost:8443 in HTTP Injector"
    echo
    echo -e "${GREEN}✅ Installation completed! You can now use SSH-Stunnel Manager.${NC}"
    echo
}

# Main installation function
main() {
    echo -e "${CYAN}SSH-Stunnel Manager Installer${NC}"
    echo -e "${CYAN}==============================${NC}"
    echo -e "${CYAN}Ubuntu 20.04 - 24.04 Compatible${NC}"
    echo
    
    # Check root privileges
    check_root
    
    # Create log file
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    local distro=$(detect_distro)
    local ubuntu_version=$(get_ubuntu_version)
    
    log "INFO" "Starting SSH-Stunnel Manager installation"
    log "INFO" "Distribution: $distro"
    if [[ "$distro" == "ubuntu" ]]; then
        log "INFO" "Ubuntu Version: $ubuntu_version"
    fi
    log "INFO" "User: $(whoami)"
    
    # Check Ubuntu support
    check_ubuntu_support
    
    # Installation steps
    update_system
    install_dependencies
    download_script
    setup_environment
    run_script_install
    
    # Show completion summary
    show_summary
    
    log "INFO" "Installation process completed successfully"
}

# Handle script interruption
trap 'log "ERROR" "Installation interrupted"; exit 1' INT TERM

# Run main installation
main "$@"
