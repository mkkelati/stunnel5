#!/bin/bash

#################################################################
# SSH-Stunnel Manager Script
# 
# A professional SSH connection manager using Stunnel for tunneling
# with TLSv1.3 encryption and TLS_AES_256_GCM_SHA384 cipher suite
#
# Author: SSH-Stunnel Manager
# Version: 1.0
# License: MIT
#################################################################

set -euo pipefail

# Global Variables
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/ssh-stunnel.log"
readonly CONFIG_DIR="/etc/stunnel"
readonly STUNNEL_CONFIG="$CONFIG_DIR/stunnel.conf"
readonly PID_DIR="/var/run/stunnel"
readonly PID_FILE="$PID_DIR/stunnel.pid"
readonly REQUIRED_TLS_VERSION="TLSv1.3"
readonly REQUIRED_CIPHER="TLS_AES_256_GCM_SHA384"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

#################################################################
# Utility Functions
#################################################################

# Logging function with timestamps
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | sudo tee -a "$LOG_FILE" >/dev/null 2>&1 || true
    
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
    if [[ $EUID -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Ensure script is run with appropriate privileges
ensure_privileges() {
    if ! check_root; then
        log "INFO" "This operation requires root privileges. Requesting sudo access..."
        exec sudo "$0" "$@"
    fi
}

# Detect Linux distribution
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

# Package manager detection and installation
install_package() {
    local package="$1"
    local distro=$(detect_distro)
    
    log "INFO" "Installing package: $package"
    
    case "$distro" in
        "ubuntu"|"debian")
            apt-get update -qq
            apt-get install -y "$package"
            ;;
        "centos"|"rhel"|"fedora")
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "$package"
            else
                yum install -y "$package"
            fi
            ;;
        *)
            log "ERROR" "Unsupported distribution: $distro"
            exit 1
            ;;
    esac
}

# Validate IP address
validate_ip() {
    local ip="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    
    if [[ $ip =~ $regex ]]; then
        for octet in $(echo "$ip" | tr '.' ' '); do
            if ((octet > 255)); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Validate hostname
validate_hostname() {
    local hostname="$1"
    local regex='^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    if [[ $hostname =~ $regex ]]; then
        return 0
    fi
    return 1
}

# Validate port number
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        return 0
    fi
    return 1
}

# Validate username
validate_username() {
    local username="$1"
    local regex='^[a-zA-Z][a-zA-Z0-9_-]{0,31}$'
    
    if [[ $username =~ $regex ]]; then
        return 0
    fi
    return 1
}

#################################################################
# Installation and Setup Functions
#################################################################

# Check if Stunnel is installed
check_stunnel_installed() {
    if command -v stunnel >/dev/null 2>&1 || command -v stunnel4 >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Install dependencies
install_dependencies() {
    log "INFO" "Installing required dependencies..."
    
    local packages=("stunnel" "openssh-server" "openssl")
    local distro=$(detect_distro)
    
    # Adjust package names based on distribution
    case "$distro" in
        "ubuntu"|"debian")
            packages=("stunnel4" "openssh-server" "openssl")
            ;;
        "centos"|"rhel"|"fedora")
            packages=("stunnel" "openssh-server" "openssl")
            ;;
    esac
    
    for package in "${packages[@]}"; do
        if ! dpkg -l "$package" >/dev/null 2>&1 && ! rpm -q "$package" >/dev/null 2>&1; then
            install_package "$package"
        else
            log "INFO" "Package $package is already installed"
        fi
    done
    
    log "INFO" "Dependencies installation completed"
}

# Setup directories and permissions
setup_directories() {
    log "INFO" "Setting up required directories..."
    
    # Create configuration directory
    if [[ ! -d "$CONFIG_DIR" ]]; then
        mkdir -p "$CONFIG_DIR"
        chmod 755 "$CONFIG_DIR"
        log "INFO" "Created directory: $CONFIG_DIR"
    fi
    
    # Create PID directory
    if [[ ! -d "$PID_DIR" ]]; then
        mkdir -p "$PID_DIR"
        chmod 755 "$PID_DIR"
        log "INFO" "Created directory: $PID_DIR"
    fi
    
    # Create log directory if it doesn't exist
    local log_dir=$(dirname "$LOG_FILE")
    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir"
        chmod 755 "$log_dir"
        log "INFO" "Created directory: $log_dir"
    fi
    
    # Ensure log file exists with proper permissions
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE"
        chmod 644 "$LOG_FILE"
        log "INFO" "Created log file: $LOG_FILE"
    fi
}

# Generate SSL certificate and key
generate_ssl_certificate() {
    local cert_dir="$CONFIG_DIR/certs"
    local cert_file="$cert_dir/stunnel.crt"
    local key_file="$cert_dir/stunnel.key"
    local pem_file="$cert_dir/stunnel.pem"
    
    log "INFO" "Generating SSL certificate and key..."
    
    # Create certificate directory
    mkdir -p "$cert_dir"
    chmod 700 "$cert_dir"
    
    # Generate private key (4096-bit RSA for enhanced security)
    openssl genrsa -out "$key_file" 4096
    
    # Generate certificate
    openssl req -new -x509 -key "$key_file" -out "$cert_file" -days 365 -subj "/C=US/ST=Default/L=Default/O=SSH-Stunnel-Manager/CN=localhost"
    
    # Combine certificate and key into PEM file
    cat "$cert_file" "$key_file" > "$pem_file"
    
    # Set proper permissions
    chmod 600 "$key_file" "$pem_file"
    chmod 644 "$cert_file"
    
    log "INFO" "SSL certificate generated at: $pem_file"
    echo "$pem_file"
}

# Install script
install_script() {
    ensure_privileges
    
    log "INFO" "Starting SSH-Stunnel Manager installation..."
    
    # Install dependencies
    install_dependencies
    
    # Setup directories
    setup_directories
    
    # Make script executable
    chmod +x "$0"
    
    # Copy script to system location (optional)
    local system_script="/usr/local/bin/$SCRIPT_NAME"
    if [[ "$0" != "$system_script" ]]; then
        cp "$0" "$system_script"
        chmod +x "$system_script"
        log "INFO" "Script installed to: $system_script"
    fi
    
    # Generate default SSL certificate
    generate_ssl_certificate
    
    # Configure SSH for security
    configure_ssh_security
    
    log "INFO" "Installation completed successfully!"
    echo -e "${GREEN}Installation completed!${NC}"
    echo -e "Run '${CYAN}$SCRIPT_NAME menu${NC}' to start the interactive menu"
}

# Configure SSH for enhanced security
configure_ssh_security() {
    local sshd_config="/etc/ssh/sshd_config"
    local backup_config="${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"
    
    log "INFO" "Configuring SSH security settings..."
    
    # Backup original config
    cp "$sshd_config" "$backup_config"
    
    # Apply security configurations
    local security_configs=(
        "Protocol 2"
        "PermitRootLogin no"
        "PasswordAuthentication yes"
        "PubkeyAuthentication yes"
        "PermitEmptyPasswords no"
        "X11Forwarding no"
        "MaxAuthTries 3"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 2"
        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
        "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
        "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
    )
    
    for config in "${security_configs[@]}"; do
        local key=$(echo "$config" | cut -d' ' -f1)
        if grep -q "^${key}" "$sshd_config"; then
            sed -i "s/^${key}.*/$config/" "$sshd_config"
        else
            echo "$config" >> "$sshd_config"
        fi
    done
    
    log "INFO" "SSH security configuration completed"
}

#################################################################
# User Management Functions
#################################################################

# Create new user
create_user() {
    local username="$1"
    local password="$2"
    
    # Validate username
    if ! validate_username "$username"; then
        log "ERROR" "Invalid username format: $username"
        return 1
    fi
    
    # Check if user already exists
    if id "$username" >/dev/null 2>&1; then
        log "ERROR" "User already exists: $username"
        return 1
    fi
    
    log "INFO" "Creating user: $username"
    
    # Create user with home directory and bash shell
    useradd -m -s /bin/bash "$username"
    
    # Set password
    echo "$username:$password" | chpasswd
    
    # Add user to appropriate groups for SSH access
    usermod -a -G ssh "$username" 2>/dev/null || true
    
    log "INFO" "User created successfully: $username"
    return 0
}

# Delete user
delete_user() {
    local username="$1"
    local remove_home="${2:-yes}"
    
    # Validate username
    if ! validate_username "$username"; then
        log "ERROR" "Invalid username format: $username"
        return 1
    fi
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        log "ERROR" "User does not exist: $username"
        return 1
    fi
    
    # Prevent deletion of system users
    local uid=$(id -u "$username")
    if ((uid < 1000)); then
        log "ERROR" "Cannot delete system user: $username (UID: $uid)"
        return 1
    fi
    
    log "INFO" "Deleting user: $username"
    
    # Kill user processes
    pkill -u "$username" 2>/dev/null || true
    
    # Delete user
    if [[ "$remove_home" == "yes" ]]; then
        userdel -r "$username"
        log "INFO" "User and home directory deleted: $username"
    else
        userdel "$username"
        log "INFO" "User deleted (home directory preserved): $username"
    fi
    
    return 0
}

# Set SSH user limits
set_ssh_limits() {
    local max_sessions="$1"
    local max_startups="$2"
    local sshd_config="/etc/ssh/sshd_config"
    
    # Validate inputs
    if ! [[ "$max_sessions" =~ ^[0-9]+$ ]] || ((max_sessions < 1 || max_sessions > 100)); then
        log "ERROR" "Invalid max sessions value: $max_sessions (must be 1-100)"
        return 1
    fi
    
    if ! [[ "$max_startups" =~ ^[0-9]+$ ]] || ((max_startups < 1 || max_startups > 100)); then
        log "ERROR" "Invalid max startups value: $max_startups (must be 1-100)"
        return 1
    fi
    
    log "INFO" "Setting SSH limits - MaxSessions: $max_sessions, MaxStartups: $max_startups"
    
    # Backup configuration
    local backup_config="${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$sshd_config" "$backup_config"
    
    # Update MaxSessions
    if grep -q "^MaxSessions" "$sshd_config"; then
        sed -i "s/^MaxSessions.*/MaxSessions $max_sessions/" "$sshd_config"
    else
        echo "MaxSessions $max_sessions" >> "$sshd_config"
    fi
    
    # Update MaxStartups
    if grep -q "^MaxStartups" "$sshd_config"; then
        sed -i "s/^MaxStartups.*/MaxStartups $max_startups/" "$sshd_config"
    else
        echo "MaxStartups $max_startups" >> "$sshd_config"
    fi
    
    # Restart SSH service
    systemctl restart sshd || service ssh restart
    
    log "INFO" "SSH limits updated and service restarted"
    return 0
}

#################################################################
# Stunnel Configuration and Management
#################################################################

# Generate Stunnel configuration
generate_stunnel_config() {
    local host="$1"
    local ssh_port="$2"
    local local_port="$3"
    local cert_file="$4"
    local key_file="$5"
    
    log "INFO" "Generating Stunnel configuration for $host:$ssh_port -> localhost:$local_port"
    
    cat > "$STUNNEL_CONFIG" << EOF
; Stunnel configuration file
; Generated by SSH-Stunnel Manager
; Date: $(date)

; Global options
pid = $PID_FILE
cert = $cert_file
key = $key_file

; Security settings - enforce TLSv1.3 with specific cipher
sslVersion = $REQUIRED_TLS_VERSION
ciphersuites = $REQUIRED_CIPHER

; Disable weak protocols and ciphers
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1.1
options = NO_TLSv1.2

; Certificate verification
verify = 0
checkHost = $host
checkIP = no

; Logging
debug = 5
output = $LOG_FILE

; Service definition
[ssh-tunnel]
accept = $local_port
connect = $host:$ssh_port
EOF

    chmod 600 "$STUNNEL_CONFIG"
    log "INFO" "Stunnel configuration generated at: $STUNNEL_CONFIG"
}

# Start Stunnel service
start_stunnel() {
    local config_file="${1:-$STUNNEL_CONFIG}"
    
    if [[ ! -f "$config_file" ]]; then
        log "ERROR" "Configuration file not found: $config_file"
        return 1
    fi
    
    # Check if already running
    if is_stunnel_running; then
        log "WARNING" "Stunnel is already running"
        return 0
    fi
    
    log "INFO" "Starting Stunnel service..."
    
    # Start Stunnel
    stunnel "$config_file"
    
    # Wait for startup
    sleep 2
    
    if is_stunnel_running; then
        log "INFO" "Stunnel started successfully"
        return 0
    else
        log "ERROR" "Failed to start Stunnel"
        return 1
    fi
}

# Stop Stunnel service
stop_stunnel() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log "INFO" "Stopping Stunnel (PID: $pid)..."
            kill "$pid"
            
            # Wait for process to stop
            local count=0
            while kill -0 "$pid" 2>/dev/null && ((count < 10)); do
                sleep 1
                ((count++))
            done
            
            if kill -0 "$pid" 2>/dev/null; then
                log "WARNING" "Force killing Stunnel process"
                kill -9 "$pid"
            fi
            
            rm -f "$PID_FILE"
            log "INFO" "Stunnel stopped successfully"
        else
            log "WARNING" "Stunnel PID file exists but process is not running"
            rm -f "$PID_FILE"
        fi
    else
        log "WARNING" "Stunnel PID file not found"
    fi
    
    # Kill any remaining stunnel processes
    pkill stunnel 2>/dev/null || true
}

# Restart Stunnel service
restart_stunnel() {
    log "INFO" "Restarting Stunnel service..."
    stop_stunnel
    sleep 2
    start_stunnel
}

# Check if Stunnel is running
is_stunnel_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Get Stunnel status
get_stunnel_status() {
    if is_stunnel_running; then
        local pid=$(cat "$PID_FILE")
        echo -e "${GREEN}Stunnel is running${NC} (PID: $pid)"
        
        # Show listening ports
        local ports=$(netstat -tlnp 2>/dev/null | grep "$pid" | awk '{print $4}' | cut -d':' -f2 | sort -n | tr '\n' ' ')
        if [[ -n "$ports" ]]; then
            echo -e "Listening on ports: ${CYAN}$ports${NC}"
        fi
    else
        echo -e "${RED}Stunnel is not running${NC}"
    fi
}

#################################################################
# Menu System
#################################################################

# Display main menu
show_main_menu() {
    clear
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║${NC}                  ${CYAN}SSH-Stunnel Manager${NC}                     ${PURPLE}║${NC}"
    echo -e "${PURPLE}║${NC}              Professional SSH Tunnel Manager               ${PURPLE}║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${YELLOW}Current Status:${NC}"
    get_stunnel_status
    echo
    echo -e "${YELLOW}Main Menu:${NC}"
    echo "1) Create User"
    echo "2) Delete User"
    echo "3) Set SSH User Limits"
    echo "4) Configure Stunnel"
    echo "5) Start Stunnel"
    echo "6) Stop Stunnel"
    echo "7) Restart Stunnel"
    echo "8) View Logs"
    echo "9) Show Status"
    echo "0) Exit"
    echo
}

# Handle user creation menu
menu_create_user() {
    echo -e "${CYAN}Create New User${NC}"
    echo "=================="
    
    read -p "Enter username: " username
    if [[ -z "$username" ]]; then
        log "ERROR" "Username cannot be empty"
        return 1
    fi
    
    if ! validate_username "$username"; then
        log "ERROR" "Invalid username format"
        return 1
    fi
    
    read -s -p "Enter password: " password
    echo
    read -s -p "Confirm password: " password_confirm
    echo
    
    if [[ "$password" != "$password_confirm" ]]; then
        log "ERROR" "Passwords do not match"
        return 1
    fi
    
    if [[ ${#password} -lt 8 ]]; then
        log "ERROR" "Password must be at least 8 characters long"
        return 1
    fi
    
    if create_user "$username" "$password"; then
        echo -e "${GREEN}User '$username' created successfully!${NC}"
    else
        echo -e "${RED}Failed to create user '$username'${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Handle user deletion menu
menu_delete_user() {
    echo -e "${CYAN}Delete User${NC}"
    echo "============="
    
    read -p "Enter username to delete: " username
    if [[ -z "$username" ]]; then
        log "ERROR" "Username cannot be empty"
        return 1
    fi
    
    if ! validate_username "$username"; then
        log "ERROR" "Invalid username format"
        return 1
    fi
    
    # Show user info
    if id "$username" >/dev/null 2>&1; then
        echo "User information:"
        echo "  Username: $username"
        echo "  UID: $(id -u "$username")"
        echo "  Home: $(eval echo ~"$username")"
        echo
    else
        log "ERROR" "User '$username' does not exist"
        return 1
    fi
    
    read -p "Delete home directory? (y/N): " delete_home
    read -p "Are you sure you want to delete user '$username'? (y/N): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        local remove_home="no"
        if [[ "$delete_home" =~ ^[Yy]$ ]]; then
            remove_home="yes"
        fi
        
        if delete_user "$username" "$remove_home"; then
            echo -e "${GREEN}User '$username' deleted successfully!${NC}"
        else
            echo -e "${RED}Failed to delete user '$username'${NC}"
        fi
    else
        echo "Deletion cancelled."
    fi
    
    read -p "Press Enter to continue..."
}

# Handle SSH limits menu
menu_set_ssh_limits() {
    echo -e "${CYAN}Set SSH User Limits${NC}"
    echo "===================="
    
    # Show current limits
    local current_sessions=$(grep "^MaxSessions" /etc/ssh/sshd_config | awk '{print $2}' || echo "not set")
    local current_startups=$(grep "^MaxStartups" /etc/ssh/sshd_config | awk '{print $2}' || echo "not set")
    
    echo "Current limits:"
    echo "  MaxSessions: $current_sessions"
    echo "  MaxStartups: $current_startups"
    echo
    
    read -p "Enter maximum concurrent sessions (1-100): " max_sessions
    read -p "Enter maximum startup connections (1-100): " max_startups
    
    if set_ssh_limits "$max_sessions" "$max_startups"; then
        echo -e "${GREEN}SSH limits updated successfully!${NC}"
        echo "New limits:"
        echo "  MaxSessions: $max_sessions"
        echo "  MaxStartups: $max_startups"
    else
        echo -e "${RED}Failed to update SSH limits${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Handle Stunnel configuration menu
menu_configure_stunnel() {
    echo -e "${CYAN}Configure Stunnel${NC}"
    echo "=================="
    
    read -p "Enter target host (IP or hostname): " host
    if [[ -z "$host" ]]; then
        log "ERROR" "Host cannot be empty"
        return 1
    fi
    
    if ! validate_ip "$host" && ! validate_hostname "$host"; then
        log "ERROR" "Invalid host format"
        return 1
    fi
    
    read -p "Enter SSH port on target host (default: 22): " ssh_port
    ssh_port=${ssh_port:-22}
    
    if ! validate_port "$ssh_port"; then
        log "ERROR" "Invalid SSH port"
        return 1
    fi
    
    read -p "Enter local port for tunnel (default: 8443): " local_port
    local_port=${local_port:-8443}
    
    if ! validate_port "$local_port"; then
        log "ERROR" "Invalid local port"
        return 1
    fi
    
    # Certificate options
    read -p "Use existing certificate? (y/N): " use_existing
    if [[ "$use_existing" =~ ^[Yy]$ ]]; then
        read -p "Enter certificate file path: " cert_file
        read -p "Enter key file path: " key_file
        
        if [[ ! -f "$cert_file" ]]; then
            log "ERROR" "Certificate file not found: $cert_file"
            return 1
        fi
        
        if [[ ! -f "$key_file" ]]; then
            log "ERROR" "Key file not found: $key_file"
            return 1
        fi
    else
        echo "Generating new certificate..."
        local pem_file=$(generate_ssl_certificate)
        cert_file="$pem_file"
        key_file="$pem_file"
    fi
    
    if generate_stunnel_config "$host" "$ssh_port" "$local_port" "$cert_file" "$key_file"; then
        echo -e "${GREEN}Stunnel configuration created successfully!${NC}"
        echo "Configuration details:"
        echo "  Target: $host:$ssh_port"
        echo "  Local port: $local_port"
        echo "  TLS Version: $REQUIRED_TLS_VERSION"
        echo "  Cipher: $REQUIRED_CIPHER"
        echo "  Certificate: $cert_file"
    else
        echo -e "${RED}Failed to create Stunnel configuration${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Handle view logs menu
menu_view_logs() {
    echo -e "${CYAN}View Logs${NC}"
    echo "=========="
    
    if [[ ! -f "$LOG_FILE" ]]; then
        echo "Log file not found: $LOG_FILE"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Choose log view option:"
    echo "1) Show last 50 lines"
    echo "2) Show last 100 lines"
    echo "3) Show all logs"
    echo "4) Follow logs (real-time)"
    
    read -p "Enter choice (1-4): " log_choice
    
    case "$log_choice" in
        1)
            tail -n 50 "$LOG_FILE"
            ;;
        2)
            tail -n 100 "$LOG_FILE"
            ;;
        3)
            cat "$LOG_FILE"
            ;;
        4)
            echo "Following logs (Press Ctrl+C to stop)..."
            tail -f "$LOG_FILE"
            ;;
        *)
            echo "Invalid choice"
            ;;
    esac
    
    if [[ "$log_choice" != "4" ]]; then
        read -p "Press Enter to continue..."
    fi
}

# Main interactive menu
interactive_menu() {
    ensure_privileges
    
    while true; do
        show_main_menu
        read -p "Enter your choice (0-9): " choice
        
        case "$choice" in
            1)
                menu_create_user
                ;;
            2)
                menu_delete_user
                ;;
            3)
                menu_set_ssh_limits
                ;;
            4)
                menu_configure_stunnel
                ;;
            5)
                echo "Starting Stunnel..."
                if start_stunnel; then
                    echo -e "${GREEN}Stunnel started successfully!${NC}"
                else
                    echo -e "${RED}Failed to start Stunnel${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            6)
                echo "Stopping Stunnel..."
                stop_stunnel
                echo -e "${GREEN}Stunnel stopped${NC}"
                read -p "Press Enter to continue..."
                ;;
            7)
                echo "Restarting Stunnel..."
                if restart_stunnel; then
                    echo -e "${GREEN}Stunnel restarted successfully!${NC}"
                else
                    echo -e "${RED}Failed to restart Stunnel${NC}"
                fi
                read -p "Press Enter to continue..."
                ;;
            8)
                menu_view_logs
                ;;
            9)
                echo
                get_stunnel_status
                echo
                read -p "Press Enter to continue..."
                ;;
            0)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice. Please try again.${NC}"
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

#################################################################
# Command Line Interface
#################################################################

# Show usage information
show_usage() {
    cat << EOF
${CYAN}SSH-Stunnel Manager${NC} - Professional SSH Tunnel Manager

${YELLOW}USAGE:${NC}
    $SCRIPT_NAME menu                          - Start interactive menu
    $SCRIPT_NAME install                       - Install dependencies and setup
    $SCRIPT_NAME start [options]               - Start Stunnel with options
    $SCRIPT_NAME stop                          - Stop Stunnel
    $SCRIPT_NAME restart [options]             - Restart Stunnel with options
    $SCRIPT_NAME status                        - Show Stunnel status
    $SCRIPT_NAME logs [lines]                  - Show logs (default: 50 lines)

${YELLOW}START/RESTART OPTIONS:${NC}
    --host HOST                                - Target host (required)
    --ssh-port PORT                            - SSH port on target (default: 22)
    --local-port PORT                          - Local tunnel port (default: 8443)
    --cert PATH                                - Certificate file path
    --key PATH                                 - Key file path (default: same as cert)

${YELLOW}EXAMPLES:${NC}
    $SCRIPT_NAME menu
    $SCRIPT_NAME start --host example.com --ssh-port 22 --local-port 8080
    $SCRIPT_NAME start --host 192.168.1.100 --cert /path/to/cert.pem
    $SCRIPT_NAME logs 100

${YELLOW}FEATURES:${NC}
    • TLSv1.3 encryption with TLS_AES_256_GCM_SHA384 cipher
    • User management (create/delete SSH users)
    • SSH connection limits configuration
    • Automatic SSL certificate generation
    • Comprehensive logging and monitoring
    • Security-hardened SSH configuration

For interactive usage, run: ${CYAN}$SCRIPT_NAME menu${NC}
EOF
}

# Parse command line arguments
parse_arguments() {
    local command="$1"
    shift
    
    case "$command" in
        "menu")
            interactive_menu
            ;;
        "install")
            install_script
            ;;
        "start"|"restart")
            local host=""
            local ssh_port="22"
            local local_port="8443"
            local cert_file=""
            local key_file=""
            
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --host)
                        host="$2"
                        shift 2
                        ;;
                    --ssh-port)
                        ssh_port="$2"
                        shift 2
                        ;;
                    --local-port)
                        local_port="$2"
                        shift 2
                        ;;
                    --cert)
                        cert_file="$2"
                        shift 2
                        ;;
                    --key)
                        key_file="$2"
                        shift 2
                        ;;
                    *)
                        log "ERROR" "Unknown option: $1"
                        show_usage
                        exit 1
                        ;;
                esac
            done
            
            # Validate required parameters
            if [[ -z "$host" ]]; then
                log "ERROR" "Host is required for $command command"
                echo "Use: $SCRIPT_NAME $command --host HOST [other options]"
                exit 1
            fi
            
            if ! validate_ip "$host" && ! validate_hostname "$host"; then
                log "ERROR" "Invalid host format: $host"
                exit 1
            fi
            
            if ! validate_port "$ssh_port"; then
                log "ERROR" "Invalid SSH port: $ssh_port"
                exit 1
            fi
            
            if ! validate_port "$local_port"; then
                log "ERROR" "Invalid local port: $local_port"
                exit 1
            fi
            
            # Handle certificate
            if [[ -z "$cert_file" ]]; then
                cert_file=$(generate_ssl_certificate)
                key_file="$cert_file"
            else
                if [[ ! -f "$cert_file" ]]; then
                    log "ERROR" "Certificate file not found: $cert_file"
                    exit 1
                fi
                if [[ -z "$key_file" ]]; then
                    key_file="$cert_file"
                fi
                if [[ ! -f "$key_file" ]]; then
                    log "ERROR" "Key file not found: $key_file"
                    exit 1
                fi
            fi
            
            # Generate configuration and start/restart
            ensure_privileges
            
            if [[ "$command" == "restart" ]]; then
                stop_stunnel
            fi
            
            generate_stunnel_config "$host" "$ssh_port" "$local_port" "$cert_file" "$key_file"
            
            if start_stunnel; then
                echo -e "${GREEN}Stunnel $command completed successfully!${NC}"
                echo "Connect to: localhost:$local_port"
                echo "Target: $host:$ssh_port"
            else
                echo -e "${RED}Stunnel $command failed${NC}"
                exit 1
            fi
            ;;
        "stop")
            ensure_privileges
            stop_stunnel
            echo -e "${GREEN}Stunnel stopped${NC}"
            ;;
        "status")
            get_stunnel_status
            ;;
        "logs")
            local lines="${1:-50}"
            if [[ ! "$lines" =~ ^[0-9]+$ ]]; then
                log "ERROR" "Invalid number of lines: $lines"
                exit 1
            fi
            
            if [[ -f "$LOG_FILE" ]]; then
                tail -n "$lines" "$LOG_FILE"
            else
                echo "Log file not found: $LOG_FILE"
            fi
            ;;
        *)
            log "ERROR" "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

#################################################################
# Main Entry Point
#################################################################

main() {
    # Handle no arguments or single 'menu' argument
    if [[ $# -eq 0 ]]; then
        echo -e "${YELLOW}SSH-Stunnel Manager${NC}"
        echo
        echo "To start the interactive menu, run:"
        echo -e "  ${CYAN}$SCRIPT_NAME menu${NC}"
        echo
        echo "For command-line usage, run:"
        echo -e "  ${CYAN}$SCRIPT_NAME --help${NC}"
        echo
        show_usage
        exit 0
    fi
    
    # Handle help
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        show_usage
        exit 0
    fi
    
    # Handle single 'menu' argument
    if [[ $# -eq 1 && "$1" == "menu" ]]; then
        interactive_menu
        exit 0
    fi
    
    # Parse command line arguments
    parse_arguments "$@"
}

# Run main function with all arguments
main "$@"
