# 🚀 SSH-Stunnel Manager - Complete Installation Guide

## 📋 Quick Installation Links

### 🎯 One-Line Installation (Recommended)
```bash
curl -fsSL https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh | sudo bash
```

### 🔗 Direct Download Links
- **Main Script**: https://raw.githubusercontent.com/mkkelati/stunnel5/main/ssh-stunnel-manager.sh
- **Installer**: https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh
- **GitHub Repository**: https://github.com/mkkelati/stunnel5

## 🔄 System Update Commands (Run First)

### Ubuntu/Debian Systems
```bash
# Update package lists and upgrade system
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y curl wget ca-certificates gnupg software-properties-common

# Run the installer
curl -fsSL https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh | sudo bash
```

### CentOS/RHEL Systems
```bash
# Update system packages
sudo yum update -y

# Install essential packages  
sudo yum install -y curl wget ca-certificates gnupg2 epel-release

# Run the installer
curl -fsSL https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh | sudo bash
```

### Fedora Systems
```bash
# Update system packages
sudo dnf update -y

# Install essential packages
sudo dnf install -y curl wget ca-certificates gnupg2

# Run the installer
curl -fsSL https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh | sudo bash
```

## 📦 Manual Installation (Alternative Method)

### Step 1: Update System Packages
```bash
# Choose your distribution:

# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y

# CentOS/RHEL  
sudo yum update -y

# Fedora
sudo dnf update -y
```

### Step 2: Install Required Packages
```bash
# Ubuntu/Debian
sudo apt install -y stunnel4 openssh-server openssl curl wget

# CentOS/RHEL
sudo yum install -y stunnel openssh-server openssl curl wget

# Fedora  
sudo dnf install -y stunnel openssh-server openssl curl wget
```

### Step 3: Download and Install Script
```bash
# Download the main script
wget https://raw.githubusercontent.com/mkkelati/stunnel5/main/ssh-stunnel-manager.sh

# Make executable
chmod +x ssh-stunnel-manager.sh

# Install to system
sudo cp ssh-stunnel-manager.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/ssh-stunnel-manager.sh

# Run installation
sudo /usr/local/bin/ssh-stunnel-manager.sh install
```

## 🎮 HTTP Injector Setup Guide

Perfect for connecting with HTTP Injector app [[memory:7493782]]:

### Step 1: Install SSH-Stunnel Manager
```bash
curl -fsSL https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh | sudo bash
```

### Step 2: Configure Tunnel for Port 443
```bash
# Start interactive menu
ssh-stunnel-manager.sh menu

# Or use command line
ssh-stunnel-manager.sh start --host YOUR_SERVER.com --ssh-port 443 --local-port 8443
```

### Step 3: HTTP Injector Configuration
- **Host**: `localhost` or `127.0.0.1`
- **Port**: `8443` (or your chosen local port)
- **Protocol**: SSL/TLS proxy - SSH
- **Remote Port**: `443`

## 🔧 Advanced Installation Options

### Custom Installation Directory
```bash
# Install to custom location
INSTALL_DIR="/opt/ssh-stunnel" curl -fsSL https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh | sudo bash
```

### Offline Installation
```bash
# Download files
wget https://raw.githubusercontent.com/mkkelati/stunnel5/main/ssh-stunnel-manager.sh
wget https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh

# Make executable
chmod +x ssh-stunnel-manager.sh install.sh

# Run offline installation
sudo ./install.sh
```

## 🔍 Verification Commands

### Check Installation
```bash
# Verify script is installed
which ssh-stunnel-manager.sh

# Check version and help
ssh-stunnel-manager.sh --help

# Test menu access
ssh-stunnel-manager.sh menu
```

### Check Dependencies
```bash
# Verify Stunnel installation
stunnel -version

# Check SSH service
systemctl status ssh  # Ubuntu/Debian
systemctl status sshd # CentOS/RHEL/Fedora

# Verify OpenSSL
openssl version
```

## 🛠️ Troubleshooting Installation

### Permission Issues
```bash
# Fix permissions
sudo chmod +x /usr/local/bin/ssh-stunnel-manager.sh
sudo chown root:root /usr/local/bin/ssh-stunnel-manager.sh
```

### Package Installation Failures
```bash
# Clean package cache and retry
sudo apt clean && sudo apt update  # Ubuntu/Debian
sudo yum clean all && sudo yum update  # CentOS/RHEL
sudo dnf clean all && sudo dnf update  # Fedora

# Retry installation
curl -fsSL https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh | sudo bash
```

### Network Issues
```bash
# Test connectivity
ping github.com
curl -I https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh

# Use alternative download method
wget --no-check-certificate https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh
sudo bash install.sh
```

## 📋 Post-Installation Steps

### 1. Create Your First User
```bash
ssh-stunnel-manager.sh menu
# Select option 1: Create User
```

### 2. Configure SSH Limits
```bash
# Set connection limits
ssh-stunnel-manager.sh menu
# Select option 3: Set SSH User Limits
```

### 3. Start Your First Tunnel
```bash
# Replace with your server details
ssh-stunnel-manager.sh start --host your-server.com --ssh-port 443 --local-port 8443
```

### 4. Verify Operation
```bash
# Check tunnel status
ssh-stunnel-manager.sh status

# View logs
ssh-stunnel-manager.sh logs

# Test connection
ssh username@localhost -p 8443
```

## 🔐 Security Recommendations

### Firewall Configuration
```bash
# Allow SSH port
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp

# Allow local tunnel port
sudo ufw allow 8443/tcp

# Enable firewall
sudo ufw enable
```

### SSH Hardening (Automatic)
The installer automatically configures:
- ✅ TLSv1.3 encryption only
- ✅ TLS_AES_256_GCM_SHA384 cipher suite
- ✅ Strong SSH ciphers and key exchange
- ✅ Disabled weak protocols
- ✅ Connection limits and timeouts

## 📞 Support and Updates

### Get Updates
```bash
# Check for script updates
cd /tmp
wget https://raw.githubusercontent.com/mkkelati/stunnel5/main/ssh-stunnel-manager.sh
chmod +x ssh-stunnel-manager.sh
sudo cp ssh-stunnel-manager.sh /usr/local/bin/
```

### Report Issues
- **GitHub Issues**: [https://github.com/mkkelati/stunnel5/issues](https://github.com/mkkelati/stunnel5/issues)
- **Check Logs**: `/var/log/ssh-stunnel.log`

### Community
- **Star the repo**: [https://github.com/mkkelati/stunnel5](https://github.com/mkkelati/stunnel5)
- **Fork and contribute**: Pull requests welcome!

---

## 🎯 Quick Start Summary

```bash
# 1. Update system and install (one command)
curl -fsSL https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh | sudo bash

# 2. Start interactive menu
ssh-stunnel-manager.sh menu

# 3. Or start tunnel directly (replace with your details)
ssh-stunnel-manager.sh start --host your-server.com --ssh-port 443 --local-port 8443

# 4. Use in HTTP Injector: localhost:8443 with SSL/TLS proxy - SSH
```

**Perfect for HTTP Injector with SSL/TLS proxy - SSH on port 443!** 🚀
