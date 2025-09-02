# SSH-Stunnel Manager

A professional SSH connection manager using Stunnel for secure tunneling with TLSv1.3 encryption and TLS_AES_256_GCM_SHA384 cipher suite.

## 🚀 Quick Installation

### One-Line Installation (Recommended)

```bash
# Download, install dependencies, and setup in one command
curl -fsSL https://raw.githubusercontent.com/mkkelati/stunnel5/main/install.sh | sudo bash
```

### Manual Installation

```bash
# Update system packages first
sudo apt update && sudo apt upgrade -y  # For Ubuntu/Debian
# OR
sudo yum update -y  # For CentOS/RHEL
# OR  
sudo dnf update -y  # For Fedora

# Download the script
wget https://raw.githubusercontent.com/mkkelati/stunnel5/main/ssh-stunnel-manager.sh

# Make it executable
chmod +x ssh-stunnel-manager.sh

# Run installation
sudo ./ssh-stunnel-manager.sh install
```

## 🎯 Features

- **🔒 TLSv1.3 Encryption**: Enforced with TLS_AES_256_GCM_SHA384 cipher suite
- **👥 User Management**: Create/delete SSH users with validation
- **📊 Session Limits**: Configure maximum concurrent SSH connections
- **🛡️ Security Hardening**: Automatic SSH security configuration
- **📋 Menu Interface**: Interactive menu-driven interface
- **⚡ CLI Support**: Command-line operations for automation
- **📝 Comprehensive Logging**: Detailed activity logs with timestamps
- **🔧 Process Management**: PID-based service control

## 🖥️ Usage

### Interactive Menu
```bash
./ssh-stunnel-manager.sh menu
```

### Command Line Examples
```bash
# Start tunnel to your server
./ssh-stunnel-manager.sh start --host your-server.com --ssh-port 443 --local-port 8443

# Check status
./ssh-stunnel-manager.sh status

# View logs
./ssh-stunnel-manager.sh logs 100

# Stop tunnel
./ssh-stunnel-manager.sh stop
```

## 🔧 HTTP Injector Configuration

Perfect for HTTP Injector app with **SSL/TLS proxy - SSH** on **port 443**:

1. Run the installation
2. Configure tunnel: `./ssh-stunnel-manager.sh start --host your-server.com --ssh-port 443 --local-port 8443`
3. In HTTP Injector, use:
   - **Host**: `localhost`
   - **Port**: `8443` (or your chosen local port)
   - **Protocol**: SSL/TLS proxy - SSH

## 📋 Requirements

- Linux (Ubuntu/Debian, CentOS/RHEL, Fedora)
- Root/sudo access for installation
- Internet connection for package downloads

## 🛠️ Supported Distributions

- ✅ Ubuntu 18.04+
- ✅ Debian 9+
- ✅ CentOS 7+
- ✅ RHEL 7+
- ✅ Fedora 30+

## 🔐 Security Features

- **Strong Encryption**: TLSv1.3 with AES-256-GCM
- **SSH Hardening**: Secure cipher suites and key exchange
- **Certificate Management**: Auto-generated 4096-bit RSA certificates
- **Input Validation**: Comprehensive parameter validation
- **Privilege Management**: Least-privilege execution

## 📖 Documentation

### Menu Options
1. **Create User** - Add new SSH users
2. **Delete User** - Remove existing users  
3. **Set SSH Limits** - Configure connection limits
4. **Configure Stunnel** - Setup tunnel parameters
5. **Start/Stop/Restart** - Service management
6. **View Logs** - Monitor activity
7. **Show Status** - Check service status

### Command Line Options
```bash
./ssh-stunnel-manager.sh [command] [options]

Commands:
  menu                    - Interactive menu
  install                 - Install dependencies
  start [options]         - Start tunnel
  stop                    - Stop tunnel
  restart [options]       - Restart tunnel
  status                  - Show status
  logs [lines]            - View logs

Start/Restart Options:
  --host HOST             - Target server
  --ssh-port PORT         - SSH port (default: 22)
  --local-port PORT       - Local port (default: 8443)
  --cert PATH             - Certificate path
  --key PATH              - Key path
```

## 🐛 Troubleshooting

### Common Issues

**Permission Denied**
```bash
sudo chmod +x ssh-stunnel-manager.sh
sudo ./ssh-stunnel-manager.sh install
```

**Package Installation Failed**
```bash
# Update package lists
sudo apt update  # Ubuntu/Debian
sudo yum update  # CentOS/RHEL
```

**Stunnel Won't Start**
```bash
# Check logs
./ssh-stunnel-manager.sh logs
# Verify configuration
sudo stunnel -version
```

## 📝 License

MIT License - Feel free to use and modify

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/mkkelati/stunnel5/issues)
- **Documentation**: This README
- **Logs**: Check `/var/log/ssh-stunnel.log`

---

⭐ **Star this repository if it helped you!**
