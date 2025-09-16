# 🍯 Multi-Service Honeypot

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Educational](https://img.shields.io/badge/Security-Educational%20Only-red.svg)](#warning)

A comprehensive, multi-service honeypot system designed for cybersecurity education, threat intelligence gathering, and attack pattern analysis.

## ⚠️ Warning

**This tool is for educational and research purposes only.** Deploy only in isolated, controlled environments. The authors are not responsible for any misuse or damage caused by this software.

## 🌟 Features

### Multi-Service Support
- **SSH Honeypot** (Port 2222) - Captures login attempts and commands
- **HTTP Honeypot** (Port 8080) - Detects web attacks (SQLi, XSS, LFI, RCE)
- **FTP Honeypot** (Port 2121) - Logs file transfer attempts  
- **Telnet Honeypot** (Port 2323) - Monitors remote access attempts

### Advanced Analytics
- 📊 Real-time attack pattern detection
- 🌍 Geographic attack distribution analysis
- 🔐 Credential harvesting and analysis
- 📈 Temporal pattern recognition
- 📋 Automated report generation
- 📉 Data visualization with charts and graphs

### Security & Deployment
- 🔒 Isolated deployment environment
- 🛡️ Firewall integration
- 📝 Comprehensive logging
- 🔄 Log rotation and management
- 🚨 Fail2ban integration
- 📱 Monitoring and alerting

## 🚀 Quick Start

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip ufw fail2ban

# Install Python dependencies
pip3 install matplotlib
```

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/chachu32/multi-service-honeypot.git
   cd multi-service-honeypot
   ```

2. **Run the deployment script** (for production setup)
   ```bash
   sudo chmod +x deploy.sh
   sudo ./deploy.sh
   ```

3. **Or run manually** (for testing)
   ```bash
   python3 honeypot.py --help
   ```

### Basic Usage

```bash
# Start all services
python3 honeypot.py

# Start specific services
python3 honeypot.py --services ssh http

# Custom ports
python3 honeypot.py --ssh-port 2222 --http-port 8080

# Analyze logs
python3 analyzer.py --report --visualize
```

## 📁 Project Structure

```
multi-service-honeypot/
├── honeypot.py          # Main honeypot application
├── analyzer.py          # Log analysis and reporting tool
├── deploy.sh           # Automated deployment script
├── README.md           # This file
├── LICENSE             # MIT License
├── requirements.txt    # Python dependencies
└── docs/
    ├── deployment.md   # Deployment guide
    ├── analysis.md     # Analysis guide
    └── security.md     # Security considerations
```

## 🔧 Configuration

### Command Line Options

```bash
usage: honeypot.py [-h] [--host HOST] [--ssh-port SSH_PORT] 
                   [--http-port HTTP_PORT] [--ftp-port FTP_PORT]
                   [--telnet-port TELNET_PORT] 
                   [--services {ssh,http,ftp,telnet} [{ssh,http,ftp,telnet} ...]]

Multi-Service Honeypot

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           Host to bind to (default: 0.0.0.0)
  --ssh-port SSH_PORT   SSH port (default: 2222)
  --http-port HTTP_PORT HTTP port (default: 8080)
  --ftp-port FTP_PORT   FTP port (default: 2121)
  --telnet-port TELNET_PORT Telnet port (default: 2323)
  --services {ssh,http,ftp,telnet} [{ssh,http,ftp,telnet} ...]
                        Services to enable (default: all)
```

### Environment Variables

```bash
export HONEYPOT_HOST="0.0.0.0"
export HONEYPOT_LOG_LEVEL="INFO"
export HONEYPOT_LOG_FILE="honeypot.log"
```

## 📊 Analysis & Reporting

### Generate Reports

```bash
# Basic analysis
python3 analyzer.py

# Full report with visualizations
python3 analyzer.py --report --visualize

# Custom log file
python3 analyzer.py --log-file custom_honeypot_data.json --report
```

### Sample Output

```
# Honeypot Analysis Report
Generated: 2024-01-15 14:30:22

## Summary
- Total log entries: 1,247
- Unique attacking IPs: 89
- Total attack attempts: 2,156
- Services targeted: 4

## Top Attacking IPs
- 192.168.1.100: 234 attempts
- 10.0.0.50: 156 attempts
- 172.16.0.25: 98 attempts

## Service Targeting
- SSH: 892 attempts (41.4%)
- HTTP: 654 attempts (30.3%)
- FTP: 387 attempts (17.9%)
- Telnet: 223 attempts (10.3%)
```

## 🛡️ Security Considerations

### Deployment Best Practices

1. **Isolation**: Deploy in isolated VMs or containers
2. **Network Segmentation**: Use separate network segments
3. **Monitoring**: Implement continuous monitoring
4. **Updates**: Keep system and dependencies updated
5. **Backup**: Regular backup of logs and configurations

### Firewall Configuration

```bash
# Allow honeypot ports
sudo ufw allow 2222/tcp  # SSH
sudo ufw allow 8080/tcp  # HTTP
sudo ufw allow 2121/tcp  # FTP
sudo ufw allow 2323/tcp  # Telnet

# Deny all other incoming
sudo ufw default deny incoming
```

## 📚 Educational Use Cases

### Learning Objectives

- **Threat Intelligence**: Understanding attack methodologies
- **Network Security**: Service hardening and monitoring
- **Incident Response**: Attack pattern recognition
- **Python Programming**: Network programming and data analysis
- **System Administration**: Service deployment and management

### Classroom Integration

- Cybersecurity courses
- Network security labs
- Threat hunting workshops
- Security research projects
- Penetration testing education

## 🔍 Attack Detection Capabilities

### SSH Attacks
- Brute force login attempts
- Credential stuffing
- SSH protocol exploits

### HTTP Attacks
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Local File Inclusion (LFI)
- Remote Code Execution (RCE)
- Directory traversal
- Web application scanning

### FTP Attacks
- Anonymous login attempts
- Brute force authentication
- FTP bounce attacks

### Telnet Attacks
- Default credential attempts
- Brute force attacks
- Protocol exploitation

## 📈 Data Analysis Features

### Statistical Analysis
- Attack frequency patterns
- Geographic distribution
- Service popularity
- Credential analysis
- User-Agent analysis

### Visualization
- Attack timeline graphs
- Service distribution charts
- Geographic heat maps
- Hourly attack patterns
- Top attacker rankings


## 🙏 Acknowledgments

- The Honeynet Project for honeypot research
- SANS Institute for cybersecurity education resources
- Open source security community
- Contributors and maintainers


### FAQ

**Q: Is this safe to run on my production network?**
A: No! This is for educational use only. Deploy in isolated environments.

**Q: Can I modify the honeypot services?**
A: Absolutely! The code is modular and designed for customization.

**Q: How do I analyze the collected data?**
A: Use the built-in analyzer.py script or export data for external analysis.

**Q: What if I detect actual malware?**
A: Handle with extreme caution. Use proper malware analysis procedures and isolated environments.

## 🚨 Ethical Use Policy

This tool is provided for:
- ✅ Educational purposes
- ✅ Authorized security research
- ✅ Legitimate cybersecurity training
- ✅ Academic research projects

This tool should NOT be used for:
- ❌ Unauthorized network monitoring
- ❌ Illegal surveillance activities
- ❌ Production environment deployment without proper authorization
- ❌ Any activity that violates local laws or regulations


**⭐ If you found this project helpful, please consider giving it a star!**

**🔒 Remember: Deploy responsibly and ethically!**
