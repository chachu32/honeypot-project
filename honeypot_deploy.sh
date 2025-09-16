#!/bin/bash

# Honeypot Deployment Script
# Helps set up the honeypot environment safely

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
HONEYPOT_USER="honeypot"
HONEYPOT_DIR="/opt/honeypot"
LOG_DIR="/var/log/honeypot"
SERVICE_NAME="honeypot"

print_banner() {
    echo -e "${GREEN}"
    echo "=================================================="
    echo "          Honeypot Deployment Script"
    echo "=================================================="
    echo -e "${NC}"
    echo -e "${RED}WARNING: This is for educational purposes only!${NC}"
    echo -e "${RED}Deploy only in isolated environments.${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi
}

install_dependencies() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    
    # Update system
    apt-get update
    
    # Install Python and required packages
    apt-get install -y python3 python3-pip python3-venv ufw fail2ban
    
    # Install Python packages
    pip3 install matplotlib
    
    echo -e "${GREEN}Dependencies installed successfully${NC}"
}

create_honeypot_user() {
    echo -e "${YELLOW}Creating honeypot user...${NC}"
    
    if ! id "$HONEYPOT_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$HONEYPOT_DIR" "$HONEYPOT_USER"
        echo -e "${GREEN}User $HONEYPOT_USER created${NC}"
    else
        echo -e "${YELLOW}User $HONEYPOT_USER already exists${NC}"
    fi
}

setup_directories() {
    echo -e "${YELLOW}Setting up directories...${NC}"
    
    # Create honeypot directory
    mkdir -p "$HONEYPOT_DIR"
    mkdir -p "$LOG_DIR"
    
    # Set permissions
    chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR"
    chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$LOG_DIR"
    chmod 755 "$HONEYPOT_DIR"
    chmod 755 "$LOG_DIR"
    
    echo -e "${GREEN}Directories created successfully${NC}"
}

setup_firewall() {
    echo -e "${YELLOW}Configuring firewall...${NC}"
    
    # Enable UFW
    ufw --force enable
    
    # Allow SSH (change port if needed)
    ufw allow 22/tcp
    
    # Allow honeypot ports
    ufw allow 2222/tcp  # SSH honeypot
    ufw allow 8080/tcp  # HTTP honeypot
    ufw allow 2121/tcp  # FTP honeypot
    ufw allow 2323/tcp  # Telnet honeypot
    
    # Deny all other incoming by default
    ufw default deny incoming
    ufw default allow outgoing
    
    echo -e "${GREEN}Firewall configured${NC}"
}

create_systemd_service() {
    echo -e "${YELLOW}Creating systemd service...${NC}"
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Multi-Service Honeypot
After=network.target

[Service]
Type=simple
User=$HONEYPOT_USER
Group=$HONEYPOT_USER
WorkingDirectory=$HONEYPOT_DIR
ExecStart=/usr/bin/python3 $HONEYPOT_DIR/honeypot.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo -e "${GREEN}Systemd service created${NC}"
}

setup_log_rotation() {
    echo -e "${YELLOW}Setting up log rotation...${NC}"
    
    cat > "/etc/logrotate.d/honeypot" << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    copytruncate
    notifempty
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}

$HONEYPOT_DIR/*.json {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    copytruncate
    notifempty
}
EOF

    echo -e "${GREEN}Log rotation configured${NC}"
}

setup_monitoring() {
    echo -e "${YELLOW}Setting up monitoring...${NC}"
    
    # Create monitoring script
    cat > "$HONEYPOT_DIR/monitor.sh" << 'EOF'
#!/bin/bash

HONEYPOT_DIR="/opt/honeypot"
LOG_FILE="$HONEYPOT_DIR/honeypot_data.json"
ALERT_THRESHOLD=10

# Check if honeypot is running
if ! systemctl is-active --quiet honeypot; then
    echo "ALERT: Honeypot service is down"
    systemctl start honeypot
fi

# Check recent activity
if [[ -f "$LOG_FILE" ]]; then
    recent_attacks=$(tail -100 "$LOG_FILE" | wc -l)
    if [[ $recent_attacks -gt $ALERT_THRESHOLD ]]; then
        echo "HIGH ACTIVITY: $recent_attacks recent attacks detected"
    fi
fi

# Generate daily report
python3 "$HONEYPOT_DIR/analyzer.py" --report --output "/tmp/daily_report.txt"
EOF

    chmod +x "$HONEYPOT_DIR/monitor.sh"
    chown "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR/monitor.sh"
    
    # Add to crontab for regular monitoring
    (crontab -l 2>/dev/null; echo "0 */6 * * * $HONEYPOT_DIR/monitor.sh") | crontab -
    
    echo -e "${GREEN}Monitoring setup complete${NC}"
}

copy_honeypot_files() {
    echo -e "${YELLOW}Please copy the following files to $HONEYPOT_DIR:${NC}"
    echo "- honeypot.py (main honeypot script)"
    echo "- analyzer.py (log analyzer script)"
    echo ""
    echo -e "${YELLOW}After copying files, run:${NC}"
    echo "chown -R $HONEYPOT_USER:$HONEYPOT_USER $HONEYPOT_DIR"
    echo "chmod +x $HONEYPOT_DIR/honeypot.py"
    echo "chmod +x $HONEYPOT_DIR/analyzer.py"
}

setup_fail2ban() {
    echo -e "${YELLOW}Configuring fail2ban for additional security...${NC}"
    
    cat > "/etc/fail2ban/jail.local" << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log

# Honeypot protection
[honeypot]
enabled = true
port = 2222,8080,2121,2323
filter = honeypot
logpath = /var/log/honeypot/honeypot.log
maxretry = 1
bantime = 86400
EOF

    # Create filter for honeypot
    cat > "/etc/fail2ban/filter.d/honeypot.conf" << 'EOF'
[Definition]
failregex = Connection to .* from <HOST>:.*
ignoreregex =
EOF

    systemctl restart fail2ban
    echo -e "${GREEN}Fail2ban configured${NC}"
}

show_next_steps() {
    echo -e "${GREEN}"
    echo "=================================================="
    echo "          Deployment Complete!"
    echo "=================================================="
    echo -e "${NC}"
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Copy honeypot.py and analyzer.py to $HONEYPOT_DIR"
    echo "2. Set proper permissions:"
    echo "   chown -R $HONEYPOT_USER:$HONEYPOT_USER $HONEYPOT_DIR"
    echo "   chmod +x $HONEYPOT_DIR/honeypot.py"
    echo "   chmod +x $HONEYPOT_DIR/analyzer.py"
    echo ""
    echo "3. Start the honeypot service:"
    echo "   systemctl start $SERVICE_NAME"
    echo "   systemctl enable $SERVICE_NAME"
    echo ""
    echo "4. Monitor the honeypot:"
    echo "   systemctl status $SERVICE_NAME"
    echo "   tail -f $LOG_DIR/honeypot.log"
    echo ""
    echo "5. Analyze logs:"
    echo "   cd $HONEYPOT_DIR"
    echo "   python3 analyzer.py --report --visualize"
    echo ""
    echo -e "${RED}SECURITY REMINDERS:${NC}"
    echo "- Deploy only in isolated environments"
    echo "- Monitor regularly for compromise attempts"
    echo "- Keep system and dependencies updated"
    echo "- Review firewall rules periodically"
    echo "- Backup log data regularly"
    echo ""
    echo -e "${YELLOW}Useful commands:${NC}"
    echo "- Start service: systemctl start $SERVICE_NAME"
    echo "- Stop service: systemctl stop $SERVICE_NAME"
    echo "- View logs: journalctl -u $SERVICE_NAME -f"
    echo "- Check status: systemctl status $SERVICE_NAME"
}

main() {
    print_banner
    
    echo -e "${YELLOW}This script will:${NC}"
    echo "1. Install required dependencies"
    echo "2. Create honeypot user and directories"
    echo "3. Configure firewall rules"
    echo "4. Set up systemd service"
    echo "5. Configure log rotation"
    echo "6. Set up monitoring"
    echo "7. Configure fail2ban"
    echo ""
    
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Deployment cancelled."
        exit 0
    fi
    
    check_root
    install_dependencies
    create_honeypot_user
    setup_directories
    setup_firewall
    create_systemd_service
    setup_log_rotation
    setup_monitoring
    setup_fail2ban
    copy_honeypot_files
    show_next_steps
}

# Run main function
main "$@"