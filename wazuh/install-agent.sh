#!/bin/bash
# Wazuh Agent Installation — verbindet diesen Rechner mit dem Wazuh Manager
# Verwendung: sudo ./install-agent.sh <MANAGER_IP>

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && err "Als root ausführen: sudo $0 <MANAGER_IP>"
[[ -z "$1"     ]] && err "Manager-IP fehlt: sudo $0 <MANAGER_IP>"

MANAGER_IP="$1"
AGENT_NAME="${2:-$(hostname)}"

log "Installiere Wazuh Agent (Manager: $MANAGER_IP)..."

if [ -f /etc/debian_version ]; then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list
    apt-get update -q
    WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" apt-get install -y wazuh-agent
elif [ -f /etc/redhat-release ]; then
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
    WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" yum install -y wazuh-agent
else
    err "Nicht unterstütztes Betriebssystem"
fi

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

log "Agent gestartet und verbunden mit $MANAGER_IP"
echo ""
echo "  Status prüfen : systemctl status wazuh-agent"
echo "  Logs          : tail -f /var/ossec/logs/ossec.log"
