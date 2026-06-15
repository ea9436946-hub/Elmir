#!/bin/bash
# Wazuh Agent Fehler beheben und starten
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[+]${NC} $1"; }
err() { echo -e "${RED}[x]${NC} $1"; }

MANAGER_IP="192.168.0.187"
AGENT_NAME="kali-digital1"

log "Stoppe und bereinige alten Agent..."
systemctl stop wazuh-agent 2>/dev/null || true
systemctl disable wazuh-agent 2>/dev/null || true

# Alte Konfiguration vollständig entfernen
rm -f /var/ossec/etc/ossec.conf
rm -f /var/ossec/etc/client.keys

log "Schreibe saubere Konfiguration..."
cat > /var/ossec/etc/ossec.conf <<EOF
<ossec_config>
  <client>
    <server>
      <address>${MANAGER_IP}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>debian, debian12</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
  </syscheck>

  <active-response>
    <disabled>no</disabled>
  </active-response>
</ossec_config>
EOF

chown root:wazuh /var/ossec/etc/ossec.conf
chmod 640 /var/ossec/etc/ossec.conf

log "Registriere Agent beim Manager..."
/var/ossec/bin/agent-auth -m "$MANAGER_IP" -A "$AGENT_NAME"

log "Starte Wazuh Agent..."
systemctl enable wazuh-agent
systemctl start wazuh-agent
sleep 5

STATUS=$(systemctl is-active wazuh-agent)
if [ "$STATUS" = "active" ]; then
    log "Agent läuft!"
    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║  Wazuh Agent erfolgreich verbunden!      ║"
    echo "╠══════════════════════════════════════════╣"
    echo "║  Manager : $MANAGER_IP"
    echo "║  Name    : $AGENT_NAME"
    echo "║  Status  : AKTIV"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "Dashboard: https://$MANAGER_IP"
    echo "Logs: tail -f /var/ossec/logs/ossec.log"
else
    err "Agent startet nicht. Letzte Logs:"
    journalctl -u wazuh-agent --no-pager -n 20
fi
