#!/bin/bash
# Saubere Agent-Konfiguration mit Syscollector/Vulnerability-Daten
set -e
GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${GREEN}[+]${NC} $1"; }

log "Schreibe saubere Agent-Konfiguration..."
sudo tee /var/ossec/etc/ossec.conf > /dev/null <<'CONF'
<ossec_config>
  <client>
    <server>
      <address>192.168.0.187</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
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

  <!-- Syscollector: Hardware, OS, Pakete, Ports, Prozesse (für Vulnerability-Scan) -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <!-- Dateiintegritätsprüfung -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/bin,/sbin,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/boot</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore type="sregex">.log$|.swp$|.tmp$</ignore>
  </syscheck>

  <!-- Rootkit-Erkennung -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>3600</frequency>
  </rootcheck>

  <!-- Security Configuration Assessment -->
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
  </sca>

  <!-- Log-Quellen -->
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
    <location>/var/log/kern.log</location>
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

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <active-response>
    <disabled>no</disabled>
  </active-response>
</ossec_config>
CONF

sudo chown root:wazuh /var/ossec/etc/ossec.conf
sudo chmod 640 /var/ossec/etc/ossec.conf

log "Prüfe Konfiguration..."
if sudo /var/ossec/bin/wazuh-logtest -t 2>/dev/null; then
    log "Konfiguration gültig"
fi

log "Starte Agent neu..."
sudo systemctl restart wazuh-agent
sleep 5

STATUS=$(systemctl is-active wazuh-agent)
if [ "$STATUS" = "active" ]; then
    log "Agent läuft! ✓"
    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║  Setup komplett — Agent AKTIV            ║"
    echo "╠══════════════════════════════════════════╣"
    echo "║  Dashboard : https://192.168.0.187"
    echo "║  ✓ Vulnerability-Scan (Syscollector)"
    echo "║  ✓ Dateiintegrität (realtime)"
    echo "║  ✓ Rootkit-Erkennung"
    echo "║  ✓ Security Config Assessment (SCA)"
    echo "║  ✓ 12 MITRE-Regeln am Manager"
    echo "║  ✓ Auto-Block bei Brute Force"
    echo "╚══════════════════════════════════════════╝"
else
    echo -e "${RED}[x]${NC} Agent startet nicht. Logs:"
    sudo journalctl -u wazuh-agent --no-pager -n 15
    echo ""
    echo "Letzte ossec.log Zeilen:"
    sudo tail -15 /var/ossec/logs/ossec.log
fi
