#!/bin/bash
# Wazuh SIEM Monitoring vollständig einrichten
set -e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

MANAGER="single-node-wazuh.manager-1"

# ── 1. Eigene Monitoring-Regeln ───────────────────────────────────────────────
log "Schreibe eigene Erkennungsregeln..."
sudo docker exec "$MANAGER" bash -c "cat > /var/ossec/etc/rules/local_rules.xml" <<'RULES'
<group name="local,siem-monitoring,">

  <!-- Brute Force SSH -->
  <rule id="100001" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5760</if_matched_sid>
    <description>Brute Force SSH: 5 fehlgeschlagene Logins in 60s</description>
    <group>authentication_failures,brute_force,</group>
  </rule>

  <!-- Root Login -->
  <rule id="100002" level="12">
    <if_sid>5501</if_sid>
    <user>root</user>
    <description>Root-Login erkannt</description>
    <group>authentication_success,privilege_escalation,</group>
  </rule>

  <!-- Sudo Befehl -->
  <rule id="100003" level="8">
    <if_sid>5402</if_sid>
    <description>Sudo-Befehl ausgeführt</description>
    <group>sudo,</group>
  </rule>

  <!-- Neue Benutzer angelegt -->
  <rule id="100004" level="10">
    <if_sid>5902</if_sid>
    <description>Neuer Benutzer angelegt</description>
    <group>account_changes,</group>
  </rule>

  <!-- Paket installiert -->
  <rule id="100005" level="6">
    <match>status installed</match>
    <description>Paket installiert via dpkg</description>
    <group>package_install,</group>
  </rule>

  <!-- Netcat / Reverse Shell Tools -->
  <rule id="100006" level="14">
    <if_sid>5400</if_sid>
    <match>nc |ncat |netcat |/dev/tcp/|bash -i</match>
    <description>Mögliche Reverse Shell erkannt</description>
    <group>attack,reverse_shell,</group>
  </rule>

  <!-- Nmap Scan erkannt -->
  <rule id="100007" level="10">
    <if_sid>5400</if_sid>
    <match>nmap |masscan |zmap </match>
    <description>Port-Scanner ausgeführt</description>
    <group>recon,port_scan,</group>
  </rule>

  <!-- /etc/passwd oder /etc/shadow geändert -->
  <rule id="100008" level="13">
    <if_sid>550</if_sid>
    <match>/etc/passwd|/etc/shadow|/etc/sudoers</match>
    <description>Kritische Systemdatei geändert</description>
    <group>integrity_check,attack,</group>
  </rule>

  <!-- Viele 404 Fehler (Web-Scan) -->
  <rule id="100009" level="8" frequency="20" timeframe="30">
    <if_matched_sid>31101</if_matched_sid>
    <description>Web-Scan erkannt: 20x HTTP 404 in 30s</description>
    <group>web,scan,</group>
  </rule>

  <!-- Cron Job geändert -->
  <rule id="100010" level="10">
    <if_sid>550,554</if_sid>
    <match>/etc/cron|/var/spool/cron</match>
    <description>Cron Job geändert — mögliche Persistenz</description>
    <group>persistence,</group>
  </rule>

</group>
RULES

# ── 2. Erweiterte Agent-Konfiguration ────────────────────────────────────────
log "Erweitere Agent-Monitoring Konfiguration..."
cat > /var/ossec/etc/ossec.conf <<'CONF'
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

  <!-- Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/bin,/sbin</directories>
    <directories check_all="yes" realtime="yes">/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/boot</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/mnttab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore type="sregex">.log$|.tmp$|.swp$</ignore>
  </syscheck>

  <!-- Rootcheck -->
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
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>

  <!-- Systeminfos -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>netstat -tulpn</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 5</command>
    <frequency>360</frequency>
  </localfile>

  <active-response>
    <disabled>no</disabled>
  </active-response>
</ossec_config>
CONF

# ── 3. Manager neu laden ──────────────────────────────────────────────────────
log "Lade Manager-Regeln neu..."
sudo docker exec "$MANAGER" /var/ossec/bin/wazuh-control restart 2>/dev/null || \
sudo docker restart "$MANAGER"

# ── 4. Agent neu starten ──────────────────────────────────────────────────────
log "Starte Agent neu..."
sudo chown root:wazuh /var/ossec/etc/ossec.conf
sudo chmod 640 /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
sleep 5

echo ""
echo -e "\033[0;36m╔══════════════════════════════════════════════════╗\033[0m"
echo -e "\033[0;36m║       SIEM Monitoring vollständig eingerichtet!  ║\033[0m"
echo -e "\033[0;36m╠══════════════════════════════════════════════════╣\033[0m"
echo -e "\033[0;36m║\033[0m  Dashboard    : https://192.168.0.187"
echo -e "\033[0;36m║\033[0m  Benutzer     : admin / SecretPassword"
echo -e "\033[0;36m║\033[0m"
echo -e "\033[0;36m║\033[0m  Überwacht wird:"
echo -e "\033[0;36m║\033[0m  ✓ SSH Brute Force"
echo -e "\033[0;36m║\033[0m  ✓ Root-Logins"
echo -e "\033[0;36m║\033[0m  ✓ Sudo-Befehle"
echo -e "\033[0;36m║\033[0m  ✓ Neue Benutzer"
echo -e "\033[0;36m║\033[0m  ✓ Reverse Shells"
echo -e "\033[0;36m║\033[0m  ✓ Port-Scanner (nmap)"
echo -e "\033[0;36m║\033[0m  ✓ Dateiänderungen /etc /bin /usr"
echo -e "\033[0;36m║\033[0m  ✓ Cron-Job Änderungen"
echo -e "\033[0;36m║\033[0m  ✓ Web-Scans (404-Flood)"
echo -e "\033[0;36m║\033[0m  ✓ Rootkit-Erkennung"
echo -e "\033[0;36m╚══════════════════════════════════════════════════╝\033[0m"
