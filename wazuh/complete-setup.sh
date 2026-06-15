#!/bin/bash
# Wazuh vollständige Konfiguration — Email Alerts + Vulnerability Scan + Active Response
set -e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

MANAGER="single-node-wazuh.manager-1"

# ── 1. Email-Konfiguration abfragen ──────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     Wazuh Komplett-Konfiguration                 ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "Gmail-Adresse für Alerts (Enter zum Überspringen): " EMAIL_TO
if [ -n "$EMAIL_TO" ]; then
    read -rp "Gmail App-Passwort (https://myaccount.google.com/apppasswords): " EMAIL_PASS
    EMAIL_FROM="$EMAIL_TO"
    SMTP_HOST="smtp.gmail.com"
    SMTP_PORT="587"
    SEND_EMAIL=true
else
    SEND_EMAIL=false
    warn "Email-Alerts übersprungen"
fi

# ── 2. Manager ossec.conf schreiben ──────────────────────────────────────────
log "Schreibe vollständige Manager-Konfiguration..."

sudo docker exec "$MANAGER" bash -c "cat > /var/ossec/etc/ossec.conf" <<MANAGERCONF
<ossec_config>

  <!-- Global -->
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>$([ "$SEND_EMAIL" = true ] && echo yes || echo no)</email_notification>
$(if [ "$SEND_EMAIL" = true ]; then
echo "    <smtp_server>$SMTP_HOST</smtp_server>"
echo "    <email_from>$EMAIL_FROM</email_from>"
echo "    <email_to>$EMAIL_TO</email_to>"
echo "    <email_maxperhour>12</email_maxperhour>"
echo "    <email_log_source>alerts.log</email_log_source>"
fi)
  </global>

  <!-- Alerts Schwellwert -->
  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>10</email_alert_level>
  </alerts>

  <!-- Remote -->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Vulnerability Detector -->
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <min_full_scan_interval>6h</min_full_scan_interval>
    <run_on_start>yes</run_on_start>

    <provider name="canonical">
      <enabled>yes</enabled>
      <os>focal</os>
      <os>jammy</os>
      <update_interval>1h</update_interval>
    </provider>

    <provider name="debian">
      <enabled>yes</enabled>
      <os>bookworm</os>
      <os>bullseye</os>
      <update_interval>1h</update_interval>
    </provider>

    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>

  <!-- Active Response -->
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <!-- Auto-Block bei Brute Force (10min) -->
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100001,5763,5764</rules_id>
    <timeout>600</timeout>
  </active-response>

  <active-response>
    <!-- host-deny bei Brute Force -->
    <command>host-deny</command>
    <location>local</location>
    <rules_id>100001</rules_id>
    <timeout>600</timeout>
  </active-response>

  <!-- Syscheck -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/bin,/sbin,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/boot</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/mnttab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore type="sregex">.log$|.swp$|.tmp$</ignore>
  </syscheck>

  <!-- Rootcheck -->
  <rootcheck>
    <disabled>no</disabled>
    <check_unixaudit>yes</check_unixaudit>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>3600</frequency>
  </rootcheck>

  <!-- Log-Analyse -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <!-- Regelverzeichnisse -->
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <!-- API -->
  <api>
    <behind_proxy_server>no</behind_proxy_server>
  </api>

  <!-- Cluster (single node) -->
  <cluster>
    <name>wazuh</name>
    <node_name>master-node</node_name>
    <node_type>master</node_type>
    <key>c98b62a9993d2f10b09e4b79bc58913b</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>127.0.0.1</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

</ossec_config>
MANAGERCONF

# ── 3. Email SMTP Auth (falls aktiviert) ─────────────────────────────────────
if [ "$SEND_EMAIL" = true ]; then
    log "Konfiguriere SMTP Authentication..."
    sudo docker exec "$MANAGER" bash -c "
    apt-get install -y libsasl2-modules postfix 2>/dev/null || true
    echo '[smtp.gmail.com]:587 ${EMAIL_FROM}:${EMAIL_PASS}' > /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
    chmod 600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
    postconf -e 'relayhost=[smtp.gmail.com]:587'
    postconf -e 'smtp_sasl_auth_enable=yes'
    postconf -e 'smtp_sasl_password_maps=hash:/etc/postfix/sasl_passwd'
    postconf -e 'smtp_sasl_security_options=noanonymous'
    postconf -e 'smtp_tls_security_level=encrypt'
    service postfix restart 2>/dev/null || true
    " 2>/dev/null
fi

# ── 4. Lokale Regeln ──────────────────────────────────────────────────────────
log "Schreibe erweiterte Erkennungsregeln..."
sudo docker exec "$MANAGER" bash -c "cat > /var/ossec/etc/rules/local_rules.xml" <<'RULES'
<group name="local,siem,">

  <rule id="100001" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5760</if_matched_sid>
    <description>SSH Brute Force: 5 Fehlversuche in 60s von $(srcip)</description>
    <mitre><id>T1110</id></mitre>
    <group>authentication_failures,brute_force,</group>
  </rule>

  <rule id="100002" level="12">
    <if_sid>5501</if_sid>
    <user>root</user>
    <description>Root-Login erfolgreich</description>
    <mitre><id>T1078</id></mitre>
    <group>authentication_success,privilege_escalation,</group>
  </rule>

  <rule id="100003" level="8">
    <if_sid>5402</if_sid>
    <description>Sudo-Befehl ausgeführt</description>
    <mitre><id>T1548.003</id></mitre>
    <group>sudo,privilege_escalation,</group>
  </rule>

  <rule id="100004" level="10">
    <if_sid>5902</if_sid>
    <description>Neuer Benutzer angelegt</description>
    <mitre><id>T1136</id></mitre>
    <group>account_changes,</group>
  </rule>

  <rule id="100005" level="14">
    <if_sid>5400</if_sid>
    <match>nc |ncat |netcat |/dev/tcp/|bash -i &gt;&amp;</match>
    <description>Mögliche Reverse Shell erkannt</description>
    <mitre><id>T1059</id></mitre>
    <group>attack,reverse_shell,</group>
  </rule>

  <rule id="100006" level="10">
    <if_sid>5400</if_sid>
    <match>nmap |masscan |zmap |nikto |gobuster |dirb </match>
    <description>Reconnaissance-Tool ausgeführt</description>
    <mitre><id>T1046</id></mitre>
    <group>recon,</group>
  </rule>

  <rule id="100007" level="13">
    <if_sid>550</if_sid>
    <match>/etc/passwd|/etc/shadow|/etc/sudoers</match>
    <description>Kritische Systemdatei geändert</description>
    <mitre><id>T1003</id></mitre>
    <group>integrity_check,attack,</group>
  </rule>

  <rule id="100008" level="10">
    <if_sid>550,554</if_sid>
    <match>/etc/cron|/var/spool/cron|/etc/crontab</match>
    <description>Cron Job geändert — mögliche Persistenz</description>
    <mitre><id>T1053</id></mitre>
    <group>persistence,</group>
  </rule>

  <rule id="100009" level="9" frequency="10" timeframe="30">
    <if_matched_sid>31101</if_matched_sid>
    <description>Web-Scan: 10x HTTP 404 in 30s</description>
    <mitre><id>T1595</id></mitre>
    <group>web,scan,</group>
  </rule>

  <rule id="100010" level="12">
    <if_sid>5400</if_sid>
    <match>chmod 777|chmod +s|chown root</match>
    <description>Verdächtige Rechteänderung erkannt</description>
    <mitre><id>T1548</id></mitre>
    <group>attack,privilege_escalation,</group>
  </rule>

  <rule id="100011" level="11">
    <if_sid>5400</if_sid>
    <match>wget |curl </match>
    <regex>http[s]?://\d+\.\d+\.\d+\.\d+</regex>
    <description>Download von IP-Adresse (kein Domainname)</description>
    <mitre><id>T1105</id></mitre>
    <group>attack,download,</group>
  </rule>

  <rule id="100012" level="14" frequency="3" timeframe="120">
    <if_matched_sid>100002</if_matched_sid>
    <description>Wiederholte Root-Logins — Kontrollverlust möglich</description>
    <mitre><id>T1078</id></mitre>
    <group>attack,privilege_escalation,</group>
  </rule>

</group>
RULES

# ── 5. Agent Vulnerability-Scan aktivieren ────────────────────────────────────
log "Aktiviere Vulnerability-Scan im Agent..."
cat >> /var/ossec/etc/ossec.conf <<'VULN'

  <!-- Vulnerability Detection -->
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
VULN

# ── 6. Manager neu starten ────────────────────────────────────────────────────
log "Starte Manager neu..."
sudo docker restart "$MANAGER"
sleep 15

# ── 7. Agent neu starten ──────────────────────────────────────────────────────
log "Starte Agent neu..."
sudo chown root:wazuh /var/ossec/etc/ossec.conf 2>/dev/null || true
sudo chmod 640 /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
sleep 5

STATUS=$(systemctl is-active wazuh-agent)

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║      Wazuh vollständig konfiguriert!             ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Dashboard  : https://192.168.0.187"
echo -e "${CYAN}║${NC}  Agent      : $STATUS"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  ✓ Brute Force → Auto-Block (10min)"
echo -e "${CYAN}║${NC}  ✓ Vulnerability Scan aktiv"
echo -e "${CYAN}║${NC}  ✓ 12 Erkennungsregeln (MITRE ATT&CK)"
echo -e "${CYAN}║${NC}  ✓ Realtime Dateiintegritätsprüfung"
$([ "$SEND_EMAIL" = true ] && echo -e "${CYAN}║${NC}  ✓ Email-Alerts an $EMAIL_TO" || echo -e "${CYAN}║${NC}  - Email-Alerts nicht eingerichtet")
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
