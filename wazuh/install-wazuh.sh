#!/bin/bash
# Wazuh All-in-One Installation Script
# Läuft auf: Ubuntu 20.04/22.04, Debian 10/11, CentOS 7/8, RHEL 7/8/9
# Quelle: https://documentation.wazuh.com/current/quickstart.html

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

# Root-Check
[[ $EUID -ne 0 ]] && err "Dieses Skript muss als root ausgeführt werden: sudo $0"

log "Wazuh All-in-One Installation startet..."

# Systemerkennung
if   [ -f /etc/debian_version ]; then DISTRO="debian"
elif [ -f /etc/redhat-release ]; then DISTRO="redhat"
else err "Nicht unterstütztes Betriebssystem"
fi

# Mindestanforderungen prüfen
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
DISK_GB=$(df -BG / | awk 'NR==2{gsub("G",""); print $4}')
[[ $RAM_MB -lt 4096 ]] && warn "Empfohlen: mindestens 4 GB RAM (vorhanden: ${RAM_MB} MB)"
[[ $DISK_GB -lt 50  ]] && warn "Empfohlen: mindestens 50 GB freier Speicher (vorhanden: ${DISK_GB} GB)"

# ── Abhängigkeiten ────────────────────────────────────────────────────────────
log "Installiere Abhängigkeiten..."
if [ "$DISTRO" = "debian" ]; then
    apt-get update -q
    apt-get install -y curl apt-transport-https lsb-release gnupg2
else
    yum install -y curl
fi

# ── Wazuh Assistant herunterladen & ausführen ─────────────────────────────────
log "Lade Wazuh-Installationsassistenten herunter..."
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Standard-Konfiguration schreiben (Single-Node)
cat > config.yml <<'EOF'
nodes:
  indexer:
    - name: node-1
      ip: "127.0.0.1"

  server:
    - name: wazuh-1
      ip: "127.0.0.1"

  dashboard:
    - name: dashboard
      ip: "127.0.0.1"
EOF

log "Generiere SSL-Zertifikate..."
bash wazuh-install.sh --generate-config-files

log "Installiere Wazuh Indexer..."
bash wazuh-install.sh --wazuh-indexer node-1

log "Installiere Wazuh Server..."
bash wazuh-install.sh --wazuh-server wazuh-1

log "Installiere Wazuh Dashboard..."
bash wazuh-install.sh --wazuh-dashboard dashboard

# ── Passwörter aus dem generierten Paket lesen ───────────────────────────────
PASS_FILE="wazuh-passwords.txt"
if [ -f "wazuh-install-files/wazuh-passwords.txt" ]; then
    PASS_FILE="wazuh-install-files/wazuh-passwords.txt"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
log "Installation abgeschlossen!"
echo ""
echo "  Dashboard URL : https://$(hostname -I | awk '{print $1}')"
echo "  Benutzer      : admin"
echo "  Passwort      : $(grep 'indexer_password\|admin' $PASS_FILE 2>/dev/null | head -1 | awk '{print $NF}' || echo 'Siehe wazuh-passwords.txt')"
echo ""
echo "  Wazuh API     : https://$(hostname -I | awk '{print $1}'):55000"
echo ""
warn "Passwörter wurden in $PASS_FILE gespeichert — sicher aufbewahren!"
echo "════════════════════════════════════════════════════════════"
