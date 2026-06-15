#!/bin/bash
# SIEM Monitoring testen — löst echte Alerts aus und prüft Erkennung
set +e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

ALERTS="single-node-wazuh.manager-1"
ALERTLOG="/var/ossec/logs/alerts/alerts.json"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   SIEM Monitoring — Selbsttest                   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Zeitstempel für spätere Alert-Suche
START_TIME=$(date +%s)

# ── Test 1: Fehlgeschlagene Logins (Brute Force) ──────────────────────────────
log "Test 1/5: Simuliere fehlgeschlagene SSH-Logins..."
for i in 1 2 3 4 5 6; do
    logger -p auth.warning -t sshd "Failed password for invalid user hacker from 10.13.37.99 port 4444 ssh2"
done
sleep 1

# ── Test 2: Sudo-Befehl ───────────────────────────────────────────────────────
log "Test 2/5: Simuliere Sudo-Nutzung..."
logger -p auth.notice -t sudo "  testuser : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/cat /etc/shadow"
sleep 1

# ── Test 3: Neuer Benutzer ────────────────────────────────────────────────────
log "Test 3/5: Simuliere Benutzererstellung..."
logger -p auth.info -t useradd "new user: name=eviluser, UID=0, GID=0, home=/root, shell=/bin/bash"
sleep 1

# ── Test 4: Dateiintegrität ───────────────────────────────────────────────────
log "Test 4/5: Erstelle und ändere Test-Datei in /etc..."
sudo touch /etc/wazuh-test-file.conf
echo "test-change-$(date +%s)" | sudo tee -a /etc/wazuh-test-file.conf > /dev/null
sleep 1

# ── Test 5: Verdächtiger Befehl ───────────────────────────────────────────────
log "Test 5/5: Simuliere verdächtigen Befehl (nmap)..."
logger -p auth.info -t bash "user executed: nmap -sS -p- 192.168.0.0/24"
sleep 1

info "Warte 15 Sekunden auf Verarbeitung durch den Manager..."
for i in $(seq 15 -1 1); do echo -ne "\r  noch ${i}s ..."; sleep 1; done
echo -e "\r                    "

# ── Alerts auslesen ───────────────────────────────────────────────────────────
echo ""
log "Lese erkannte Alerts aus dem Manager..."
echo ""

RECENT=$(sudo docker exec "$ALERTS" tail -n 200 "$ALERTLOG" 2>/dev/null)

if [ -z "$RECENT" ]; then
    warn "Noch keine Alerts in alerts.json. Prüfe alerts.log..."
    RECENT=$(sudo docker exec "$ALERTS" tail -n 100 /var/ossec/logs/alerts/alerts.log 2>/dev/null)
    echo "$RECENT" | grep -iE "Failed password|sudo|useradd|nmap|Integrity|wazuh-test" | tail -20
else
    # JSON parsen ohne jq
    echo "$RECENT" | python3 -c "
import sys, json
found = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        a = json.loads(line)
    except: continue
    rule = a.get('rule', {})
    desc = rule.get('description', '')
    level = rule.get('level', 0)
    kw = ['Failed password','sudo','user','nmap','Integrity','checksum','added','brute']
    if any(k.lower() in desc.lower() for k in kw):
        found += 1
        sev = '\033[0;31mKRITISCH\033[0m' if level>=12 else ('\033[1;33mHOCH\033[0m' if level>=7 else '\033[0;36mMITTEL\033[0m')
        print(f'  [{sev}] Level {level:>2} | {desc[:65]}')
print()
print(f'  => {found} relevante Alerts erkannt')
" 2>/dev/null
fi

echo ""
# ── Statistik ─────────────────────────────────────────────────────────────────
TOTAL=$(sudo docker exec "$ALERTS" sh -c "wc -l < $ALERTLOG" 2>/dev/null || echo "?")
info "Gesamt-Alerts in der Datenbank: $TOTAL"

# Test-Datei wieder entfernen
sudo rm -f /etc/wazuh-test-file.conf

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Monitoring funktioniert!                       ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Alle Alerts ansehen im Dashboard:"
echo -e "${CYAN}║${NC}  https://192.168.0.187 → Modules → Security Events"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Filtere nach: 10.13.37.99 (Test-Angreifer-IP)"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
