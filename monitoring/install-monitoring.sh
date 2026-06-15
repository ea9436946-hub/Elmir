#!/bin/bash
# Komplettes System-Monitoring einrichten
# Wazuh (SIEM) + Suricata (IDS) + Prometheus + Grafana + Elmir
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

HOST_IP=$(hostname -I | awk '{print $1}')
SCRIPT_DIR="$(dirname "$(realpath "$0")")"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Komplettes SIEM + System-Monitoring Setup          ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║  Wazuh SIEM  ✓ (bereits aktiv)                       ║${NC}"
echo -e "${CYAN}║  Suricata IDS  → wird installiert                    ║${NC}"
echo -e "${CYAN}║  Prometheus    → wird installiert                    ║${NC}"
echo -e "${CYAN}║  Grafana       → wird installiert                    ║${NC}"
echo -e "${CYAN}║  Elmir SIEM    → wird installiert                    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Netzwerk-Interface erkennen ───────────────────────────────────────────────
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
log "Erkanntes Netzwerk-Interface: $IFACE"
sed -i "s/- interface: eth0/- interface: $IFACE/" "$SCRIPT_DIR/config/suricata/suricata.yaml"
sed -i "s/-i eth0/-i $IFACE/" "$SCRIPT_DIR/docker-compose.monitoring.yml"

# ── vm.max_map_count setzen ───────────────────────────────────────────────────
sysctl -w vm.max_map_count=262144 >/dev/null

# ── Stack starten ─────────────────────────────────────────────────────────────
log "Starte Monitoring-Stack (Suricata, Prometheus, Grafana, Elmir)..."
cd "$SCRIPT_DIR"
docker compose -f docker-compose.monitoring.yml up -d

log "Warte auf Grafana..."
for i in $(seq 1 24); do
    if curl -s http://localhost:3000/api/health 2>/dev/null | grep -q "ok"; then
        break
    fi
    sleep 5
done

# ── Grafana: Node-Exporter Dashboard importieren ──────────────────────────────
log "Importiere Grafana Dashboards..."

# Node Exporter Full (ID 1860)
curl -s -X POST http://admin:Monitor2024!@localhost:3000/api/dashboards/import \
    -H "Content-Type: application/json" \
    -d '{
        "dashboard": null,
        "inputs": [{"name": "DS_PROMETHEUS", "type": "datasource", "pluginId": "prometheus", "value": "Prometheus"}],
        "folderId": 0,
        "overwrite": true,
        "path": "https://grafana.com/api/dashboards/1860/revisions/latest/download"
    }' > /dev/null 2>&1 || true

# Alternativ: Direkt via API herunterladen und importieren
DASH_JSON=$(curl -s "https://grafana.com/api/dashboards/1860/revisions/latest/download" 2>/dev/null)
if [ -n "$DASH_JSON" ]; then
    curl -s -X POST "http://admin:Monitor2024!@localhost:3000/api/dashboards/import" \
        -H "Content-Type: application/json" \
        -d "{\"dashboard\": $DASH_JSON, \"overwrite\": true, \"inputs\": [{\"name\": \"DS_PROMETHEUS\", \"type\": \"datasource\", \"pluginId\": \"prometheus\", \"value\": \"Prometheus\"}], \"folderId\": 0}" \
        > /dev/null 2>&1 && log "Node-Exporter Dashboard importiert" || warn "Dashboard-Import übersprungen (kein Internet)"
fi

# ── Wazuh: Suricata-Logs integrieren ──────────────────────────────────────────
log "Integriere Suricata-Logs in Wazuh Agent..."
if ! grep -q "suricata" /var/ossec/etc/ossec.conf 2>/dev/null; then
    sudo sed -i '/<\/ossec_config>/i\
  <localfile>\
    <log_format>json</log_format>\
    <location>/var/lib/docker/volumes/monitoring_suricata-logs/_data/eve.json</location>\
    <label key="app">suricata</label>\
  </localfile>' /var/ossec/etc/ossec.conf
    sudo systemctl restart wazuh-agent
    log "Suricata-Logs in Wazuh eingebunden"
fi

# ── Status ausgeben ───────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Komplettes Monitoring AKTIV!                       ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🛡  Wazuh SIEM       https://${HOST_IP}"
echo -e "${CYAN}║${NC}      Login: admin / SecretPassword"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  📊  Grafana          http://${HOST_IP}:3000"
echo -e "${CYAN}║${NC}      Login: admin / Monitor2024!"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  📈  Prometheus       http://${HOST_IP}:9090"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🔍  Elmir SIEM       http://${HOST_IP}:8080"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  🚨  Suricata IDS     läuft auf $IFACE"
echo -e "${CYAN}║${NC}      Logs: docker logs suricata"
echo -e "${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Was wird überwacht:"
echo -e "${CYAN}║${NC}  ✓ System (CPU, RAM, Disk, Netzwerk) → Grafana"
echo -e "${CYAN}║${NC}  ✓ Sicherheitsereignisse (Logins, Sudo) → Wazuh"
echo -e "${CYAN}║${NC}  ✓ Netzwerkverkehr & Angriffe → Suricata"
echo -e "${CYAN}║${NC}  ✓ Dateiintegrität (/etc, /bin, /usr) → Wazuh"
echo -e "${CYAN}║${NC}  ✓ Schwachstellen (CVEs) → Wazuh"
echo -e "${CYAN}║${NC}  ✓ Log-Aggregation → Elmir"
echo -e "${CYAN}║${NC}  ✓ Alerts → Alertmanager"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
