#!/bin/bash
# Wazuh Single-Node Setup — alles in einem Schritt
# Ausführen auf DEINEM Rechner: sudo bash setup.sh
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║        Wazuh SIEM — Automatisches Setup          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Voraussetzungen ───────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Als root ausführen: sudo bash $0"

RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
[[ $RAM_MB -lt 3500 ]] && warn "Wenig RAM: ${RAM_MB}MB. Wazuh benötigt mind. 4GB."

# ── Docker installieren (falls nicht vorhanden) ───────────────────────────────
if ! command -v docker &>/dev/null; then
    log "Docker nicht gefunden — installiere Docker..."
    if [ -f /etc/debian_version ]; then
        apt-get update -q
        apt-get install -y ca-certificates curl gnupg lsb-release
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg \
            | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
$(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
        apt-get update -q
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    elif [ -f /etc/redhat-release ]; then
        yum install -y yum-utils
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    fi
    systemctl enable --now docker
    log "Docker installiert"
else
    log "Docker bereits vorhanden: $(docker --version)"
fi

# ── vm.max_map_count für OpenSearch ──────────────────────────────────────────
log "Setze vm.max_map_count..."
sysctl -w vm.max_map_count=262144
grep -q vm.max_map_count /etc/sysctl.conf && \
    sed -i 's/.*vm.max_map_count.*/vm.max_map_count=262144/' /etc/sysctl.conf || \
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf

# ── Wazuh Docker-Konfiguration herunterladen ──────────────────────────────────
WAZUH_VERSION="4.7.3"
INSTALL_DIR="/opt/wazuh-docker"

log "Lade Wazuh Docker-Konfiguration ($WAZUH_VERSION)..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

curl -sL "https://github.com/wazuh/wazuh-docker/archive/refs/tags/v${WAZUH_VERSION}.tar.gz" \
    | tar -xz -C "$INSTALL_DIR" --strip-components=1

cd "$INSTALL_DIR/single-node"

# ── SSL-Zertifikate generieren ────────────────────────────────────────────────
log "Generiere SSL-Zertifikate..."
docker compose -f generate-indexer-certs.yml run --rm generator
log "Zertifikate erstellt"

# ── Wazuh Stack starten ───────────────────────────────────────────────────────
log "Starte Wazuh Stack (Manager + Indexer + Dashboard)..."
docker compose up -d

# ── Warten bis Dashboard bereit ist ──────────────────────────────────────────
log "Warte auf Dashboard (kann 2-3 Minuten dauern)..."
for i in $(seq 1 36); do
    if curl -sk https://localhost/ | grep -q "wazuh\|opensearch\|login" 2>/dev/null; then
        log "Dashboard ist bereit!"
        break
    fi
    echo -n "."
    sleep 5
done
echo ""

# ── Elmir SIEM mit Wazuh verbinden ───────────────────────────────────────────
info "Konfiguriere Elmir Syslog-Empfang von Wazuh..."
ELMIR_DIR="$(dirname "$(realpath "$0")")/.."
if [ -f "$ELMIR_DIR/config.yaml" ]; then
    info "Elmir config.yaml gefunden — Wazuh sendet Alerts an Port 5514"
fi

# ── Ausgabe ───────────────────────────────────────────────────────────────────
HOST_IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║            Wazuh erfolgreich gestartet!          ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Dashboard : ${GREEN}https://${HOST_IP}${NC}"
echo -e "${CYAN}║${NC}  Benutzer  : ${GREEN}admin${NC}"
echo -e "${CYAN}║${NC}  Passwort  : ${GREEN}SecretPassword123!${NC}"
echo -e "${CYAN}║${NC}                                                  ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  API       : ${GREEN}https://${HOST_IP}:55000${NC}"
echo -e "${CYAN}║${NC}  Install-Dir: ${GREEN}${INSTALL_DIR}${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Logs   : docker compose -C $INSTALL_DIR/single-node logs -f ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Stop   : docker compose -C $INSTALL_DIR/single-node down    ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
warn "Passwort in Produktion ändern!"
echo ""

# ── Wazuh Agent lokal installieren (optional) ─────────────────────────────────
read -rp "Wazuh Agent auch auf diesem Rechner installieren? [j/N] " INSTALL_AGENT
if [[ "$INSTALL_AGENT" =~ ^[jJyY]$ ]]; then
    bash "$(dirname "$0")/install-agent.sh" "127.0.0.1" "$(hostname)"
fi
