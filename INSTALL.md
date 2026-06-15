# Wazuh SIEM — Installation auf deinem Rechner

## Voraussetzungen

- Ubuntu 20.04/22.04 oder Debian 11/12
- Mind. 4 GB RAM, 50 GB freier Speicher
- Internetverbindung

## Ein-Befehl-Installation

Auf **deinem eigenen Rechner** ausführen:

```bash
git clone https://github.com/ea9436946-hub/Elmir.git
cd Elmir
sudo bash wazuh/setup.sh
```

Das Skript:
1. Installiert Docker automatisch (falls nicht vorhanden)
2. Setzt Kernel-Parameter für OpenSearch
3. Lädt die Wazuh Docker-Konfiguration herunter
4. Generiert SSL-Zertifikate
5. Startet Wazuh Manager + Indexer + Dashboard
6. Optional: installiert Wazuh Agent auf dem gleichen Rechner

## Nach der Installation

| Was | Wo |
|-----|----|
| Dashboard | https://DEINE-IP |
| Benutzer | `admin` |
| Passwort | `SecretPassword123!` |
| Wazuh API | https://DEINE-IP:55000 |
| Wazuh Agent registrieren | `sudo bash wazuh/install-agent.sh DEINE-IP` |

## Weitere Rechner überwachen

Auf jedem weiteren Rechner:
```bash
curl -O https://raw.githubusercontent.com/ea9436946-hub/Elmir/main/wazuh/install-agent.sh
sudo bash install-agent.sh <WAZUH-SERVER-IP>
```

## Verwaltung

```bash
cd /opt/wazuh-docker/single-node

# Status
docker compose ps

# Logs
docker compose logs -f

# Stoppen
docker compose down

# Neu starten
docker compose restart
```
