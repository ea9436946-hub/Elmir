# Wazuh SIEM Integration

Zwei Installationswege stehen zur Verfügung:

---

## Option A — Docker (empfohlen für Tests/Homelab)

**Voraussetzungen:** Docker + Docker Compose, mind. 4 GB RAM

```bash
cd wazuh/
docker-compose -f docker-compose.wazuh.yml up -d
```

Dashboard öffnen: **https://localhost** (Port 443)
- Benutzer: `admin`
- Passwort: `SecretPassword123!`  ← in Produktion ändern!

---

## Option B — Natives Wazuh auf dem Rechner installieren

**Voraussetzungen:** Ubuntu 20.04/22.04 oder Debian 10/11, mind. 4 GB RAM, 50 GB Disk

```bash
chmod +x wazuh/install-wazuh.sh
sudo wazuh/install-wazuh.sh
```

Das Skript installiert automatisch:
- Wazuh Indexer (OpenSearch)
- Wazuh Manager
- Wazuh Dashboard

---

## Wazuh Agent auf weiteren Rechnern

Verbindet jeden weiteren Linux-Rechner mit dem Wazuh Manager:

```bash
chmod +x wazuh/install-agent.sh
sudo wazuh/install-agent.sh <MANAGER_IP> [agent-name]
```

---

## Integration mit Elmir SIEM

Elmir kann Wazuh-Alerts per Syslog empfangen. In `/var/ossec/etc/ossec.conf` hinzufügen:

```xml
<syslog_output>
  <level>9</level>
  <server>127.0.0.1</server>
  <port>5514</port>
</syslog_output>
```

Dann Wazuh neu starten: `systemctl restart wazuh-manager`

---

## Ports

| Dienst            | Port       |
|-------------------|------------|
| Dashboard (HTTPS) | 443        |
| Agent-Events      | 1514/udp   |
| Agent-Registrierung | 1515     |
| REST API          | 55000      |
| Indexer (OpenSearch) | 9200    |
