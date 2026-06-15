# Elmir SIEM

Security Information and Event Management System — Python-basiertes SIEM für Linux-Umgebungen.

## Features

- **Log-Collector**: Überwacht Dateien (auth.log, syslog, Apache/Nginx access logs) in Echtzeit via Tailing
- **Syslog-Listener**: UDP + TCP auf Port 5514
- **Parser**: auth.log, Apache Combined Log, Nginx, Syslog
- **Korrelations-Engine**: Brute-Force-Erkennung, Port-Scan-Erkennung, Privilege-Escalation-Erkennung
- **Alert-Manager**: E-Mail + Slack-Webhook-Benachrichtigungen
- **Web-Dashboard**: Echtzeit-Übersicht auf Port 8080
- **SQLite-Speicher**: Persistente Event- und Alert-Datenbank

## Schnellstart

```bash
# Abhängigkeiten installieren
pip install -r requirements.txt

# Konfiguration anpassen
cp .env.example .env
nano config.yaml

# Starten
python -m siem.main
```

Dashboard öffnen: http://localhost:8080

## Docker

```bash
docker-compose up -d
```

## Korrelationsregeln

| Regel | Beschreibung | Schwellwert |
|-------|-------------|-------------|
| `brute_force_detection` | Mehrfache fehlgeschlagene Logins von einer IP | 5 in 60s |
| `port_scan_detection` | Viele Fehler-Antworten (404/403) von einer IP | 20 in 30s |
| `privilege_escalation` | `su root` oder gefährliche `sudo`-Befehle | sofort |

## Konfiguration

Alle Einstellungen in `config.yaml`. Umgebungsvariablen überschreiben:

| Variable | Beschreibung |
|----------|-------------|
| `SIEM_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `SIEM_DB_PATH` | Pfad zur SQLite-Datenbank |
| `SIEM_DASHBOARD_PORT` | Dashboard-Port (Standard: 8080) |
| `SMTP_*` | E-Mail-Konfiguration |
| `WEBHOOK_URL` | Slack/Teams-Webhook-URL |

## Tests ausführen

```bash
python tests/test_parsers.py
python tests/test_correlations.py
```

## Projektstruktur

```
siem/
├── main.py              # Einstiegspunkt
├── config.py            # Konfiguration
├── collectors/          # Log-Quellen
├── parsers/             # Log-Format-Parser
├── correlations/        # Regelengine + Regeln
├── alerts/              # Benachrichtigungen
├── storage/             # SQLite-Speicher
└── dashboard/           # Flask Web-Dashboard
```
