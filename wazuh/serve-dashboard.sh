#!/bin/bash
# Startet das Custom SIEM Dashboard auf Port 9000
PORT="${1:-9000}"
DIR="$(dirname "$(realpath "$0")")"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Wazuh Custom Dashboard gestartet!      ║"
echo "╠══════════════════════════════════════════╣"
echo "║  URL: http://$(hostname -I | awk '{print $1}'):$PORT"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Strg+C zum Beenden"
echo ""

cd "$DIR"
python3 -m http.server "$PORT" --bind 0.0.0.0
