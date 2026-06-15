#!/bin/bash
# Wazuh Passwort automatisch finden und zurücksetzen
set -e

NEW_PASS="S3cur3SIEM#2024"
INDEXER="https://localhost:9200"

echo "[+] Suche aktuelles Passwort..."
CURRENT_PASS=""
for PASS in "SecretPassword123!" "admin" "SecretPassword" "wazuh" "Wazuh1234!" "changeme"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" -u "admin:$PASS" "$INDEXER")
    if [ "$CODE" = "200" ]; then
        CURRENT_PASS="$PASS"
        echo "[+] Passwort gefunden: $PASS"
        break
    fi
done

if [ -z "$CURRENT_PASS" ]; then
    echo "[!] Kein Standard-Passwort funktioniert. Versuche Neustart..."
    sudo docker restart single-node-wazuh.indexer-1
    sleep 30
    for PASS in "SecretPassword123!" "admin"; do
        CODE=$(curl -sk -o /dev/null -w "%{http_code}" -u "admin:$PASS" "$INDEXER")
        if [ "$CODE" = "200" ]; then
            CURRENT_PASS="$PASS"
            break
        fi
    done
fi

if [ -z "$CURRENT_PASS" ]; then
    echo "[x] Passwort konnte nicht gefunden werden."
    echo "    Zeige Indexer-Logs:"
    sudo docker logs single-node-wazuh.indexer-1 2>&1 | tail -20
    exit 1
fi

echo "[+] Setze neues Passwort..."
RESULT=$(curl -sk -u "admin:$CURRENT_PASS" \
    -X PUT "$INDEXER/_plugins/_security/api/internalusers/admin" \
    -H "Content-Type: application/json" \
    -d "{\"password\": \"$NEW_PASS\", \"backend_roles\": [\"admin\"], \"attributes\": {}}")

echo "[+] API-Antwort: $RESULT"

if echo "$RESULT" | grep -q "UPDATED\|CREATED"; then
    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║   Passwort erfolgreich geändert!         ║"
    echo "╠══════════════════════════════════════════╣"
    echo "║  Dashboard: https://$(hostname -I | awk '{print $1}')"
    echo "║  Benutzer : admin"
    echo "║  Passwort : $NEW_PASS"
    echo "╚══════════════════════════════════════════╝"
else
    echo "[x] Fehler beim Ändern. Antwort: $RESULT"
fi
