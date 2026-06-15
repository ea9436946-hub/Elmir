#!/bin/bash
# Wazuh admin Passwort zurücksetzen
set -e

NEW_PASS="${1:-WazuhAdmin2024!}"

echo "[+] Generiere neuen Passwort-Hash..."
HASH=$(sudo docker exec single-node-wazuh.indexer-1 \
    /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$NEW_PASS" 2>/dev/null | tail -1)

echo "[+] Hash: $HASH"

# internal_users.yml im Container aktualisieren
sudo docker exec single-node-wazuh.indexer-1 bash -c "
sed -i 's|hash: .*|hash: \"$HASH\"|' \
    /usr/share/wazuh-indexer/opensearch-security/internal_users.yml
"

echo "[+] Wende Sicherheitskonfiguration an..."
sudo docker exec single-node-wazuh.indexer-1 bash -c "
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd /usr/share/wazuh-indexer/opensearch-security \
    -icl -nhnv \
    -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
    -cert   /usr/share/wazuh-indexer/certs/admin.pem \
    -key    /usr/share/wazuh-indexer/certs/admin-key.pem \
    -h 127.0.0.1
" 2>&1 | tail -5

echo ""
echo "✅ Passwort wurde zurückgesetzt!"
echo "   Benutzer : admin"
echo "   Passwort : $NEW_PASS"
echo "   Dashboard: https://$(hostname -I | awk '{print $1}')"
