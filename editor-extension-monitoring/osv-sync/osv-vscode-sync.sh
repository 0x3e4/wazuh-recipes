#!/bin/bash
# OSV -> Wazuh VS Code malicious-extension ruleset sync.
#
# Fetches the OSV VSCode malware feed, regenerates a version-aware ruleset, and reloads Wazuh
# ONLY when the ruleset actually changed. Validates the XML first and rolls back if the manager
# fails to start. Must run as root (writes etc/rules and restarts the manager).
#
# Install (root):
#   install -d /opt/wazuh-osv
#   install -m 0755 osv-vscode-sync.py /opt/wazuh-osv/
#   install -m 0750 osv-vscode-sync.sh /opt/wazuh-osv/
# Root crontab (weekly — OSV changes rarely):
#   30 3 * * 1 /opt/wazuh-osv/osv-vscode-sync.sh >> /var/log/osv-vscode-sync.log 2>&1
#
# Overridable via environment:
#   OSV_SYNC_PY     path to osv-vscode-sync.py   (default: next to this script)
#   OSV_RULES_FILE  output ruleset path          (default: /var/ossec/etc/rules/editor_extensions_osv.xml)
#   WAZUH_CONTROL   wazuh-control binary          (default: /var/ossec/bin/wazuh-control)

set -uo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PY="${OSV_SYNC_PY:-$SCRIPT_DIR/osv-vscode-sync.py}"
RULES="${OSV_RULES_FILE:-/var/ossec/etc/rules/editor_extensions_osv.xml}"
WAZUH_CONTROL="${WAZUH_CONTROL:-/var/ossec/bin/wazuh-control}"
TMP=$(mktemp); BAK="${RULES}.bak"

# 1. fetch + generate (needs outbound HTTPS to storage.googleapis.com)
if ! /usr/bin/env python3 "$PY" "$TMP"; then
  echo "$(date) ERROR: OSV fetch/generate failed; keeping current ruleset"; rm -f "$TMP"; exit 1
fi
# 2. validate XML before trusting it
if ! python3 -c "import xml.etree.ElementTree as ET; ET.fromstring('<root>'+open('$TMP').read()+'</root>')" 2>/dev/null; then
  echo "$(date) ERROR: generated XML invalid; aborting"; rm -f "$TMP"; exit 1
fi
# 3. no change -> nothing to do (avoids needless restarts)
if cmp -s "$TMP" "$RULES" 2>/dev/null; then rm -f "$TMP"; echo "$(date) OSV ruleset unchanged"; exit 0; fi
# 4. swap in, restart, roll back if the manager fails to come up
[ -f "$RULES" ] && cp -f "$RULES" "$BAK"
install -m 0640 "$TMP" "$RULES"; rm -f "$TMP"
chown root:wazuh "$RULES" 2>/dev/null || true
if "$WAZUH_CONTROL" restart >/dev/null 2>&1; then
  echo "$(date) OSV ruleset updated; wazuh-manager restarted"
else
  echo "$(date) ERROR: manager failed to start; rolling back OSV ruleset"
  [ -f "$BAK" ] && cp -f "$BAK" "$RULES" && "$WAZUH_CONTROL" restart >/dev/null 2>&1
  exit 1
fi
