#!/bin/sh
# ClamAV quarantine - Wazuh Active Response (Linux agent).
#
# ClamAV only DETECTS by default; this AR script performs the remediation Defender does
# natively: on a ClamAV detection (rule 100931) Wazuh runs this on the endpoint and MOVES the
# infected file into a quarantine dir with permissions 000 (reversible - it does NOT delete).
#
# Deploy on each ubuntu/debian agent:
#   sudo install -o root -g wazuh -m 0750 clamav-quarantine.sh /var/ossec/active-response/bin/
# and add ossec/clamav-active-response.snippet.xml to the MANAGER's ossec.conf, restart manager.
#
# Wazuh AR (4.2+) protocol: a JSON object arrives on stdin with .command ("add"/"delete") and
# .parameters.alert. We act only on "add" and only when the detected path resolves to a real,
# regular file outside a small denylist of system dirs (never quarantine e.g. /bin, /etc).

LOG="/var/ossec/logs/active-responses.log"
QDIR="/var/ossec/quarantine"
TAG="wazuh-ClamAV-quarantine"

log() { printf '%s %s: %s\n' "$(date '+%Y/%m/%d %H:%M:%S')" "$TAG" "$1" >> "$LOG" 2>/dev/null; }

INPUT=$(cat)

# Parse command + infected path from the alert (python3 is present on Debian/Ubuntu).
PARSED=$(printf '%s' "$INPUT" | python3 - <<'PY' 2>/dev/null
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
cmd = d.get("command", "")
alert = d.get("parameters", {}).get("alert", {})
data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
# decoder stores clamav.path either nested (data.clamav.path) or flat ("clamav.path")
path = ""
cav = data.get("clamav")
if isinstance(cav, dict):
    path = cav.get("path", "") or ""
if not path:
    path = data.get("clamav.path", "") or data.get("url", "") or ""
print(cmd)
print(path)
PY
)
CMD=$(printf '%s\n' "$PARSED" | sed -n '1p')
FILE=$(printf '%s\n' "$PARSED" | sed -n '2p')

[ "$CMD" = "add" ] || { log "ignoring command='$CMD'"; exit 0; }
[ -n "$FILE" ] || { log "no infected path in alert; nothing to do"; exit 0; }

# Safety: absolute path, must be a regular file, and not under a system directory.
case "$FILE" in
    /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/lib/*|/lib64/*|/usr/lib/*|/etc/*|/boot/*|/proc/*|/sys/*|/dev/*|/run/*)
        log "REFUSING to quarantine system path: $FILE"; exit 0 ;;
    /*) : ;;
    *)  log "REFUSING non-absolute path: $FILE"; exit 0 ;;
esac
[ -f "$FILE" ] || { log "path not a regular file (already removed/quarantined?): $FILE"; exit 0; }

mkdir -p "$QDIR" 2>/dev/null && chmod 700 "$QDIR" 2>/dev/null
STAMP=$(date '+%Y%m%d-%H%M%S')
DEST="$QDIR/${STAMP}_$(basename "$FILE")"
if mv -f -- "$FILE" "$DEST" 2>/dev/null; then
    chmod 000 "$DEST" 2>/dev/null
    log "quarantined '$FILE' -> '$DEST'"
else
    log "FAILED to quarantine '$FILE' (permission?)"
fi
exit 0
