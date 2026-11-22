#!/bin/bash
#  ---------------------------------------------------------------------------
#  Keycloak of the IdentityBrokering mobile sample, for a physical phone.
#  start: the sample environment of Docker/ with the profile brokering (Keycloak
#  on http://localhost:18180/auth, realm iamclient4d, SPID demo identity provider
#  on 18443, CIE simulator on 18444), then "adb reverse" of the three ports: on
#  the phone localhost is the phone, the USB cable brings it to this machine.
#  Usage: ./keycloak.sh [start|reverse|logs|stop]
#    start    start the environment (built the first time), forward the ports to the phone
#    reverse  forward the ports again (needed after reconnecting the phone)
#    logs     follow the Keycloak log, Ctrl+C to leave
#    stop     remove the forwards, stop the environment (data kept: see Docker/delete-volumes.sh)
#  Ports from Docker/.env (KC_PORT, SPID_CHECK_PORT, CIE_CHECK_PORT).
#  Optional variables: ADB (default: adb from the PATH), ANDROID_SERIAL (with more
#  than one device).
#  ---------------------------------------------------------------------------

set -euo pipefail

ENV_DIR=$(cd "$(dirname "$0")/../../../Docker" && pwd)
if [ -f "$ENV_DIR/.env" ]; then
  set -a
  # bash 3.2 (macOS) cannot source a process substitution
  eval "$(tr -d '\r' < "$ENV_DIR/.env")"
  set +a
fi
ADB=${ADB:-adb}
KC_PORT=${KC_PORT:-18180}
SPID_CHECK_PORT=${SPID_CHECK_PORT:-18443}
CIE_CHECK_PORT=${CIE_CHECK_PORT:-18444}
PORTS="$KC_PORT $SPID_CHECK_PORT $CIE_CHECK_PORT"

reverse() {
  if ! command -v "$ADB" > /dev/null 2>&1; then
    echo "[WARNING] adb not found: $ADB (set ADB)"
    return 1
  fi
  "$ADB" start-server > /dev/null 2>&1 || true
  if ! "$ADB" devices | grep -q 'device$'; then
    echo "[WARNING] No phone connected: plug it in with USB debugging on, authorize this machine, then: $0 reverse"
    return 1
  fi
  for LPort in $PORTS; do
    if ! "$ADB" reverse "tcp:$LPort" "tcp:$LPort" > /dev/null; then
      echo "[ERROR] adb reverse tcp:$LPort failed (more than one device? set ANDROID_SERIAL)"
      return 1
    fi
  done
  echo "--- Phone: localhost:$KC_PORT, :$SPID_CHECK_PORT and :$CIE_CHECK_PORT forwarded to this machine"
  "$ADB" reverse --list
}

start() {
  bash "$ENV_DIR/start.sh" brokering
  reverse || true
  echo
  echo "App, Connection card: base URL http://localhost:$KC_PORT/auth, realm iamclient4d, client iam4d-sample-app"
  echo "Users: demo / demo (Keycloak, realm-admin), ada / password123 (SPID spid-test), marcopolo / password123 (CIE)"
}

stop() {
  if command -v "$ADB" > /dev/null 2>&1; then
    for LPort in $PORTS; do "$ADB" reverse --remove "tcp:$LPort" > /dev/null 2>&1 || true; done
  fi
  bash "$ENV_DIR/stop.sh"
}

case "${1:-start}" in
  start) start ;;
  reverse) reverse ;;
  logs) bash "$ENV_DIR/logs.sh" keycloak ;;
  stop) stop ;;
  *) echo "Usage: $0 [start|reverse|logs|stop]"; exit 1 ;;
esac
