#!/bin/bash
# Starts the Keycloak of the samples and waits until it is ready; can be run again at any time.
# Usage: ./start.sh [brokering] [tls] [logs]
#   brokering  also the SPID demo identity provider and the CIE simulator
#   tls        also the HTTPS gateway: Keycloak on https://DOMAIN_NAME:GATEWAY_PORT/auth (.env)
#   logs       then follow the logs (Ctrl+C leaves them, the services keep running)
# The services of a profile not given are stopped (e.g. start.sh after start.sh tls).
# Passwords: generated in secrets/ at the first start. Settings: .env (see .env.example).
set -euo pipefail
cd "$(dirname "$0")"

PROFILES=()
TLS=0
BROKERING=0
LOGS=0
for ARG in "$@"; do
  case "$ARG" in
    brokering) PROFILES+=(--profile brokering); BROKERING=1 ;;
    tls) PROFILES+=(--profile tls); TLS=1 ;;
    logs) LOGS=1 ;;
    *) echo "Usage: $0 [brokering] [tls] [logs]" >&2; exit 2 ;;
  esac
done

if ! command -v docker > /dev/null 2>&1; then
  echo "[ERROR] docker not found: install Docker (Docker Desktop, or Docker Engine with the compose plugin)" >&2
  exit 1
fi

bash ./setup-secrets.sh

# Settings used here too (Compose reads .env by itself); CR removed, in case it was edited on Windows
if [ -f .env ]; then
  set -a
  # bash 3.2 (macOS) cannot source a process substitution
  eval "$(tr -d '\r' < .env)"
  set +a
fi
KC_PORT=${KC_PORT:-18180}
SPID_CHECK_PORT=${SPID_CHECK_PORT:-18443}
CIE_CHECK_PORT=${CIE_CHECK_PORT:-18444}
if [ "$TLS" = 1 ]; then
  export IAM_PUBLIC_URL="https://${DOMAIN_NAME:-localhost}:${GATEWAY_PORT:-24443}/auth"
else
  unset IAM_PUBLIC_URL
fi
URL=${IAM_PUBLIC_URL:-http://localhost:$KC_PORT/auth}

# Services of the profiles not given: the gateway would front a Keycloak with another URL
REMOVE=()
[ "$BROKERING" = 1 ] || REMOVE+=(spid-saml-check cie-simulator)
[ "$TLS" = 1 ] || REMOVE+=(gateway)
if [ ${#REMOVE[@]} -gt 0 ]; then
  docker compose --profile brokering --profile tls rm --stop --force "${REMOVE[@]}" > /dev/null 2>&1 || true
fi

echo "--- Starting (first time: images are downloaded and built, a few minutes)"
docker compose ${PROFILES[@]+"${PROFILES[@]}"} up -d --build --wait

echo
echo "Keycloak ready: $URL (admin: ${IAM_ADMIN_USER:-admin}, password in secrets/kc_admin_password.txt)"
echo "Realm iamclient4d: $URL/realms/iamclient4d"
echo "  users: demo / demo (realm-admin), student / Student#2026, scientist / Scientist#2026"
if [ "$BROKERING" = 1 ]; then
  echo "SPID demo identity provider: http://localhost:$SPID_CHECK_PORT/demo (users: /demo/users, e.g. ada / password123)"
  echo "CIE simulator: http://localhost:$CIE_CHECK_PORT/demo (metadata for Keycloak: http://cie-simulator:$CIE_CHECK_PORT/demo/metadata.xml)"
fi
if [ "$TLS" = 1 ]; then
  echo "Self-signed certificate: config/nginx/ssl/certs/certificate.crt"
fi

if [ "$LOGS" = 1 ]; then
  docker compose ${PROFILES[@]+"${PROFILES[@]}"} logs -f
fi
