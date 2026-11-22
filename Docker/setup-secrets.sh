#!/bin/bash
# Generates the passwords of the sample environment in secrets/ (24 letters and digits):
# Keycloak admin, PostgreSQL admin, PostgreSQL user keycloak. An existing, non-empty file is kept.
# Called by start.sh; delete-volumes.sh does not touch them.
set -euo pipefail
cd "$(dirname "$0")"

SECRETS_DIR=secrets
mkdir -p "$SECRETS_DIR"

process_secret() {
  local LFile="$SECRETS_DIR/$1.txt" LPass=""
  if [ -s "$LFile" ]; then
    return 0
  fi
  while [ ${#LPass} -lt 24 ]; do
    LPass="$LPass$(head -c 64 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  done
  printf '%s' "${LPass:0:24}" > "$LFile"
  echo "[OK] Generated $LFile"
}

process_secret kc_admin_password
process_secret pg_admin_password
process_secret pg_keycloak_password
