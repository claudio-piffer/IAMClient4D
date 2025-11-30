#!/bin/bash

set -euo pipefail

TEMPLATE_FILE=".env.template"
ENV_FILE=".env"
SECRETS_DIR="secrets"
KEYCLOAK_SECRET_FILE="$SECRETS_DIR/pg_keycloak_password.txt"
CERT_SCRIPT="./config/nginx/ssl/generate-cert.sh"
SELF_SIGNED=0
DOMAIN_NAME=""

echo
echo "Making all .sh scripts executable..."
chmod +x *.sh

echo
echo "===================================================="
echo " IAM Client 4D - First Time Setup (Linux)"
echo "===================================================="
echo

chmod +x ./config/db/setup-schema.sh

# ============================================
# Parse command line arguments
# ============================================
for arg in "$@"; do
  if [[ "$arg" == "-self-signed" ]]; then
    SELF_SIGNED=1
  fi
done

# ============================================
# STEP 1: Check/Create secret files
# ============================================
echo "--- [1/4] Checking/Creating secrets using setup-secrets.sh..."

if [ ! -f "./setup-secrets.sh" ]; then
  echo "[ERROR] './setup-secrets.sh' is missing! Cannot generate passwords."
  exit 1
fi

chmod +x ./setup-secrets.sh
./setup-secrets.sh
echo "  [OK] Secret management process complete."
echo

# ============================================
# STEP 2: Generate .env from template
# ============================================
echo "--- [2/4] Generating '$ENV_FILE' from '$TEMPLATE_FILE' (preserving comments)..."

if [ ! -f "$TEMPLATE_FILE" ]; then
  echo "[ERROR] Template file '$TEMPLATE_FILE' not found!"
  exit 1
fi

if [ ! -f "$KEYCLOAK_SECRET_FILE" ]; then
  echo "[ERROR] Secret file '$KEYCLOAK_SECRET_FILE' was not created. Aborting."
  exit 1
fi

IAM_DB_PASS=$(< "$KEYCLOAK_SECRET_FILE")

# Carica tutte le variabili dalla template
declare -A template_vars
while IFS='=' read -r key val; do
  [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
  template_vars["$key"]="$val"
done < <(grep -v '^#' "$TEMPLATE_FILE" | grep -v '^$')

# Espande le variabili (preservando i commenti)
{
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^#.*$ || -z "$line" ]]; then
      echo "$line"
    else
      key="${line%%=*}"
      value="${line#*=}"

      # Sostituisce tutte le variabili nel valore
      for var in "${!template_vars[@]}"; do
        value="${value//\$\{$var\}/${template_vars[$var]}}"
      done

      if [[ "$key" == "DOMAIN_NAME" ]]; then
        DOMAIN_NAME="$value"
      fi

      echo "$key=$value"
    fi
  done < "$TEMPLATE_FILE"

  echo ""
  echo "IAM_DB_PASS=$IAM_DB_PASS"
} > "$ENV_FILE"

echo "  [OK] '$ENV_FILE' created successfully with resolved values."
echo

# ============================================
# STEP 3: Check/Create required docker volumes
# ============================================
echo "--- [3/4] Checking for required Docker volumes..."

# Carica tutte le variabili da .env
set -o allexport
source "$ENV_FILE"
set +o allexport

NEEDS_VOLUME_CREATION=0
if ! docker volume inspect "$IAM_DB_VOLUME_NAME" >/dev/null 2>&1; then
  echo "[INFO] Volume '$IAM_DB_VOLUME_NAME' is missing."
  NEEDS_VOLUME_CREATION=1
else
  echo "  [OK] Volume '$IAM_DB_VOLUME_NAME' exists."
fi

if ! docker volume inspect "$IAM_DB_LARC_VOLUME_NAME" >/dev/null 2>&1; then
  echo "[INFO] Volume '$IAM_DB_LARC_VOLUME_NAME' is missing."
  NEEDS_VOLUME_CREATION=1
else
  echo "  [OK] Volume '$IAM_DB_LARC_VOLUME_NAME' exists."
fi

if [ $NEEDS_VOLUME_CREATION -eq 1 ]; then
  echo "[ACTION] Creating missing volumes..."
  if [ -f "./create-volumes.sh" ]; then
    chmod +x ./create-volumes.sh
    ./create-volumes.sh
  else
    echo "[ERROR] './create-volumes.sh' not found! Cannot create volumes."
    exit 1
  fi
fi
echo

# ============================================
# STEP 3.5: Optional self-signed certificate
# ============================================
if [ "$SELF_SIGNED" -eq 1 ]; then
  echo "--- [3.5/4] Generating self-signed SSL certificate for domain: $DOMAIN_NAME"

  if [ -f "$CERT_SCRIPT" ]; then
    chmod +x "$CERT_SCRIPT"
    "$CERT_SCRIPT" "$DOMAIN_NAME"
    echo "  [OK] Self-signed certificate generated."
  else
    echo "[ERROR] SSL certificate script '$CERT_SCRIPT' not found!"
    exit 1
  fi
  echo
fi

# ============================================
# STEP 4: Final instructions
# ============================================
echo "--- [4/4] Setup complete!"
echo
echo "You can now start the services by running:"
echo "  ./start.sh or ./start.sh -logs"
echo