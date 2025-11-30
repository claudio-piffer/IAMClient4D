#!/bin/bash

set -euo pipefail

SECRETS_DIR="./secrets"

# Ensure the directory exists
if [ ! -d "$SECRETS_DIR" ]; then
    echo "[INFO] Creating secrets directory: $SECRETS_DIR"
    mkdir -p "$SECRETS_DIR"
fi

process_secret() {
    local name="$1"
    local file="$SECRETS_DIR/$name.txt"

    echo "--- Checking for ${name}.txt..."

    if [ ! -s "$file" ]; then
        echo "  [INFO] Generating 24-char password for $name..."
        local pass=""
        while [ ${#pass} -lt 24 ]; do
            part=$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9')
            pass="$pass$part"
        done
        printf "%s" "${pass:0:24}" > "$file"
        echo "  [OK] Password saved to $file."
    else
        echo "  [OK] $file already exists and is not empty. Skipping."
    fi
}

echo
echo "===================================================="
echo "  Checking and generating secret files..."
echo "===================================================="
echo

process_secret "pg_admin_password"
process_secret "pg_keycloak_password"

echo
echo "===================================================="
echo "  Secret setup check complete."
echo "===================================================="
