#!/bin/bash

set -euo pipefail

ENV_FILE=".env"

if [ -f "$ENV_FILE" ]; then
    set -a
    source "$ENV_FILE"
    set +a
    echo "Variables loaded from $ENV_FILE"
else
    echo "Error: $ENV_FILE not found."
    exit 1
fi

CONTAINER_DB_VOLUME_NAME="${IAM_DB_VOLUME_NAME}"
CONTAINER_DB_LOG_ARCH_VOLUME_NAME="${IAM_DB_LARC_VOLUME_NAME}"

CONTAINER_DB_VOLUME_DEVICE="${PWD}/db/keycloak/data"
CONTAINER_DB_LARC_VOLUME_DEVICE="${PWD}/db/keycloak/pg_log_archive"

# ===================================================
# Safe directory creation (checks for path conflicts)
# ===================================================
ensure_directory() {
    local path="$1"
    if [ -e "$path" ] && [ ! -d "$path" ]; then
        echo "[ERROR] '$path' exists but is not a directory. Remove or rename it."
        exit 1
    fi
    mkdir -p "$path"
}

echo "Ensuring local directories exist..."
ensure_directory "$CONTAINER_DB_VOLUME_DEVICE"
ensure_directory "$CONTAINER_DB_LARC_VOLUME_DEVICE"

# ===================================================
# Set permission
# ===================================================
sudo chown -R 999:999 "$CONTAINER_DB_VOLUME_DEVICE"
sudo chmod -R 700 "$CONTAINER_DB_VOLUME_DEVICE"

sudo chown -R 999:999 "$CONTAINER_DB_LARC_VOLUME_DEVICE"
sudo chmod -R 700 "$CONTAINER_DB_LARC_VOLUME_DEVICE"

# ===================================================
# Volume creation
# ===================================================
echo "Creating database data volume: ${CONTAINER_DB_VOLUME_NAME}"
#docker volume rm "${CONTAINER_DB_VOLUME_NAME}" >/dev/null 2>&1 || true
docker volume create \
    --driver local \
    --opt type=none \
    --opt device="${CONTAINER_DB_VOLUME_DEVICE}" \
    --opt o=bind \
    "${CONTAINER_DB_VOLUME_NAME}"

echo "Creating log archive volume: ${CONTAINER_DB_LOG_ARCH_VOLUME_NAME}"
#docker volume rm "${CONTAINER_DB_LOG_ARCH_VOLUME_NAME}" >/dev/null 2>&1 || true
docker volume create \
    --driver local \
    --opt type=none \
    --opt device="${CONTAINER_DB_LARC_VOLUME_DEVICE}" \
    --opt o=bind \
    "${CONTAINER_DB_LOG_ARCH_VOLUME_NAME}"

echo "Volumes created successfully."