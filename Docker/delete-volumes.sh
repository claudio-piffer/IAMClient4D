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

echo "Attempting to remove Docker volumes: ${IAM_DB_VOLUME_NAME}, ${IAM_DB_LARC_VOLUME_NAME}"
docker volume rm -f "${IAM_DB_VOLUME_NAME}" "${IAM_DB_LARC_VOLUME_NAME}" 2>/dev/null || true
echo "Volume removal process finished."