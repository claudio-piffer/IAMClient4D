#!/bin/bash

set -euo pipefail

if [ ! -f ".env" ]; then
  echo "[ERROR] Configuration file '.env' not found."
  echo "Please run './first-setup.sh' first to generate it."
  exit 1
fi

echo "--- Starting Docker Compose services in detached mode..."
docker compose up -d

echo
echo "--- Services started. ---"
echo

if [[ "$1" == "-logs" ]]; then
  echo "--- Showing real-time logs (press Ctrl+C to stop)..."
  docker compose logs -f
fi