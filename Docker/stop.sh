#!/bin/bash

set -euo pipefail

echo "Stopping removing containers, network and volumes..."
docker compose down

echo "Shutdown complete."
