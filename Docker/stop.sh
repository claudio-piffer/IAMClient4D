#!/bin/bash
# Stops and removes the containers of the sample environment, of every profile.
# Data (realm, users, identity providers saved by the samples) stays in the volume: see delete-volumes.sh.
set -euo pipefail
cd "$(dirname "$0")"
docker compose --profile brokering --profile tls down
