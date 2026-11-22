#!/usr/bin/env sh
# Stops and removes the test Keycloak (the database is in memory: nothing is kept).
set -e
cd "$(dirname "$0")"
docker compose down
