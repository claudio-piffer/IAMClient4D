#!/bin/bash
# Stops the sample environment and deletes its database: the next start imports the realm again
# from config/keycloak/realm/realm.json. Passwords in secrets/ and the certificate are kept.
set -euo pipefail
cd "$(dirname "$0")"
docker compose --profile brokering --profile tls down --volumes
