#!/bin/bash
# Follows the logs of the sample environment (Ctrl+C to leave). Usage: ./logs.sh [service]
#   service: keycloak, db, spid-saml-check, cie-simulator or gateway (default: all)
set -euo pipefail
cd "$(dirname "$0")"
docker compose --profile brokering --profile tls logs -f "$@"
