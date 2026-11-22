#!/usr/bin/env sh
# Builds and starts the test Keycloak, spid-saml-check and the CIE simulator, and waits until they are ready.
# Optional variables: KC_VERSION, SPID_VERSION, CIE_VERSION, SPID_SHA256, CIE_SHA256, KC_PORT,
# SPID_CHECK_VERSION, SPID_CHECK_PORT, CIE_CHECK_PORT (see docker-compose.yml).
set -e
cd "$(dirname "$0")"
docker compose up -d --build --wait
echo "Keycloak ready: http://localhost:${KC_PORT:-18080} (admin/admin)"
echo "SPID demo identity provider: http://localhost:${SPID_CHECK_PORT:-8443}/demo (users: /demo/users)"
echo "CIE simulator: http://localhost:${CIE_CHECK_PORT:-8444}/demo, metadata for Keycloak: http://cie-simulator:${CIE_CHECK_PORT:-8444}/demo/metadata.xml"
