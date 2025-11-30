#!/bin/sh
set -euo pipefail

echo "[INFO] Expanding nginx configuration templates..."

envsubst '$DOMAIN_NAME $GATEWAY_PORT $SSL_TRUSTED_CERT $ENABLE_SSL_STAPLING $ENABLE_SSL_STAPLING_VERIFY $CORS_ALLOWED_ORIGINS $CORS_ALLOW_METHODS $CORS_ALLOW_HEADERS' \
  < /etc/nginx/templates/default.conf.template \
  > /etc/nginx/conf.d/default.conf

envsubst '' \
  < /etc/nginx/templates/proxy-headers.conf.template \
  > /etc/nginx/includes/proxy-headers.conf

echo "[INFO] Starting nginx..."
exec nginx -g "daemon off;"