#!/bin/sh
# Gateway of the profile tls: self-signed certificate for DOMAIN_NAME (plus localhost and
# 127.0.0.1) when certs/ has none, then the nginx configuration from the templates.
# Delete certs/certificate.crt and certs/private.key to generate them again (e.g. new DOMAIN_NAME).
set -eu

CERTS=/etc/nginx/ssl/certs
if [ ! -s "$CERTS/certificate.crt" ] || [ ! -s "$CERTS/private.key" ]; then
  SAN="DNS:localhost,IP:127.0.0.1"
  if echo "$DOMAIN_NAME" | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
    SAN="IP:$DOMAIN_NAME,$SAN"
  elif [ "$DOMAIN_NAME" != localhost ]; then
    SAN="DNS:$DOMAIN_NAME,$SAN"
  fi
  echo "[INFO] Self-signed certificate for $DOMAIN_NAME ($SAN)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
    -subj "/O=IAMClient4D samples/CN=$DOMAIN_NAME" -addext "subjectAltName=$SAN" \
    -keyout "$CERTS/private.key" -out "$CERTS/certificate.crt" 2>/dev/null
fi
openssl x509 -in "$CERTS/certificate.crt" -noout -subject -enddate -fingerprint -sha256

envsubst '$DOMAIN_NAME $GATEWAY_PORT' < /etc/nginx/templates/default.conf.template \
  > /etc/nginx/conf.d/default.conf
mkdir -p /etc/nginx/includes
cp /etc/nginx/templates/proxy-headers.conf.template /etc/nginx/includes/proxy-headers.conf

exec nginx -g "daemon off;"
