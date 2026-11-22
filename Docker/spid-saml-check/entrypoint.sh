#!/usr/bin/env bash
# Starts spid-saml-check for the test Keycloak or the sample one (Docker/docker-compose.yml).
# The image listens over plain HTTP but advertises https://localhost:8443: server.json and the demo
# IdP entity ID are rewritten for http://localhost:$NODE_HTTPS_PORT (spid-sp-test checks the
# Destination of the AuthnRequest against the entity ID), then Keycloak's SP metadata is registered.
# IAM4D_PROFILE=cie: the same demo IdP stands in for CIE ID (login pages relabelled, see below).
set -e
# Admin password of Keycloak from a file (sample environment), otherwise KC_ADMIN_PASSWORD or admin
if [ -n "${KC_ADMIN_PASSWORD_FILE}" ] && [ -f "${KC_ADMIN_PASSWORD_FILE}" ]; then
  KC_ADMIN_PASSWORD=$(cat "${KC_ADMIN_PASSWORD_FILE}")
  export KC_ADMIN_PASSWORD
fi
PORT="${NODE_HTTPS_PORT:-8443}"
CONFIG=/spid-saml-check/src/config
if [ "${IAM4D_PROFILE}" = "cie" ]; then
  CN="CIE simulator (spid-saml-check demo IdP)"
else
  CN="spid-saml-check demo IdP"
fi

# Demo IdP signing key: generated for this container instead of the one in the image, whose
# certificate changes with the image version and expires (2.2.5: 13 March 2027). register.sh
# sets the certificate on the SPID provider of the realm (trust.js).
KEY_DIR=/tmp/iam4d-demo-idp
if [ ! -f "${KEY_DIR}/cert.pem" ]; then
  mkdir -p "${KEY_DIR}"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -subj "/C=IT/O=IAMClient4D test/CN=${CN}" \
    -keyout "${KEY_DIR}/pkcs8.pem" -out "${KEY_DIR}/cert.pem" 2>/dev/null
  # The demo IdP expects a PKCS#1 key (it adds the RSA PRIVATE KEY header)
  openssl rsa -in "${KEY_DIR}/pkcs8.pem" -traditional -out "${KEY_DIR}/key.pem" 2>/dev/null
fi
CERT=$(grep -v -- '-----' "${KEY_DIR}/cert.pem" | tr -d '\n')
KEY=$(grep -v -- '-----' "${KEY_DIR}/key.pem" | tr -d '\n')
# idp_demo.json: metadata of the demo IdP; idp.json: credentials that sign its responses
sed -i -e "s#\"certificate\": *\"[^\"]*\"#\"certificate\": \"${CERT}\"#" \
       -e "s#\"privateKey\": *\"[^\"]*\"#\"privateKey\": \"${KEY}\"#" "${CONFIG}/idp_demo.json" "${CONFIG}/idp.json"
sed -i "s#\"entityID\": *\"[^\"]*\"#\"entityID\": \"http://localhost:${PORT}/demo\"#" "${CONFIG}/idp_demo.json"
echo "Demo IdP signing certificate: $(openssl x509 -in "${KEY_DIR}/cert.pem" -noout -fingerprint -sha256 -enddate | tr '\n' ' ')"

if [ "${IAM4D_PROFILE}" = "cie" ]; then
  # The demo IdP checks each AuthnRequest with spid-sp-test and its SPID profile, not the CIE one
  sed -i -e 's#"checkStrict": *true#"checkStrict": false#' -e 's#"checkExtra": *true#"checkExtra": false#' \
    "${CONFIG}/idp_demo.json"
  # Text only: no SPID or AgID logos, and nothing that looks like the CIE ID service
  VIEWS=/spid-saml-check/src/client/view
  for VIEW in demo_login demo_confirm demo_loading demo_response_error; do
    FILE="${VIEWS}/${VIEW}.handlebars"
    grep -q 'id="iam4d-cie"' "${FILE}" && continue
    sed -i -e 's|<title>SPID</title>|<title>Simulatore CIE (test locale)</title>|' \
      -e 's|Entra con SPID|Entra|' \
      -e 's|</head>|<style id="iam4d-cie">.spid-logo img, #idp-logo, #spid-agid-logo, .italia-it-button-icon { display: none; }</style></head>|' \
      -e 's|<div class="width-one-whole spid-logo">|&<h2>Simulatore CIE</h2><p>Ambiente di test locale: non \&egrave; il servizio CIE ID</p>|' \
      "${FILE}"
  done
fi

cat > /spid-saml-check/src/config/server.json <<EOF
{
  "host": "http://localhost",
  "port": ${PORT},
  "basepath": "",
  "useProxy": false,
  "useHttps": false,
  "httpsPrivateKey": "./config/spid-saml-check.key",
  "httpsCertificate": "./config/spid-saml-check.crt"
}
EOF
bash /iam4d/register.sh &
exec /entrypoint.sh
