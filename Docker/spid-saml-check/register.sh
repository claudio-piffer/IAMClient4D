#!/usr/bin/env bash
# Registers the SP metadata of the realm with the demo IdP of spid-saml-check (register.js).
# SPID (default): first makes Keycloak trust the demo IdP key on spid-test (trust.js) and adds the
# kc-admin-api scope to the sample client when the realm has it (admin-api-scope.js), then registers
# the SPID SP metadata, and again whenever it changes (e.g. spid-test deleted and saved again by the
# application).
# CIE (IAM4D_PROFILE=cie): the application creates the cie provider later, with the certificate of
# the imported metadata; the CIE SP metadata is registered again whenever it changes.
PORT="${NODE_HTTPS_PORT:-8443}"
METADATA_URL="${SP_METADATA_URL:-${SPID_SP_METADATA_URL:-http://keycloak:8080/realms/iam4d-sample/spid-sp-metadata}}"
METADATA_FILE=/tmp/iam4d-sp-metadata.xml

. ~/.nvm/nvm.sh >/dev/null

if [ "${IAM4D_PROFILE}" = "cie" ]; then
  # Without CIE providers Keycloak answers 500 to the CIE SP metadata and logs an error: look for one
  # through the Admin REST API first (admin token renewed every 50 s, it lasts 60)
  KEYCLOAK="${KEYCLOAK_URL:-http://keycloak:8080}"
  REALM="${IAM4D_REALM:-iam4d-sample}"
  # Compared without the ID and the signature, which change at every download
  COMPARED=/tmp/iam4d-sp-metadata-compared.xml
  REGISTERED=/tmp/iam4d-sp-metadata-registered.xml
  TOKEN_TIME=0
  rm -f "${REGISTERED}"
  while true; do
    if [ $(( $(date +%s) - TOKEN_TIME )) -ge 50 ]; then
      TOKEN=$(curl -fs -d grant_type=password -d client_id=admin-cli -d "username=${KC_ADMIN:-admin}" \
        -d "password=${KC_ADMIN_PASSWORD:-admin}" "${KEYCLOAK}/realms/master/protocol/openid-connect/token" |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
      [ -n "${TOKEN}" ] && TOKEN_TIME=$(date +%s)
    fi
    if curl -fs -o /dev/null "http://localhost:${PORT}/demo/metadata.xml" &&
       curl -fs -H "Authorization: Bearer ${TOKEN}" "${KEYCLOAK}/admin/realms/${REALM}/identity-provider/instances" |
         grep -q '"providerId":"cieid-saml"' &&
       curl -fs -o "${METADATA_FILE}" "${METADATA_URL}" &&
       sed -E -e 's/ ID="[^"]*"//' -e 's#<([A-Za-z]+:)?Signature[ >].*</([A-Za-z]+:)?Signature>##' \
         "${METADATA_FILE}" > "${COMPARED}" &&
       ! cmp -s "${COMPARED}" "${REGISTERED}" &&
       node /iam4d/register.js "${METADATA_FILE}" "${METADATA_URL}" 2>/dev/null; then
      cp "${COMPARED}" "${REGISTERED}"
    fi
    sleep 5
  done
fi

rm -f /tmp/iam4d-registered
for _ in $(seq 1 60); do
  if curl -fs -o /dev/null "http://localhost:${PORT}/demo/metadata.xml" &&
     node /iam4d/trust.js /tmp/iam4d-demo-idp/cert.pem &&
     node /iam4d/admin-api-scope.js &&
     curl -fs -o "${METADATA_FILE}" "${METADATA_URL}" &&
     node /iam4d/register.js "${METADATA_FILE}" "${METADATA_URL}"; then
    touch /tmp/iam4d-registered
    break
  fi
  sleep 5
done
if [ ! -f /tmp/iam4d-registered ]; then
  echo "SPID SP metadata not registered: ${METADATA_URL}" >&2
  exit 1
fi

# Then the application can delete spid-test and save it again from the demo IdP metadata (SPID page of
# the samples, "SPID test (spid-saml-check)"): the SPID SP metadata is registered again whenever it
# changes. Without SPID providers Keycloak answers 500 to the SPID SP metadata and logs an error: look
# for one through the Admin REST API first (admin token renewed every 50 s, it lasts 60)
KEYCLOAK="${KEYCLOAK_URL:-http://keycloak:8080}"
REALM="${IAM4D_REALM:-iam4d-sample}"
# Compared without the ID and the signature, which change at every download
COMPARED=/tmp/iam4d-sp-metadata-compared.xml
REGISTERED=/tmp/iam4d-sp-metadata-registered.xml
sed -E -e 's/ ID="[^"]*"//' -e 's#<([A-Za-z]+:)?Signature[ >].*</([A-Za-z]+:)?Signature>##' \
  "${METADATA_FILE}" > "${REGISTERED}"
TOKEN_TIME=0
while true; do
  sleep 5
  if [ $(( $(date +%s) - TOKEN_TIME )) -ge 50 ]; then
    TOKEN=$(curl -fs -d grant_type=password -d client_id=admin-cli -d "username=${KC_ADMIN:-admin}" \
      -d "password=${KC_ADMIN_PASSWORD:-admin}" "${KEYCLOAK}/realms/master/protocol/openid-connect/token" |
      sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
    [ -n "${TOKEN}" ] && TOKEN_TIME=$(date +%s)
  fi
  if curl -fs -H "Authorization: Bearer ${TOKEN}" "${KEYCLOAK}/admin/realms/${REALM}/identity-provider/instances" |
       grep -q '"providerId":"spid-saml"' &&
     curl -fs -o "${METADATA_FILE}" "${METADATA_URL}" &&
     sed -E -e 's/ ID="[^"]*"//' -e 's#<([A-Za-z]+:)?Signature[ >].*</([A-Za-z]+:)?Signature>##' \
       "${METADATA_FILE}" > "${COMPARED}" &&
     ! cmp -s "${COMPARED}" "${REGISTERED}" &&
     node /iam4d/register.js "${METADATA_FILE}" "${METADATA_URL}"; then
    cp "${COMPARED}" "${REGISTERED}"
  fi
done
