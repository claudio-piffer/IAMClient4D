#!/bin/bash

# generate-cert.sh
# This script reads the DOMAIN_NAME from the .env file in the project root
# and generates a self-signed ECC certificate and private key.

set -euo pipefail

# --- Setup Variables and Colors ---
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
PROJECT_ROOT=$(realpath "$SCRIPT_DIR/../../../")
ENV_FILE="$PROJECT_ROOT/.env"

CERT_DIR="$SCRIPT_DIR/certs"
OUTPUT_KEY_PATH="$CERT_DIR/private.key"
OUTPUT_CRT_PATH="$CERT_DIR/certificate.crt"
CONF_PATH="$SCRIPT_DIR/openssl.tmp.cnf"

GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)

# --- Prerequisite Checks ---
if ! command -v openssl &>/dev/null; then
    echo "${YELLOW}ERROR: The 'openssl' command was not found. Please install it.${RESET}"
    exit 1
fi

mkdir -p "$CERT_DIR"

if [[ -f "$OUTPUT_KEY_PATH" && -f "$OUTPUT_CRT_PATH" ]]; then
    echo "${GREEN}Certificate files already exist in '$CERT_DIR'. Skipping generation.${RESET}"
    exit 0
fi

DOMAIN_NAME=$(hostname)
if [[ -f "$ENV_FILE" ]]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs)
    DOMAIN_NAME=${DOMAIN_NAME,,}  # force lowercase
fi

echo "Using domain: ${YELLOW}$DOMAIN_NAME${RESET}"

if [[ "$DOMAIN_NAME" == *.* ]]; then
    FQDN=$DOMAIN_NAME
    DNS_NAMES=("$DOMAIN_NAME")
else
    FQDN="$DOMAIN_NAME.local"
    DNS_NAMES=("$DOMAIN_NAME" "$FQDN")
fi

IP_ADDRESSES=$(ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' || true)
if [[ -n "$IP_ADDRESSES" ]]; then
    echo "Detected IP Addresses: ${YELLOW}${IP_ADDRESSES//$'\n'/, }${RESET}"
fi

{
    echo "[req]"
    echo "distinguished_name = req_distinguished_name"
    echo "req_extensions = v3_req"
    echo "prompt = no"
    echo "[req_distinguished_name]"
    echo "CN = $DOMAIN_NAME"
    echo "O = IAMClient4D"
    echo "OU = IT Department dev team"
    echo "L = Bergamo"
    echo "ST = Lombardia"
    echo "C = IT"
    echo "[v3_req]"
    echo "subjectAltName = @alt_names"
    echo "[alt_names]"

    i=1
    for dns in "${DNS_NAMES[@]}"; do
        echo "DNS.$i = $dns"
        ((i++))
    done

    if [[ -n "$IP_ADDRESSES" ]]; then
        i=1
        while read -r ip; do
            echo "IP.$i = $ip"
            ((i++))
        done <<< "$IP_ADDRESSES"
    fi
} > "$CONF_PATH"

echo "Generating ECC private key and certificate into: $CERT_DIR"

openssl ecparam -name prime256v1 -genkey -noout -out "$OUTPUT_KEY_PATH"

openssl req -x509 -new -key "$OUTPUT_KEY_PATH" \
    -out "$OUTPUT_CRT_PATH" \
    -days 365 \
    -config "$CONF_PATH" \
    -extensions v3_req

rm -f "$CONF_PATH"

echo ""
echo "${GREEN}Process completed!${RESET}"
echo "Files generated in '${YELLOW}$CERT_DIR${RESET}':"
echo "- Private Key:     ${YELLOW}$OUTPUT_KEY_PATH${RESET}"
echo "- Certificate:     ${YELLOW}$OUTPUT_CRT_PATH${RESET}"