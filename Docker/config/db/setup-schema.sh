#!/bin/bash
set -e

echo "****** CREATING keycloak DATABASE ******"

DB_PASS=$(< /run/secrets/pg_keycloak_password.txt)

psql -v ON_ERROR_STOP=1 --username postgres <<EOF
CREATE USER keycloak WITH PASSWORD '${DB_PASS}';
CREATE DATABASE keycloak OWNER keycloak;
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
EOF

PGPASSWORD="${DB_PASS}" psql -v ON_ERROR_STOP=1 --username keycloak --dbname keycloak <<EOF
CREATE SCHEMA IF NOT EXISTS keycloak AUTHORIZATION keycloak;
EOF

echo "****** keycloak DATABASE CREATED ******"
