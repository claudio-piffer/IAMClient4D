# syntax=docker/dockerfile:1
# Keycloak for the identity brokering test, with the SPID and CIE ID extensions.
# The extensions are built for one Keycloak minor: keep the three versions on the same minor,
# with the SHA-256 of the two jars (GitHub shows it next to each release asset).
# Exact tag: a floating one (26.8) may resolve to an old image already in the Docker cache.
ARG KC_VERSION=26.8.2
FROM quay.io/keycloak/keycloak:${KC_VERSION}

ARG SPID_VERSION=26.8.1
ARG SPID_SHA256=a499161de815156c50208efb6d550a63c64be443e3e494523d737781c5494688
ARG CIE_VERSION=26.8.1
ARG CIE_SHA256=103c7615fe12b783147e80ff8104cbba9b5ce0d80a57b491cdedea7cd100c8e4

# italia/spid-keycloak-provider: provider 'spid-saml'
ADD --checksum=sha256:${SPID_SHA256} --chown=keycloak:keycloak --chmod=644 \
    https://github.com/italia/spid-keycloak-provider/releases/download/${SPID_VERSION}/spid-provider.jar \
    /opt/keycloak/providers/spid-provider.jar

# lscorcia/keycloak-cieid-provider: provider 'cieid-saml'
ADD --checksum=sha256:${CIE_SHA256} --chown=keycloak:keycloak --chmod=644 \
    https://github.com/lscorcia/keycloak-cieid-provider/releases/download/${CIE_VERSION}/cieid-provider.jar \
    /opt/keycloak/providers/cieid-provider.jar
