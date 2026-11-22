# nginx with openssl, to generate the self-signed certificate of the gateway (profile tls)
FROM nginx:stable-alpine
RUN apk add --no-cache openssl
COPY entrypoint.sh /iam4d-entrypoint.sh
ENTRYPOINT ["/bin/sh", "/iam4d-entrypoint.sh"]
