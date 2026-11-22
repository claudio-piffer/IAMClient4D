# TLS test

Certificate validation and public key pinning over real TLS handshakes, no Keycloak.

Three local HTTPS servers (Indy + TaurusTLS, `127.0.0.1:18943-18945`) present the certificates of [`certs`](certs):

| Certificate | Key | Validity |
|---|---|---|
| `rsa.pem` | RSA 2048 | 2026-2046, self-signed, SAN `IP:127.0.0.1` |
| `expired.pem` | RSA 2048 | 2020-2021 |
| `ec.pem` | ECDSA P-256 | 2026-2046 |

The client is the `THTTPClient` of `TIAM4DHTTPClientFactory` with the SSL helper and validator of the library, as `TIAM4DKeycloakClient` builds it: the checks see what WinHTTP (Windows) or libcurl (Linux) reports.

The expected pins are constants computed with OpenSSL, not with IAMClient4D:

```bash
openssl x509 -in certs/rsa.pem -noout -modulus | cut -d= -f2 | tr -d '\r\n' | openssl dgst -sha256
```

| Check | Windows | Linux |
|---|---|---|
| strict: self-signed refused; self-signed mode: accepted, expired refused, ECDSA accepted | yes | yes |
| pin from the OpenSSL recipe accepted (any case, one of several); other pin refused, the reported hash is the OpenSSL one | yes | - |
| strict with the right pin still refused; expired with its pin refused; ECDSA with pins refused | yes | - |
| `AddPinnedPublicKeys` raises `ENotSupportedException` | - | yes |

```bat
tests\TLS\run_tests.bat [Win32|Win64|Linux64]
```

`OPENSSL_DIR`: folder of libcrypto/libssl for the Windows servers (default `C:\OpenSSL4-<platform>\bin`, then `C:\OpenSSL3-<platform>\bin`). Linux uses the OpenSSL of the distribution. Without OpenSSL the program exits with 2 (0 with `IAM4D_ALLOW_SKIP=1`).

The certificates are test material only (private keys included on purpose). To make them again (the pins in `IAM4DTLSTest.dpr` change):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.pem -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" -not_before 20260101000000Z -not_after 20460101000000Z
openssl req -x509 -newkey rsa:2048 -nodes -keyout expired.key -out expired.pem -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" -not_before 20200101000000Z -not_after 20210101000000Z
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ec.key -out ec.pem -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" -not_before 20260101000000Z -not_after 20460101000000Z
```
