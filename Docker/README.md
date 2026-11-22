# Keycloak for the samples (Docker)

One local Keycloak for every sample of IAMClient4D: realm `iamclient4d` with all the clients, redirect URIs and test users the samples expect, the SPID and CIE ID extensions, and, on request, a SPID demo identity provider, a CIE simulator and an HTTPS gateway. Local development only: plain HTTP on `127.0.0.1`, development mode, test users with known passwords.

The integration tests have their own throwaway Keycloak (`tests/IdentityProvider/docker`, in-memory database, realm `iam4d-sample`) built from the same image: see [tests/IdentityProvider](../tests/IdentityProvider/README.md).

## Prerequisites

- **Docker** with Compose v2.17 or later (`docker compose version`): Docker Desktop on Windows and macOS, Docker Engine with the compose plugin on Linux. On Windows Docker can also run inside WSL (Docker Engine in the default distribution, no Docker Desktop): the `.cmd` scripts use `docker` from the Windows PATH and otherwise run the `.sh` script in WSL.
- Internet access the first time: the images are downloaded and the Keycloak image is built (the SPID and CIE jars come from GitHub, checked against their SHA-256).
- Free ports on `127.0.0.1`: `18180` (Keycloak), and with the profiles `18443`, `18444`, `24443`.

## Steps

From this folder (Linux/macOS: the `.sh` script of the same name):

```bat
start.cmd                 & rem Keycloak + PostgreSQL; waits until Keycloak is ready
start.cmd brokering       & rem also the SPID demo identity provider and the CIE simulator
start.cmd brokering tls   & rem also the HTTPS gateway
stop.cmd                  & rem stop; data kept in the volume
delete-volumes.cmd        & rem stop and remove the data: the next start imports the realm again
logs.cmd [service]        & rem follow the logs: keycloak, db, spid-saml-check, cie-simulator, gateway
```

`start` can be run again at any time: it builds what changed, starts what is missing and stops the services of a profile not given (e.g. `start.cmd` after `start.cmd tls`). The first start:

1. `setup-secrets` generates three random passwords in `secrets/` (Keycloak admin, PostgreSQL admin, PostgreSQL user `keycloak`); an existing file is kept.
2. PostgreSQL creates the database and the schema `keycloak` (`config/db/setup-schema.sh`).
3. Keycloak creates the admin user of the master realm and imports `config/keycloak/realm/realm.json`. The realm is imported only when it does not exist: after a change to `realm.json`, `delete-volumes` and `start`.
4. With `brokering`, the two spid-saml-check containers register the SP metadata of the realm and trust their signing certificate (see below).

With Docker inside WSL, `start.cmd` opens a minimized *IAMClient4D WSL keep-alive* window: WSL stops its VM when no WSL process is left, and the containers with it. `stop.cmd` and `delete-volumes.cmd` close it.

Optional settings go in `.env` next to `docker-compose.yml`: copy `.env.example` and uncomment what you change (ports, admin user name, versions, gateway host name). `.env` and `secrets/` are not committed.

## Ports and URLs

| Service | URL | Profile |
|---------|-----|---------|
| Keycloak | `http://localhost:18180/auth` (`KC_PORT`) | always |
| Realm of the samples | `http://localhost:18180/auth/realms/iamclient4d` (the issuer) | always |
| Admin console | `http://localhost:18180/auth/admin` | always |
| SPID demo identity provider | `http://localhost:18443/demo` (`SPID_CHECK_PORT`) | `brokering` |
| CIE simulator | `http://localhost:18444/demo` (`CIE_CHECK_PORT`) | `brokering` |
| HTTPS gateway | `https://localhost:24443/auth` (`DOMAIN_NAME`, `GATEWAY_PORT`) | `tls` |

The ports of Keycloak and of the simulators are published on `127.0.0.1` only. The gateway is published on every interface, for a phone or another machine on the LAN: set `DOMAIN_NAME` in `.env` to the host name or IP address they use.

With `tls` Keycloak publishes `https://DOMAIN_NAME:GATEWAY_PORT/auth` as its URL, so the issuer becomes `https://DOMAIN_NAME:GATEWAY_PORT/auth/realms/iamclient4d`: point every sample at that URL (DMVC: `IAM4D_ISSUER`, with `IAM4D_ALLOW_SELF_SIGNED=true`). The gateway generates a self-signed certificate at its first start (`config/nginx/ssl/certs/`, EC P-256, valid 825 days, names `localhost`, `127.0.0.1` and `DOMAIN_NAME`) and prints its SHA-256 fingerprint in its log.

## Realm `iamclient4d`

| Client | Type | Used by |
|--------|------|---------|
| `iam4d-sample-app` | public, authorization code with PKCE S256; redirect URIs `http://localhost/oauth2callback` and `http://127.0.0.1/oauth2callback` (any port, RFC 8252) and `it.iam4d.identitybrokering:/oauth2callback`; scope `kc-admin-api` (Admin REST API audience) and audience `api-server` | VCL KeycloakClient, VCL and FMX IdentityBrokering |
| `iam4d-sample-unigui` | public, authorization code with PKCE; redirect URIs `http://localhost:8077/?oauthcallback=keycloak` and `http://localhost:8077/*` | uniGUI KeycloakWebApp |
| `iam4d-sample-service` | confidential, client credentials only, secret `iam4d-test-only-secret`; its service account has `calculator-user`; audience `api-server` | VCL KeycloakClient (Client Credentials tab), DMVC servers |
| `calculator-web` | confidential, authorization code with PKCE S256, secret `calculator-web-test-only-secret`; redirect URI `http://localhost:8092/auth/callback`, post-logout redirect URI `http://localhost:8092/`; audience `api-server` | DMVC Calculator web client |
| `api-server` | confidential, no flow: the audience of the DMVC servers, owner of the client roles `calculator-user` and `calculator-advanced` | DMVC servers |

| User | Password | Roles |
|------|----------|-------|
| `demo` | `demo` | `realm-admin` (identity provider and user administration from the samples) |
| `student` | `Student#2026` | `calculator-user` |
| `scientist` | `Scientist#2026` | `calculator-user`, `calculator-advanced` |

The client secrets and passwords above are sample values, public with the repository: never reuse them outside this local Keycloak. Tokens last 5 minutes, SSO sessions 30 minutes idle and 10 hours at most. The master realm admin is `admin` (`IAM_ADMIN_USER`), with the password in `secrets/kc_admin_password.txt`.

## Samples

| Sample | Start | What it uses |
|--------|-------|--------------|
| [VCL KeycloakClient](../samples/VCL/KeycloakClient) | `start.cmd` | `iam4d-sample-app` (login on the Keycloak page or with an identity provider alias), `iam4d-sample-service` (Client Credentials tab), `demo` for the user management tab |
| [VCL IdentityBrokering](../samples/VCL/IdentityBrokering/README.md) | `start.cmd brokering` | `iam4d-sample-app`, `demo`; SPID `spid-test` (`ada` / `password123`), CIE provider created from the sample (`marcopolo` / `password123`); other providers saved from the sample or with `identity-providers/*.ps1` |
| [FMX IdentityBrokering](../samples/FMX/IdentityBrokering/README.md) | `samples/FMX/IdentityBrokering/keycloak.cmd` (`start.cmd brokering`, then `adb reverse` of 18180, 18443, 18444) | as the VCL version, redirect URI `it.iam4d.identitybrokering:/oauth2callback` |
| [uniGUI KeycloakWebApp](../samples/uniGUI/KeycloakWebApp) | `start.cmd` (`brokering` for SPID and CIE on the Keycloak page) | `iam4d-sample-unigui` on `http://localhost:8077`, `demo` |
| [DMVC ScientificCalculator](../samples/DMVC/ScientificCalculator/README.md) servers | `start.cmd` | issuer `http://localhost:18180/auth/realms/iamclient4d`, audience `api-server`, roles `calculator-user` / `calculator-advanced`; tokens from `iam4d-sample-service`, `student`, `scientist` |
| DMVC ScientificCalculator web client | `start.cmd` | `calculator-web` (`CALC_WEB_CLIENT_SECRET=calculator-web-test-only-secret`), `student`, `scientist` |
| DMVC SwaggerAPIVersioning | `start.cmd` | issuer and audience as the calculator servers |

## SPID and CIE (profile `brokering`)

The Keycloak image (`keycloak/Dockerfile`) adds the SPID extension of [italia/spid-keycloak-provider](https://github.com/italia/spid-keycloak-provider) (provider type `spid-saml`) and the CIE ID extension of [lscorcia/keycloak-cieid-provider](https://github.com/lscorcia/keycloak-cieid-provider) (`cieid-saml`). They are built for one Keycloak minor: keep `KC_VERSION`, `SPID_VERSION` and `CIE_VERSION` on the same minor, and give `SPID_SHA256` and `CIE_SHA256` (shown by GitHub next to each release asset) when you change the extension versions.

The profile runs two containers of [italia/spid-saml-check](https://github.com/italia/spid-saml-check) 2.2.5, the AgID SPID test suite (image `italia/spid-saml-check`, used unmodified; the scripts in `spid-saml-check/` configure it at start):

- **SPID demo identity provider** (`spid-saml-check`, `http://localhost:18443/demo`). The realm has the SPID provider `spid-test` bound to it, with the mappers `fiscalNumber`, `email`, `name` and `familyName`; the realm user profile declares `fiscalNumber`. Users: `http://localhost:18443/demo/users`, e.g. `ada` / `password123`. At start the container trusts its new signing certificate on `spid-test` and registers the SPID SP metadata of the realm; then it registers it again whenever it changes (e.g. a SPID provider saved from a sample).
- **CIE simulator** (`cie-simulator`, `http://localhost:18444/demo`): the same tool relabelled *Simulatore CIE* (text only), with the request checks of the SPID profile off. It is not CIE ID and does not check the CIE rules. The realm has no CIE provider: the samples create it (*Local test (CIE simulator)*, metadata `http://cie-simulator:18444/demo/metadata.xml`, the name Keycloak reaches in Docker); a few seconds later the simulator has registered its SP metadata. Users as above, level 3, e.g. `marcopolo` / `password123`, within 60 seconds. CIE ID returns no email: Keycloak asks for it at the first login.

The real SPID and CIE identity servers accept only service providers registered with AgID or the Ministry of the Interior: with this Keycloak their login page opens, but the login cannot complete.

## Other identity providers

`identity-providers/` has a PowerShell script per provider: it creates or updates the provider in the realm `iamclient4d` through the Admin REST API, with the same configuration as the IAMClient4D builder, and prints the redirect URI to register at the provider, `http://localhost:18180/auth/realms/iamclient4d/broker/<alias>/endpoint`.

| Script | Provider (alias) | Environment variables (or the parameters of the same name, or asked) |
|--------|------------------|-------------------------------------------------|
| `entra.ps1` | Microsoft Entra ID (`entra`) | `ENTRA_TENANT`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` |
| `microsoft.ps1` | personal Microsoft accounts (`microsoft`) | `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` |
| `google.ps1` | Google (`google`) | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| `facebook.ps1` | Facebook (`facebook`) | `FACEBOOK_APP_ID`, `FACEBOOK_APP_SECRET` |
| `github.ps1`, `gitlab.ps1`, `linkedin.ps1` | GitHub, GitLab.com, LinkedIn | `<PROVIDER>_CLIENT_ID`, `<PROVIDER>_CLIENT_SECRET` |
| `oauth2.ps1` | any OAuth 2.0 provider | `OAUTH2_AUTHORIZATION_URL`, `OAUTH2_TOKEN_URL`, `OAUTH2_USERINFO_URL`, `OAUTH2_CLIENT_ID`, `OAUTH2_CLIENT_SECRET`; scopes and claims as parameters |
| `oidc.ps1` | any OpenID Connect provider (`oidc`) | `OIDC_DISCOVERY_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` |

```bat
powershell -ExecutionPolicy Bypass -File identity-providers\google.ps1 -ClientId <client-id>
```

On Linux and macOS: `pwsh identity-providers/google.ps1 -ClientId <client-id>`. The scripts read the admin password from `secrets/kc_admin_password.txt`; `-KeycloakUrl`, `-Realm`, `-AdminUser` and `-AdminPassword` point them at another Keycloak (e.g. the test one). Keep real client secrets out of the repository: pass them in the environment or type them when asked. The providers stay in the database until `delete-volumes`.

## Reset

- `delete-volumes`: removes the database; the next `start` imports the realm again (providers and users created from the samples are gone). The passwords in `secrets/` are kept and reused.
- From scratch: `delete-volumes`, then delete `secrets/`, `.env` and the files in `config/nginx/ssl/certs/` (except `.gitkeep`).

## Troubleshooting

- **Port already in use** (`Bind for 127.0.0.1:18180 failed`): set `KC_PORT` (or `SPID_CHECK_PORT`, `CIE_CHECK_PORT`, `GATEWAY_PORT`) in `.env` and start again; then change the base URL in the samples too. `spid-test` takes the SPID port when the realm is imported: after a change of `SPID_CHECK_PORT`, `delete-volumes`.
- **Keycloak does not start after `secrets/` was deleted** (`password authentication failed for user "keycloak"`): PostgreSQL keeps the passwords of its first start, in the volume. Put the old files back, or `delete-volumes`. The Keycloak admin password is likewise set only at the first start: a new `kc_admin_password.txt` does not change it, and the simulators then cannot configure the realm.
- **Certificate of the gateway**: it is made for the `DOMAIN_NAME` of its first start. After a change of `DOMAIN_NAME`, or when it expires, delete the files in `config/nginx/ssl/certs/` and `start.cmd tls`. Browsers warn about a self-signed certificate: trust `certificate.crt` on the test machine, or accept the warning.
- **Containers stop by themselves** (Docker inside WSL): the WSL VM stopped because no WSL process was left. Keep the *IAMClient4D WSL keep-alive* window of `start.cmd` open, or a WSL terminal, and run `start.cmd` again.
- **`spid-test` login fails at the demo identity provider** after saving a SPID provider from a sample: wait a few seconds, the SP metadata is registered again; `logs.cmd spid-saml-check` shows it. An `SQLITE_ERROR` in that log at start is harmless.
- **`401` from the Admin REST API** with a token of another client: since Keycloak 26.8.2 the token needs the audience of the client scope `kc-admin-api`, a default scope only of `iam4d-sample-app` here.
