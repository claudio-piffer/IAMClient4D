<div align="center">

![IAMClient4D Logo](images/IAMClient4D_logo.png)

### OAuth 2.0 / OpenID Connect client for Delphi, built for Keycloak

Login for desktop and mobile apps, server-side web apps and services; JWT validation for REST APIs (DMVCFramework); Keycloak Admin REST API for users, roles and identity providers.

[Quick start](#quick-start-in-5-minutes) • [Scenarios](#scenarios) • [Reference](docs/reference/) • [Migration from 2.x](docs/MIGRATION_3.0.md) • [Changelog](CHANGELOG.md)

</div>

---

## Contents

- [What it is](#what-it-is)
- [Requirements and platforms](#requirements-and-platforms)
- [Quick start in 5 minutes](#quick-start-in-5-minutes)
- [Scenarios](#scenarios)
  - [Desktop app](#desktop-app)
  - [Mobile app (Android, iOS)](#mobile-app-android-ios)
  - [Server-side web app](#server-side-web-app)
  - [REST API with DMVCFramework](#rest-api-with-dmvcframework)
  - [Calling a protected API](#calling-a-protected-api)
  - [Service to service](#service-to-service)
  - [Keycloak Admin API](#keycloak-admin-api)
  - [Identity brokering](#identity-brokering)
- [Security](#security)
- [Errors](#errors)
- [Migration from 2.x](#migration-from-2x)
- [Reference](#reference)
- [License, contributing, roadmap](#license-contributing-roadmap)

---

## What it is

IAMClient4D is a Delphi library for OAuth 2.0 and OpenID Connect, with Keycloak as its reference server:

- **Client side**: Authorization Code with PKCE through the system browser (local callback server on desktop, private-use URI scheme on mobile, external callback for web servers), Client Credentials, password grant; refresh, revocation, logout, user info, id_token claims; tokens kept encrypted in memory.
- **Server side**: JWT validation (signature through the JWKS, claims, `at+jwt`) and a DMVCFramework 3.5 filter bundle that protects controllers and Minimal API routes, with role, scope and group helpers.
- **Administration**: users, credentials, realm and client roles, groups, sessions and identity providers through the Keycloak Admin REST API, with builders for Entra ID, Google, Facebook, GitHub, SAML, SPID, CIE and others.
- **Async.Core**: the promise library under every `...Async` method (`OnSuccess`, `OnError`, `OnFinally`, `Run`), usable on its own.

Every network call has a synchronous and an asynchronous version; errors are typed exceptions with an error code.

## Requirements and platforms

| | |
|---|---|
| Delphi | 12 or later; tested with Delphi 13 (`IAMClient4D.Config.inc` stops older compilers) |
| Keycloak | 25 or later; tested with 25.0, 26.7 and 26.8. With 26.8.2 or later the Admin API needs the `kc-admin-api` client scope ([KeycloakSetup.md](docs/reference/KeycloakSetup.md#admin-rest-api-client)) |
| DMVCFramework | 3.5.0-silicon-rc10 or later, only for the DMVC integration (not included: clone it into `src/Lib/delphimvcframework`, the path used by the samples) |
| Crypto provider | LockBox3 (default, bundled), TaurusTLS with OpenSSL 3.x/4.x (`IAM4D_TAURUSTLS`), or TMS Cryptography Pack (`IAM4D_TMS`, commercial). ES256/384/512 need TaurusTLS or TMS |

| Platform | Status |
|---|---|
| Windows 32 and 64 bit | tested (test suites, VCL and FMX samples) |
| Linux 64 bit | tested (test suites, DMVC servers) |
| Android 64 bit | tested on a device (FMX IdentityBrokering sample) |
| Android 32 bit | compiles |
| iOS | compiles; device test pending |
| macOS (ARM 64) | compiles only |

### Installation

Clone with the submodule (TaurusTLS, needed only for the OpenSSL provider): `git clone --recurse-submodules <repository URL>`.

There is no package: add the folders to the search path of the project (relative to the repository root; the `.dproj` files of the samples use the same lists).

| Use | Search path |
|---|---|
| Every project | `src`; `src\Lib\DelphiCSPRNG\src`; `src\Lib\LockBox3\ciphers`; `src\Lib\LockBox3\cryptography`; `src\Lib\LockBox3\hashes`; `src\Lib\LockBox3\library surface`; `src\Lib\LockBox3\RSA`; `src\Lib\LockBox3\utilities` |
| DMVCFramework servers | also `src\DMVCMiddleware`; `src\Lib\delphimvcframework\sources`; `src\Lib\delphimvcframework\lib\loggerpro`; `src\Lib\delphimvcframework\lib\swagdoc\Source`; `src\Lib\delphimvcframework\lib\dmustache` (DMVCFramework cloned into `src\Lib\delphimvcframework`, or your own copy) |
| Android and iOS apps | also `src\FMX` |
| OpenSSL provider (`IAM4D_TAURUSTLS`) | also `src\Lib\TaurusTLS\Source` ([Security.md](docs/reference/Security.md)) |
| TMS provider (`IAM4D_TMS`) | also the TMS Cryptography Pack sources |

The bundled libraries keep their licenses (see each folder of `src\Lib`): [LockBox3](https://github.com/TurboPack/LockBox3) (MPL 2.0, with a patch: use the bundled copy), [DelphiCSPRNG](https://github.com/jimmckeeth/DelphiCSPRNG), [TaurusTLS](https://github.com/TaurusTLS-Developers/TaurusTLS) (submodule). [DelphiMVCFramework](https://github.com/danieleteti/delphimvcframework) (Apache 2.0) is not included.

## Quick start in 5 minutes

1. **Start Keycloak** with the sample environment (Docker with Compose; on Windows Docker Desktop or Docker inside WSL):

   ```bat
   Docker\start.cmd
   ```

   Keycloak answers on `http://localhost:18180/auth`, realm `iamclient4d`, with the clients and users of every sample. Test users: `demo` / `demo` (`realm-admin`), `student` / `Student#2026`, `scientist` / `Scientist#2026`. Ports, profiles (`brokering` for SPID and CIE, `tls` for HTTPS) and troubleshooting: [Docker/README.md](Docker/README.md).

2. **Run the VCL sample** `samples/VCL/KeycloakClient/KeycloakClient.dproj` (Win32 or Win64). Its fields are already set to the environment: *Login* opens the browser, sign in as `demo` / `demo`; the sample shows the claims of the id_token, the granted scopes and the access token, and has *Refresh*, *User info*, *Revoke*, *Logout*, the Admin API and the Client Credentials flow (`iam4d-sample-service`, secret `iam4d-test-only-secret`).

3. **The same login in your code**, against the same realm:

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('http://localhost:18180/auth', 'iamclient4d', 'iam4d-sample-app')
  .BuildAsync
  .OnSuccess(
    procedure(const AClient: IIAM4DClient)
    begin
      LClient := AClient; // keep the client: releasing it cancels the login
      LClient.StartAuthorizationFlowAsync
        .OnSuccess(
          procedure(const AAccessToken: string)
          begin
            ShowMessage('Signed in as ' + LClient.GetIDTokenClaims.PreferredUsername);
          end)
        .OnError(
          procedure(const E: Exception)
          begin
            ShowMessage(E.ClassName + ': ' + E.Message);
          end)
        .Run;
    end)
  .Run;
```

`BuildAsync` reads the discovery document of the realm (`/.well-known/openid-configuration`) off the main thread; the login opens the system browser and listens on `http://localhost:<random port>/oauth2callback`. Plain `http` is accepted only for the loopback: a real Keycloak is reached through `https`. To configure a Keycloak of your own: [KeycloakSetup.md](docs/reference/KeycloakSetup.md).

The other samples:

| Sample | What it shows |
|---|---|
| [`samples/VCL/KeycloakClient`](samples/VCL/KeycloakClient) | desktop login, session, Admin API, Client Credentials |
| [`samples/VCL/IdentityBrokering`](samples/VCL/IdentityBrokering/README.md) | login through SPID, CIE and other providers; providers saved through the Admin API |
| [`samples/FMX/IdentityBrokering`](samples/FMX/IdentityBrokering/README.md) | the same on Android and iOS, with the redirect on a private-use scheme |
| [`samples/DMVC/ScientificCalculator`](samples/DMVC/ScientificCalculator/README.md) | REST API with controllers and with Minimal API routes, roles from the token; server-side web client with login and logout |
| [`samples/uniGUI/KeycloakWebApp`](samples/uniGUI/KeycloakWebApp) | uniGUI web app with the external callback |

---

## Scenarios

The examples use the sample environment where it fits; replace URL, realm and client with yours. Full API: [docs/reference](docs/reference/).

### Desktop app

Authorization Code with PKCE through the system browser and a local callback server (RFC 8252). Register `http://localhost/oauth2callback` as redirect URI of a public client: Keycloak ignores the port of a loopback redirect URI.

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('http://localhost:18180/auth', 'iamclient4d', 'iam4d-sample-app')
  .WithScopes(['openid', 'profile', 'email'])
  .Build;

// Run returns the operation: Cancel ends a login left open in the browser
var LLogin := LClient.StartAuthorizationFlowAsync
  .OnSuccess(
    procedure(const AAccessToken: string)
    begin
      ShowMessage('Scopes: ' + string.Join(' ', LClient.GetGrantedScopes));
    end)
  .OnError(
    procedure(const E: Exception)
    begin
      ShowMessage(E.Message);
    end)
  .Run;
```

- **Cancel**: `Cancel` on the operation, or `CancelAuthorizationFlow`, ends the login as cancelled: `OnFinally` runs, `OnError` does not.
- **Session**: `GetAccessToken` returns a valid token and refreshes it when it is about to expire; `GetIDTokenClaims`, `GetGrantedScopes`, `GetUserInfo`; `RevokeTokens` (RFC 7009) ends the session of this client, `Logout` the whole Keycloak session. When the refresh token is refused, `EIAM4DRefreshTokenExpiredException` asks for a new login.
- **Options of one login**: `TIAM4DAuthRequestOptions` for a stronger or fresher authentication without another client:

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
LClient.StartAuthorizationFlowAsync(TIAM4DAuthRequestOptions.Create
    .WithPrompt(IAM4D_PROMPT_LOGIN) // ask for the credentials again
    .WithMaxAge(0)                  // auth_time checked against the request
    .WithLoginHint('scientist'))
  .Run;
```

  `WithPrompt`, `WithMaxAge`, `WithAcrValues` and `WithKeycloakAction` (e.g. the change-password page, outcome in `GetKeycloakActionStatus`) exist on the builder too.
- **Forms**: keep the client in a field, do not wait for an operation on the main thread, and do not free a form while one of its operations is pending: the VCL samples count them with `samples/VCL/Common/Samples.PendingOperations.pas`.
- **No browser**: `TIAM4DPlatformUtils.OpenURLHandler` replaces the system browser (embedded browser, tests).

Details: [Core.md](docs/reference/Core.md).

### Mobile app (Android, iOS)

The authorization server redirects to a private-use URI scheme (RFC 8252 7.1) that the operating system hands back to the app. Register the redirect URI as is (`it.iam4d.identitybrokering:/oauth2callback` in the sample realm).

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('https://keycloak.example.com', 'iamclient4d', 'iam4d-sample-app')
  .WithAppRedirect('it.iam4d.identitybrokering:/oauth2callback')
  .Build;
LClient.StartAuthorizationFlowAsync
  .OnSuccess(
    procedure(const AAccessToken: string)
    begin
      // signed in: the app was reopened by the redirect
    end)
  .Run;
```

Once at startup, call `TIAM4DAppRedirectListener.Install` (unit `IAMClient4D.FMX.AppRedirect`, folder `src\FMX`): it passes the URLs the system hands to the app to `TIAM4DAppRedirect.HandleURL`, and opens the login page in a Custom Tab on Android and in Safari or an `ASWebAuthenticationSession` (`ilbAuthenticationSession`) on iOS.

- **Android**: main activity `android:launchMode="singleTask"` and an intent filter `VIEW` / `DEFAULT` / `BROWSABLE` with `<data android:scheme="..."/>` in `AndroidManifest.template.xml`.
- **iOS**: `CFBundleURLTypes` with the scheme in `info.plist.TemplateiOS.xml`.
- A login pending when the system kills the app is lost: the user signs in again. PKCE keeps another app that claims the same scheme from exchanging the code.

Details and the complete app: [Core.md](docs/reference/Core.md), [`samples/FMX/IdentityBrokering`](samples/FMX/IdentityBrokering/README.md).

### Server-side web app

The web server receives the redirect itself (`WithExternalCallback`) and keeps one client per pending login and per session. A confidential client sends its secret as well as PKCE.

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
// Login request: redirect the browser to the URL, keep LClient under its state
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('http://localhost:18180/auth', 'iamclient4d', 'calculator-web',
    'calculator-web-test-only-secret')
  .WithExternalCallback('http://localhost:8092/auth/callback')
  .Build;
LClient.InitializeAuthorizationFlow;
var LAuthorizationURL := LClient.GenerateAuthURL;

// Callback: code, state and iss of the query string. State, iss (RFC 9207), code exchange
// and id_token are checked; a state can be completed once
var LAccessToken := LClient.CompleteAuthorizationFlow('<code>', '<state>', '<iss>');

// Sign out: the browser goes to the logout URL, which returns to the post logout redirect URI
var LLogoutURL := LClient.GenerateLogoutURL('http://localhost:8092/');
LClient.Logout;
```

The complete web client (htmx, session cookie, CSRF, expired logins): [`samples/DMVC/ScientificCalculator`](samples/DMVC/ScientificCalculator/README.md).

### REST API with DMVCFramework

`IAM4DJWTBundle` validates the bearer token of every request (signature through the JWKS of the issuer, `iss`, `aud`, `exp`, token type) and fills `Context.LoggedUser`, so controller actions and Minimal API routes are protected; Swagger gets the bearer scheme. Register it before the controllers and before `SwaggerHTTPFilter`:

<!-- snippet ver=3.0 kind=decl ctx=dmvc_engine -->
```delphi
procedure ConfigureEngine(const AEngine: TMVCEngine);
begin
  AEngine.Use(IAM4DJWTBundle(
    'http://localhost:18180/auth/realms/iamclient4d', // issuer
    'api-server'));                                   // expected audience
end;
```

In a controller action:

<!-- snippet ver=3.0 kind=body ctx=dmvc_ctx -->
```delphi
Context.RequireAnyRole(['calculator-user']); // 403 "Insufficient permissions" otherwise
var LUserName := Context.JWT.PreferredUsername;
var LAdvanced := Context.Keycloak.GetClientAccess('api-server').HasRole('calculator-advanced');
```

- `[IAM4DPublic]` on a controller or an action opens it to anonymous requests; `IAM4DJWTEndpointFilter` protects a Minimal API route group.
- Roles, scopes, groups and claim names are case-sensitive; the client roles come from the `Audience` (and `ExpectedAzp`) client.
- RFC 9068 `at+jwt` access tokens are accepted; an unreachable identity provider answers 503 with `Retry-After`.
- `TIAM4DJWTMiddlewareConfig` for the other settings: JWKS URL, pinned keys, clock skew, claim names. `TIAM4DJWTMiddleware` is deprecated (it does not protect Minimal API routes).

Details: [DMVC.md](docs/reference/DMVC.md). Without DMVC, `TIAM4DJWTValidator` validates a token anywhere: [Security.md](docs/reference/Security.md).

### Calling a protected API

`TIAM4DAuthorizedHTTPClient` sends the access token of a client as bearer: it renews the token when it expires and retries once after a 401. It sends the token only over HTTPS (loopback excepted) and never follows a redirect.

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.AuthorizedHTTP -->
```delphi
var LApi := TIAM4DAuthorizedHTTPClient.Create(LClient);
try
  var LResponse := LApi.Get('http://localhost:8090/api/elementary/power?base=2&exponent=10');
  Writeln(LResponse.StatusCode, ' ', LResponse.ContentAsString);
finally
  LApi.Free;
end;
```

One instance per thread; TLS, proxy and timeouts on its `HTTPClient`. Details: [Core.md](docs/reference/Core.md).

### Service to service

Client Credentials: the service signs in with its own secret, no user involved.

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForClientCredentials('http://localhost:18180/auth', 'iamclient4d', 'iam4d-sample-service',
    'iam4d-test-only-secret')
  .Build;
var LAccessToken := LClient.AuthenticateClient; // GetAccessToken then asks for a new token when it expires
```

The password grant (`ForPassword`, `AuthenticatePassword`) exists for trusted or legacy clients: it needs *Direct access grants* on a client of its own, and cannot use brokered providers, MFA or required actions (deprecated by RFC 9700). Its errors are typed: `EIAM4DInvalidCredentialsException`, `EIAM4DAccountNotFullySetUpException`, `EIAM4DAccountDisabledException`.

### Keycloak Admin API

`TIAM4DKeycloakUserManager` calls the Admin REST API with the token of a client: a user with the roles of `realm-management` (the sample user `demo` has `realm-admin`) or a service account.

<!-- snippet ver=3.0 kind=body ctx=client,umgr -->
```delphi
LUserManager := TIAM4DKeycloakUserManager.Create(LClient); // base URL and realm of the client

var LUser := TIAM4DUser.Create('john.doe', 'john.doe@example.com', 'John', 'Doe');
var LUserID := LUserManager.CreateUser(LUser);
LUserManager.AssignClientRoleByClientID(LUserID, 'api-server', 'calculator-user');
LUserManager.SendVerifyEmail(LUserID);
```

Users, credentials, required actions, realm and client roles, groups, sessions, federated identities, batches; every method has an `...Async` version in `IIAM4DUserManagerAsync`. HTTP errors are typed (`EIAM4DUserNotFoundException`, `EIAM4DUserAlreadyExistsException`, `EIAM4DInsufficientPermissionsException`, ...). With Keycloak 26.8.2 or later the client needs the `kc-admin-api` scope. Details: [AdminAPI.md](docs/reference/AdminAPI.md).

### Identity brokering

Keycloak signs the user in through another provider (Entra ID, Google, SPID, CIE, ...) and issues its own tokens: the application does not change. The alias of a provider as `kc_idp_hint` skips the Keycloak login page:

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
LClient.StartAuthorizationFlowAsync('spid-test') // SPID provider of the sample realm (profile brokering)
  .Run;
```

The providers are configured from code through `IIAM4DIdentityProviderManager`, with builders that keep secure defaults (PKCE, signature and issuer checks):

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.IdentityProvider.Core,IAMClient4D.IdentityProvider.Builders,IAMClient4D.IdentityProvider.Keycloak -->
```delphi
var LManager: IIAM4DIdentityProviderManager := TIAM4DKeycloakIdentityProviderManager.Create(LClient);
LManager.SaveIdentityProvider(TIAM4DEntraIdPBuilder.New('entra')
  .WithTenant('<tenant ID>')
  .WithClient('<application ID>', '<client secret>')
  .Build);
```

Builders for Entra ID, Microsoft accounts, Google, Facebook, LinkedIn, GitHub, GitLab, any OpenID Connect, OAuth 2.0 or SAML 2.0 provider, SPID and CIE; mappers, metadata import and SAML SP metadata. Details: [IdentityBrokering.md](docs/reference/IdentityBrokering.md).

---

## Security

What the library checks without being asked:

- **Login**: PKCE S256, `state` and `nonce` from the CSPRNG, `iss` of the authorization response (RFC 9207), a code exchanged once; the callback server checks the `Host` header.
- **id_token**: signature through the JWKS, `iss`, `aud`, `azp`, `typ`, `exp` / `iat` (300 s of tolerance), `nonce`, `auth_time` against `max_age`, at the login, at every refresh and in Client Credentials; `GetUserInfo` refuses a `sub` other than the one of the id_token.
- **JWT**: exact `alg` from an allow-list (never `none` or HMAC), RSA keys of 2048 bits or more, `crit` refused, canonical base64url, numeric time claims, `jti` replay check; JWKS refreshed as a whole, an unknown `kid` refreshes it at most every 30 s.
- **Transport**: `http://` refused outside the loopback, redirects never followed, certificates validated by the system; pinned public keys checked in strict mode too (JWKS included).
- **Tokens and secrets**: tokens kept AES-256 encrypted in memory (CBC + HMAC with LockBox3, GCM with TaurusTLS or TMS); request bodies with secrets and passwords zeroed after sending; error messages without query strings.

What is up to you:

1. `https` with valid certificates; `WithAllowSelfSignedSSL` and `WithAllowInsecureHTTP` only for test environments.
2. Public clients with PKCE for desktop and mobile apps; *Direct access grants* off on every client that does not need them.
3. The least scopes and roles; a separate client for the Admin API.
4. Client secrets out of the sources and rotated.
5. No tokens, passwords or secrets in logs.

Details: [Security.md](docs/reference/Security.md), [Storage.md](docs/reference/Storage.md).

## Errors

Every error of the library is an `EIAM4DException` with an `ErrorCode` (`TIAM4DErrorCode`); subclasses tell the cases apart that call for a different reaction:

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
try
  var LAccessToken := LClient.GetAccessToken;
except
  on E: EIAM4DRefreshTokenExpiredException do
    ShowMessage('Session expired: sign in again');
  on E: EIAM4DNetworkTimeoutException do
    ShowMessage('Keycloak did not answer in time');
  on E: EIAM4DException do
    ShowMessage(Format('Error %d: %s', [Ord(E.ErrorCode), E.Message]));
end;
```

| Exception | When |
|---|---|
| `EIAM4DRefreshTokenExpiredException` | the refresh token was refused: tokens cleared, a new login is needed |
| `EIAM4DOAuth2CallbackException` | the authorization server answered with an error (`access_denied`, `login_required`, ...) |
| `EIAM4DSecurityValidationException` and subclasses | a token, a state or an issuer did not pass the checks |
| `EIAM4DNetworkTimeoutException`, `EIAM4DNetworkUnreachableException`, `EIAM4DSSLCertificateException` | network and TLS |
| `EIAM4DHTTPClientErrorException`, `EIAM4DHTTPServerErrorException` and subclasses | Admin API answers (403, 404, 409, other 4xx, 5xx) |
| `EIAM4DInvalidConfigurationException` | configuration refused (e.g. `http://` to a remote host, an `http` endpoint in the discovery of an `https` realm) |
| `EIAM4DDiscoveryFailedException` | the discovery document of the realm cannot be read (wrong URL or realm, a proxy page) |

A cancelled login is not an error: it ends with `OnFinally` and without `OnError`. In the async API the exception reaches `OnError` as a copy with all its fields. The complete hierarchy and the error codes: [Core.md](docs/reference/Core.md).

## Migration from 2.x

3.0 changes behaviour in several places, mostly toward stricter checks: `http://` and redirects refused, id_token fully validated, typed network and Admin API exceptions, case-sensitive roles in DMVC, `TIAM4DJWTMiddleware` deprecated. [docs/MIGRATION_3.0.md](docs/MIGRATION_3.0.md) lists every change with the code before and after; the [CHANGELOG](CHANGELOG.md) has the complete list.

## Reference

| Document | Contents |
|---|---|
| [Core.md](docs/reference/Core.md) | builder, flows, callback modes, session, logout and revocation, discovery cache, HTTP clients, exceptions |
| [Security.md](docs/reference/Security.md) | JWT validator, JWKS, SSL modes and pinning, crypto providers |
| [Storage.md](docs/reference/Storage.md) | encrypted token storage, custom storage |
| [AdminAPI.md](docs/reference/AdminAPI.md) | users, roles, groups, sessions through the Admin REST API |
| [IdentityBrokering.md](docs/reference/IdentityBrokering.md) | `kc_idp_hint`, provider management and builders, SPID and CIE |
| [DMVC.md](docs/reference/DMVC.md) | filter bundle, Minimal API, helpers, configuration |
| [AsyncCore.md](docs/reference/AsyncCore.md) | promises, dispatch modes, combinators, retries |
| [KeycloakSetup.md](docs/reference/KeycloakSetup.md) | realm, clients for each scenario, users and roles |

The tests (console suites for Win32, Win64 and Linux64, one against a real Keycloak): [tests/README.md](tests/README.md).

---

## License, contributing, roadmap

**License**: Apache License 2.0, see [LICENSE](LICENSE). Copyright (c) 2018-2025 Claudio Piffer. The bundled libraries keep their own licenses.

**Contributing**: issues and pull requests are welcome. In an issue give the Delphi, Keycloak and platform versions, a minimal example and the logs without tokens or secrets. In a pull request follow the style of the code, document the public API with `///` comments, and add tests to the suite of the area (`tests/`).

**Roadmap 3.1**:

- persistent session storage;
- `GetAccessToken` without decrypting under an exclusive lock;
- Device Authorization Grant, `private_key_jwt`, token introspection, multiple issuers, Token Exchange, DPoP;
- async version of `TIAM4DAuthorizedHTTPClient`.

**Acknowledgments**: [Keycloak](https://www.keycloak.org/), [DMVCFramework](https://github.com/danieleteti/delphimvcframework) by Daniele Teti, [LockBox3](https://github.com/TurboPack/LockBox3), [DelphiCSPRNG](https://github.com/jimmckeeth/DelphiCSPRNG) by Jim McKeeth, [TaurusTLS](https://github.com/TaurusTLS-Developers/TaurusTLS), [italia/spid-keycloak-provider](https://github.com/italia/spid-keycloak-provider) and [keycloak-cieid-provider](https://github.com/lscorcia/keycloak-cieid-provider).

**Support**: [GitHub Issues](https://github.com/claudio-piffer/IAMClient4D/issues), [GitHub Discussions](https://github.com/claudio-piffer/IAMClient4D/discussions), [contact the author](mailto:claudio.piffer@gmail.com).

> This documentation was written with the help of AI (Claude Code) and checked against the code: every Delphi block compiles with Delphi 13. If you find an error, please open an issue.
