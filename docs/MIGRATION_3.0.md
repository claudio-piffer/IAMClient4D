# IAMClient4D 3.0 Migration Guide (from 2.x)

This guide lists what you have to change, or check, when you move an application from IAMClient4D 2.x to 3.0. Most 2.x code compiles on 3.0 unchanged. The work is mostly in the behaviours that 3.0 makes stricter, where code still compiles but the result at run time is different.

How to read it:

- each item has a **before** (2.1) and an **after** (3.0) snippet when the code changes, and a **what to do** line;
- the "after" snippets compile against 3.0. The "before" snippets compile against 2.1, except the DMVC ones: the 2.1 middleware needs a DMVCFramework release older than 3.5, which 3.0 does not support, so they are checked against the 2.1 declarations only;
- the full list of differences, unit by unit, with references to the source, is in [`docs/release-3.0/API_DIFF_2.1_3.0.md`](release-3.0/API_DIFF_2.1_3.0.md) (Italian).

Contents:

1. [Requirements](#1-requirements)
2. [Security: stricter behaviours](#2-security-stricter-behaviours)
3. [Interfaces](#3-interfaces)
4. [Removed and deprecated](#4-removed-and-deprecated)
5. [Errors and exceptions](#5-errors-and-exceptions)
6. [Admin API](#6-admin-api)
7. [Async.Core](#7-asynccore)
8. [Data: dates, scope, logout](#8-data-dates-scope-logout)
9. [DMVCFramework](#9-dmvcframework)
10. [What you gain](#10-what-you-gain)
11. [Checklist](#11-checklist)

---

## 1. Requirements

| | 2.x | 3.0 |
|---|---|---|
| Delphi | 12.3 or later (not checked) | Delphi 12 or later, tested with Delphi 13. `IAMClient4D.Config.inc` stops older compilers with a fatal error |
| DMVCFramework | 3.4 or later | **3.5.0-silicon-rc10 or later**: the middleware uses `TMVCUser` and the filter bundles |
| Keycloak | 22 or later | 25 or later, tested with 25.0, 26.7 and 26.8 |
| Crypto provider | LockBox3 (default) or TMS | LockBox3 (default), TMS, or TaurusTLS/OpenSSL 3.x-4.x. TMS and TaurusTLS cannot be enabled together |
| Platforms | Win32, Win64 | Win32, Win64, Linux64, Android, iOS, macOS |

**What to do:**

- update DMVCFramework to 3.5.0-silicon-rc10 or later before you update the middleware. The 2.x middleware does not compile on DMVC 3.5, and the 3.0 middleware does not compile on 3.4;
- with Keycloak 26.8.2 or later, Admin REST API tokens need the audience of the `kc-admin-api` client scope: add that scope to the default client scopes of the client that calls the Admin API, otherwise every call answers 401;
- on Linux, public key pinning is not supported: `AddPinnedPublicKeys` and `WithPinnedPublicKeys` raise `ENotSupportedException`.

---

## 2. Security: stricter behaviours

These changes need no code changes when your setup is already correct. They break test setups and misconfigured servers, so check each one.

### 2.1 Plain `http://` is refused outside the loopback

`BaseURL`, an external callback URL and every endpoint of the discovery document must use `https`, unless the host is `localhost`, `127.0.0.0/8` or `::1`. In an `https` realm, an `http` endpoint in the discovery document is refused too. The error is `EIAM4DInvalidConfigurationException`.

Before (2.1), accepted:

<!-- snippet ver=2.1 kind=body ctx=client -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('http://keycloak.test.lan:8080', 'demo', 'demo_public')
  .Build;
```

After (3.0), only for a test server:

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('http://keycloak.test.lan:8080', 'demo', 'demo_public')
  .WithAllowInsecureHTTP // test environments only: tokens travel in clear
  .Build;
```

**What to do:** use `https` in production. Use `WithAllowInsecureHTTP` only in tests, and never ship it.

### 2.2 HTTP redirects are not followed

The library clients no longer follow 3xx responses. In 2.x a 307 sent the form, with the client secret, to whatever `Location` said. A 3xx is now an error that names the `Location`.

**What to do:** point `BaseURL` to the final address of Keycloak. If a proxy redirects (for example `http` → `https`, or a path without the final `/`), fix the URL or the proxy.

### 2.3 The `iss` of the authorization response is checked (RFC 9207)

When the discovery document announces `authorization_response_iss_parameter_supported`, as Keycloak 26 does, the callback must carry an `iss` equal to the issuer of the client. With the local callback server and the app redirect, the library checks it on its own: a wrong or missing `iss` fails the login with `EIAM4DCallbackHandlerException`.

In the external callback mode (web applications), your code reads the callback parameters, so it must pass `iss` too.

Before (2.1):

<!-- snippet ver=2.1 kind=decl ctx=client -->
```delphi
procedure HandleCallback(const ACode, AState: string);
begin
  LClient.CompleteAuthorizationFlow(ACode, AState);
end;
```

After (3.0):

<!-- snippet ver=3.0 kind=decl ctx=client -->
```delphi
procedure HandleCallback(const ACode, AState, AIss: string);
begin
  // AIss: the iss query parameter of the callback URL ('' when absent)
  LClient.CompleteAuthorizationFlow(ACode, AState, AIss);
end;
```

**What to do:** forward the `iss` query parameter of the callback. When `AIss` is empty, the external mode does not check it, and the login works without the RFC 9207 protection.

Also in the external mode, the flow context is taken before the code exchange: after a failed `CompleteAuthorizationFlow` you cannot retry with the same `state`. Start a new login.

### 2.4 The id_token is fully validated

In 2.x only the `nonce` of the id_token was checked. 3.0 validates it as a JWT at the code exchange, at every refresh and in Client Credentials when an id_token is present:

- the signature, checked with the realm JWKS;
- `iss` equal to the issuer, `aud` equal to the client ID, `azp` equal to the client ID when present;
- `typ` equal to `ID`;
- `exp` and `iat`, with 300 seconds of clock skew.

After a refresh, `sub`, `aud` and `nonce` must also be equal to those of the login.

Errors raise `EIAM4DSecurityValidationException` (it was `EIAM4DException`).

**What to do:**

- the client must reach the JWKS endpoint of the realm: a login now makes one more GET, and if the JWKS cannot be downloaded the login fails with `EIAM4DJWKSUnavailableException`;
- keep the clocks of the client and of Keycloak in sync: a skew above 5 minutes fails the login.

### 2.5 JWT: exact `alg`, RSA keys of 2048 bits or more

- The `alg` header is compared exactly (RFC 7515): `rs256` is no longer RS256. The names in `SetAllowedAlgs` must be the registered ones.
- When a JWK declares `alg`, it must be equal to the `alg` of the token. Keys with `use: enc` are no longer used to verify signatures.
- RSA keys must have a modulus of 2048 to 16384 bits, and a valid exponent. A smaller key fails with `EIAM4DJWTSignatureInvalidException`.
- Tokens with a `crit` header, non-canonical base64url, or non-numeric `exp`/`nbf`/`iat` are refused.
- A JWKS refresh replaces the whole key set of the issuer: a key that Keycloak no longer publishes stops validating at the next refresh.
- The `issuer` of the discovery document must be the requested one: a Keycloak frontend URL or a proxy that changes the issuer breaks validation.

Allowing 1024-bit keys, only for a legacy identity provider you cannot fix:

<!-- snippet ver=3.0 kind=body ctx=jwt uses=IAMClient4D.Security.Crypto.Interfaces -->
```delphi
// Process-wide: set it at startup, before any token is validated
TIAM4DRSAPublicKey.MinModulusBits := TIAM4DRSAPublicKey.LOWEST_MIN_MODULUS_BITS; // 1024
```

**What to do:** check that `SetAllowedAlgs` lists `RS256`, `PS256`, `ES256`... in upper case. Keycloak keys are 2048 bits or larger by default.

### 2.6 TLS: pins are enforced in strict mode

- In 2.x, `svmStrict` installed no certificate callback, so pinned public keys were never checked. In 3.0 the pins are checked after the system validation, also when the JWKS is downloaded.
- On Android, in `svmStrict`, the verdict of the platform now counts: an untrusted CA or an expired certificate is refused.
- In `svmAllowSelfSigned`, a 2.x bug refused every certificate as soon as a pin was set. Pins are now compared without regard to case, and pinning works.

**What to do:** if you set pins, check that they are the SHA-256 hashes of the current certificate keys, and add the hash of the next key before you rotate it.

### 2.7 Other stricter checks

- `TIAM4DPlatformUtils.OpenURL` opens only `http` and `https` URLs and returns False for any other scheme (`mailto:`, custom protocols).
- `GetUserInfo` raises `EIAM4DSecurityValidationException` when the `sub` of the response is not the `sub` of the id_token.
- The local callback server answers 400 to a `Host` header other than `localhost`, `127.0.0.1` or `[::1]`, to a callback with a wrong `state` (the login keeps waiting), and to a second callback for the same `state`.
- `state` and `nonce` come from a CSPRNG.

### 2.8 Login cancelled: no more `OnError`

`CancelAuthorizationFlow`, destroying the client during a login, and a new login that replaces a pending one now end the pending promise as **Cancelled**. `OnError` is not called; `OnFinally` is.

Before (2.1), a cancelled login reached `OnError`:

<!-- snippet ver=2.1 kind=body ctx=client,ui -->
```delphi
LClient.StartAuthorizationFlowAsync
  .OnSuccess(
    procedure(const AAccessToken: string)
    begin
      ShowMessage('Logged in');
    end)
  .OnError(
    procedure(const AException: Exception)
    begin
      ShowMessage('Login failed or cancelled: ' + AException.Message);
    end)
  .Run;
```

After (3.0), react to the end of the flow in `OnFinally`:

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
LClient.StartAuthorizationFlowAsync
  .OnSuccess(
    procedure(const AAccessToken: string)
    begin
      ShowMessage('Logged in');
    end)
  .OnError(
    procedure(const AException: Exception)
    begin
      // Not called when the login is cancelled
      ShowMessage('Login failed: ' + AException.Message);
    end)
  .OnFinally(
    procedure
    begin
      // Success, error or cancellation: restore the UI here
    end)
  .Run;
```

The opposite also changed: an OAuth2 error response with the `state` of the flow (`error=access_denied`, `login_required`) now ends the login with `EIAM4DOAuth2CallbackException`, whose `Context` holds `error` and `error_description`. In 2.x the promise never ended.

---

## 3. Interfaces

### 3.1 New methods: implementers only

If you call these interfaces, your code compiles unchanged: the existing methods only gained optional parameters at the end, or new overloads. If you **implement** them (test doubles, decorators), add the new methods:

| Interface | New or changed members |
|---|---|
| `IIAM4DClient` | `AuthenticatePassword(Async)`, `CompleteAuthorizationFlow(Async)` with `AIss`, `GenerateAuthURL` and `StartAuthorizationFlowAsync` overloads, `InitializeAuthorizationFlow(AOptions)`, `GenerateLogoutURL`, `RevokeTokens(Async)`, `InvalidateAccessToken`, `GetIDTokenClaims`, `GetGrantedScopes`, `HasGrantedScope`, `GetKeycloakActionStatus`, `GetRedirectURI`, `CancelAuthorizationFlow` |
| `IIAM4DClientConfigBuilder` | `ForPassword`, `ForAuthorizationCode` with `AClientSecret`, `WithAllowInsecureHTTP`, `WithAppRedirect`, `WithAppActivation`, `WithCallbackPort`, `WithLoopbackRedirectHost`, `WithIdentityProvider`, `WithKeycloakAction`, `WithPrompt`, `WithMaxAge` |
| `IIAM4DUserManager` | `LinkFederatedIdentity`, `UnlinkFederatedIdentity` |
| `IIAM4DUserManagerAsync` | `LinkFederatedIdentityAsync`, `UnlinkFederatedIdentityAsync` |
| `IIAM4DSSLCertificateValidator` | `HasPinnedPublicKeys`; `ValidateCertificate` has a new parameter (3.3) |

The GUIDs of `IIAM4DUserManager` and `IIAM4DStorageCryptoProvider` changed. This matters only if your code writes them as strings.

`IIAM4DUserManager` is not meant as an extension point. To change its behaviour, wrap `TIAM4DKeycloakUserManager` instead of implementing the interface from scratch.

### 3.2 Authorization request options

The login options can now be passed per request with `TIAM4DAuthRequestOptions`. The 2.x calls still compile; the record is the way to pass more than one hint.

Before (2.1):

<!-- snippet ver=2.1 kind=body ctx=client -->
```delphi
LClient.StartAuthorizationFlowAsync.Run;
```

After (3.0):

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
LClient.StartAuthorizationFlowAsync(
  TIAM4DAuthRequestOptions.Create
    .WithLoginHint('john.doe@example.com')
    .WithIdpHint('google')
    .WithPrompt('login'))
  .Run;
```

### 3.3 Custom certificate validators

`ValidateCertificate` receives the verdict of the platform, and the interface has `HasPinnedPublicKeys`. The value `crrStrictModeBypass` of `TIAM4DCertificateRejectionReason` became `crrSystemValidationFailed`.

Before (2.1):

<!-- snippet ver=2.1 kind=decl ctx=security -->
```delphi
type
  TMyValidator = class(TInterfacedObject, IIAM4DSSLCertificateValidator)
  private
    FMode: TIAM4DSSLValidationMode;
  public
    procedure SetValidationMode(AMode: TIAM4DSSLValidationMode);
    function GetValidationMode: TIAM4DSSLValidationMode;
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
    procedure ClearPinnedPublicKeys;
    function ValidateCertificate(const Certificate: TCertificate): Boolean;
  end;

procedure TMyValidator.SetValidationMode(AMode: TIAM4DSSLValidationMode);
begin
  FMode := AMode;
end;

function TMyValidator.GetValidationMode: TIAM4DSSLValidationMode;
begin
  Result := FMode;
end;

procedure TMyValidator.AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
begin
end;

procedure TMyValidator.ClearPinnedPublicKeys;
begin
end;

function TMyValidator.ValidateCertificate(const Certificate: TCertificate): Boolean;
begin
  Result := Certificate.Expiry > Now;
end;
```

After (3.0):

<!-- snippet ver=3.0 kind=decl ctx=security -->
```delphi
type
  TMyValidator = class(TInterfacedObject, IIAM4DSSLCertificateValidator)
  private
    FMode: TIAM4DSSLValidationMode;
  public
    procedure SetValidationMode(AMode: TIAM4DSSLValidationMode);
    function GetValidationMode: TIAM4DSSLValidationMode;
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
    procedure ClearPinnedPublicKeys;
    function HasPinnedPublicKeys: Boolean;
    function ValidateCertificate(const Certificate: TCertificate; ASystemAccepted: Boolean): Boolean;
  end;

procedure TMyValidator.SetValidationMode(AMode: TIAM4DSSLValidationMode);
begin
  FMode := AMode;
end;

function TMyValidator.GetValidationMode: TIAM4DSSLValidationMode;
begin
  Result := FMode;
end;

procedure TMyValidator.AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
begin
end;

procedure TMyValidator.ClearPinnedPublicKeys;
begin
end;

function TMyValidator.HasPinnedPublicKeys: Boolean;
begin
  Result := False;
end;

function TMyValidator.ValidateCertificate(const Certificate: TCertificate; ASystemAccepted: Boolean): Boolean;
begin
  // In svmStrict the verdict of the platform must be kept
  Result := ((FMode <> svmStrict) or ASystemAccepted) and (Certificate.Expiry > Now);
end;
```

### 3.4 `SetOnCodeReceived` of the callback handlers

The callback receives a third argument, the `kc_action_status` of the response (Keycloak application-initiated actions). The method moved to `TIAM4DRedirectCallbackHandlerBase`.

Before (2.1):

<!-- snippet ver=2.1 kind=decl uses=IAMClient4D.Callback.Handler.Local -->
```delphi
procedure HookCallback(AHandler: TIAM4DLocalCallbackHandler);
begin
  AHandler.SetOnCodeReceived(
    procedure(ACode, AState: string)
    begin
      // exchange the code
    end);
end;
```

After (3.0):

<!-- snippet ver=3.0 kind=decl uses=IAMClient4D.Callback.Handler.Local -->
```delphi
procedure HookCallback(AHandler: TIAM4DLocalCallbackHandler);
begin
  AHandler.SetOnCodeReceived(
    procedure(ACode, AState, AKeycloakActionStatus: string)
    begin
      // exchange the code; AKeycloakActionStatus is '' outside Keycloak actions
    end);
end;
```

---

## 4. Removed and deprecated

### 4.1 Removed

| Removed | Replacement |
|---|---|
| Unit `IAMClient4D.Common.TokenValidator` (`TIAM4DTokenValidator`, `IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS`) | `IIAM4DTokenStorage.IsAccessTokenValid` / `IsRefreshTokenValid`, or the expiry fields of `TIAM4DTokens` (UTC) |
| `IAM4D_OAUTH2_CALLBACK_PORT_MIN` / `IAM4D_OAUTH2_CALLBACK_PORT_MAX` | none: they were not used. `WithCallbackPort` sets a fixed port |
| `TValidatedTokenCacheEntry` | none: internal type, public by mistake |
| `IEventWrapper` / `TEventWrapper` (Async.Core) | none: moved to the implementation section |
| `TAsyncOperationController<T>.SetResult` (protected) | `TrySetResult`, for subclasses |
| `TIAM4DCertificateRejectionReason.crrStrictModeBypass` | `crrSystemValidationFailed` (same ordinal) |

In 2.x an expiry of 0 meant "never expires" for `TIAM4DTokenValidator`. In 3.0 the storage checks treat 0 as expired.

Before (2.1):

<!-- snippet ver=2.1 kind=decl uses=IAMClient4D.Core,IAMClient4D.Common.TokenValidator -->
```delphi
function NeedsRefresh(const ATokens: TIAM4DTokens): Boolean;
begin
  Result := not TIAM4DTokenValidator.IsAccessTokenValid(ATokens, 30);
end;
```

After (3.0):

<!-- snippet ver=3.0 kind=decl uses=IAMClient4D.Core,System.DateUtils -->
```delphi
function NeedsRefresh(const ATokens: TIAM4DTokens): Boolean;
begin
  // AccessTokenExpiry is UTC; 0 means no token
  Result := (ATokens.AccessToken = '') or
    (ATokens.AccessTokenExpiry <= TDateTime.NowUTC + 30 / SecsPerDay);
end;
```

Usually you do not need either: `GetAccessToken` refreshes the token when it is about to expire (`WithTokenExpiryBuffer`).

### 4.2 Deprecated (warning W1000)

| Deprecated | Use instead |
|---|---|
| `TIAM4DJWTMiddleware` | `IAM4DJWTBundle` (section 9.1). The middleware does not protect Minimal API routes |
| `CONTEXT_KEY_STD_JSON`, `CONTEXT_KEY_KC_JSON` | `Context.JWT`, `Context.Keycloak`: the keys are no longer populated |
| `CACHE_KEY`, `KC_CACHE_KEY` | nothing: no longer used |
| `EIAM4DAccessTokenExpiredException`, `EIAM4DInvalidAuthCodeException`, `EIAM4DPKCEValidationException`, `EIAM4DAuthorizationTimeoutException`, `EIAM4DEndpointsNotConfiguredException`, `EIAM4DUnknownRequiredActionException`, `EIAM4DTokenInvalidException`, `EIAM4DAuthorizationCancelledException` | never raised: remove the `except` branches (a cancelled login: section 2.8) |

---

## 5. Errors and exceptions

### 5.1 Refresh: `EIAM4DRefreshTokenExpiredException`

In 2.x any refresh error cleared the tokens, and `invalid_grant` arrived as a generic `EIAM4DException` ("Token endpoint failed: 400"). In 3.0:

- `invalid_grant` (session ended, refresh token expired or revoked) raises `EIAM4DRefreshTokenExpiredException` and clears the tokens;
- network errors, timeouts and 5xx keep the tokens: `IsAuthenticated` stays True and a later call can refresh them.

Before (2.1):

<!-- snippet ver=2.1 kind=body ctx=client,ui -->
```delphi
try
  LClient.GetAccessToken;
except
  on E: EIAM4DException do
    ShowMessage('Please log in again'); // any error ended the session
end;
```

After (3.0):

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
try
  LClient.GetAccessToken;
except
  on E: EIAM4DRefreshTokenExpiredException do
    ShowMessage('Please log in again'); // session over, tokens cleared
  on E: EIAM4DNetworkUnreachableException do
    ShowMessage('Identity provider unreachable, retry later'); // tokens kept
end;
```

### 5.2 Network errors are library exceptions

The RTL `ENetHTTPClientException` and `ENetHTTPRequestException` no longer leave the library. They become:

- `EIAM4DNetworkTimeoutException`, where `ResponseTimeout` now limits the whole request;
- `EIAM4DNetworkUnreachableException`;
- `EIAM4DSSLCertificateException`.

The retrying helpers (`GetWithRetry`, `PostFormUrlEncodedWithRetry`) no longer retry timeouts and certificate errors. After the last attempt they return the 429/5xx response instead of raising.

Before (2.1):

<!-- snippet ver=2.1 kind=body ctx=client,ui -->
```delphi
try
  LClient.GetUserInfo;
except
  on E: ENetHTTPClientException do
    ShowMessage('Network error: ' + E.Message);
end;
```

After (3.0):

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
try
  LClient.GetUserInfo;
except
  on E: EIAM4DNetworkTimeoutException do
    ShowMessage('Timeout: ' + E.Message);
  on E: EIAM4DNetworkUnreachableException do
    ShowMessage('Network error: ' + E.Message);
end;
```

### 5.3 Hierarchy changes

The order of the `except` branches matters, because some classes have a new ancestor:

| Class | 2.x ancestor | 3.0 ancestor |
|---|---|---|
| `EIAM4DUserNotFoundException`, `EIAM4DRoleNotFoundException`, `EIAM4DGroupNotFoundException` | `EIAM4DException` | `EIAM4DHTTPNotFoundException` |
| `EIAM4DUserAlreadyExistsException` | `EIAM4DException` | `EIAM4DHTTPConflictException` |
| `EIAM4DInsufficientPermissionsException` | `EIAM4DException` | `EIAM4DHTTPClientErrorException` |
| `EIAM4DStorageCryptoException` | `Exception` | `EIAM4DException` |

So a branch `on E: EIAM4DHTTPClientErrorException` placed first also catches "not found", "already exists" and 403. An `on E: EIAM4DException` placed before the storage branch also catches storage crypto errors.

Other exception changes:

- the errors of the OAuth2 callback are `EIAM4DOAuth2CallbackException`, a sibling of `EIAM4DCallbackHandlerException`;
- the JWT errors are typed subclasses of `EIAM4DSecurityValidationException`: `EIAM4DJWTIssuerMismatchException`, `EIAM4DJWTSignatureInvalidException`, `EIAM4DJWKSKeyNotFoundException`, `EIAM4DJWKSUnavailableException`;
- the exceptions that `WaitForResult` re-raises keep `ErrorCode`, `Context` and `StatusCode`;
- `ErrorCode` tells more: an expired, not yet valid or wrong-audience JWT is `ecJWTExpired`, `ecJWTNotYetValid`, `ecJWTAudienceMismatch` (it was `ecUnknown`); a refused id_token keeps the code of the failed check, `ecTokenInvalid` only when there is none; a wrong `nonce` is `ecNonceValidationFailed`. Code that compares `ErrorCode = ecTokenInvalid` for the id_token should test the class `EIAM4DSecurityValidationException`;
- a discovery document that cannot be read raises `EIAM4DDiscoveryFailedException` (`ecDiscoveryFailed`), still an `EIAM4DException`.

---

## 6. Admin API

### 6.1 Typed HTTP errors, "not found" is 404

In 2.x every HTTP status other than 200/201/204 raised `EIAM4DInvalidConfigurationException`. In 3.0 each status raises its own exception:

| Status | Exception |
|---|---|
| 403 | `EIAM4DInsufficientPermissionsException` |
| 404 | `EIAM4DHTTPNotFoundException`, or its subclasses `EIAM4DUserNotFoundException`, `EIAM4DRoleNotFoundException`, `EIAM4DGroupNotFoundException` |
| 409 | `EIAM4DHTTPConflictException`, or `EIAM4DUserAlreadyExistsException` from `CreateUser` |
| other 4xx | `EIAM4DHTTPClientErrorException` |
| 5xx | `EIAM4DHTTPServerErrorException` |

Before (2.1):

<!-- snippet ver=2.1 kind=body ctx=umgr,ui -->
```delphi
try
  LUserManager.GetUserByUsername('john.doe');
except
  on E: EIAM4DUserNotFoundException do
    ShowMessage('No such user');
  on E: EIAM4DInvalidConfigurationException do
    ShowMessage('Keycloak error: ' + E.Message); // 403, 409, 500...
end;
```

After (3.0):

<!-- snippet ver=3.0 kind=body ctx=umgr,ui -->
```delphi
try
  LUserManager.GetUserByUsername('john.doe');
except
  on E: EIAM4DUserNotFoundException do
    ShowMessage('No such user');
  on E: EIAM4DInsufficientPermissionsException do
    ShowMessage('Missing realm-management roles');
  on E: EIAM4DHTTPServerErrorException do
    ShowMessage('Keycloak unavailable: ' + E.Message);
end;
```

Error messages carry at most 500 characters of the response body: the full body is in `ResponseBody`. The URL in the message has no query string.

### 6.2 `UpdateUser` replaces the profile

In 2.x, empty `Email`, `FirstName` and `LastName` were not sent, so they could not be cleared, and an empty `RequiredActions` was not sent either. In 3.0 the record replaces the profile: empty fields clear the values on Keycloak, and `RequiredActions` is always sent. The only exception is an empty `Username`, which is not sent.

Before (2.1), a partial record:

<!-- snippet ver=2.1 kind=body ctx=umgr -->
```delphi
var LUser: TIAM4DUser;
LUser.ID := '5f2c0a5e-0000-0000-0000-000000000000';
LUser.Email := 'john.doe@example.com';
LUser.Enabled := True;
LUserManager.UpdateUser(LUser); // names and required actions left as they were
```

After (3.0), read, change, update:

<!-- snippet ver=3.0 kind=body ctx=umgr -->
```delphi
var LUser := LUserManager.GetUser('5f2c0a5e-0000-0000-0000-000000000000');
LUser.Email := 'john.doe@example.com';
LUserManager.UpdateUser(LUser); // every field of LUser is sent
```

### 6.3 Other Admin API changes

- **Names are case-sensitive.** Role, client role and group names are compared exactly, as Keycloak does: `HasRole`, `HasClientRole`, `Assign*ByName`, the group path lookups and `TIAM4DRoleLookupCache`. IDs stay case-insensitive. A role by name is read with `GET roles/{name}`.
- **`GetGroups` returns the whole tree, flattened.** 2.x returned the top level only. To keep only the top level, keep the groups whose `Path` has one `/`.
- **Validation before the request:**
  - paging with `FirstResult` < 0 or `MaxResults` < 1 raises `EIAM4DInvalidConfigurationException`;
  - the `TemporaryPassword` of `CreateUser(s)` must be 8 to 4096 characters, else `EIAM4DInvalidUserDataException`;
  - an empty path segment, or `.` or `..` (for example `UnlockUser('')`), raises `EIAM4DInvalidConfigurationException`.
- **Duplicate emails:** `GetUserByEmail` and `TryGetUserByEmail` raise `EIAM4DInvalidUserDataException` when two users share the email. 2.x returned the first one. In 2.x these two methods and `IsUserLocked` did not reach Keycloak at all (a local variable hid the URL).
- **Username lookups** accept any non-empty name of up to 255 characters, including `@` and `+`. `ValidateUsername` accepts `@` and `+` too.
- **Other methods:**
  - `IsUserLocked` returns False only for 404 and raises the other errors;
  - `RevokeUserSession(UserID, SessionID)` raises `EIAM4DHTTPNotFoundException` when the session is not of that user;
  - `AssignClientRolesToUser` checks every role and sends one request per client.
- **Redirects and path encoding:** redirects are not followed, so a 3xx raises `EIAM4DInvalidConfigurationException`. Path segments are encoded with `%20`, where 2.x used `+`, so a role with a space was not found.
- **HTTP clients:** each manager keeps a pool of up to 4 HTTP clients.

---

## 7. Async.Core

### 7.1 `RunWithTimeout` ends with `EAsyncTimeoutException`

In 2.x a timeout ended the operation as Cancelled (`EAsyncCancelException`). In 3.0 it ends as Faulted with `EAsyncTimeoutException`, and the task receives a cancellation request.

Before (2.1):

<!-- snippet ver=2.1 kind=body ctx=async,ui -->
```delphi
try
  TAsyncCore.RunWithTimeout<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := 'done';
    end, 5000).WaitForResult;
except
  on E: EAsyncCancelException do
    ShowMessage('Timed out or cancelled');
end;
```

After (3.0):

<!-- snippet ver=3.0 kind=body ctx=async,ui -->
```delphi
try
  TAsyncCore.RunWithTimeout<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := 'done';
    end, 5000).WaitForResult;
except
  on E: EAsyncTimeoutException do
    ShowMessage('Timed out');
  on E: EAsyncCancelException do
    ShowMessage('Cancelled');
end;
```

### 7.2 `dmQueue` is always queued

`dmQueue` now uses `TThread.ForceQueue`: called from the main thread, the callback runs at the next turn of the message loop, not inside the call. `TAsyncTaskCompletionSource` uses `dmQueue` by default.

**What to do:** in a console application or a service without a message loop, call `CheckSynchronize`, or use the new `dmInline` mode, which runs callbacks on the thread that completes the operation:

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
LClient.GetUserInfoAsync
  .DispatchMode(TAsyncCallbackDispatchMode.dmInline) // no main thread needed
  .OnSuccess(
    procedure(const AUserInfo: TIAM4DUserInfo)
    begin
      ShowMessage(AUserInfo.PreferredUsername);
    end)
  .Run;
```

### 7.3 Other Async.Core changes

- **Callback exceptions:** an exception raised inside `OnSuccess`, `OnFinally` or `OnCancelled` no longer changes the state of the operation. In 2.x an exception in `OnSuccess` turned Completed into Faulted and ran `OnError`. It now goes to `TAsyncCore.OnUnhandledError` when assigned, otherwise to `ApplicationHandleException` on the main thread; without either, it is dropped.
- **The exception in `OnError`** is the original object, with all its fields. Do not free it or keep a reference to it.
- **Combinators** (`ContinueWith`, `WhenAll`, `WhenAny`, `RunWithTimeout`) no longer need the main thread. `Cancel` on their result ends it at once.
- **`Delay` and `RunWithRetry`** wait on a shared timer, not on a blocked pool thread, so `Cancel` during the wait ends them at once.
- **`RunWithRetry` arguments:** `AMaxRetries` < 0 raises `EArgumentOutOfRangeException` at the call. The new optional `AShouldRetry` filters the errors to retry.
- **`OnCancelled`** accepts more than one handler.

---

## 8. Data: dates, scope, logout

### 8.1 DMVC: dates in ISO 8601 UTC

`LoggedUser.CustomData['exp']`, `['iat']` and `['auth_time']` were written with `DateTimeToStr` in the locale of the server. They are now ISO 8601 in UTC. `LoggedSince` is UTC too.

Before (2.1):

<!-- snippet ver=2.1 kind=body ctx=dmvc_ctx -->
```delphi
var LExpiry := StrToDateTime(Context.LoggedUser.CustomData['exp']); // server locale
```

After (3.0):

<!-- snippet ver=3.0 kind=body ctx=dmvc_ctx uses=System.DateUtils -->
```delphi
var LExpiry := ISO8601ToDate(Context.LoggedUser.CustomData['exp'], True); // UTC
```

All the library clocks use `TDateTime.NowUTC`. The 2.x calculation was one hour off during the repeated hour at the end of daylight saving time.

### 8.2 Granted scopes

The token response scope is kept: `TIAM4DTokens.Scope`, `GetGrantedScopes`, `HasGrantedScope`. The JSON of the token serializer has a `scope` field. A 2.x JSON still loads, with an empty `Scope`.

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
if not LClient.HasGrantedScope('offline_access') then
  ShowMessage('Keycloak did not grant offline_access');
```

### 8.3 Logout with a back-channel POST

- **The request:** with a refresh token, `Logout` sends a POST to the `end_session_endpoint`, carrying `client_id`, the secret and `refresh_token`. 2.x sent a server-side GET with `id_token_hint`, and only in Authorization Code. A 200 or 204 means the session is closed, and `invalid_grant` means it was already closed. The GET with `id_token_hint` is used only when there is no refresh token.
- **Tokens and scopes:** `Logout` always clears the tokens, even when the request fails, and still raises the error. In 2.x the configured scopes were emptied as well, so the next login asked for `openid` only. They are now restored.
- **Browser logout:** `GenerateLogoutURL` is public, so you can end the SSO session in the browser too.

### 8.4 Discovery cache

The discovery document is cached per process for one hour, per realm URL and SSL mode. A change on the server is seen after an hour, or after `TIAM4DDiscoveryCache.Clear`.

---

## 9. DMVCFramework

### 9.1 From the middleware to the filter bundle

`TIAM4DJWTMiddleware` still works, but it is deprecated. The filter bundle also protects Minimal API routes.

Before (2.1):

<!-- snippet ver=2.1 kind=body ctx=dmvc_engine -->
```delphi
FEngine.AddMiddleware(TIAM4DJWTMiddleware.Create(
  'https://keycloak.example.com/realms/demo', // Issuer
  'demo_api'));                               // Audience
```

After (3.0):

<!-- snippet ver=3.0 kind=body ctx=dmvc_engine -->
```delphi
// Before the controllers and before the Swagger filter
FEngine.Use(IAM4DJWTBundle(
  'https://keycloak.example.com/realms/demo', // Issuer
  'demo_api'));                               // Audience
```

### 9.2 Configuration errors at startup

- An empty `Issuer` or `TokenHeaderName` raises `EIAM4DInvalidConfigurationException` when the authenticator is created.
- So does an empty `Audience` while `AudienceValidationEnabled` is on. In 2.x the server started and answered 401 to every token.
- A `TIAM4DJWTMiddlewareConfig` filled field by field, without `Create`, now gets the defaults of `Create`, through a managed record `Initialize`. In 2.x the fields were zero: audience check off, skew 0, empty header.
- The default HTTP timeouts are 10000 ms to connect and 15000 ms to receive (2.x: 30000/60000).
- `JWKS_URL`, `RolesClaimName` and `SubjectClaimName` are now used. 2.x ignored them.

### 9.3 Requests that are no longer let through

- **OPTIONS** requests are authenticated like the other verbs. Handle the CORS preflight before the IAMClient4D filter.
- **Swagger paths:** GET requests whose path contains `swagger`, `openapi` or `api-docs` and ends with `.json` are no longer exempt. Mark a controller that serves its own document with `[IAM4DPublic]`.
- **Invalid tokens with `AllowAnonymous`:** an invalid token now gets 401 `invalid_token`. Only a request without a token passes as anonymous.
- **ID tokens:** the payload `typ` must be `Bearer` (`ExpectedTokenType`). A Keycloak id_token with the right `aud` used to pass. A token without `typ` still passes.

### 9.4 Roles, scopes and claims

- **Client roles:** `LoggedUser.Roles` holds the client roles of `Audience` and `ExpectedAzp` only. 2.x added those of every client in `resource_access`.
- **Case-sensitive comparisons:** role de-duplication, `HasRole`, `HasScope`, `HasGroup` and `amr` of the DTOs are now case-sensitive.
- **`RequireAnyRole` / `RequireAllRoles`** check `LoggedUser.Roles`. 2.x read the `roles` claim, which Keycloak does not emit, so these calls always answered 403.
- **`GetCustomClaim`** reads a top-level key: `'address.country'` is the name of a claim, not a path. Read the nested value from `Context.JWT` instead.
- **403 responses** say only "Insufficient permissions" and send a `WWW-Authenticate` with `insufficient_scope`. The required roles go to the log (`LogW`).
- **A down identity provider** gives 503 `temporarily_unavailable` with `Retry-After`. 2.x answered 401.
- **The 401 message** for a token that was sent and rejected is "Invalid or expired JWT token".

Before (2.1), a nested claim read as a path:

<!-- snippet ver=2.1 kind=body ctx=dmvc_ctx -->
```delphi
var LCountry := Context.GetCustomClaim('address.country', '');
```

After (3.0):

<!-- snippet ver=3.0 kind=body ctx=dmvc_ctx -->
```delphi
// 'address' is the claim name; the nested value is read from the JSON object
var LCountry := '';
var LAddress := Context.GetCustomClaim('address', '');
if LAddress <> '' then
begin
  var LJSON := TJSONObject.ParseJSONValue(LAddress);
  try
    if LJSON is TJSONObject then
      LCountry := TJSONObject(LJSON).GetValue<string>('country', '');
  finally
    LJSON.Free;
  end;
end;
```

### 9.5 `at+jwt` tokens

The header `typ` of the access tokens may be `JWT` or `at+jwt` (RFC 9068, Keycloak client option "Use 'at+jwt' as access token header type"). To accept `JWT` only, as 2.x did:

<!-- snippet ver=3.0 kind=body ctx=dmvc_engine -->
```delphi
var LConfig := TIAM4DJWTMiddlewareConfig.Create(
  'https://keycloak.example.com/realms/demo', 'demo_api', '');
LConfig.AllowedHeaderTypes := ['JWT']; // 2.x behaviour
FEngine.Use(IAM4DJWTBundle(LConfig));
```

### 9.6 Context keys

`CONTEXT_KEY_STD_JSON` and `CONTEXT_KEY_KC_JSON` are no longer populated: use `Context.JWT` and `Context.Keycloak`. `JWT_Auth_Status` is now always set. Besides `authenticated` and `not_authenticated`, it can be `invalid_token` or `unavailable`.

---

## 10. What you gain

- **Stricter security:** full id_token validation, RFC 9207 `iss`, ES256/384/512 with TMS and TaurusTLS, pins that are actually enforced, no plain HTTP, no redirects, and safer JWKS rotation.
- **New login options:** the TaurusTLS/OpenSSL provider; Android, iOS and macOS with the app redirect and `ASWebAuthenticationSession`; a `127.0.0.1` loopback redirect (RFC 8252); request options, Keycloak application-initiated actions, and token revocation and logout URL.
- **Admin API:** identity providers (Entra ID, Google, Facebook, SPID, CIE), federated identities, typed errors, and a pool of HTTP clients.
- **DMVCFramework 3.5:** filter bundles, Minimal API, OpenAPI 3, claims transformation, and 503 when the identity provider is down.
- **Async.Core:** works without a main thread, has `dmInline`, never blocks a pool thread on waits, and keeps the exceptions intact.

See the [README](../README.md) for the details.

---

## 11. Checklist

1. DMVCFramework 3.5.0-silicon-rc10 or later; Delphi 12 or later; Keycloak 25 or later (with 26.8.2+, add `kc-admin-api` to the Admin API client).
2. Every URL is `https`, final (no redirects), with the issuer equal to the discovery `issuer`; `WithAllowInsecureHTTP` only in tests.
3. Client and Keycloak clocks in sync (id_token checked with 5 minutes of skew); the JWKS endpoint is reachable from the client.
4. External callback mode: pass `iss` to `CompleteAuthorizationFlow`.
5. Login cancellation handled in `OnFinally`, not in `OnError`.
6. `except` blocks: `EIAM4DRefreshTokenExpiredException`, `EIAM4DNetwork*`, typed Admin API exceptions, new ancestors.
7. `UpdateUser` with a full record (read, change, update); role and group names with the exact case; `GetGroups` returns the whole tree.
8. `TIAM4DTokenValidator` replaced; deprecated exceptions and context keys removed.
9. Async.Core: `EAsyncTimeoutException` handled; `dmInline` or `CheckSynchronize` without a message loop.
10. DMVC: `IAM4DJWTBundle` with an `Audience`; CORS preflight before the filter; `[IAM4DPublic]` on public documents; dates of `CustomData` read as ISO 8601 UTC.
