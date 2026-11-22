# Changelog

All notable changes to IAMClient4D are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-11-22

### Highlights

- Security review of the whole library: the id_token is fully validated, `iss` (RFC 9207) is checked, redirects are not followed, plain `http://` is refused outside the loopback, pins are enforced in strict mode, JWT and JWKS checks follow the RFCs strictly.
- Mobile apps: login through a redirect on a private-use URI scheme (RFC 8252), with Custom Tabs on Android and `ASWebAuthenticationSession` on iOS.
- Identity brokering: direct login with `kc_idp_hint`, and identity provider management through the Admin REST API with builders for Entra ID, Microsoft accounts, Google, Facebook, LinkedIn, GitHub, GitLab, generic OIDC, SAML and OAuth 2.0, SPID and CIE.
- DMVCFramework 3.5 filter bundle that protects controllers and Minimal API routes; RFC 9068 (`at+jwt`) access tokens accepted.
- Session API: options of one login (`prompt`, `max_age`, `acr_values`, `login_hint`), id_token claims, granted scopes, token revocation (RFC 7009), RP-Initiated Logout URL, password grant, HTTP client for protected APIs.
- TaurusTLS (OpenSSL 3.x/4.x) crypto provider, ES256/ES384/ES512 verification, typed exceptions with error codes everywhere.
- Builds for Win32, Win64, Linux64, Android, Android64 and iOS; a Docker environment (`Docker/`) runs every sample.

### Breaking

The [migration guide](docs/MIGRATION_3.0.md) explains each item and how to adapt the code.

- Requirements: Delphi 12 or later (tested with Delphi 13); DMVCFramework 3.5.0-silicon-rc10 or later for the DMVC integration; Keycloak 25 or later, and with Keycloak 26.8.2 or later the Admin API client needs the `kc-admin-api` client scope.
- `http://` to a host other than the loopback is refused for `BaseURL` and the external callback URL (`WithAllowInsecureHTTP` for test environments); a realm on `https` with an `http` endpoint in its discovery document is refused.
- HTTP redirects are not followed by any client of the library: a 3xx is an error naming the `Location`.
- The `iss` of the authorization response must match the issuer when the discovery document announces `authorization_response_iss_parameter_supported` (Keycloak 26 does).
- The id_token is validated at the code exchange, at the refresh and in Client Credentials: signature through the JWKS, `iss`, `aud`, `azp`, `typ`, `exp`/`iat` with 300 s of tolerance, nonce, `auth_time` against `max_age`. A clock off by more than 5 minutes or an unreachable JWKS fails the login.
- JWT: `alg` compared exactly, RSA keys below 2048 bits refused, `crit` refused, canonical base64url only, numeric time claims only, the `alg` of the JWK binding, encryption keys ignored, the issuer of the discovery checked.
- TLS: pinned public keys are checked in `svmStrict` too, also for the JWKS; on Android the verdict of the platform counts; pinning on Linux raises `ENotSupportedException`. `IIAM4DSSLCertificateValidator.ValidateCertificate` receives the platform verdict, `crrStrictModeBypass` became `crrSystemValidationFailed`.
- Network errors raise `EIAM4DNetworkTimeoutException`, `EIAM4DSSLCertificateException` or `EIAM4DNetworkUnreachableException` instead of the RTL `ENetHTTP*` exceptions.
- A refresh refused with `invalid_grant` raises `EIAM4DRefreshTokenExpiredException` and clears the tokens; other refresh errors keep them.
- A cancelled login ends as Cancelled (`OnFinally`, no `OnError`); OAuth2 error responses raise `EIAM4DOAuth2CallbackException`.
- `TIAM4DPlatformUtils.OpenURL` opens only `http` and `https` URLs.
- Admin API: HTTP errors raise typed exceptions (403, 404, 409, other 4xx, 5xx) instead of `EIAM4DInvalidConfigurationException`, "not found" is a 404 exception, `UpdateUser` replaces the profile (empty fields are cleared), names of roles and groups are case-sensitive, `GetGroups` returns the whole tree, duplicate emails, paging values and temporary passwords are validated.
- Exception hierarchies: Admin API exceptions descend from the HTTP exceptions, `EIAM4DStorageCryptoException` descends from `EIAM4DException`; check the order of `except` blocks.
- Async.Core: `RunWithTimeout` ends with `EAsyncTimeoutException`, `dmQueue` is always queued (`ForceQueue`), an exception in a callback no longer changes the state of the operation.
- DMVC: `TIAM4DJWTMiddleware` is deprecated in favour of `IAM4DJWTBundle` (the middleware does not protect Minimal API routes); empty `Issuer`, `TokenHeaderName` or `Audience` (with audience validation) are configuration errors; OPTIONS and Swagger paths are authenticated; `AllowAnonymous` refuses invalid tokens; the payload `typ` must be `Bearer`; client roles come only from `Audience`/`ExpectedAzp`; roles, scopes, groups and claim names are case-sensitive; `GetCustomClaim` reads top-level keys; dates of `LoggedUser.CustomData` in ISO 8601 UTC; `CONTEXT_KEY_*_JSON` are no longer filled.
- Interfaces with new methods (`IIAM4DClient`, `IIAM4DClientConfigBuilder`, `IIAM4DUserManager`, `IIAM4DUserManagerAsync`, `IIAM4DSSLCertificateValidator`) break their implementers; `TIAM4DLocalCallbackHandler.SetOnCodeReceived` receives code, state and `kc_action_status`.

### Added

- **Mobile apps**: callback mode `cbmAppRedirect` and `WithAppRedirect(URI)` for a private-use URI scheme; `TIAM4DAppRedirect.HandleURL`; `src/FMX` with `TIAM4DAppRedirectListener` (Android intent, iOS `OpenURL`), Android Custom Tabs and, on iOS, `TIAM4DIOSLoginBrowser` (`ilbSafari`, `ilbAuthenticationSession`).
- **Login options**: `TIAM4DAuthRequestOptions` for one login (`acr_values`, `prompt`, `max_age`, `ui_locales`, `login_hint`, `kc_idp_hint`, other parameters); `WithPrompt`, `WithMaxAge`, `WithKeycloakAction` and `GetKeycloakActionStatus`; `WithCallbackPort`, `WithLoopbackRedirectHost` (`127.0.0.1`, RFC 8252 8.3), `WithAppActivation` (Windows); `ForAuthorizationCode` with a client secret.
- **Session**: `GetIDTokenClaims` (`TIAM4DIDTokenClaims`), `GetGrantedScopes` / `HasGrantedScope`, `InvalidateAccessToken`, `RevokeTokens` / `RevokeTokensAsync` (RFC 7009), public `GenerateLogoutURL` (RP-Initiated Logout).
- **Password grant**: `ForPassword` and `AuthenticatePassword(Async)`, with `EIAM4DInvalidCredentialsException`, `EIAM4DAccountNotFullySetUpException` and `EIAM4DAccountDisabledException`.
- **`TIAM4DAuthorizedHTTPClient`**: HTTP client for an API protected by the tokens of an `IIAM4DClient` (bearer renewed when it expires, one retry after a 401, HTTPS only, no redirects).
- **Discovery cache**: `TIAM4DDiscoveryCache`, one hour per realm URL and SSL mode.
- **`TIAM4DPlatformUtils.OpenURLHandler`**: replaces the system browser (tests, embedded browsers).
- **Identity brokering**: `WithIdentityProvider` and the `AIdpHint` arguments (`kc_idp_hint`, `IAM4D_IDP_HINT_NONE`); `IIAM4DIdentityProviderManager` (sync and async: providers, mappers, mapper types, `ImportConfig`, SP metadata, paging); builders for Entra ID, Microsoft, Google, Facebook, LinkedIn, GitHub (and Enterprise), GitLab, generic OIDC, SAML 2.0, OAuth 2.0, SPID and CIE, with secure defaults that `WithConfig` cannot turn off.
- **Admin API**: `LinkFederatedIdentity` / `UnlinkFederatedIdentity`, `TIAM4DUser.FederationLink`, `EIAM4DHTTPNotFoundException`, `EIAM4DHTTPConflictException`.
- **DMVCFramework 3.5**: `IAM4DJWTBundle`, `IAM4DJWTEndpointFilter` (Minimal API route groups), `IAM4DSwaggerSecurityHTTPFilter`, `[IAM4DPublic]`, `IIAM4DJWTAuthenticator` shared by several filters; OpenAPI 3 security injection; 503 with `Retry-After` when the identity provider is unavailable (`EIAM4DJWKSUnavailableException`); `JWKS_URL`, `PinnedPublicKeys`, `SSLValidator` and `AllowedHeaderTypes` in `TIAM4DJWTMiddlewareConfig`.
- **JWT**: `SetAllowedHeaderTypes` (RFC 9068 `at+jwt`), `SetExpectedTokenType`, ES256/ES384/ES512 (`IAMClient4D.Security.JWT.Verifiers.ECDSA`), `TIAM4DJWKSProvider.SetJWKSUri`, `TIAM4DRSAPublicKey.MinModulusBits`.
- **TaurusTLS (OpenSSL 3.x/4.x) crypto provider** (`IAM4D_TAURUSTLS`): RS*, PS* and ES* verification, AES-256-GCM token storage, public key cache.
- **Storage**: `TIAM4DAESMemoryTokenStorageRawKey32.Create(ACryptoProvider, AAAD)` for a custom crypto provider; the granted scope stored with the tokens.
- **Async.Core**: `dmInline` dispatch mode, `FromOperation`, `RegisterExceptionCloner` (exceptions copied with all their fields), `RunWithRetry` with `AShouldRetry` and `ExponentialJitter`, `ADispatchMode` on the combinators, `PendingTimerCount`.
- **HTTP**: `TIAM4DHTTPClientFactory.Execute`, one request bounded by `ResponseTimeout`.
- **Version constants**: `IAM4D_VERSION`, `IAM4D_VERSION_MAJOR`, `IAM4D_VERSION_MINOR`, `IAM4D_VERSION_PATCH`.
- **Samples**: one Docker environment for all of them (`Docker/`: Keycloak 26.8 with SPID and CIE extensions, PostgreSQL, SPID and CIE simulators, TLS gateway); `samples/VCL/IdentityBrokering`, `samples/FMX/IdentityBrokering` (Android, iOS), `samples/DMVC/ScientificCalculator` (controller and Minimal API servers, web client); the VCL KeycloakClient sample shows the id_token claims, the granted scopes and the revocation, the web client signs out through the browser.
- **Tests**: console suites `JWT`, `Crypto`, `TLS`, `HTTPTimeout`, `Async`, `KeycloakClient`, `DMVC/RuntimeTest` and `IdentityProvider` (against a real Keycloak), for Win32, Win64 and Linux64.

### Changed

- The `THTTPClient` of a client is a pool: the requests of one client run in parallel; `ResponseTimeout` bounds the whole request.
- `Logout` sends the refresh token to the end session endpoint (back-channel POST) and always clears the tokens; the configured scopes are restored.
- `Build` / `BuildAsync` configure on the calling thread without a fixed 30 s limit; the original exception is raised.
- `GetUserInfo` refuses a `sub` other than the one of the id_token; `TIAM4DUserInfo.GetCustomClaims` is case-sensitive.
- `state` and `nonce` come from the CSPRNG; the code of a callback is exchanged once; in external mode a failed exchange cannot be retried with the same state.
- The JWKS of an issuer is replaced as a whole at every refresh; an unknown `kid` triggers at most one refresh every 30 s; a key is served from the cache while it is refreshed in the background.
- Clients without pins share one JWKS provider per process.
- Error messages are cut (512 characters) and URLs in messages carry no query.
- Error codes: the JWT validator sets `ecJWTExpired`, `ecJWTNotYetValid` and `ecJWTAudienceMismatch`; a refused id_token keeps the code of the failed check (`ecTokenInvalid` when there is none); a wrong or missing `nonce` is `ecNonceValidationFailed`.
- A discovery document that cannot be read (HTTP error or redirect, invalid JSON) raises `EIAM4DDiscoveryFailedException` (`ecDiscoveryFailed`) with its URL.
- JWT header `typ` `application/jwt` is accepted.
- DMVC: default HTTP timeouts 10 s / 15 s; a rejected token is logged at most once per `RejectedTokenWarningIntervalSec`; 403 answers say only "Insufficient permissions".
- `WithScopes`, `WithTimeouts` and the SSL methods of the builder keep `TokenExpiryBufferSeconds`; a second `For*` resets the settings of the previous flow.
- User-Agent of the HTTP clients: `IAMClient4D/3.0.0`.

### Fixed

- Linux64, Android and iOS builds (2.1 compiled for Windows only).
- Pins in `svmAllowSelfSigned` refused every certificate (case of the hash).
- Concurrent LockBox3 operations rejected valid tokens; TMS token storage and ECDSA verification never worked.
- Login: an error response of the authorization server left the promise pending; a second login or `ConfigureAsync` left the first one pending; `Cancel` did not stop the callback server; `Stop` of the callback server could hang.
- A refresh response without `refresh_token` or `scope` lost the session; a late refresh could overwrite a newer session.
- Admin API: `GetUserByEmail`, `TryGetUserByEmail` and `IsUserLocked` never reached Keycloak; required actions freed twice; client roles assigned to the client of the first role; groups by path missed subgroups; a role with a space was not found; a batch used one token for all its items.
- Async.Core: combinators blocked in console applications, services and DMVC servers; `Delay` and retries held a pool thread; `WhenAll` with a result-less operation never ended; `TAsyncTaskCompletionSource` leaked.
- UTC time taken from the local time zone (an hour off at the end of daylight saving time).
- `TIAM4DUser.Create` set `CreatedTimestamp` in seconds instead of milliseconds.
- DMVC: `JWKS_URL`, `RolesClaimName` and `SubjectClaimName` were ignored; `RequireAnyRole` / `RequireAllRoles` read a claim Keycloak does not send; `SetExpectedAzp('')` did not reset.

### Security

- Callback server: `Host` header checked (DNS rebinding), callbacks with another state ignored, `no-store` pages.
- Form bodies with secrets and passwords zeroed after sending.
- An empty expected issuer refuses the token without contacting the issuer of the token.
- `jti` replay check and registration in one step; the validated-token cache never outlives `iat` plus `SetIatMaxAge` or a removed key.
- `RevokeUserSession` checks that the session belongs to the user; empty, `.` and `..` path segments refused before any request (`UnlockUser('')` unlocked the whole realm).
- Identity provider builders: PKCE, signature and issuer checks on by default; trust email refused where the email is not verified (nOAuth).
- LockBox3 IV seeded from the CSPRNG.
- The copy of the storage key made by the builder is zeroed once the storage is created.

### Removed

- Unit `IAMClient4D.Common.TokenValidator` (`TIAM4DTokenValidator`, `IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS`): the token storage checks the expiry.
- `IAM4D_OAUTH2_CALLBACK_PORT_MIN` / `IAM4D_OAUTH2_CALLBACK_PORT_MAX` (never used).
- `TValidatedTokenCacheEntry` (internal record, public by mistake).
- `IEventWrapper` / `TEventWrapper` (internal helpers of `Async.Core`).
- `TAsyncOperationController<T>.SetResult` (protected), replaced by `TrySetResult`.
- Deprecated (warning W1000, removed in a later major version): `TIAM4DJWTMiddleware`, `CONTEXT_KEY_STD_JSON`, `CONTEXT_KEY_KC_JSON`, and the exceptions that are never raised (`EIAM4DAccessTokenExpiredException`, `EIAM4DInvalidAuthCodeException`, `EIAM4DPKCEValidationException`, `EIAM4DAuthorizationTimeoutException`, `EIAM4DEndpointsNotConfiguredException`, `EIAM4DUnknownRequiredActionException`, `EIAM4DTokenInvalidException`, `EIAM4DAuthorizationCancelledException`).

## [2.1.0] - 2026-03-21

### Added

- **Public URI scheme helper**
  - Added `TIAM4DPlatformUtils.TryGetURIScheme` to validate and extract URI schemes without relying on Delphi-version-specific `TURI` properties

- **Recursive group path resolution in User Management**
  - Nested Keycloak groups are now resolved through `subGroups`, so path-based APIs work correctly for hierarchical groups
  - Affects lookup, membership operations, and user listing by group path

- **Explicit JWT audience validation flag**
  - Added `IIAM4DJWTValidatorConfigurable` for advanced validator settings without breaking the base validator interface
  - Audience (`aud`) validation can now be disabled explicitly while preserving the secure default (`True`)
  - Intended for legacy/custom JWT access token profiles, not as the recommended setting for OIDC ID Tokens

### Changed

- **Platform URI launcher behavior**
  - `TIAM4DPlatformUtils.OpenURL` now opens generic URIs through the default system handler instead of allowing only HTTP(S)
  - Dangerous schemes such as `file:`, `javascript:`, and `data:` are still rejected
  - Desktop Authorization Code flow continues to require `http` / `https` authorization URLs explicitly

#### User Management API Cleanup (Breaking Change)

- **Breaking DTO cleanup for client roles**
  - `TIAM4DRole.ContainerID` now stores the internal Keycloak client UUID (`containerId`)
  - `TIAM4DRole.ClientID` now stores the logical Keycloak `clientId`
  - `TIAM4DRole.ClientName` has been removed
  - Client-role helper APIs, JSON mapping, and README examples were updated to use the new semantics

- **Breaking API rename for client-specific helpers**
  - `AssignClientRoleByName` / `AssignClientRoleByNameAsync` -> `AssignClientRoleByClientID` / `AssignClientRoleByClientIDAsync`
  - `RemoveClientRoleByName` / `RemoveClientRoleByNameAsync` -> `RemoveClientRoleByClientID` / `RemoveClientRoleByClientIDAsync`
  - `GetClientRolesByName` / `GetClientRolesByNameAsync` -> `GetClientRolesByClientID` / `GetClientRolesByClientIDAsync`
  - `GetUserClientRolesByName` / `GetUserClientRolesByNameAsync` -> `GetUserClientRolesByClientID` / `GetUserClientRolesByClientIDAsync`
  - `RemoveClientRolesFromUserByName` / `RemoveClientRolesFromUserByNameAsync` -> `RemoveClientRolesFromUserByClientID` / `RemoveClientRolesFromUserByClientIDAsync`
  - `HasClientRoleByName` / `HasClientRoleByNameAsync` -> `HasClientRoleByClientID` / `HasClientRoleByClientIDAsync`
  - `GetClients(const AClientName)` / `GetClientsAsync(const AClientName)` -> `GetClientByClientID` / `GetClientByClientIDAsync`
  - `GetUserClientRolesByClientID` now returns roles with both `ContainerID` and `ClientID` populated

#### Crypto Provider Selection (Breaking Change)

- **Compile-time mutual exclusivity**: LockBox3 and TMS are now mutually exclusive at compile-time
  - Default: LockBox3 (without define)
  - With `{$DEFINE IAM4D_TMS}`: TMS only, LockBox3 excluded

- **Simplified enums**:
  - `TIAM4DCryptoProviderType`: now `cpDefault`, `cpCustom` (removed `cpLockBox3`, `cpTMS`)
  - `TIAM4DStorageCryptoProviderType`: now `scpDefault`, `scpCustom` (removed `scpLockBox3`, `scpTMS`)

- **Updated factories**:
  - `TIAM4DCryptoProviderFactory.CreateProvider` automatically uses the compiled provider
  - New method `GetDefaultProviderName` to identify the active provider

#### Migration Guide

| API v2.0.0 | Current API |
|------------|-------------|
| `CreateProvider(cpLockBox3)` | `CreateProvider(cpDefault)` or `CreateProvider()` |
| `CreateProvider(cpTMS)` | `CreateProvider(cpDefault)` (with `IAM4D_TMS` define) |
| `scpLockBox3` | `scpDefault` |
| `scpTMS` | `scpDefault` (with `IAM4D_TMS` define) |

#### OAuth2 / OIDC Flow Hardening

- **Builder bootstrap alignment**
  - Certificate pinning is now applied before discovery/configuration requests in both sync and async builder flows
  - Builder completion now propagates async configuration failures instead of returning partially configured clients

- **Consistent UTC token handling**
  - Token expiry values are now stored and validated consistently in UTC across serializer, storage, and validator code paths

- **Safer URL generation**
  - Authorization and logout URLs now use proper percent-encoding for query parameters instead of `DelimitedText`

- **Isolated HTTP request state**
  - UserInfo requests now send `Authorization` as per-request headers instead of mutating the shared `THTTPClient`
  - Token endpoint calls restore the previous `ContentType` after form submissions

- **DMVC middleware cache behavior**
  - Cached claims now preserve and reuse the raw JWT payload instead of reparsing DTO JSON as if it were the original token payload
  - JWKS provider configuration is now isolated per middleware instance
  - Middleware configuration now exposes an explicit audience-validation flag and propagates it to compatible validators

- **Authorization flow cleanup**
  - Desktop Authorization Code flow now rolls back listener state and OAuth context if browser launch or URL generation fails
  - Cancelling the authorization flow also clears the in-memory OAuth context

- **POSIX browser launcher quoting**
  - macOS/Linux URL launch now quotes the target URL safely before invoking `open` / `xdg-open`

### Fixed

- **AES memory token storage deadlock**
  - Fixed lock re-entry when clearing invalid or undecryptable token blobs
  - Token loading no longer calls public clearing logic while already holding internal storage locks

- **Token expiry timezone bugs**
  - Fixed access/refresh token validity checks that compared UTC expiries against local time

- **JWT validation and JWKS caching**
  - Fixed issuer validation order so untrusted `iss` values are rejected before discovery/JWKS fetch
  - Fixed replay protection bypass where cached tokens skipped `jti` reuse validation
  - `ClearCache()` now clears the negative `kid` cache as documented
  - Manual JWKS keys now correctly override prior negative-cache misses

- **Callback server robustness**
  - Fixed nil-callback dereferences in the Indy callback server on non-IAM, root, and 404 requests
  - Fixed DMVC authentication error handling when `RawWebResponse` is not assigned

- **OAuth / HTTP request correctness**
  - Fixed malformed `Authorization: Bearer` header generation in UserInfo requests. **Thank's to LACH Christophe**
  - Fixed stale bearer headers leaking across shared `THTTPClient` requests

- **User Management behavior**
  - Fixed path-based group lookup for nested groups
  - Fixed `GetUsersInGroupByPath`, add/remove membership by path, and related group path APIs for hierarchical groups
  - `GetClients` and `GetClientByClientID` no longer hide role-loading failures by returning silently partial client data
  - `GetUsersCount` now raises on invalid non-numeric responses instead of silently returning `0`
  - `TIAM4DRoleHelper.ToJSON` now emits `containerId` consistently for client roles

- **DMVC JWT helper consistency**
  - Fixed cache-hit paths so helper methods rebuild JWT/Keycloak DTOs from the original cached claims payload

- **Crypto utility validation**
  - `GenerateSecureRandomBytes()` now validates `ACount` before allocating the result buffer, ensuring documented exception behavior for invalid values

- **Async retry and cancellation semantics**
  - `RunWithRetry` now propagates `EAsyncCancelException` immediately instead of retrying cancelled work
  - Final retry failures now re-raise the original exception instead of wrapping it in a generic `EAsyncException`

- **SSL validator callback reentrancy**
  - `OnCertificateValidation` is now invoked after releasing the internal validator lock, preventing callback-induced deadlocks during TLS validation

- **Local callback error notification lifetime**
  - Fixed exception forwarding in the local callback handler to avoid invalid exception ownership and use-after-free risks on error paths

- **Hash computation edge cases**
  - TMS, LockBox3, and RSA JWT verifier hash helpers now compute digests with a single shared code path per call
  - Empty input buffers are handled correctly without dereferencing `AData[0]` / `AMessage[0]`
  - Unsupported hash algorithms now fail consistently across providers instead of returning silent empty results

### Removed

### Security

- **Sensitive OAuth error data redaction**
  - State and nonce mismatch errors no longer expose secret correlation values in exception messages

- **JWT / network trust boundaries**
  - Prevented outbound issuer-driven discovery/JWKS fetches before expected issuer validation
  - Restored `jti` replay checks even when token validation is served from cache

- **Certificate pinning bootstrap coverage**
  - Initial discovery/configuration HTTPS requests are now covered by configured public key pinning

- **Shell injection hardening**
  - Hardened POSIX browser launch code against shell metacharacters in authorization URLs

---

## [2.0.0] - 2026-01-07

Complete Delphi client library for Keycloak and OAuth2/OpenID Connect integration with enterprise-grade security features.

### Added

#### JWT Validation Factory

- **`TIAM4DJWTValidatorFactory`** (`IAMClient4D.Security.JWT.Factory.pas`)
  - Factory class for creating `IIAM4DJWTValidator` instances
  - Returns interface references for automatic lifetime management
  - 11 overloaded `CreateValidator` methods covering all common use cases
  - Supports pluggable crypto providers (LockBox3, TMS, custom)

#### Crypto Provider System

- **`TIAM4DCryptoProviderFactory`** (`IAMClient4D.Security.Crypto.Factory.pas`)
  - Factory for creating `IIAM4DCryptoProvider` instances
  - Compile-time crypto library selection (LockBox3 default, TMS with `IAM4D_TMS` define)

- **`TIAM4DCryptoProviderType`** (`IAMClient4D.Security.Crypto.Interfaces.pas`)
  - Enumeration: `cpDefault`, `cpCustom`
  - `cpDefault` uses the compiled provider automatically

- **TMS Cryptography Pack Support** (`IAMClient4D.Security.Crypto.TMS.pas`)
  - Optional provider enabled via `{$DEFINE IAM4D_TMS}` in `IAMClient4D.Config.inc`
  - ECDSA support: ES256, ES384, ES512 (not available in LockBox3)
  - RSA PKCS#1 v1.5: RS256, RS384, RS512
  - RSA-PSS: PS256, PS384, PS512
  - Uses constant-time operations for security
  - Compiles as empty stub when TMS is not available

- **Configuration Include File** (`IAMClient4D.Config.inc`)
  - Centralized conditional compilation symbols
  - Simple enable/disable for optional features

#### Pluggable Storage Crypto Providers

- **`IIAM4DStorageCryptoProvider`** (`IAMClient4D.Storage.Crypto.Interfaces.pas`)
  - Interface for storage encryption abstraction
  - `TIAM4DStorageCryptoProviderType` enum: `scpDefault`, `scpCustom`

- **`TIAM4DStorageCryptoProviderFactory`** (`IAMClient4D.Storage.Crypto.Factory.pas`)
  - Factory for creating storage crypto provider instances

- **LockBox3 Storage Provider** (`IAMClient4D.Storage.Crypto.LockBox3.pas`)
  - AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
  - Default provider, always available
  - Frame format: [IV 16B][Ciphertext][HMAC Tag 32B]

- **TMS Storage Provider** (`IAMClient4D.Storage.Crypto.TMS.pas`)
  - AES-256-GCM (Authenticated Encryption with Associated Data)
  - Requires `IAM4D_TMS` define
  - Frame format: [Nonce 12B][Ciphertext][Tag 16B]
  - Compiles as empty stub when TMS not available

#### Synchronous API for Server Contexts

Complete synchronous API for server applications (DMVCFramework, web apps) where code already executes in worker threads. Using async methods in these contexts would add unnecessary overhead.

**Core Operations** (`IAMClient4D.Core.pas`):
- `GetAccessToken`: Gets valid token (auto-refresh if expired)
- `AuthenticateClient`: Client Credentials flow authentication
- `CompleteAuthorizationFlow(ACode, AState)`: Completes Authorization Code flow
- `GetUserInfo`: Retrieves user info from UserInfo endpoint
- `Logout`: Performs logout and clears tokens

**User Management** (`IAMClient4D.UserManagement.Keycloak.pas`):

| Category | Methods |
|----------|---------|
| **Users** | `CreateUser`, `GetUser`, `GetUserByUsername`, `GetUserByEmail`, `UpdateUser`, `DeleteUser`, `SearchUsers` |
| **Passwords** | `SetPassword`, `SendPasswordResetEmail`, `SendVerifyEmail` |
| **Roles** | `GetRealmRoles`, `GetUserRoles`, `AssignRolesToUser`, `RemoveRolesFromUser`, `AssignRoleByName`, `RemoveRoleByName` |
| **Client Roles** | `GetClientRolesByClientID`, `AssignClientRoleByClientID`, `RemoveClientRoleByClientID`, `HasClientRoleByClientID` |
| **Groups** | `GetGroups`, `GetUserGroups`, `AddUserToGroupByPath`, `RemoveUserFromGroupByPath`, `IsMemberOfGroup` |
| **Sessions** | `GetUserSessions`, `LogoutUser`, `RevokeUserSession`, `GetUserSessionCount` |
| **State** | `EnableUser`, `DisableUser`, `UnlockUser`, `IsUserLocked`, `IsUserFederated` |
| **Queries** | `HasRole`, `GetRoleByName`, `GetGroupByPath`, `GetUsersWithRole`, `GetUsersInGroupByPath` |

**Usage Example** (DMVCFramework controller):
```pascal
procedure TMyController.CreateUserEndpoint;
var
  LUser: TIAM4DUser;
begin
  // Already in worker thread - use sync API directly
  LUser := TIAM4DUser.Create('john.doe', 'john@example.com', 'John', 'Doe');
  try
    var LUserID := FUserManager.CreateUser(LUser);  // Sync call
    FUserManager.AssignRoleByName(LUserID, 'user'); // Sync call
    Render(201, TJSONObject.Create.AddPair('id', LUserID));
  except
    on E: EIAM4DUserManagementException do
      Render(E.HttpStatusCode, E.Message);
  end;
end;
```

### Algorithm Support by Provider

| Algorithm | LockBox3 | TMS |
|-----------|----------|-----|
| RS256/384/512 | Yes | Yes |
| PS256/384/512 | Yes | Yes |
| ES256/384/512 | No | Yes |
| AES-256-CBC | Yes | Yes |
| AES-256-GCM | No | Yes |

### Storage Encryption Comparison

| Feature | LockBox3 (CBC+HMAC) | TMS (GCM) |
|---------|---------------------|-----------|
| Algorithm | AES-256-CBC + HMAC-SHA256 | AES-256-GCM |
| Authentication | Encrypt-then-MAC | Native AEAD |
| IV/Nonce Size | 16 bytes | 12 bytes |
| Tag Size | 32 bytes (HMAC) | 16 bytes |
| Performance | Two-pass | Single-pass |
| Availability | Always | Requires `IAM4D_TMS` |

---

### Security Fixes

#### Critical

- **ID Token Nonce Validation**: Fixed vulnerability where nonce was extracted from ID Token without signature verification. Now uses `TIAM4DJWTValidator` to verify JWT signature before extracting claims.
  - File: `IAMClient4D.Keycloak.pas`

- **RSA-PSS Support**: Implemented full RSA-PSS signature verification (PS256, PS384, PS512) per RFC 8017.
  - New file: `IAMClient4D.Security.JWT.Verifiers.RSAPSS.pas`
  - Uses Windows CNG API on Windows, pure Pascal implementation on other platforms

- **RSA Timing Attack**: Removed optimized small exponent path in RSA verification to prevent timing side-channel attacks.
  - File: `IAMClient4D.Security.JWT.Verifiers.RSA.pas`

- **SecureZero Compiler Optimization**: Fixed `SecureZero()` to use volatile write pattern preventing dead-store elimination across all platforms.
  - File: `IAMClient4D.Common.SecureMemory.pas`

#### High Priority

- **Token Memory Zeroing**: Added `Clear()` method to `TIAM4DTokens` record to securely wipe tokens from memory.
- **SSL Validator Documentation**: Added comprehensive documentation clarifying singleton vs per-instance SSL validator patterns.
- **Callback Threading Comment**: Fixed misleading comment about main thread execution in async callbacks.
- **JWKS Cache Refresh**: Added automatic JWKS cache refresh on signature verification failure to handle key rotation.

#### Medium Priority

- **Builder Pattern Refactoring**: Eliminated code duplication in `With*()` methods.
- **HTTP Exception Mapping**: HTTP errors now raise specific exception types (`EIAM4DHTTPClientErrorException` for 4xx, `EIAM4DHTTPServerErrorException` for 5xx).
- **Sleep() Documentation**: Added warning documentation about blocking `Sleep()` in retry methods.
- **JWT jti/iat Validation**: Added optional JWT ID replay prevention and token age validation.
- **Timing-Safe String Compare**: Added `SecureStringEquals()` for constant-time string comparison.
- **Interface Segregation**: Split `IIAM4DClient` into specialized interfaces while maintaining backward compatibility.

#### Low Priority

- **Authorization Flow Timeout**: Added configurable timeout (default: 5 minutes).
- **State Format Documentation**: Added documentation explaining the 32-character hexadecimal state format.
- **Hash Collision Fix**: Added sanity check in claim caching to detect hash collisions.

---

[Unreleased]: https://github.com/claudio-piffer/IAMClient4D/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/claudio-piffer/IAMClient4D/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/claudio-piffer/IAMClient4D/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/claudio-piffer/IAMClient4D/releases/tag/v2.0.0
