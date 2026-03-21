# Changelog

All notable changes to IAMClient4D are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [2.0.0] - 2025-01-07

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

[Unreleased]: https://github.com/claudio-piffer/IAMClient4D/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/claudio-piffer/IAMClient4D/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/claudio-piffer/IAMClient4D/releases/tag/v2.0.0
