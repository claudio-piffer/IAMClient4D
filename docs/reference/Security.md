# Security reference

JWT validation, signature verifiers, JWKS keys, crypto providers, TLS certificate validation and pinning, HTTP client configuration and the plain HTTP rules of IAMClient4D 3.0. The client flows are in [Core.md](Core.md), token storage in [Storage.md](Storage.md), the DMVC JWT filter (which uses the validator described here) in [DMVC.md](DMVC.md). Changes from 2.x: [MIGRATION_3.0.md](../MIGRATION_3.0.md), sections 2 and 3.3.

The examples use the sample environment of [Docker/README.md](../../Docker/README.md): issuer `http://localhost:18180/auth/realms/iamclient4d`, audience `api-server`.

## Contents

- [JWT validation](#jwt-validation)
  - [Validation steps](#validation-steps)
  - [Constructors](#constructors)
  - [Configuration](#configuration)
  - [Validated token cache](#validated-token-cache)
  - [Example](#example)
  - [Interfaces](#interfaces)
  - [Factory](#factory)
  - [Exceptions](#exceptions)
- [Signature verifiers](#signature-verifiers)
- [JWKS provider](#jwks-provider)
- [Crypto providers](#crypto-providers)
- [TLS certificate validation](#tls-certificate-validation)
- [HTTP client configuration](#http-client-configuration)
- [Plain HTTP rules](#plain-http-rules)
- [Tests](#tests)

## JWT validation

Units: `IAMClient4D.Security.JWT` (`TIAM4DJWTValidator`), `IAMClient4D.Security.Core` (interfaces).

`TIAM4DJWTValidator` validates a signed JWT (JWS compact serialization): structure, header, signature with a key of the JWKS of the expected issuer, and claims. `ValidateToken` returns `True` with the parsed claims, or raises; it never returns `False`.

The issuer is required. Keys are looked up (and discovered) only for the configured issuer, never for the `iss` of the token: with an empty expected issuer every token is refused without network requests.

### Validation steps

In this order; the first failure raises.

| # | Check | Rule |
|---|---|---|
| 1 | Token cache | A token validated before (same SHA-256) returns a copy of its claims and skips every step below. See [Validated token cache](#validated-token-cache). |
| 2 | Expected issuer | Not empty. |
| 3 | Structure | Exactly 3 parts; each one canonical base64url (alphabet `A-Z a-z 0-9 - _`, no padding, no length 4n+1, unused bits zero). An empty signature is left to the `alg` checks. |
| 4 | Header and payload | JSON objects. |
| 5 | `alg` | Present; `none` refused (any case); in the allow-list, exact case-sensitive match (RFC 7515). |
| 6 | Header `typ` | With `StrictTyp` (default on): present and in the allowed header types (default `JWT`), case-insensitive, `application/` prefix optional. |
| 7 | `crit` | Present: refused (no extension is supported, RFC 7515 4.1.11). |
| 8 | Payload `typ` | With `SetExpectedTokenType`: a `typ` claim must be a string equal (case-sensitive) to the expected value. A token without `typ` passes. |
| 9 | `iss` | Present, equal to the expected issuer after removing trailing `/` on both sides; constant-time, case-sensitive. |
| 10 | Key | From the JWKS provider, for the expected issuer and the `kid` of the header; with a provider that implements `IIAM4DJWKSKeySelector`, only keys of the type of `alg`. No key: `EIAM4DJWKSKeyNotFoundException`. |
| 11 | Key `alg` | When the JWK declares `alg`, it must equal the `alg` of the token (RFC 8725 3.1). |
| 12 | Signature | Through the signature verifier. Invalid: `EIAM4DJWTSignatureInvalidException`. |
| 13 | `aud` | When audience validation is on (default): an expected audience must be configured; `aud` present, a non-empty string equal to it, or an array containing it. Other JSON types refused. `ErrorCode` `ecJWTAudienceMismatch`. |
| 14 | `azp` | With `SetExpectedAzp`: present and equal. Otherwise, with audience validation on and `SetRequireAzpWhenMultipleAud(True)` (default): required when `aud` is an array of more than one value (an array of one value is a single audience). |
| 15 | `jti` | With `SetJtiValidation`: present (the replay check is step 19). |
| 16 | `iat` | With `SetIatMaxAge`: present, not later than now + clock skew, not older than the max age. |
| 17 | `exp` | Present; refused when `exp <= now - clock skew` (`ErrorCode` `ecJWTExpired`). |
| 18 | `nbf` | Optional; refused when `now + clock skew < nbf` (`ErrorCode` `ecJWTNotYetValid`). |
| 19 | `jti` replay | With `SetJtiValidation`: a `jti` already seen is refused. |

`exp`, `nbf` and `iat` must be JSON numbers (NumericDate, a fraction is allowed): a string, a negative value, a value past 9999-12-31 or a non-finite one is refused. `nbf` is rounded up, the others down. The public function `TryGetNumericDateClaim(AClaims, AName, out AValue, ARoundUp)` applies the same rules: `False` when the claim is absent or `null`.

Issuer, audience and `azp` are compared in constant time. `sub` is not checked.

### Constructors

All take the expected issuer and audience. Without a verifier, a `TUniversalJWTSignatureVerifier` on the compiled crypto provider is created. Without a JWKS provider, the validator creates a `TIAM4DJWKSProvider` of its own with the HTTP configuration given (no sharing between validators).

| Parameters after issuer and audience | Verifier | JWKS provider | HTTP configuration |
|---|---|---|---|
| `AHTTPConfig` | default | own | `AHTTPConfig` |
| `AVerifier, AHTTPConfig` | `AVerifier` | own | `AHTTPConfig` |
| `ASSLValidationMode = svmStrict` | default | own | 30 s connection, 60 s response |
| `AVerifier, ASSLValidationMode` | `AVerifier` | own | 30 s / 60 s |
| `AJWKSProvider, AHTTPConfig` | default | `AJWKSProvider` | `AHTTPConfig` |
| `AVerifier, AJWKSProvider, AHTTPConfig` | `AVerifier` | `AJWKSProvider` | `AHTTPConfig` |
| `AJWKSProvider, ASSLValidationMode = svmStrict` | default | `AJWKSProvider` | 30 s / 60 s |

A `nil` custom verifier raises `EIAM4DSecurityValidationException`. The HTTP configuration is used only by the JWKS provider the validator creates.

`TIAM4DJWTValidator` is a `TInterfacedObject` and `ValidateToken` is not public on the class: keep an `IIAM4DJWTValidator` reference, which also owns the object, and call `ValidateToken` through it. The `Set*` methods are public on the class.

### Configuration

Defaults are those of a validator created directly. The Keycloak client (id_token) and the DMVC filter change some of them: see the notes below the table.

| Method | Default | Effect |
|---|---|---|
| `ClockSkewSeconds` (property of `IIAM4DJWTValidator`) | 5 | Tolerance on `exp`, `nbf`, `iat` and the `jti` retention. 0 to 300; outside: `EIAM4DSecurityValidationException`. |
| `SetAllowedAlgs(AAlgs)` | the algorithms of the verifier (`GetSupportedAlgorithms` of the crypto provider) | Allow-list, exact case-sensitive names. An empty list refuses every token. `none` is refused anyway; HS* is never supported by a verifier. |
| `SetStrictTyp(AValue)` | `True` | Checks the header `typ` (step 6). `False` skips the check. |
| `SetAllowedHeaderTypes(ATypes)` | `['JWT']` | Header `typ` values accepted with `StrictTyp`. `['JWT', 'at+jwt']` also accepts RFC 9068 access tokens (Keycloak client option "Use 'at+jwt' as access token header type"); `['at+jwt']` only those. Keep `['JWT']` for ID tokens. Empty list or empty value: `EArgumentException`. |
| `SetExpectedTokenType(AValue)` | `''` (not checked) | Expected payload `typ` (RFC 8725 3.11): Keycloak writes `Bearer` in access tokens, `ID` in ID tokens. Keeps an ID token from being accepted as an access token. |
| `SetAudienceValidationEnabled(AValue)` | `True` | Checks `aud` (step 13). Disable only for token profiles without a usable `aud`. Also on `IIAM4DJWTValidatorConfigurable`. |
| `SetExpectedAzp(AValue)` | `''` (not checked) | Expected `azp` (step 14). |
| `SetRequireAzpWhenMultipleAud(AValue)` | `True` | `azp` required when `aud` has several values (OIDC Core). Ignored with audience validation off. |
| `SetJtiValidation(AEnabled, ATTLSeconds = 3600)` | off | Replay check: a token is accepted once, also by parallel requests (check and registration are one atomic step). A `jti` is remembered until `exp` + clock skew, and at least `ATTLSeconds`. TTL 0 to 86400, otherwise `EIAM4DSecurityValidationException`. Past 100000 remembered `jti` values every token is refused. Disabling it clears the remembered values. The token cache is not used while it is on. |
| `ClearJtiCache` | | Forgets the remembered `jti` values. |
| `SetIatMaxAge(AMaxAgeSeconds)` | 0 (off) | Maximum token age from `iat`. Negative: `EIAM4DSecurityValidationException`. |
| `SetTokenCacheEnabled(AValue)` | `True` | Validated token cache. `False` clears it. |
| `SetMaxTokenCacheEntries(AValue)` | 10000 | At least 1. |
| `SetTokenCacheCleanupInterval(AValue)` | 60 s | Interval of the removal of expired entries. At least 1. |
| `SetTokenCachePreExpiryBuffer(AValue)` | 30 s | A cached token stops being a hit this many seconds before `exp`. At least 0. |
| `ClearTokenCache` | | Empties the token cache. |

Every policy setter (clock skew, algorithms, header and payload types, audience, `azp`, `jti`, `iat` max age, pre-expiry buffer) clears the token cache.

Configure the validator before the first validation: the setters are not synchronized with `ValidateToken`. `ValidateToken` is safe for concurrent calls (the signature verifier and the JWKS provider are shared across threads).

Settings applied by the library:

- Keycloak client, id_token: clock skew 300 s, `SetIatMaxAge(300 + max(response timeout in s, 60))`, token cache off, expected token type `ID`, audience = client ID, issuer = the one of the discovery document.
- DMVC filter: clock skew 60 s, expected token type `Bearer`, header types `['JWT', 'at+jwt']` (see [DMVC.md](DMVC.md)).

### Validated token cache

On by default, keyed by the SHA-256 of the token. A hit takes only a shared lock (`TLightweightMREW`) and returns a copy of the parsed claims. An entry is a hit until the earliest of:

- `exp` minus the pre-expiry buffer (30 s);
- `iat` plus the max age, when `SetIatMaxAge` is set;
- 300 seconds after the token was added: then it is validated again, so a key removed from the JWKS stops being accepted.

A token without `exp` is not cached. When the cache is full, expired entries are dropped, then one eighth of the entries, least recently used first.

### Example

<!-- snippet ver=3.0 kind=decl ctx=jwt,security uses=IAMClient4D.Security.JWT.JWKS -->
```delphi
// Returns the subject of a valid access token of the sample realm
function ValidateAccessToken(const AToken: string): string;
var
  LValidator: TIAM4DJWTValidator;
  LValidatorRef: IIAM4DJWTValidator;
  LClaims: TJSONObject;
begin
  LValidator := TIAM4DJWTValidator.Create(
    'http://localhost:18180/auth/realms/iamclient4d', 'api-server', svmStrict);
  LValidatorRef := LValidator; // owns the object from here on
  LValidator.SetAllowedHeaderTypes(['JWT', 'at+jwt']);
  LValidator.SetExpectedTokenType('Bearer');
  try
    LValidatorRef.ValidateToken(AToken, LClaims);
    try
      Result := LClaims.GetValue<string>('sub', '');
    finally
      LClaims.Free;
    end;
  except
    on E: EIAM4DJWKSUnavailableException do
      // Keys not available: the identity provider is down, the token is not invalid
      raise;
    on E: EIAM4DSecurityValidationException do
      Result := ''; // token refused: E.Message says why
  end;
end;
```

A real server creates the validator once and shares it; one validator per call refetches the JWKS every time.

### Interfaces

Unit `IAMClient4D.Security.Core`.

| Interface | Members | Notes |
|---|---|---|
| `IIAM4DJWTValidator` | `ValidateToken(AToken, out AClaims): Boolean`, `ClockSkewSeconds`, `ExpectedIssuer`, `ExpectedAudience`, `ExpectedAzp` | The caller frees `AClaims`. |
| `IIAM4DJWTValidatorConfigurable` | `AudienceValidationEnabled`, `SetExpectedAzp`, `SetRequireAzpWhenMultipleAud` | Optional, separate so that third-party validators need not implement it. `TIAM4DJWTValidator` implements both. |
| `IIAM4DJWTSignatureVerifier` | `Verify(ASigningInput, ASignatureBytes, APublicKeyJWK, AAlg): Boolean`, `GetSupportedAlgorithms` | Must be safe for concurrent use. `GetSupportedAlgorithms` gives the default allow-list. |
| `IIAM4DJWKSProvider` | `GetPublicKey(AIssuer, AKeyId)`, `SetManualKey`, `ClearCache`, `SetCacheTTL`, `SetSSLValidationMode` | `GetPublicKey` returns a new object the caller frees; a missing key raises `EIAM4DJWKSKeyNotFoundException` (`TIAM4DJWKSProvider`) or returns `nil` (other implementations: the validator treats it as missing). `SetManualKey` copies the JWK. |
| `IIAM4DJWKSKeySelector` | `GetPublicKeyForAlg(AIssuer, AKeyId, AAlg)` | Optional for a JWKS provider: among keys sharing a `kid` (RFC 7517 4.5), the one whose type fits `alg` (RS*/PS*: RSA; ES256/384/512: EC P-256/384/521). Used by the validator when present. |

### Factory

Unit `IAMClient4D.Security.JWT.Factory`. `TIAM4DJWTValidatorFactory.CreateValidator` has 11 overloads that return an `IIAM4DJWTValidator`; each call creates a new validator. After issuer and audience they take, in this order, an optional crypto provider (`IIAM4DCryptoProvider`) or provider type (`TIAM4DCryptoProviderType`), an optional JWKS provider, and either an SSL validation mode (default `svmStrict`, 30 s / 60 s timeouts) or a `TIAM4DHTTPClientConfig`. `cpDefault` is the compiled provider; `cpCustom` raises `EArgumentException` (pass the provider instance instead).

<!-- snippet ver=3.0 kind=body ctx=jwt,security uses=IAMClient4D.Security.JWT.Factory,IAMClient4D.Security.JWT.JWKS -->
```delphi
// Shared JWKS provider of the process (strict TLS, 10 s timeouts)
var LValidator: IIAM4DJWTValidator := TIAM4DJWTValidatorFactory.CreateValidator(
  'http://localhost:18180/auth/realms/iamclient4d', 'api-server',
  TIAM4DJWKSProvider.GetInstance, svmStrict);
(LValidator as IIAM4DJWTValidatorConfigurable).SetExpectedAzp('iam4d-sample-service');
```

The factory returns the interface only: header and payload types, `jti`, `iat` and cache settings need a `TIAM4DJWTValidator` created directly.

### Exceptions

Unit `IAMClient4D.Exceptions` (and `IAMClient4D.Security.JWT.JWKS`). All descend from `EIAM4DSecurityValidationException`: a single `on E: EIAM4DSecurityValidationException` catches every refusal. Any other exception raised during validation is wrapped in an `EIAM4DSecurityValidationException` ("General error during JWT validation").

| Exception | Raised when |
|---|---|
| `EIAM4DJWTIssuerMismatchException` | `iss` is not the expected issuer |
| `EIAM4DJWKSKeyNotFoundException` | no signing key with the `kid` (and the type of `alg`) in the JWKS of the issuer |
| `EIAM4DJWTSignatureInvalidException` | the signature does not verify (also an RSA key below `MinModulusBits`) |
| `EIAM4DJWKSUnavailableException` | discovery or JWKS endpoint unreachable, failing or invalid, and no cached key usable. Not a token error: a server answers 503, not 401. `RetryAfterSeconds`: when the provider contacts the identity provider again (0 = unknown). |
| `EIAM4DSecurityValidationException` | every other check |

## Signature verifiers

Units `IAMClient4D.Security.JWT.Verifiers.*`. All implement `IIAM4DJWTSignatureVerifier`, are stateless, and are safe for concurrent use when the crypto provider is. Algorithm names are case-sensitive. Each has a constructor without arguments (compiled crypto provider) and one with an `IIAM4DCryptoProvider`. `Verify` returns `False` for a bad key or signature.

| Class (unit) | Algorithms | Rules |
|---|---|---|
| `TUniversalJWTSignatureVerifier` (`.Universal`) | RS*, PS*, ES* | Dispatches to the three below. An `alg` that is not RS/PS/ES 256/384/512, or not supported by the provider (`SupportsAlgorithm`), raises `EIAM4DSecurityValidationException` with the provider name and its algorithms. `GetSupportedAlgorithms` = those of the provider. Property `CryptoProvider`. |
| `TRSAJWTSignatureVerifier` (`.RSA`) | RS256, RS384, RS512 | JWK `n` and `e`; key checked with `TIAM4DRSAPublicKey.IsValid`; leading zero bytes of `n` ignored; signature exactly as long as the modulus. Builds the EMSA-PKCS1-v1_5 encoding and passes it to `RSAVerifyPKCS1`. |
| `TRSAPSSJWTSignatureVerifier` (`.RSAPSS`) | PS256, PS384, PS512 | Same key and length checks; `RSAVerifyPSS` with MGF1, salt length = hash length (32, 48, 64). |
| `TECDSAJWTSignatureVerifier` (`.ECDSA`) | ES256, ES384, ES512 | JWK `kty` `EC` and `crv` of the algorithm (P-256, P-384, P-521), `x` and `y` of the full coordinate size (32, 48, 66 bytes); signature raw `R || S` (64, 96, 132 bytes), not DER. A provider implementing `IIAM4DECDSAMessageVerifier` receives the signing input; the others receive its digest through `ECDSAVerify`. |

### RSA key rules

`TIAM4DRSAPublicKey` (unit `IAMClient4D.Security.Crypto.Interfaces`), applied by the verifiers and by every built-in provider. `IsValid(AModulus, AExponent)` is `True` when:

- `n` is odd, from `MinModulusBits` to 16384 bits (`MAX_MODULUS_BITS`);
- `e` is odd, 3 <= e < n;
- `e` is at most 64 bits when `n` exceeds 3072 bits.

`MinModulusBits` (class property, process-wide) defaults to 2048 (RFC 7518 3.3 and 4.2). It accepts 1024 to 16384; other values raise `EArgumentOutOfRangeException`. Set it at startup, before tokens are validated, and only for a legacy identity provider:

<!-- snippet ver=3.0 kind=body ctx=jwt uses=IAMClient4D.Security.Crypto.Interfaces -->
```delphi
TIAM4DRSAPublicKey.MinModulusBits := 1024; // legacy only: 1024-bit RSA is no longer secure
```

Other members: `Stripped` (value without leading zero bytes), `ModulusSize` (k in bytes).

## JWKS provider

Unit `IAMClient4D.Security.JWT.JWKS`. `TIAM4DJWKSProvider` implements `IIAM4DJWKSProvider` and `IIAM4DJWKSKeySelector`. It serves several issuers.

### Key lookup

- **Discovery**: `<issuer>/.well-known/openid-configuration`. The document must carry the requested `issuer` (OpenID Connect Discovery 1.0 4.3, trailing `/` ignored) and a `jwks_uri`. The `jwks_uri` of each issuer is cached; it is discovered again after the cache TTL or a failed JWKS fetch.
- **`SetJWKSUri(AIssuer, AJWKSUri)`**: keys fetched from `AJWKSUri` without discovery (identity providers without discovery, or a JWKS reachable at another address). An empty `AJWKSUri` goes back to discovery. Kept by `ClearCache`. Empty issuer: `EIAM4DSecurityValidationException`.
- **`jwks_uri` scheme**: must be `http://` or `https://`, and `https://` when the issuer is `https://`. This applies to the discovered value and to `SetJWKSUri`; otherwise `EIAM4DSecurityValidationException` (raised as `EIAM4DJWKSUnavailableException` during discovery).
- **Signing keys only**: `kty` `RSA` or `EC`, `use` absent or `sig`, `key_ops` absent or containing `verify` (RFC 7517 4.2, 4.3).
- **Selection**: the first signing key with the `kid` of the token and, through `GetPublicKeyForAlg`, of the key type of `alg`. A token without `kid` gets the first matching key.
- **Manual keys**: `SetManualKey(AIssuer, AKeyId, AJWK)` stores a copy that takes precedence over the fetched keys for that issuer and `kid` (tests, static configuration). `GetPublicKeyForAlg` returns manual keys as they are.

### Cache and refresh

| Behaviour | Default | Setter |
|---|---|---|
| Key cache TTL | 3600 s | `SetCacheTTL(ASeconds)`, >= 0 |
| Cached keys, least recently used dropped | 100 | `SetMaxCachedKeys(ACount)`, >= 1 |
| Minimum interval between two refreshes of one issuer | 30 s | `SetMinRefreshIntervalSeconds(ASeconds)`, >= 0 (0 disables the limit: not recommended) |
| Negative `kid` cache TTL | 60 s | `SetNegativeKidTTLSeconds(ASeconds)`, >= 0 |
| Negative `kid` cache size (expired, then oldest dropped) | 1000 | `SetMaxNegativeKidEntries(ACount)`, >= 1 |

Out-of-range values raise `EIAM4DSecurityValidationException`.

- **Unknown `kid`** (key rotation): refreshes the JWKS of the issuer, at most once per interval. Within the interval the token is refused without network requests, and a failed refresh is not retried.
- **Single flight**: one refresh per issuer at a time; concurrent callers wait for it or use the keys already cached.
- **Replacement**: a refresh replaces the whole key set of the issuer. A key no longer published stops validating when the refresh ends.
- **Stale while revalidate**: a cached key past its TTL is returned at once and the JWKS is refreshed on a background thread (one per issuer, at most once per interval). A provider not held through an interface reference refreshes inside the request instead.
- **Identity provider down**: expired keys stay usable up to 24 hours past the TTL. With no usable key: `EIAM4DJWKSUnavailableException`.
- **HTTP**: one `THTTPClient` per provider, shared by all issuers, created by `TIAM4DHTTPClientFactory` (no redirects). Requests are not serialized. Each request ends within the response timeout; network errors, 429 and transient 5xx are retried, a timeout or a certificate error is not (`GetWithRetry`, at most 3 attempts).

Other members: `ClearCache` (keys, negative cache, discovery results and refresh intervals; manual keys and `SetJWKSUri` kept), `TryPrefetch(AIssuer)` (fills the cache, never raises), `NegativeKidCacheCount` (diagnostics), `SetSSLValidationMode(AMode)`.

Thread safety: all public methods are thread-safe (`TLightweightMREW` for the caches).

### Constructors and instances

| Constructor | HTTP configuration | TLS validator |
|---|---|---|
| `Create(AHTTPConfig)` | `AHTTPConfig` | own, in the mode of `AHTTPConfig` |
| `Create(AHTTPConfig, ASSLValidator)` | `AHTTPConfig` | `ASSLValidator`, shared with the caller (its pinned keys apply; `SetSSLValidationMode` changes its mode). `nil`: `EArgumentNilException`. |
| `Create(ASSLValidationMode = svmStrict)` | 10 s connection, 10 s response | own |

- `GetInstance` / `ReleaseInstance`: a process-wide instance created with `Create` (strict, 10 s / 10 s).
- `TIAM4DSharedJWKSProviders`: one provider per HTTP configuration (SSL mode and timeouts), used by the Keycloak clients without pinned keys, so a host that creates a client per login reuses the keys already fetched. `Acquire(AHTTPConfig, AIssuer, AJWKSUri)` (`nil` when disabled), `Clear`, `Count`, `Enabled` (default `True`; `False` drops the shared providers). A client with pinned keys uses a provider of its own, with its validator. Thread-safe.

Hold a provider you create through an `IIAM4DJWKSProvider` reference: it is reference-counted, and the background refresh needs it.

<!-- snippet ver=3.0 kind=body ctx=jwt,security uses=IAMClient4D.Security.JWT.JWKS -->
```delphi
const
  CIssuer = 'http://localhost:18180/auth/realms/iamclient4d';
var LJWKS := TIAM4DJWKSProvider.Create(TIAM4DHTTPClientConfig.Create(10000, 20000, svmStrict));
var LJWKSRef: IIAM4DJWKSProvider := LJWKS;
// No discovery request: the JWKS address is known
LJWKS.SetJWKSUri(CIssuer, CIssuer + '/protocol/openid-connect/certs');
LJWKS.SetMinRefreshIntervalSeconds(60);
// Validators sharing the provider share its keys
var LApiValidator: IIAM4DJWTValidator := TIAM4DJWTValidator.Create(CIssuer, 'api-server', LJWKSRef, svmStrict);
var LAppValidator: IIAM4DJWTValidator := TIAM4DJWTValidator.Create(CIssuer, 'iam4d-sample-app', LJWKSRef, svmStrict);
```

## Crypto providers

Unit `IAMClient4D.Security.Crypto.Interfaces` (contracts), `IAMClient4D.Security.Crypto.Factory` (selection).

The provider is chosen at compile time in `src/IAMClient4D.Config.inc`, or with the same symbol in the project defines. Exactly one is compiled; the units of the others compile as empty stubs.

| Symbol | Derived define | JWT signatures (unit) | Token storage (unit) | Requirements |
|---|---|---|---|---|
| none (default) | `IAM4D_CRYPTO_LOCKBOX3` | LockBox3: `IAMClient4D.Security.Crypto.LockBox3` | AES-256-CBC + HMAC-SHA256: `IAMClient4D.Storage.Crypto.LockBox3` | LockBox3, shipped in `src/Lib/LockBox3` |
| `IAM4D_TMS` | `IAM4D_CRYPTO_TMS` | TMS Cryptography Pack: `IAMClient4D.Security.Crypto.TMS` | AES-256-GCM: `IAMClient4D.Storage.Crypto.TMS` | TMS Cryptography Pack sources in the search path (commercial license) |
| `IAM4D_TAURUSTLS` | `IAM4D_CRYPTO_TAURUSTLS` | OpenSSL through TaurusTLS: `IAMClient4D.Security.Crypto.TaurusTLS`, `IAMClient4D.Crypto.TaurusTLS.Common` | AES-256-GCM: `IAMClient4D.Storage.Crypto.TaurusTLS` | `src\Lib\TaurusTLS\Source` in the search path (Indy of Delphi), OpenSSL 3.0 or later deployed |

Both `IAM4D_TMS` and `IAM4D_TAURUSTLS`: fatal compilation error. To enable one, remove the dot in `{.$DEFINE IAM4D_TMS}` or `{.$DEFINE IAM4D_TAURUSTLS}`, then rebuild everything. `src/Lib/TaurusTLS` is a git submodule: `git submodule update --init src/Lib/TaurusTLS`.

| Algorithms | LockBox3 | TMS | TaurusTLS |
|---|---|---|---|
| RS256, RS384, RS512 | yes | yes | yes |
| PS256, PS384, PS512 | yes | yes | yes |
| ES256, ES384, ES512 | no | yes | yes |
| `GetProviderName` | `LockBox3` | `TMS Cryptography Pack` | `TaurusTLS (OpenSSL)` |

- RSA keys from `MinModulusBits` to 16384 bits for every provider; TMS verifies moduli up to 8192 bits, larger valid keys fail verification.
- With LockBox3, ES* tokens are refused as unsupported (and ES* is not in the default allow-list); `ECDSAVerify` raises `EIAM4DCryptoNotSupportedException`.
- TMS verifies ECDSA only over the message (`IIAM4DECDSAMessageVerifier`); `ECDSAVerify` over a precomputed digest raises `EIAM4DCryptoNotSupportedException`.
- All three providers are safe for concurrent use. LockBox3 and TMS create their objects per call.

`TIAM4DCryptoProviderFactory.CreateProvider(AType = cpDefault)` returns a new compiled provider; `cpCustom` raises `EArgumentException`. `GetDefaultProviderName` gives the name above.

### Custom provider

Implement `IIAM4DCryptoProvider` and pass it to `TUniversalJWTSignatureVerifier.Create(AProvider)` or to a `CreateValidator` overload. It must be safe for concurrent use: a validator shares one verifier, and so one provider, across threads.

| Method | Contract |
|---|---|
| `RSAVerifyPKCS1(AExpectedEM, ASignature, AModulus, AExponent)` | `ASignature^e mod n` equal to the EMSA-PKCS1-v1_5 encoding `AExpectedEM`. Big-endian values; signature exactly k bytes. |
| `RSAVerifyPSS(AMessage, ASignature, AModulus, AExponent, AHashAlg, ASaltLen)` | RSASSA-PSS over the message (hashed by the provider). |
| `ECDSAVerify(AHash, AR, AS_, AX, AY, ACurve)` | Over the digest of the curve hash (32, 48, 64 bytes); `R`, `S`, `x`, `y` of the full coordinate size. `False` for any other size. Not supported: raise `EIAM4DCryptoNotSupportedException`. |
| `GetSupportedAlgorithms`, `SupportsAlgorithm(AAlg)` | Case-sensitive names. |
| `GetProviderName` | For messages and logs. |

Reject keys that fail `TIAM4DRSAPublicKey.IsValid` and signatures that are not exactly k bytes, as the built-in providers do. Optionally implement `IIAM4DECDSAMessageVerifier.ECDSAVerifyMessage(AMessage, ...)` to receive the signing input instead of its digest.

### TaurusTLS (OpenSSL)

- RS*: raw RSA public operation (`BN_mod_exp`), encoded message compared in constant time. PS* and ES*: `EVP_DigestVerify` over the message; `ECDSAVerify` over a digest: `EVP_PKEY_verify`.
- Public keys imported as DER SubjectPublicKeyInfo (`d2i_PUBKEY`), without the RSA/EC_KEY APIs deprecated in OpenSSL 3.0.
- OpenSSL is loaded on the first provider creation (thread-safe); OpenSSL older than 3.0 or missing raises `EIAM4DOpenSSLException` (`ecCryptoProviderUnavailable`). TaurusTLS loads both libcrypto and libssl: deploy both. If the application already uses TaurusTLS for TLS, the same libraries are shared.
- Library names searched by TaurusTLS: Win64 `libcrypto-4-x64.dll` then `-3-x64`, Win32 `libcrypto-4.dll` then `-3`, Unix `.so.4` then `.so.3` (and the matching libssl). Other platforms: see the TaurusTLS documentation.

`TIAM4DOpenSSL` (unit `IAMClient4D.Crypto.TaurusTLS.Common`), all members thread-safe:

| Member | Description |
|---|---|
| `LibraryPath` | Folder of libcrypto and libssl. Empty: environment variable `OPENSSL_LIBRARY_PATH`, then the OS search path. Effective only if set before OpenSSL is loaded. |
| `EnsureLoaded` | Loads OpenSSL on the first call and checks the version; once loaded, takes no lock. |
| `VersionNumber`, `VersionText` | `OPENSSL_VERSION_NUMBER` format; `major.minor.patch`. |
| `LastErrorMessage` | Drains the OpenSSL error queue of the calling thread. |

Public key cache of `TIAM4DTaurusTLSCryptoProvider` (class members, shared by all instances): parsed keys (`EVP_PKEY`) for PS* and ES*, keyed by the DER SubjectPublicKeyInfo, so a rotated key is a new entry. RS* parses no key.

| Member | Description |
|---|---|
| `KeyCacheCapacity` | Default 64 (`DEFAULT_KEY_CACHE_CAPACITY`), 0 disables, at most 4096 (`MAX_KEY_CACHE_CAPACITY`); other values `EArgumentOutOfRangeException`. Least recently used dropped first. |
| `KeyCacheStats` | `TIAM4DKeyCacheStats`: `Count`, `Capacity`, `Hits`, `Misses`, `Evictions`. |
| `ClearKeyCache` | Frees the cached keys (counters kept). |

Keys are freed when dropped, at unit finalization and when TaurusTLS unloads OpenSSL.

## TLS certificate validation

Unit `IAMClient4D.Common.Security`.

### Validation modes

`TIAM4DSSLValidationMode`:

| Mode | Certificate accepted when |
|---|---|
| `svmStrict` (default) | the platform accepts it (chain, host name, dates) and, with pinned keys, its key is pinned |
| `svmAllowSelfSigned` | its subject is not empty and the current time is within its validity dates; chain and host name are not checked. With pinned keys, its key must be pinned. Without pins it is insecure: tests only. |

The Keycloak client sets the mode with `WithStrictSSL` / `WithAllowSelfSignedSSL` of the builder ([Core.md](Core.md)). The HTTPS gateway of the sample environment (`tls` profile) has a self-signed certificate:

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('https://localhost:24443/auth', 'iamclient4d', 'iam4d-sample-app')
  .WithAllowSelfSignedSSL // test certificate: chain and host name not checked
  .Build;
```

### When the validator is called

The library installs `OnValidateServerCertificate` on a `THTTPClient` only when it is needed (`TIAM4DHTTPClientSSLHelper.IsCallbackNeeded`): in `svmAllowSelfSigned`, or with pinned keys. In `svmStrict` without pins the platform alone validates. On Android the callback is always installed, because the Android `THTTPClient` without a callback accepts an untrusted CA and an expired certificate (it records the failure in `SecureFailureReasons` and goes on); with the callback the verdict of the platform counts.

### Public key pinning

- Pins are checked in both modes, on every request of the client: discovery, token, userinfo, logout, and the JWKS download of the id_token validation. In `svmStrict` the certificate must also pass the system validation.
- A pin is the SHA-256, as 64 hex characters (any case), of `TCertificate.PublicKey` as `THTTPClient` reports it: the RSA modulus as uppercase hex (Windows, Android, macOS/iOS). It is not the RFC 7469 SPKI hash: `THTTPClient` reports no DER.
- Only RSA keys can be pinned. A certificate whose platform reports no key (EC) is refused once pins are set; on macOS/iOS only 2048-bit RSA keys are reported. The `tls` gateway of the sample environment uses an EC P-256 certificate, so it cannot be pinned.
- Linux: libcurl validates the certificate without calling back, so `AddPinnedPublicKeys` raises `ENotSupportedException` (and `Build` with `WithPinnedPublicKeys`).
- Pin the key of the next certificate too, so that a key rotation does not lock the clients out.

Computing a pin from the server certificate with OpenSSL (the same recipe `tests/TLS` uses):

```bash
openssl s_client -connect host:443 -servername host </dev/null | openssl x509 > server.pem
openssl x509 -in server.pem -noout -modulus | cut -d= -f2 | tr -d '\r\n' | openssl dgst -sha256
```

`TIAM4DSSLCertificateValidator.CalculatePublicKeyHash(TCertificate.PublicKey)` gives the same value from code (PEM headers and whitespace removed, SHA-256 of the UTF-8 text, hex). A refused certificate reports its hash in the message of `OnCertificateValidation`.

The client sets pins with `WithPinnedPublicKeys` (builder) or `AddPinnedPublicKeys` / `ClearPinnedPublicKeys` (`IIAM4DClient`); the DMVC filter with `PinnedPublicKeys` or `SSLValidator` of its configuration ([DMVC.md](DMVC.md)).

### IIAM4DSSLCertificateValidator

| Method | Description |
|---|---|
| `SetValidationMode(AMode)`, `GetValidationMode` | Validation mode. |
| `AddPinnedPublicKeys(AHashes)` | Adds pins. Empty, not 64 characters or not hex: `EArgumentException`; Linux: `ENotSupportedException`. An empty array is ignored. |
| `ClearPinnedPublicKeys`, `HasPinnedPublicKeys` | |
| `ValidateCertificate(ACertificate, ASystemAccepted): Boolean` | `ASystemAccepted` is the verdict of the platform; `svmStrict` must require it. |

`TIAM4DSSLCertificateValidator` implements it, thread-safe (critical section), default mode `svmStrict`. Class functions `CalculatePublicKeyHash` and `NormalizePublicKeyFormat`.

`OnCertificateValidation` (`TIAM4DCertificateValidationEvent`: `Sender`, `Certificate`, `Accepted`, `Reason`, `Message`) is raised after the decision, for logging and diagnostics; exceptions in the handler are swallowed. It is raised only when the callback is installed (see above). `Reason` is a `TIAM4DCertificateRejectionReason`: `crrNone`, `crrEmptySubject`, `crrNotYetValid`, `crrExpired`, `crrPublicKeyPinningFailed`, `crrSystemValidationFailed`, `crrUnknown`. The validator of the Keycloak client is internal: to use the event, create the validator yourself, for example for a JWKS provider:

<!-- snippet ver=3.0 kind=decl ctx=jwt,security uses=IAMClient4D.Security.JWT.JWKS -->
```delphi
type
  TCertificateLog = class
  public
    procedure CertificateValidated(Sender: TObject; const Certificate: TCertificate;
      Accepted: Boolean; Reason: TIAM4DCertificateRejectionReason; const Message: string);
  end;

procedure TCertificateLog.CertificateValidated(Sender: TObject; const Certificate: TCertificate;
  Accepted: Boolean; Reason: TIAM4DCertificateRejectionReason; const Message: string);
begin
  if not Accepted then
    Writeln('Certificate of ', Certificate.Subject, ' refused: ', Message);
end;

// JWKS provider whose downloads accept only a pinned server key
function CreatePinnedJWKSProvider(const ALog: TCertificateLog): IIAM4DJWKSProvider;
var
  LValidator: TIAM4DSSLCertificateValidator;
  LValidatorRef: IIAM4DSSLCertificateValidator;
begin
  LValidator := TIAM4DSSLCertificateValidator.Create;
  LValidatorRef := LValidator;
  LValidator.OnCertificateValidation := ALog.CertificateValidated;
  // SHA-256 of the modulus of the server certificate (OpenSSL recipe above)
  LValidator.AddPinnedPublicKeys(['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']);
  Result := TIAM4DJWKSProvider.Create(TIAM4DHTTPClientConfig.Default, LValidatorRef);
end;
```

A custom validator implements `IIAM4DSSLCertificateValidator` (see [MIGRATION_3.0.md](../MIGRATION_3.0.md), section 3.3) and is connected to a `THTTPClient` through `TIAM4DHTTPClientSSLHelper`.

## HTTP client configuration

Unit `IAMClient4D.Core`.

### TIAM4DHTTPClientConfig

Record. `ConnectionTimeout` bounds name resolution and connection; `ResponseTimeout` bounds each whole request of the library (connection, sending, response) and is also the send timeout. Milliseconds.

| Member | Description |
|---|---|
| `Create(AConnectionTimeout = 30000, AResponseTimeout = 60000, ASSLValidationMode = svmStrict)` | |
| `Default` | 30000, 60000, `svmStrict`. |
| `FromClientConfig(AClientConfig)` | Timeouts and SSL mode of a `TIAM4DClientConfig`. |
| `ConnectionTimeout`, `ResponseTimeout`, `SSLValidationMode` | Read/write. |

### TIAM4DHTTPClientFactory

Creates `THTTPClient` instances; the caller frees them. Every client has the timeouts of the configuration, `SendTimeout` = `ResponseTimeout`, user agent `IAMClient4D/3.0.0` and `HandleRedirects = False`: a 3xx is returned, never followed (it could go to `http://` or another host with the credentials and without the pin check).

| Method | Description |
|---|---|
| `CreateHTTPClient(AConfig)`, `CreateHTTPClient(AClientConfig)`, `CreateHTTPClient` | SSL mode of the configuration (default configuration for the last). `svmAllowSelfSigned` uses a shared validator in that mode, without pins. |
| `CreateHTTPClient(AClientConfig, ASSLHelper)` | Validates with the validator of `ASSLHelper` (its pins included); the caller keeps the helper alive and frees it. |
| `Execute(AClient, AMethod, AURL, ASource, AHeaders)` | One request bounded by `ResponseTimeout` as a whole (WinHTTP alone applies it per network operation; on Windows the request is cancelled at the deadline). Raises `EIAM4DNetworkTimeoutException`, `EIAM4DSSLCertificateException` (certificate refused), `EIAM4DNetworkUnreachableException` (other network errors), never a raw `ENetException`. |
| `GetWithRetry(AClient, AUrl, AHeaders, AMaxRetries = 3)`, `PostFormUrlEncodedWithRetry(AClient, AUrl, AForm, AHeaders, AMaxRetries = 3)` | Up to `AMaxRetries` attempts, with exponential backoff, for network errors, 429 and transient 5xx; no retry of 4xx, of a timeout or of a certificate error. After the last attempt a 429/5xx response is returned, not raised. |

`TIAM4DHTTPClientSSLHelper` bridges an `IIAM4DSSLCertificateValidator` and `THTTPClient.OnValidateServerCertificate` (`ValidateServerCertificate`, `KeepPlatformVerdict`, `IsCallbackNeeded`, `SSLValidator`). Its owner frees it.

`IIAM4DClient.CreateHTTPClient` returns a client with the SSL configuration and pins of the Keycloak client ([Core.md](Core.md)).

## Plain HTTP rules

A URL is plain HTTP to a non-loopback host when it starts with `http://` and its host is not `localhost`, an IPv4 literal in `127.0.0.0/8` or `::1` (`TIAM4DClientConfig.IsInsecureHTTPURL`; an unparsable URL counts as non-loopback). A name such as `127.0.0.1.example.com` is not the loopback.

| Where | Rule | Override |
|---|---|---|
| Keycloak client `BaseURL` and external callback URL | Plain HTTP to a non-loopback host: `EIAM4DInvalidConfigurationException` at `Build` / configuration | `WithAllowInsecureHTTP` (builder), `TIAM4DClientConfig.WithAllowInsecureHTTP` |
| `GenerateLogoutURL` post-logout redirect URI | HTTP(S) only; plain HTTP to a non-loopback host refused | same `AllowInsecureHTTP` |
| Discovery document of an `https` realm | Any `http` endpoint (authorization, token, userinfo, end session, revocation, JWKS): `EIAM4DInvalidConfigurationException` | none |
| App redirect (`WithAppRedirect`) | Private-use scheme only; `http` and `https` refused (`EArgumentException`) | none |
| JWKS provider | `jwks_uri` must be HTTP(S), and HTTPS for an HTTPS issuer | none |
| `TIAM4DAuthorizedHTTPClient` | Bearer not sent over plain HTTP to a non-loopback host (`EIAM4DInvalidConfigurationException`); a URL that is not HTTP(S): `EArgumentException`; redirects never followed | `AllowInsecureHTTP` property |

`AllowInsecureHTTP` defaults to `False` everywhere. Code, tokens, passwords and client secrets then travel in clear text: use it only in test environments (for example Keycloak on the LAN for a phone), never in production.

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
// Keycloak on the LAN, reached from a test device
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('http://192.168.1.10:18180/auth', 'iamclient4d', 'iam4d-sample-app')
  .WithAllowInsecureHTTP // test environments only
  .Build;
```

The validator and the JWKS provider used on their own (outside the client) apply only the `jwks_uri` rule: an `http://` issuer is accepted on any host.

## Tests

| Folder | Covers |
|---|---|
| [tests/JWT](../../tests/JWT/README.md) | Validator and JWKS provider against a fake identity provider: `alg`, issuer isolation, unknown `kid` storms, refresh interval, negative cache, stale keys, signing keys only, discovery issuer, `SetJWKSUri`, token cache, parallel `jti` replay. |
| [tests/Crypto](../../tests/Crypto/README.md) | Each crypto provider against RFC 7515/7520 and OpenSSL JWS vectors, AES-256-GCM vectors, AES token storage. |
| [tests/TLS](../../tests/TLS/README.md) | Validation modes and pinning over real TLS handshakes (Windows, Linux). |
