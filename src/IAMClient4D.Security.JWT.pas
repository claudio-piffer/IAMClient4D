{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.JWT.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2025 Claudio Piffer
  License    : Apache License, Version 2.0, January 2004
  Source URL : https://github.com/claudio-piffer/IAMClient4D

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  ---------------------------------------------------------------------------
}

unit IAMClient4D.Security.JWT;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.NetEncoding,
  System.DateUtils,
  System.TimeSpan,
  System.SyncObjs,
  System.Generics.Collections,
  System.Net.URLClient,
  System.Net.HttpClient,
  IAMClient4D.Security.Core,
  IAMClient4D.Core,
  IAMClient4D.Common.Security,
  IAMClient4D.Common.JSONUtils;

type
  /// <summary>
  /// JWT validator implementation for token signature and claims validation.
  /// </summary>
  /// <remarks>
  /// Validates signature and claims (exp/nbf/iss and optionally aud). Uses TIAM4DJWKSProvider for
  /// thread-safe JWKS handling with auto-discovery, caching, and key rotation support.
  /// Issuer: required. Keys are looked up (and discovered) only for the expected issuer, never for the
  /// token iss; with an empty expected issuer every token is rejected without network requests.
  /// Security hardening: Algorithm allow-list (case-sensitive), key alg (when present) equal to the token alg,
  /// optional typ='JWT' check, configurable clock skew.
  /// Thread-safety: All operations are thread-safe via internal JWKS provider.
  /// </remarks>
  TIAM4DJWTValidator = class(TInterfacedObject, IIAM4DJWTValidator, IIAM4DJWTValidatorConfigurable)
  private
  const
    /// <summary>Maximum allowed clock skew in seconds (5 minutes)</summary>
    MAX_CLOCK_SKEW_SECONDS = 300;
    /// <summary>Maximum JTI cache entries to prevent Memory DoS attacks</summary>
    MAX_JTI_CACHE_ENTRIES = 100000;
    /// <summary>JTI cache cleanup interval in seconds (throttled to avoid O(n) on every call)</summary>
    JTI_CLEANUP_INTERVAL_SECONDS = 60;
    /// <summary>Default maximum cached validated tokens</summary>
    DEFAULT_MAX_TOKEN_CACHE_ENTRIES = 10000;
    /// <summary>Default token cache cleanup interval in seconds</summary>
    DEFAULT_TOKEN_CACHE_CLEANUP_INTERVAL = 60;
    /// <summary>Default pre-expiry buffer: remove tokens N seconds before actual expiry</summary>
    DEFAULT_TOKEN_CACHE_PRE_EXPIRY_BUFFER = 30;
    /// <summary>A cached token is validated again after this many seconds: a key removed from the JWKS
    /// stops being accepted within this time</summary>
    MAX_TOKEN_CACHE_ENTRY_AGE_SECONDS = 300;
  type
    /// <summary>Validated token: parsed claims (owned, never modified) and the end of the hit window (UTC):
    /// exp minus the pre-expiry buffer, iat plus the max age, at most MAX_TOKEN_CACHE_ENTRY_AGE_SECONDS.</summary>
    TTokenCacheEntry = class
    public
      Claims: TJSONObject;
      ValidUntil: TDateTime;
      // LRU: updated with TInterlocked under the read lock
      LastUsedTicks: Int64;
      destructor Destroy; override;
    end;
  private
    FExpectedIssuer: string;
    FExpectedAudience: string;
    FAudienceValidationEnabled: Boolean;
    FExpectedAzp: string;
    FRequireAzpWhenMultipleAud: Boolean;
    FClockSkewSeconds: Integer;

    FSignatureVerifier: IIAM4DJWTSignatureVerifier;
    FJWKSProvider: IIAM4DJWKSProvider;
    FHTTPConfig: TIAM4DHTTPClientConfig;

    FAllowedAlgs: TArray<string>; // allow-list (e.g. ['RS256','PS256'])
    FStrictTyp: Boolean; // True: header typ must be one of FAllowedHeaderTypes
    FAllowedHeaderTypes: TArray<string>; // normalized: lower case, without 'application/'
    FExpectedTokenType: string; // typ claim of the payload ('' = not checked)

    // Replay prevention (jti cache)
    FJtiValidationEnabled: Boolean;
    FJtiCache: TDictionary<string, TDateTime>;
    FJtiCacheTTL: Integer; // seconds
    FJtiCacheLock: TObject;
    FLastJtiCleanup: TDateTime; // UTC timestamp of last cleanup

    // Token age validation (iat)
    FIatMaxAge: Integer; // seconds, 0 = disabled

    // Validated token cache (avoids re-validation of same token)
    FTokenCacheEnabled: Boolean;
    FTokenCache: TObjectDictionary<string, TTokenCacheEntry>;
    FTokenCacheLock: TLightweightMREW;
    FMaxTokenCacheEntries: Integer;
    FTokenCacheCleanupInterval: Integer; // seconds
    FTokenCachePreExpiryBuffer: Integer; // seconds before exp to remove from cache
    FLastTokenCacheCleanup: TDateTime; // UTC timestamp of last cleanup

    function ValidateClaims(const Claims: TJSONObject; const ExpectedIssuer, ExpectedAudience: string): Boolean;
    function GetUtcNow: TDateTime;
    function InternalVerifySignature(const ASigningInput: string; const ASignatureBytes: TBytes; const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;

    function IsAlgAllowed(const AAlg: string): Boolean;
    function IsHeaderTypeAllowed(const ATyp: string): Boolean;
    /// <summary>
    /// True for a canonical base64url segment: alphabet A-Z a-z 0-9 - _, no padding, no length
    /// of 4n+1, unused bits of the last character zero (the decoder skips other characters and
    /// drops those bits, so different strings would give the same token).
    /// </summary>
    class function IsBase64URLSegment(const ASegment: string): Boolean; static;
    /// <summary>
    /// Normalizes issuer URL by removing trailing slash for consistent comparison.
    /// </summary>
    /// <remarks>
    /// Keycloak issuer URLs may or may not have trailing slash depending on configuration.
    /// This normalization ensures consistent matching regardless of trailing slash presence.
    /// </remarks>
    function NormalizeIssuer(const S: string): string;

    // JTI cache management
    procedure CleanupExpiredJtiEntries;
    function TryRegisterJti(const AJti: string; AExpiryUTC: TDateTime): Boolean;

    // Token validation cache management
    function TryGetCachedToken(const AToken: string; out AClaims: TJSONObject): Boolean;
    procedure AddTokenToCache(const AToken: string; const AClaims: TJSONObject);
    procedure CleanupExpiredTokens;
    /// <summary>Drops the least recently used entries until ACount are free</summary>
    procedure EvictOldestTokens(ACount: Integer);
    /// <summary>Cache key of a token: its SHA-256, not the token of several KB</summary>
    class function TokenCacheKey(const AToken: string): string; static;

    // Constant-time claim comparison helpers (prevents timing attacks)
    function SecureCompareIssuer(const AIssuer, AExpected: string): Boolean;
    function SecureCompareAudience(const AAudience, AExpected: string): Boolean;
    function SecureCompareAzp(const AAzp, AExpected: string): Boolean;

    // Common initialization (avoids constructor chaining bug in Delphi)
    procedure DoInit(const AExpectedIssuer, AExpectedAudience: string;
      const AVerifier: IIAM4DJWTSignatureVerifier;
      const AJWKSProvider: IIAM4DJWKSProvider;
      const AHTTPConfig: TIAM4DHTTPClientConfig);
  protected
    /// <summary>
    /// Validates JWT token signature and claims, returns parsed claims if valid.
    /// </summary>
    function ValidateToken(const AToken: string; out AClaims: TJSONObject): Boolean;

    /// <summary>
    /// Returns clock skew tolerance in seconds.
    /// </summary>
    function GetClockSkewSeconds: Integer;

    /// <summary>
    /// Sets clock skew tolerance in seconds.
    /// </summary>
    procedure SetClockSkewSeconds(const AValue: Integer);

    /// <summary>
    /// Returns expected issuer for validation.
    /// </summary>
    function GetExpectedIssuer: string;

    /// <summary>
    /// Returns expected audience for validation.
    /// </summary>
    function GetExpectedAudience: string;

    /// <summary>
    /// Returns whether audience validation is enabled.
    /// </summary>
    function GetAudienceValidationEnabled: Boolean;

    /// <summary>
    /// Returns expected authorized party for validation.
    /// </summary>
    function GetExpectedAzp: string;
  public
    /// <summary>
    /// Creates JWT validator with automatic universal verifier (supports RS256, RS384, RS512, PS256, etc.).
    /// Recommended for most use cases.
    /// </summary>
    constructor Create(const AExpectedIssuer, AExpectedAudience: string;
      const AHTTPConfig: TIAM4DHTTPClientConfig); overload;

    /// <summary>
    /// Creates JWT validator with custom signature verifier (for third-party implementations).
    /// Use this when you need to inject a custom verifier implementation.
    /// </summary>
    constructor Create(const AExpectedIssuer, AExpectedAudience: string;
      const AVerifier: IIAM4DJWTSignatureVerifier;
      const AHTTPConfig: TIAM4DHTTPClientConfig); overload;

    /// <summary>
    /// Creates JWT validator with automatic verifier and SSL validation mode (uses default timeouts).
    /// </summary>
    constructor Create(const AExpectedIssuer, AExpectedAudience: string;
      const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict); overload;

    /// <summary>
    /// Creates JWT validator with custom verifier and SSL validation mode (uses default timeouts).
    /// </summary>
    constructor Create(const AExpectedIssuer, AExpectedAudience: string;
      const AVerifier: IIAM4DJWTSignatureVerifier;
      const ASSLValidationMode: TIAM4DSSLValidationMode); overload;

    /// <summary>
    /// Creates JWT validator with automatic verifier and JWKS provider.
    /// </summary>
    constructor Create(const AExpectedIssuer, AExpectedAudience: string;
      const AJWKSProvider: IIAM4DJWKSProvider;
      const AHTTPConfig: TIAM4DHTTPClientConfig); overload;

    /// <summary>
    /// Creates JWT validator with custom verifier and JWKS provider.
    /// </summary>
    constructor Create(const AExpectedIssuer, AExpectedAudience: string;
      const AVerifier: IIAM4DJWTSignatureVerifier;
      const AJWKSProvider: IIAM4DJWKSProvider;
      const AHTTPConfig: TIAM4DHTTPClientConfig); overload;

    /// <summary>
    /// Creates JWT validator with automatic verifier, JWKS provider and SSL validation mode.
    /// </summary>
    constructor Create(const AExpectedIssuer, AExpectedAudience: string;
      const AJWKSProvider: IIAM4DJWKSProvider;
      const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict); overload;

    /// <summary>
    /// Destroys the validator with its token and jti caches; the JWKS provider keeps its keys.
    /// </summary>
    destructor Destroy; override;

    /// <summary>Sets the algorithm allow-list (e.g., ['RS256','PS256']), matched case-sensitively. Empty list rejects all tokens.</summary>
    procedure SetAllowedAlgs(const AAlgs: TArray<string>);

    /// <summary>Enables/disables strict typ='JWT' header validation.</summary>
    procedure SetStrictTyp(const AValue: Boolean);

    /// <summary>
    /// Header typ values accepted while StrictTyp is on (default ['JWT']), case-insensitive, the
    /// 'application/' prefix optional (RFC 7515 4.1.9). ['JWT', 'at+jwt'] accepts the access
    /// tokens of RFC 9068 too (Keycloak: client option "Use 'at+jwt' as access token header
    /// type"); ['at+jwt'] only those. Keep ['JWT'] for ID tokens: an at+jwt is not one.
    /// </summary>
    /// <exception cref="EArgumentException">Empty list or empty value</exception>
    procedure SetAllowedHeaderTypes(const ATypes: TArray<string>);

    /// <summary>
    /// Expected value of the typ claim of the payload (explicit typing, RFC 8725 3.11): Keycloak
    /// writes 'Bearer' in access tokens and 'ID' in ID tokens. Empty (default): not checked.
    /// </summary>
    /// <remarks>
    /// A token with another typ is refused, so an ID token is not accepted as an access token.
    /// A token without the typ claim (identity providers other than Keycloak) is not refused.
    /// </remarks>
    procedure SetExpectedTokenType(const AValue: string);

    /// <summary>Sets expected Client ID in azp claim (empty string = not validated).</summary>
    procedure SetExpectedAzp(const AValue: string);

    /// <summary>Enables/disables audience (aud) validation (default: enabled).</summary>
    procedure SetAudienceValidationEnabled(const AValue: Boolean);

    /// <summary>Requires azp claim when aud contains multiple audiences (default: True, per OIDC specification).</summary>
    /// <remarks>Ignored when audience validation is disabled.</remarks>
    procedure SetRequireAzpWhenMultipleAud(const AValue: Boolean);

    /// <summary>
    /// Enables JWT ID (jti) validation with cache for replay attack prevention.
    /// </summary>
    /// <param name="AEnabled">True to enable jti validation</param>
    /// <param name="ATTLSeconds">Cache TTL in seconds (how long to remember used jtis)</param>
    /// <remarks>
    /// When enabled, tokens with previously seen jti claims will be rejected: a token is accepted once,
    /// also by parallel requests (check and add are atomic). A jti is remembered until the token
    /// expires (exp plus clock skew), and for at least ATTLSeconds. Past 100000 remembered jtis every
    /// token is refused. The validated token cache is not used while jti validation is enabled.
    /// </remarks>
    procedure SetJtiValidation(const AEnabled: Boolean; const ATTLSeconds: Integer = 3600);

    /// <summary>
    /// Sets maximum allowed token age based on iat (issued-at) claim.
    /// </summary>
    /// <param name="AMaxAgeSeconds">Maximum token age in seconds (0 = disabled)</param>
    /// <remarks>
    /// When enabled, tokens older than the specified age will be rejected.
    /// This provides protection against token theft by limiting how long a token can be used.
    /// </remarks>
    procedure SetIatMaxAge(const AMaxAgeSeconds: Integer);

    /// <summary>
    /// Clears the jti cache manually. Useful for testing or memory management.
    /// </summary>
    procedure ClearJtiCache;

    /// <summary>
    /// Enables/disables validated token caching (default: enabled).
    /// </summary>
    /// <remarks>
    /// When enabled, successfully validated tokens are cached until exp minus the pre-expiry buffer,
    /// iat plus the max age (SetIatMaxAge), and for at most 5 minutes: then the token is validated
    /// again, so a key removed from the JWKS stops being accepted. The policy setters clear the cache.
    /// Subsequent requests with the same token skip signature verification and claims parsing:
    /// a hit returns a copy of the cached claims under the shared (read) lock.
    /// Not used while jti validation is enabled.
    /// Thread-safe: Uses TLightweightMREW for optimal read-heavy performance.
    /// </remarks>
    procedure SetTokenCacheEnabled(const AValue: Boolean);

    /// <summary>
    /// Sets maximum number of cached validated tokens (default: 10000).
    /// </summary>
    /// <remarks>
    /// When the cache is full the expired entries are dropped, then an eighth of the entries,
    /// least recently used first. Entries are keyed by the SHA-256 of the token.
    /// </remarks>
    procedure SetMaxTokenCacheEntries(const AValue: Integer);

    /// <summary>
    /// Sets token cache cleanup interval in seconds (default: 60).
    /// </summary>
    /// <remarks>
    /// Expired tokens are removed from cache periodically at this interval.
    /// </remarks>
    procedure SetTokenCacheCleanupInterval(const AValue: Integer);

    /// <summary>
    /// Sets pre-expiry buffer in seconds (default: 30).
    /// </summary>
    /// <remarks>
    /// Tokens are removed from cache N seconds before their actual expiration time.
    /// This prevents serving tokens that are about to expire.
    /// </remarks>
    procedure SetTokenCachePreExpiryBuffer(const AValue: Integer);

    /// <summary>
    /// Clears all cached validated tokens manually.
    /// </summary>
    procedure ClearTokenCache;
  end;

/// <summary>
/// Reads a NumericDate claim (exp, nbf, iat, auth_time: RFC 7519 2, seconds since the epoch, also
/// with a fraction). False when the claim is absent or null. A value that is not a JSON number,
/// not finite or out of range raises EIAM4DSecurityValidationException. ARoundUp rounds a
/// fraction up (nbf: never earlier than the issuer said), otherwise down (exp, iat, auth_time).
/// </summary>
function TryGetNumericDateClaim(const AClaims: TJSONObject; const AName: string; out AValue: Int64;
  ARoundUp: Boolean = False): Boolean;

implementation

uses
  System.Hash,
  System.Math,
  System.Generics.Defaults,
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Security.JWT.Verifiers.Universal,
  IAMClient4D.Security.JWT.JWKS,
  IAMClient4D.Exceptions;

const
  // 9999-12-31T23:59:59Z: the last second UnixToDateTime and the date formats handle
  MAX_NUMERIC_DATE = 253402300799;

function TryGetNumericDateClaim(const AClaims: TJSONObject; const AName: string; out AValue: Int64;
  ARoundUp: Boolean): Boolean;
var
  LValue: TJSONValue;
  LSeconds: Double;
begin
  AValue := 0;
  Result := False;
  if not Assigned(AClaims) then
    Exit;
  LValue := AClaims.GetValue(AName);
  if (LValue = nil) or (LValue is TJSONNull) then
    Exit;
  // A string, a boolean or an object is not a NumericDate, even when it reads as a number
  if not (LValue is TJSONNumber) then
    raise EIAM4DSecurityValidationException.CreateFmt('Claim %s is not a number (NumericDate).', [AName]);
  try
    LSeconds := TJSONNumber(LValue).AsDouble;
  except
    on EConvertError do
      raise EIAM4DSecurityValidationException.CreateFmt('Claim %s is not a valid NumericDate.', [AName]);
  end;
  if IsNan(LSeconds) or IsInfinite(LSeconds) or (LSeconds < 0) or (LSeconds > MAX_NUMERIC_DATE) then
    raise EIAM4DSecurityValidationException.CreateFmt('Claim %s is out of range for a NumericDate.', [AName]);
  // Trunc gives an Int64 (Floor and Ceil an Integer, past 2038 they overflow); the value is >= 0
  AValue := Trunc(LSeconds);
  if ARoundUp and (Frac(LSeconds) > 0) then
    Inc(AValue);
  Result := True;
end;

{ TIAM4DJWTValidator }

procedure TIAM4DJWTValidator.DoInit(const AExpectedIssuer, AExpectedAudience: string;
  const AVerifier: IIAM4DJWTSignatureVerifier;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  FHTTPConfig := AHTTPConfig;

  if Assigned(AVerifier) then
    FSignatureVerifier := AVerifier
  else
    FSignatureVerifier := TUniversalJWTSignatureVerifier.Create;

  if Assigned(AJWKSProvider) then
    FJWKSProvider := AJWKSProvider
  else
    FJWKSProvider := TIAM4DJWKSProvider.Create(FHTTPConfig);

  FExpectedIssuer := AExpectedIssuer;
  FExpectedAudience := AExpectedAudience;
  FAudienceValidationEnabled := True;
  FExpectedAzp := '';
  FRequireAzpWhenMultipleAud := True;
  FClockSkewSeconds := 5;

  FAllowedAlgs := FSignatureVerifier.GetSupportedAlgorithms;
  FStrictTyp := True;
  FAllowedHeaderTypes := ['jwt'];
  FExpectedTokenType := '';

  FJtiValidationEnabled := False;
  FJtiCache := TDictionary<string, TDateTime>.Create;
  FJtiCacheTTL := 3600;
  FJtiCacheLock := TObject.Create;
  FLastJtiCleanup := 0;

  // Initialize iat max age (disabled by default)
  FIatMaxAge := 0;

  // Initialize token validation cache (enabled by default)
  FTokenCacheEnabled := True;
  FTokenCache := TObjectDictionary<string, TTokenCacheEntry>.Create([doOwnsValues]);
  FMaxTokenCacheEntries := DEFAULT_MAX_TOKEN_CACHE_ENTRIES;
  FTokenCacheCleanupInterval := DEFAULT_TOKEN_CACHE_CLEANUP_INTERVAL;
  FTokenCachePreExpiryBuffer := DEFAULT_TOKEN_CACHE_PRE_EXPIRY_BUFFER;
  FLastTokenCacheCleanup := 0;
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  inherited Create;
  DoInit(AExpectedIssuer, AExpectedAudience, nil, nil, AHTTPConfig);
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AVerifier: IIAM4DJWTSignatureVerifier;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  inherited Create;
  if not Assigned(AVerifier) then
    raise EIAM4DSecurityValidationException.Create('Custom verifier cannot be nil.');
  DoInit(AExpectedIssuer, AExpectedAudience, AVerifier, nil, AHTTPConfig);
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const ASSLValidationMode: TIAM4DSSLValidationMode);
var
  LConfig: TIAM4DHTTPClientConfig;
begin
  inherited Create;
  LConfig := TIAM4DHTTPClientConfig.Create(30000, 60000, ASSLValidationMode);
  DoInit(AExpectedIssuer, AExpectedAudience, nil, nil, LConfig);
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AVerifier: IIAM4DJWTSignatureVerifier;
  const ASSLValidationMode: TIAM4DSSLValidationMode);
var
  LConfig: TIAM4DHTTPClientConfig;
begin
  inherited Create;
  if not Assigned(AVerifier) then
    raise EIAM4DSecurityValidationException.Create('Custom verifier cannot be nil.');
  LConfig := TIAM4DHTTPClientConfig.Create(30000, 60000, ASSLValidationMode);
  DoInit(AExpectedIssuer, AExpectedAudience, AVerifier, nil, LConfig);
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  inherited Create;
  DoInit(AExpectedIssuer, AExpectedAudience, nil, AJWKSProvider, AHTTPConfig);
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AVerifier: IIAM4DJWTSignatureVerifier;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  inherited Create;
  if not Assigned(AVerifier) then
    raise EIAM4DSecurityValidationException.Create('Custom verifier cannot be nil.');
  DoInit(AExpectedIssuer, AExpectedAudience, AVerifier, AJWKSProvider, AHTTPConfig);
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const ASSLValidationMode: TIAM4DSSLValidationMode);
var
  LConfig: TIAM4DHTTPClientConfig;
begin
  inherited Create;
  LConfig := TIAM4DHTTPClientConfig.Create(30000, 60000, ASSLValidationMode);
  DoInit(AExpectedIssuer, AExpectedAudience, nil, AJWKSProvider, LConfig);
end;

destructor TIAM4DJWTValidator.Destroy;
begin
  FreeAndNil(FJtiCache);
  FreeAndNil(FJtiCacheLock);
  FreeAndNil(FTokenCache);
  // TLightweightMREW is a record, no Free needed

  FSignatureVerifier := nil;
  FJWKSProvider := nil;

  inherited;
end;

function TIAM4DJWTValidator.GetClockSkewSeconds: Integer;
begin
  Result := FClockSkewSeconds;
end;

function TIAM4DJWTValidator.GetExpectedAudience: string;
begin
  Result := FExpectedAudience;
end;

function TIAM4DJWTValidator.GetAudienceValidationEnabled: Boolean;
begin
  Result := FAudienceValidationEnabled;
end;

function TIAM4DJWTValidator.GetExpectedIssuer: string;
begin
  Result := FExpectedIssuer;
end;

function TIAM4DJWTValidator.GetUtcNow: TDateTime;
begin
  Result := TDateTime.NowUTC;
end;

procedure TIAM4DJWTValidator.SetClockSkewSeconds(const AValue: Integer);
begin
  if AValue < 0 then
    raise EIAM4DSecurityValidationException.Create('Clock skew seconds must be >= 0');
  if AValue > MAX_CLOCK_SKEW_SECONDS then
    raise EIAM4DSecurityValidationException.CreateFmt(
      'Clock skew seconds must be <= %d (5 minutes). Higher values weaken security.', [MAX_CLOCK_SKEW_SECONDS]);
  FClockSkewSeconds := AValue;
  ClearTokenCache;
end;

function TIAM4DJWTValidator.IsAlgAllowed(const AAlg: string): Boolean;
var
  LAllowed: string;
begin
  // RFC 7515 4.1.1: alg values are case-sensitive
  for LAllowed in FAllowedAlgs do
    if LAllowed = AAlg then
      Exit(True);
  Result := False;
end;

function TIAM4DJWTValidator.NormalizeIssuer(const S: string): string;
begin
  Result := S.TrimRight(['/']);
end;

function TIAM4DJWTValidator.ValidateClaims(const Claims: TJSONObject; const ExpectedIssuer, ExpectedAudience: string): Boolean;
var
  LIssuer: string;
  LAudienceValue: TJSONValue;
  LAudienceString: string;
  LAudienceArray: TJSONArray;
  LAzp: string;
  LJti: string;
  LIatTimestamp: Int64;
  LIatDateTime: TDateTime;
  LIsMultipleAud: Boolean;
  LExpiryTimestamp: Int64;
  LNotBeforeTimestamp: Int64;
  LExpiryDateTime: TDateTime;
  LNotBeforeDateTime: TDateTime;
  LCurrentTimeUTC: TDateTime;
  LFound: Boolean;
  LItem: TJSONValue;
begin
  if not Assigned(Claims) then
    raise EIAM4DSecurityValidationException.Create('Claims object is nil.');

  LCurrentTimeUTC := GetUtcNow;
  LIsMultipleAud := False;

  LIssuer := Claims.GetValue<string>('iss', '');
  if LIssuer.Trim.IsEmpty then
    raise EIAM4DSecurityValidationException.Create('Missing issuer claim (iss).');

  LIssuer := NormalizeIssuer(LIssuer);
  var LExpected := NormalizeIssuer(ExpectedIssuer);

  if not SecureCompareIssuer(LIssuer, LExpected) then
    raise EIAM4DJWTIssuerMismatchException.Create(LExpected, LIssuer);

  if FAudienceValidationEnabled then
  begin
    // An empty expected audience would match no token, or an aud "" element: a configuration error
    if ExpectedAudience.Trim.IsEmpty then
      raise EIAM4DSecurityValidationException.Create(
        'Audience validation is enabled but no expected audience is configured.');
    LAudienceValue := Claims.GetValue<TJSONValue>('aud', nil);
    if not Assigned(LAudienceValue) then
      raise EIAM4DSecurityValidationException.Create('Missing audience claim (aud).', ecJWTAudienceMismatch);

    if LAudienceValue is TJSONString then
    begin
      LAudienceString := (LAudienceValue as TJSONString).Value;
      if LAudienceString.Trim.IsEmpty then
        raise EIAM4DSecurityValidationException.Create('Audience claim (aud) is empty.', ecJWTAudienceMismatch);

      if not SecureCompareAudience(LAudienceString, ExpectedAudience) then
        raise EIAM4DSecurityValidationException.CreateFmt('Invalid audience. Expected "%s", got "%s".',
          [ExpectedAudience, LAudienceString], ecJWTAudienceMismatch);
    end
    else if LAudienceValue is TJSONArray then
    begin
      LAudienceArray := LAudienceValue as TJSONArray;
      // OIDC Core 3.1.3.7: an array of one value is a single audience
      LIsMultipleAud := LAudienceArray.Count > 1;
      LFound := False;

      for LItem in LAudienceArray do
      begin
        if (LItem <> nil) and (LItem is TJSONString) then
        begin
          if SecureCompareAudience((LItem as TJSONString).Value, ExpectedAudience) then
            LFound := True;
        end;
      end;
      if not LFound then
        raise EIAM4DSecurityValidationException.CreateFmt('Audience "%s" not found in audience array.',
          [ExpectedAudience], ecJWTAudienceMismatch);
    end
    else
      raise EIAM4DSecurityValidationException.CreateFmt('Invalid audience claim format: expected string or array, got %s.',
        [LAudienceValue.ClassName], ecJWTAudienceMismatch);
  end;

  LAzp := Claims.GetValue<string>('azp', '');

  if not FExpectedAzp.Trim.IsEmpty then
  begin
    if LAzp.Trim.IsEmpty then
      raise EIAM4DSecurityValidationException.Create('Missing authorized party (azp) claim.');

    if not SecureCompareAzp(LAzp, FExpectedAzp) then
      raise EIAM4DSecurityValidationException.CreateFmt(
        'Invalid authorized party. Expected "%s", got "%s".', [FExpectedAzp, LAzp]);
  end
  else if FAudienceValidationEnabled then
  begin
    if LIsMultipleAud and FRequireAzpWhenMultipleAud then
    begin
      if LAzp.Trim.IsEmpty then
        raise EIAM4DSecurityValidationException.Create(
          'Authorized party (azp) is required when audience contains multiple values (per OIDC spec).');
    end;
  end;

  if FJtiValidationEnabled then
  begin
    LJti := Claims.GetValue<string>('jti', '');
    if LJti.Trim.IsEmpty then
      raise EIAM4DSecurityValidationException.Create('Missing JWT ID (jti) claim - required when jti validation is enabled.');
  end;

  if FIatMaxAge > 0 then
  begin
    if not TryGetNumericDateClaim(Claims, 'iat', LIatTimestamp) then
      LIatTimestamp := 0;
    if LIatTimestamp = 0 then
      raise EIAM4DSecurityValidationException.Create('Missing issued-at (iat) claim - required when iat max age validation is enabled.');

    LIatDateTime := System.DateUtils.UnixToDateTime(LIatTimestamp);

    if LIatDateTime > LCurrentTimeUTC + (FClockSkewSeconds / IAM4D_SECOND_PER_DAY) then
      raise EIAM4DSecurityValidationException.CreateFmt(
        'Token iat claim is in the future (UTC: %s, Now+Skew (UTC): %s).',
        [FormatDateTime('yyyy-mm-dd hh:nn:ss', LIatDateTime),
          FormatDateTime('yyyy-mm-dd hh:nn:ss', LCurrentTimeUTC + (FClockSkewSeconds / IAM4D_SECOND_PER_DAY))]);

    if SecondsBetween(LCurrentTimeUTC, LIatDateTime) > FIatMaxAge then
      raise EIAM4DSecurityValidationException.CreateFmt(
        'Token is too old. Issued at (UTC): %s, Max age: %d seconds.',
        [FormatDateTime('yyyy-mm-dd hh:nn:ss', LIatDateTime), FIatMaxAge]);
  end;

  if not TryGetNumericDateClaim(Claims, 'exp', LExpiryTimestamp) then
    LExpiryTimestamp := 0;
  if LExpiryTimestamp = 0 then
    raise EIAM4DSecurityValidationException.Create('Missing or invalid expiration time claim (exp).');

  LExpiryDateTime := System.DateUtils.UnixToDateTime(LExpiryTimestamp);

  if LExpiryDateTime <= LCurrentTimeUTC - (FClockSkewSeconds / IAM4D_SECOND_PER_DAY) then
    raise EIAM4DSecurityValidationException.CreateFmt('Token expired. Expiration (UTC): %s, Now-Skew (UTC): %s.',
      [FormatDateTime('yyyy-mm-dd hh:nn:ss', LExpiryDateTime),
        FormatDateTime('yyyy-mm-dd hh:nn:ss', LCurrentTimeUTC - (FClockSkewSeconds / IAM4D_SECOND_PER_DAY))],
      ecJWTExpired);

  if not TryGetNumericDateClaim(Claims, 'nbf', LNotBeforeTimestamp, True) then
    LNotBeforeTimestamp := 0;
  if LNotBeforeTimestamp > 0 then
  begin
    LNotBeforeDateTime := System.DateUtils.UnixToDateTime(LNotBeforeTimestamp);

    // RFC 7519 4.1.5: the skew tolerates an issuer clock ahead of ours
    if LCurrentTimeUTC + (FClockSkewSeconds / IAM4D_SECOND_PER_DAY) < LNotBeforeDateTime then
      raise EIAM4DSecurityValidationException.CreateFmt('Token used before not-before time. NBF (UTC): %s, Now+Skew (UTC): %s.',
        [FormatDateTime('yyyy-mm-dd hh:nn:ss', LNotBeforeDateTime),
          FormatDateTime('yyyy-mm-dd hh:nn:ss', LCurrentTimeUTC + (FClockSkewSeconds / IAM4D_SECOND_PER_DAY))],
        ecJWTNotYetValid);
  end;

  // Check and add in one step: two parallel requests with the same token cannot both pass
  if FJtiValidationEnabled and not TryRegisterJti(LJti, LExpiryDateTime) then
    raise EIAM4DSecurityValidationException.CreateFmt('Token replay detected: jti "%s" has already been used.', [LJti]);

  Result := True;
end;

function TIAM4DJWTValidator.InternalVerifySignature(const ASigningInput: string; const ASignatureBytes: TBytes; const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;
begin
  Result := FSignatureVerifier.Verify(ASigningInput, ASignatureBytes, APublicKeyJWK, AAlg);
end;

function TIAM4DJWTValidator.ValidateToken(const AToken: string; out AClaims: TJSONObject): Boolean;
var
  LParts: TArray<string>;
  LHeaderB64, LPayloadB64, LSignatureB64: string;
  LHeaderBytes, LPayloadBytes, LSignatureBytes: TBytes;
  LHeaderJSON: TJSONObject;
  LPublicKeyJWK: TJSONObject;
  LKeyAlg, LTypClaim: TJSONValue;
  LKid, LAlg, LIssuer, LTyp, LExpectedIssuer: string;
  LMustFreePublicKey: Boolean;
  LKeySelector: IIAM4DJWKSKeySelector;
begin
  Result := False;
  AClaims := nil;
  LPublicKeyJWK := nil;
  LHeaderJSON := nil;
  LMustFreePublicKey := False;

  // A token validated before skips signature and claims checks (no cache with jti validation:
  // a token is accepted once)
  if TryGetCachedToken(AToken, AClaims) then
    Exit(True);

  try
    try
      // No trusted issuer to look keys up for: the token iss is never used for discovery
      LExpectedIssuer := NormalizeIssuer(FExpectedIssuer);
      if LExpectedIssuer.Trim.IsEmpty then
        raise EIAM4DSecurityValidationException.Create(
          'No expected issuer configured: JWT validation requires the issuer URL of the identity provider.');

      LParts := AToken.Split(['.']);
      if Length(LParts) <> 3 then
        raise EIAM4DSecurityValidationException.Create('Invalid JWT format: must have 3 parts separated by dots.');

      LHeaderB64 := LParts[0];
      LPayloadB64 := LParts[1];
      LSignatureB64 := LParts[2];

      // An empty signature (alg none) is refused by the alg checks, with their own message
      if not (IsBase64URLSegment(LHeaderB64) and IsBase64URLSegment(LPayloadB64) and
        (LSignatureB64.IsEmpty or IsBase64URLSegment(LSignatureB64))) then
        raise EIAM4DSecurityValidationException.Create(
          'Invalid JWT format: each part must be base64url without padding (RFC 7515 2).');

      try
        LHeaderBytes := TNetEncoding.Base64URL.DecodeStringToBytes(LHeaderB64);
      except
        on E: Exception do
          raise EIAM4DSecurityValidationException.CreateFmt('Invalid JWT header (base64url): %s', [E.Message]);
      end;

      try
        LPayloadBytes := TNetEncoding.Base64URL.DecodeStringToBytes(LPayloadB64);
      except
        on E: Exception do
          raise EIAM4DSecurityValidationException.CreateFmt('Invalid JWT payload (base64url): %s', [E.Message]);
      end;

      try
        LSignatureBytes := TNetEncoding.Base64URL.DecodeStringToBytes(LSignatureB64);
      except
        on E: Exception do
          raise EIAM4DSecurityValidationException.CreateFmt('Invalid JWT signature (base64url): %s', [E.Message]);
      end;

      LHeaderJSON := TIAM4DJSONUtils.SafeParseJSONObject(TEncoding.UTF8.GetString(LHeaderBytes), 'JWT header');
      AClaims := TIAM4DJSONUtils.SafeParseJSONObject(TEncoding.UTF8.GetString(LPayloadBytes), 'JWT payload');

      LKid := LHeaderJSON.GetValue<string>('kid', '');
      LAlg := LHeaderJSON.GetValue<string>('alg', '');
      LTyp := LHeaderJSON.GetValue<string>('typ', '');

      if LAlg.Trim.IsEmpty then
        raise EIAM4DSecurityValidationException.Create('JWT header missing algorithm (alg).');

      if SameText(LAlg, 'none') then
        raise EIAM4DSecurityValidationException.Create('JWT with alg=none is not allowed.');

      if not IsAlgAllowed(LAlg) then
        raise EIAM4DSecurityValidationException.CreateFmt('JWT algorithm "%s" not allowed by policy.', [LAlg]);

      if FStrictTyp and not IsHeaderTypeAllowed(LTyp) then
      begin
        if (Length(FAllowedHeaderTypes) = 1) and (FAllowedHeaderTypes[0] = 'jwt') then
          raise EIAM4DSecurityValidationException.Create('JWT header typ is missing or not "JWT".');
        raise EIAM4DSecurityValidationException.CreateFmt('JWT header typ "%s" is missing or not one of %s.',
          [LTyp, string.Join(', ', FAllowedHeaderTypes)]);
      end;

      // RFC 7515 4.1.11: no extension is supported, so a token that requires one is refused
      if Assigned(LHeaderJSON.Values['crit']) then
        raise EIAM4DSecurityValidationException.Create(
          'JWT header crit lists extensions that are not supported (RFC 7515 4.1.11).');

      if not FExpectedTokenType.IsEmpty then
      begin
        LTypClaim := AClaims.Values['typ'];
        if Assigned(LTypClaim) and not ((LTypClaim is TJSONString) and
          SameStr(TJSONString(LTypClaim).Value, FExpectedTokenType)) then
          raise EIAM4DSecurityValidationException.CreateFmt(
            'JWT typ claim %s is not the expected token type "%s".', [LTypClaim.ToJSON, FExpectedTokenType]);
      end;

      LIssuer := AClaims.GetValue<string>('iss', '');
      if LIssuer.Trim.IsEmpty then
        raise EIAM4DSecurityValidationException.Create('JWT payload missing issuer (iss) claim.');

      LIssuer := NormalizeIssuer(LIssuer);
      if not SecureCompareIssuer(LIssuer, LExpectedIssuer) then
        raise EIAM4DJWTIssuerMismatchException.Create(LExpectedIssuer, LIssuer);

      // Key lookup (and OIDC discovery) only for the configured issuer, never for the token iss.
      // A provider that can, picks among keys sharing the kid the one of the token algorithm
      if Supports(FJWKSProvider, IIAM4DJWKSKeySelector, LKeySelector) then
        LPublicKeyJWK := LKeySelector.GetPublicKeyForAlg(LExpectedIssuer, LKid, LAlg)
      else
        LPublicKeyJWK := FJWKSProvider.GetPublicKey(LExpectedIssuer, LKid);
      LMustFreePublicKey := True;

      if not Assigned(LPublicKeyJWK) then
        raise EIAM4DJWKSKeyNotFoundException.Create(LKid, LExpectedIssuer);

      // RFC 7517 4.4, RFC 8725 3.1: a key that declares alg verifies that algorithm only
      LKeyAlg := LPublicKeyJWK.Values['alg'];
      if Assigned(LKeyAlg) and not ((LKeyAlg is TJSONString) and (TJSONString(LKeyAlg).Value = LAlg)) then
        raise EIAM4DSecurityValidationException.CreateFmt(
          'JWT algorithm "%s" does not match the algorithm of the key (kid="%s", alg=%s).', [LAlg, LKid, LKeyAlg.ToJSON]);

      var ASigningInput := LHeaderB64 + '.' + LPayloadB64;
      if not InternalVerifySignature(ASigningInput, LSignatureBytes, LPublicKeyJWK, LAlg) then
        raise EIAM4DJWTSignatureInvalidException.Create(LKid, LAlg);

      if not ValidateClaims(AClaims, FExpectedIssuer, FExpectedAudience) then
        Exit;

      // Add validated token to cache for future requests
      AddTokenToCache(AToken, AClaims);

      Result := True;
    except
      on E: EIAM4DSecurityValidationException do
      begin
        if Assigned(AClaims) then
          AClaims.Free;
        AClaims := nil;
        raise;
      end;
      on E: Exception do
      begin
        if Assigned(AClaims) then
          AClaims.Free;
        AClaims := nil;
        raise EIAM4DSecurityValidationException.CreateFmt('General error during JWT validation: %s', [E.Message]);
      end;
    end;
  finally
    if Assigned(LHeaderJSON) then
      LHeaderJSON.Free;

    if LMustFreePublicKey and Assigned(LPublicKeyJWK) then
      LPublicKeyJWK.Free;
  end;
end;

procedure TIAM4DJWTValidator.SetAllowedAlgs(const AAlgs: TArray<string>);
begin
  FAllowedAlgs := Copy(AAlgs);
  ClearTokenCache;
end;

procedure TIAM4DJWTValidator.SetStrictTyp(const AValue: Boolean);
begin
  FStrictTyp := AValue;
  ClearTokenCache;
end;

function NormalizeHeaderType(const AValue: string): string;
begin
  Result := AValue.Trim.ToLower;
  if Result.StartsWith('application/') then
    Result := Result.Substring(Length('application/'));
end;

procedure TIAM4DJWTValidator.SetAllowedHeaderTypes(const ATypes: TArray<string>);
var
  LTypes: TArray<string>;
  LType: string;
begin
  if Length(ATypes) = 0 then
    raise EArgumentException.Create('Allowed header types cannot be empty (SetStrictTyp(False) skips the check)');
  LTypes := nil;
  for LType in ATypes do
  begin
    if NormalizeHeaderType(LType).IsEmpty then
      raise EArgumentException.Create('Allowed header type cannot be empty');
    LTypes := LTypes + [NormalizeHeaderType(LType)];
  end;
  FAllowedHeaderTypes := LTypes;
  ClearTokenCache;
end;

function TIAM4DJWTValidator.IsHeaderTypeAllowed(const ATyp: string): Boolean;
var
  LTyp, LAllowed: string;
begin
  LTyp := NormalizeHeaderType(ATyp);
  if LTyp.IsEmpty then
    Exit(False);
  for LAllowed in FAllowedHeaderTypes do
    if LAllowed = LTyp then
      Exit(True);
  Result := False;
end;

procedure TIAM4DJWTValidator.SetExpectedTokenType(const AValue: string);
begin
  FExpectedTokenType := AValue.Trim;
  ClearTokenCache;
end;

class function TIAM4DJWTValidator.IsBase64URLSegment(const ASegment: string): Boolean;
var
  C: Char;
  LValue: Integer;
begin
  if (ASegment = '') or (Length(ASegment) mod 4 = 1) then
    Exit(False);
  for C in ASegment do
    if not CharInSet(C, ['A'..'Z', 'a'..'z', '0'..'9', '-', '_']) then
      Exit(False);
  // 4n+2 characters: the last carries 2 bits of data and 4 unused; 4n+3: 4 bits and 2 unused
  C := ASegment[High(ASegment)];
  case C of
    'A'..'Z': LValue := Ord(C) - Ord('A');
    'a'..'z': LValue := Ord(C) - Ord('a') + 26;
    '0'..'9': LValue := Ord(C) - Ord('0') + 52;
    '-': LValue := 62;
  else
    LValue := 63;
  end;
  case Length(ASegment) mod 4 of
    2: Result := (LValue and $0F) = 0;
    3: Result := (LValue and $03) = 0;
  else
    Result := True;
  end;
end;

function TIAM4DJWTValidator.GetExpectedAzp: string;
begin
  Result := FExpectedAzp;
end;

procedure TIAM4DJWTValidator.SetExpectedAzp(const AValue: string);
begin
  FExpectedAzp := AValue;
  ClearTokenCache;
end;

procedure TIAM4DJWTValidator.SetAudienceValidationEnabled(const AValue: Boolean);
begin
  FAudienceValidationEnabled := AValue;
  ClearTokenCache;
end;

procedure TIAM4DJWTValidator.SetRequireAzpWhenMultipleAud(const AValue: Boolean);
begin
  FRequireAzpWhenMultipleAud := AValue;
  ClearTokenCache;
end;

procedure TIAM4DJWTValidator.SetJtiValidation(const AEnabled: Boolean; const ATTLSeconds: Integer);
begin
  if ATTLSeconds < 0 then
    raise EIAM4DSecurityValidationException.Create('JTI cache TTL must be >= 0');
  if ATTLSeconds > 86400 then // 24 hours max
    raise EIAM4DSecurityValidationException.Create('JTI cache TTL must be <= 86400 (24 hours)');

  FJtiValidationEnabled := AEnabled;
  FJtiCacheTTL := ATTLSeconds;

  // With jti validation the token cache is not used
  ClearTokenCache;
  if not AEnabled then
    ClearJtiCache;
end;

procedure TIAM4DJWTValidator.SetIatMaxAge(const AMaxAgeSeconds: Integer);
begin
  if AMaxAgeSeconds < 0 then
    raise EIAM4DSecurityValidationException.Create('IAT max age must be >= 0');
  FIatMaxAge := AMaxAgeSeconds;
  ClearTokenCache;
end;

procedure TIAM4DJWTValidator.ClearJtiCache;
begin
  if Assigned(FJtiCache) and Assigned(FJtiCacheLock) then
  begin
    TMonitor.Enter(FJtiCacheLock);
    try
      FJtiCache.Clear;
    finally
      TMonitor.Exit(FJtiCacheLock);
    end;
  end;
end;

procedure TIAM4DJWTValidator.CleanupExpiredJtiEntries;
var
  LKey: string;
  LExpiredKeys: TList<string>;
  LExpiryTime: TDateTime;
  LNow: TDateTime;
begin
  if not Assigned(FJtiCache) then
    Exit;

  LNow := GetUtcNow;
  LExpiredKeys := TList<string>.Create;
  try
    for LKey in FJtiCache.Keys do
    begin
      LExpiryTime := FJtiCache[LKey];
      if LExpiryTime < LNow then
        LExpiredKeys.Add(LKey);
    end;

    for LKey in LExpiredKeys do
      FJtiCache.Remove(LKey);
  finally
    LExpiredKeys.Free;
  end;
end;

function TIAM4DJWTValidator.TryRegisterJti(const AJti: string; AExpiryUTC: TDateTime): Boolean;
var
  LNowUTC, LExpiryTime: TDateTime;
begin
  TMonitor.Enter(FJtiCacheLock);
  try
    LNowUTC := GetUtcNow;

    if SecondsBetween(LNowUTC, FLastJtiCleanup) >= JTI_CLEANUP_INTERVAL_SECONDS then
    begin
      CleanupExpiredJtiEntries;
      FLastJtiCleanup := LNowUTC;
    end;

    if FJtiCache.ContainsKey(AJti) then
      Exit(False);

    if FJtiCache.Count >= MAX_JTI_CACHE_ENTRIES then
    begin
      CleanupExpiredJtiEntries;

      if FJtiCache.Count >= MAX_JTI_CACHE_ENTRIES then
        raise EIAM4DSecurityValidationException.CreateFmt(
          'JTI replay cache exceeded maximum capacity (%d entries). Possible DoS attack or cache TTL too long.',
          [MAX_JTI_CACHE_ENTRIES]);
    end;

    // Remembered while the token is still accepted (exp plus skew), and for at least the TTL
    LExpiryTime := IncSecond(AExpiryUTC, FClockSkewSeconds);
    if LExpiryTime < IncSecond(LNowUTC, FJtiCacheTTL) then
      LExpiryTime := IncSecond(LNowUTC, FJtiCacheTTL);
    FJtiCache.Add(AJti, LExpiryTime);
    Result := True;
  finally
    TMonitor.Exit(FJtiCacheLock);
  end;
end;

{ Token validation cache methods }

destructor TIAM4DJWTValidator.TTokenCacheEntry.Destroy;
begin
  Claims.Free;
  inherited;
end;

class function TIAM4DJWTValidator.TokenCacheKey(const AToken: string): string;
begin
  Result := THashSHA2.GetHashString(AToken, THashSHA2.TSHA2Version.SHA256);
end;

function TIAM4DJWTValidator.TryGetCachedToken(const AToken: string; out AClaims: TJSONObject): Boolean;
var
  LEntry: TTokenCacheEntry;
  LNowUTC: TDateTime;
  LKey: string;
begin
  Result := False;
  AClaims := nil;

  if not FTokenCacheEnabled or FJtiValidationEnabled then
    Exit;

  if not Assigned(FTokenCache) then
    Exit;

  LNowUTC := GetUtcNow;

  // Hits need only the shared lock: entries are replaced or freed under the exclusive one
  LKey := TokenCacheKey(AToken);
  FTokenCacheLock.BeginRead;
  try
    if FTokenCache.TryGetValue(LKey, LEntry) and (LNowUTC < LEntry.ValidUntil) then
    begin
      AClaims := LEntry.Claims.Clone as TJSONObject;
      TInterlocked.Exchange(LEntry.LastUsedTicks, TThread.GetTickCount64);
      Result := True;
    end;
  finally
    FTokenCacheLock.EndRead;
  end;
end;

procedure TIAM4DJWTValidator.AddTokenToCache(const AToken: string; const AClaims: TJSONObject);
var
  LKey: string;
  LEntry: TTokenCacheEntry;
  LExpTimestamp, LIatTimestamp: Int64;
  LNowUTC, LValidUntil, LAgeLimit: TDateTime;
begin
  if not FTokenCacheEnabled or FJtiValidationEnabled then
    Exit;

  if not Assigned(FTokenCache) then
    Exit;

  if not Assigned(AClaims) then
    Exit;

  // Claims already validated: the helper does not raise here
  if not TryGetNumericDateClaim(AClaims, 'exp', LExpTimestamp) or (LExpTimestamp = 0) then
    Exit; // Token without exp cannot be cached

  LNowUTC := GetUtcNow;

  // A hit skips every check: the window ends before the token would fail one of them
  LValidUntil := UnixToDateTime(LExpTimestamp) - (FTokenCachePreExpiryBuffer / SecsPerDay);
  if FIatMaxAge > 0 then
  begin
    if not TryGetNumericDateClaim(AClaims, 'iat', LIatTimestamp) then
      Exit;
    LAgeLimit := UnixToDateTime(LIatTimestamp + FIatMaxAge);
    if LAgeLimit < LValidUntil then
      LValidUntil := LAgeLimit;
  end;
  LAgeLimit := IncSecond(LNowUTC, MAX_TOKEN_CACHE_ENTRY_AGE_SECONDS);
  if LAgeLimit < LValidUntil then
    LValidUntil := LAgeLimit;
  if LValidUntil <= LNowUTC then
    Exit;

  LKey := TokenCacheKey(AToken);
  LEntry := TTokenCacheEntry.Create;
  try
    LEntry.Claims := AClaims.Clone as TJSONObject;
    LEntry.ValidUntil := LValidUntil;
    LEntry.LastUsedTicks := TThread.GetTickCount64;

    FTokenCacheLock.BeginWrite;
    try
      // Periodic cleanup (throttled)
      if SecondsBetween(LNowUTC, FLastTokenCacheCleanup) >= FTokenCacheCleanupInterval then
      begin
        CleanupExpiredTokens;
        FLastTokenCacheCleanup := LNowUTC;
      end;

      // Full: expired entries first, then an eighth of the least recently used in one scan
      // (one full scan per Max/8 new tokens, not one per token)
      if (not FTokenCache.ContainsKey(LKey)) and (FTokenCache.Count >= FMaxTokenCacheEntries) then
      begin
        CleanupExpiredTokens;
        FLastTokenCacheCleanup := LNowUTC;
        if FTokenCache.Count >= FMaxTokenCacheEntries then
          EvictOldestTokens(FTokenCache.Count - FMaxTokenCacheEntries + 1 + FMaxTokenCacheEntries div 8);
      end;

      // Owned by the cache from here on (a replaced entry is freed)
      FTokenCache.AddOrSetValue(LKey, LEntry);
      LEntry := nil;
    finally
      FTokenCacheLock.EndWrite;
    end;
  finally
    LEntry.Free;
  end;
end;

procedure TIAM4DJWTValidator.CleanupExpiredTokens;
var
  LExpiredKeys: TList<string>;
  LPair: TPair<string, TTokenCacheEntry>;
  LKey: string;
  LNowUTC: TDateTime;
begin
  // Called ONLY inside write lock
  if not Assigned(FTokenCache) then
    Exit;

  LNowUTC := GetUtcNow;
  LExpiredKeys := TList<string>.Create;
  try
    for LPair in FTokenCache do
      if LNowUTC >= LPair.Value.ValidUntil then
        LExpiredKeys.Add(LPair.Key);

    for LKey in LExpiredKeys do
      FTokenCache.Remove(LKey);
  finally
    LExpiredKeys.Free;
  end;
end;

procedure TIAM4DJWTValidator.EvictOldestTokens(ACount: Integer);
var
  LPairs: TArray<TPair<string, TTokenCacheEntry>>;
  I: Integer;
begin
  // Called ONLY inside write lock: no reader updates LastUsedTicks meanwhile
  if not Assigned(FTokenCache) or (FTokenCache.Count = 0) or (ACount <= 0) then
    Exit;

  LPairs := FTokenCache.ToArray;
  TArray.Sort<TPair<string, TTokenCacheEntry>>(LPairs, TComparer<TPair<string, TTokenCacheEntry>>.Construct(
    function(const A, B: TPair<string, TTokenCacheEntry>): Integer
    begin
      if A.Value.LastUsedTicks < B.Value.LastUsedTicks then
        Result := -1
      else if A.Value.LastUsedTicks > B.Value.LastUsedTicks then
        Result := 1
      else
        Result := 0;
    end));
  for I := 0 to Min(ACount, Length(LPairs)) - 1 do
    FTokenCache.Remove(LPairs[I].Key);
end;

procedure TIAM4DJWTValidator.SetTokenCacheEnabled(const AValue: Boolean);
begin
  FTokenCacheEnabled := AValue;
  if not AValue then
    ClearTokenCache;
end;

procedure TIAM4DJWTValidator.SetMaxTokenCacheEntries(const AValue: Integer);
begin
  if AValue < 1 then
    raise EIAM4DSecurityValidationException.Create('Max token cache entries must be >= 1');
  FMaxTokenCacheEntries := AValue;
end;

procedure TIAM4DJWTValidator.SetTokenCacheCleanupInterval(const AValue: Integer);
begin
  if AValue < 1 then
    raise EIAM4DSecurityValidationException.Create('Token cache cleanup interval must be >= 1');
  FTokenCacheCleanupInterval := AValue;
end;

procedure TIAM4DJWTValidator.SetTokenCachePreExpiryBuffer(const AValue: Integer);
begin
  if AValue < 0 then
    raise EIAM4DSecurityValidationException.Create('Token cache pre-expiry buffer must be >= 0');
  FTokenCachePreExpiryBuffer := AValue;
  ClearTokenCache;
end;

procedure TIAM4DJWTValidator.ClearTokenCache;
begin
  if Assigned(FTokenCache) then
  begin
    FTokenCacheLock.BeginWrite;
    try
      FTokenCache.Clear;
    finally
      FTokenCacheLock.EndWrite;
    end;
  end;
end;

function TIAM4DJWTValidator.SecureCompareIssuer(const AIssuer, AExpected: string): Boolean;
begin
  Result := SecureStringEquals(AIssuer, AExpected);
end;

function TIAM4DJWTValidator.SecureCompareAudience(const AAudience, AExpected: string): Boolean;
begin
  Result := SecureStringEquals(AAudience, AExpected);
end;

function TIAM4DJWTValidator.SecureCompareAzp(const AAzp, AExpected: string): Boolean;
begin
  // Use constant-time comparison to prevent timing attacks
  Result := SecureStringEquals(AAzp, AExpected);
end;

end.
