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
  /// Validates signature and claims (exp/nbf/iss/aud). Uses TIAM4DJWKSProvider for
  /// thread-safe JWKS handling with auto-discovery, caching, and key rotation support.
  /// Security hardening: Algorithm allow-list, optional typ='JWT' check, configurable clock skew.
  /// Thread-safety: All operations are thread-safe via internal JWKS provider.
  /// </remarks>
  TIAM4DJWTValidator = class(TInterfacedObject, IIAM4DJWTValidator)
  private
  const
    /// <summary>Maximum allowed clock skew in seconds (5 minutes)</summary>
    MAX_CLOCK_SKEW_SECONDS = 300;
    /// <summary>Maximum JTI cache entries to prevent Memory DoS attacks</summary>
    MAX_JTI_CACHE_ENTRIES = 100000;
    /// <summary>JTI cache cleanup interval in seconds (throttled to avoid O(n) on every call)</summary>
    JTI_CLEANUP_INTERVAL_SECONDS = 60;
  private
    FExpectedIssuer: string;
    FExpectedAudience: string;
    FExpectedAzp: string;
    FRequireAzpWhenMultipleAud: Boolean;
    FClockSkewSeconds: Integer;

    FSignatureVerifier: IIAM4DJWTSignatureVerifier;
    FJWKSProvider: IIAM4DJWKSProvider;
    FSSLValidator: TIAM4DSSLCertificateValidator;
    FHTTPConfig: TIAM4DHTTPClientConfig;

    FAllowedAlgs: TArray<string>; // allow-list (es. ['RS256','PS256'])
    FStrictTyp: Boolean; // se True richiede typ='JWT' nell'header

    // Replay prevention (jti cache)
    FJtiValidationEnabled: Boolean;
    FJtiCache: TDictionary<string, TDateTime>;
    FJtiCacheTTL: Integer; // seconds
    FJtiCacheLock: TObject;
    FLastJtiCleanup: TDateTime; // UTC timestamp of last cleanup

    // Token age validation (iat)
    FIatMaxAge: Integer; // seconds, 0 = disabled

    function ValidateClaims(const Claims: TJSONObject; const ExpectedIssuer, ExpectedAudience: string): Boolean;
    function GetUtcNow: TDateTime;
    function InternalVerifySignature(const ASigningInput: string; const ASignatureBytes: TBytes; const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;

    function IsAlgAllowed(const AAlg: string): Boolean;
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
    function IsJtiAlreadyUsed(const AJti: string): Boolean;
    procedure AddJtiToCache(const AJti: string);

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
    /// Destroys validator and clears JWKS cache.
    /// </summary>
    destructor Destroy; override;

    /// <summary>Sets the algorithm allow-list (e.g., ['RS256','PS256']). Empty list rejects all tokens.</summary>
    procedure SetAllowedAlgs(const AAlgs: TArray<string>);

    /// <summary>Enables/disables strict typ='JWT' header validation.</summary>
    procedure SetStrictTyp(const AValue: Boolean);

    /// <summary>Sets expected Client ID in azp claim (empty string = not validated).</summary>
    procedure SetExpectedAzp(const AValue: string);

    /// <summary>Requires azp claim when aud contains multiple audiences (default: True, per OIDC specification).</summary>
    procedure SetRequireAzpWhenMultipleAud(const AValue: Boolean);

    /// <summary>
    /// Enables JWT ID (jti) validation with cache for replay attack prevention.
    /// </summary>
    /// <param name="AEnabled">True to enable jti validation</param>
    /// <param name="ATTLSeconds">Cache TTL in seconds (how long to remember used jtis)</param>
    /// <remarks>
    /// When enabled, tokens with previously seen jti claims will be rejected.
    /// The cache is automatically cleaned up to remove expired entries.
    /// Thread-safe: Uses internal locking for cache access.
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
  end;

implementation

uses
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Security.JWT.Verifiers.Universal,
  IAMClient4D.Security.JWT.JWKS,
  IAMClient4D.Exceptions;

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

  FSSLValidator := TIAM4DSSLCertificateValidator.Create;
  FSSLValidator.SetValidationMode(FHTTPConfig.SSLValidationMode);

  FExpectedIssuer := AExpectedIssuer;
  FExpectedAudience := AExpectedAudience;
  FExpectedAzp := '';
  FRequireAzpWhenMultipleAud := True;
  FClockSkewSeconds := 5;

  FAllowedAlgs := FSignatureVerifier.GetSupportedAlgorithms;
  FStrictTyp := True;

  FJtiValidationEnabled := False;
  FJtiCache := TDictionary<string, TDateTime>.Create;
  FJtiCacheTTL := 3600;
  FJtiCacheLock := TObject.Create;
  FLastJtiCleanup := 0;

  // Initialize iat max age (disabled by default)
  FIatMaxAge := 0;
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
  FreeAndNil(FSSLValidator);
  FreeAndNil(FJtiCache);
  FreeAndNil(FJtiCacheLock);

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

function TIAM4DJWTValidator.GetExpectedIssuer: string;
begin
  Result := FExpectedIssuer;
end;

function TIAM4DJWTValidator.GetUtcNow: TDateTime;
begin
  Result := TTimeZone.Local.ToUniversalTime(Now());
end;

procedure TIAM4DJWTValidator.SetClockSkewSeconds(const AValue: Integer);
begin
  if AValue < 0 then
    raise EIAM4DSecurityValidationException.Create('Clock skew seconds must be >= 0');
  if AValue > MAX_CLOCK_SKEW_SECONDS then
    raise EIAM4DSecurityValidationException.CreateFmt(
      'Clock skew seconds must be <= %d (5 minutes). Higher values weaken security.', [MAX_CLOCK_SKEW_SECONDS]);
  FClockSkewSeconds := AValue;
end;

function TIAM4DJWTValidator.IsAlgAllowed(const AAlg: string): Boolean;

  function SameTextArrayContains(const Arr: TArray<string>; const Value: string): Boolean;
  var
    LS: string;
  begin
    Result := False;
    for LS in Arr do
      if SameText(LS, Value) then
        Exit(True);
  end;

begin
  Result := SameTextArrayContains(FAllowedAlgs, AAlg);
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
    raise EIAM4DSecurityValidationException.CreateFmt('Invalid issuer. Expected "%s", got "%s".', [LExpected, LIssuer]);

  LAudienceValue := Claims.GetValue<TJSONValue>('aud', nil);
  if not Assigned(LAudienceValue) then
    raise EIAM4DSecurityValidationException.Create('Missing audience claim (aud).');

  if LAudienceValue is TJSONString then
  begin
    LAudienceString := (LAudienceValue as TJSONString).Value;
    if LAudienceString.Trim.IsEmpty then
      raise EIAM4DSecurityValidationException.Create('Audience claim (aud) is empty.');

    if not SecureCompareAudience(LAudienceString, ExpectedAudience) then
      raise EIAM4DSecurityValidationException.CreateFmt('Invalid audience. Expected "%s", got "%s".', [ExpectedAudience, LAudienceString]);
  end
  else if LAudienceValue is TJSONArray then
  begin
    LIsMultipleAud := True;
    LAudienceArray := LAudienceValue as TJSONArray;
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
      raise EIAM4DSecurityValidationException.CreateFmt('Audience "%s" not found in audience array.', [ExpectedAudience]);
  end
  else
    raise EIAM4DSecurityValidationException.CreateFmt('Invalid audience claim format: expected string or array, got %s.', [LAudienceValue.ClassName]);

  LAzp := Claims.GetValue<string>('azp', '');

  if not FExpectedAzp.Trim.IsEmpty then
  begin
    if LAzp.Trim.IsEmpty then
      raise EIAM4DSecurityValidationException.Create('Missing authorized party (azp) claim.');

    if not SecureCompareAzp(LAzp, FExpectedAzp) then
      raise EIAM4DSecurityValidationException.CreateFmt(
        'Invalid authorized party. Expected "%s", got "%s".', [FExpectedAzp, LAzp]);
  end
  else
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

    if IsJtiAlreadyUsed(LJti) then
      raise EIAM4DSecurityValidationException.CreateFmt('Token replay detected: jti "%s" has already been used.', [LJti]);
  end;

  if FIatMaxAge > 0 then
  begin
    LIatTimestamp := Claims.GetValue<Int64>('iat', 0);
    if LIatTimestamp = 0 then
      raise EIAM4DSecurityValidationException.Create('Missing issued-at (iat) claim - required when iat max age validation is enabled.');

    LIatDateTime := System.DateUtils.UnixToDateTime(LIatTimestamp);

    if LIatDateTime > LCurrentTimeUTC then
      raise EIAM4DSecurityValidationException.CreateFmt(
        'Token iat claim is in the future (UTC: %s). Possible clock skew or replay attack.',
        [FormatDateTime('yyyy-mm-dd hh:nn:ss', LIatDateTime)]);

    if SecondsBetween(LCurrentTimeUTC, LIatDateTime) > FIatMaxAge then
      raise EIAM4DSecurityValidationException.CreateFmt(
        'Token is too old. Issued at (UTC): %s, Max age: %d seconds.',
        [FormatDateTime('yyyy-mm-dd hh:nn:ss', LIatDateTime), FIatMaxAge]);
  end;

  LExpiryTimestamp := Claims.GetValue<Int64>('exp', 0);
  if LExpiryTimestamp = 0 then
    raise EIAM4DSecurityValidationException.Create('Missing or invalid expiration time claim (exp).');

  LExpiryDateTime := System.DateUtils.UnixToDateTime(LExpiryTimestamp);

  if LExpiryDateTime <= LCurrentTimeUTC - (FClockSkewSeconds / IAM4D_SECOND_PER_DAY) then
    raise EIAM4DSecurityValidationException.CreateFmt('Token expired. Expiration (UTC): %s, Now-Skew (UTC): %s.',
      [FormatDateTime('yyyy-mm-dd hh:nn:ss', LExpiryDateTime),
        FormatDateTime('yyyy-mm-dd hh:nn:ss', LCurrentTimeUTC - (FClockSkewSeconds / IAM4D_SECOND_PER_DAY))]);

  LNotBeforeTimestamp := Claims.GetValue<Int64>('nbf', 0);
  if LNotBeforeTimestamp > 0 then
  begin
    LNotBeforeDateTime := System.DateUtils.UnixToDateTime(LNotBeforeTimestamp);

    if LCurrentTimeUTC - (FClockSkewSeconds / IAM4D_SECOND_PER_DAY) < LNotBeforeDateTime then
      raise EIAM4DSecurityValidationException.CreateFmt('Token used before not-before time. NBF (UTC): %s, Now-Skew (UTC): %s.',
        [FormatDateTime('yyyy-mm-dd hh:nn:ss', LNotBeforeDateTime),
          FormatDateTime('yyyy-mm-dd hh:nn:ss', LCurrentTimeUTC - (FClockSkewSeconds / IAM4D_SECOND_PER_DAY))]);
  end;

  if FJtiValidationEnabled then
  begin
    LJti := Claims.GetValue<string>('jti', '');
    if not LJti.IsEmpty then
      AddJtiToCache(LJti);
  end;

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
  LKid, LAlg, LIssuer, LTyp: string;
  LMustFreePublicKey: Boolean;
begin
  Result := False;
  AClaims := nil;
  LPublicKeyJWK := nil;
  LHeaderJSON := nil;
  LMustFreePublicKey := False;

  try
    try
      LParts := AToken.Split(['.']);
      if Length(LParts) <> 3 then
        raise EIAM4DSecurityValidationException.Create('Invalid JWT format: must have 3 parts separated by dots.');

      LHeaderB64 := LParts[0];
      LPayloadB64 := LParts[1];
      LSignatureB64 := LParts[2];

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

      if FStrictTyp and (not SameText(LTyp, 'JWT')) then
        raise EIAM4DSecurityValidationException.Create('JWT header typ is missing or not "JWT".');

      LIssuer := AClaims.GetValue<string>('iss', '');
      if LIssuer.Trim.IsEmpty then
        raise EIAM4DSecurityValidationException.Create('JWT payload missing issuer (iss) claim - required for JWKS auto-discovery.');

      LIssuer := NormalizeIssuer(LIssuer);

      LPublicKeyJWK := FJWKSProvider.GetPublicKey(LIssuer, LKid);
      LMustFreePublicKey := True;

      if not Assigned(LPublicKeyJWK) then
        raise EIAM4DSecurityValidationException.CreateFmt(
          'Public key not found via JWKS provider for issuer "%s" and kid "%s"', [LIssuer, LKid]);

      var ASigningInput := LHeaderB64 + '.' + LPayloadB64;
      if not InternalVerifySignature(ASigningInput, LSignatureBytes, LPublicKeyJWK, LAlg) then
        raise EIAM4DSecurityValidationException.CreateFmt('JWT signature verification failed (kid="%s", alg="%s").', [LKid, LAlg]);

      if not ValidateClaims(AClaims, FExpectedIssuer, FExpectedAudience) then
        Exit;

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
end;

procedure TIAM4DJWTValidator.SetStrictTyp(const AValue: Boolean);
begin
  FStrictTyp := AValue;
end;

function TIAM4DJWTValidator.GetExpectedAzp: string;
begin
  Result := FExpectedAzp;
end;

procedure TIAM4DJWTValidator.SetExpectedAzp(const AValue: string);
begin
  FExpectedAzp := AValue;
end;

procedure TIAM4DJWTValidator.SetRequireAzpWhenMultipleAud(const AValue: Boolean);
begin
  FRequireAzpWhenMultipleAud := AValue;
end;

procedure TIAM4DJWTValidator.SetJtiValidation(const AEnabled: Boolean; const ATTLSeconds: Integer);
begin
  if ATTLSeconds < 0 then
    raise EIAM4DSecurityValidationException.Create('JTI cache TTL must be >= 0');
  if ATTLSeconds > 86400 then // 24 hours max
    raise EIAM4DSecurityValidationException.Create('JTI cache TTL must be <= 86400 (24 hours)');

  FJtiValidationEnabled := AEnabled;
  FJtiCacheTTL := ATTLSeconds;

  if not AEnabled then
    ClearJtiCache;
end;

procedure TIAM4DJWTValidator.SetIatMaxAge(const AMaxAgeSeconds: Integer);
begin
  if AMaxAgeSeconds < 0 then
    raise EIAM4DSecurityValidationException.Create('IAT max age must be >= 0');
  FIatMaxAge := AMaxAgeSeconds;
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

function TIAM4DJWTValidator.IsJtiAlreadyUsed(const AJti: string): Boolean;
var
  LNowUTC: TDateTime;
begin
  Result := False;
  if not FJtiValidationEnabled or AJti.IsEmpty then
    Exit;

  TMonitor.Enter(FJtiCacheLock);
  try
    LNowUTC := GetUtcNow;

    if SecondsBetween(LNowUTC, FLastJtiCleanup) >= JTI_CLEANUP_INTERVAL_SECONDS then
    begin
      CleanupExpiredJtiEntries;
      FLastJtiCleanup := LNowUTC;
    end;

    Result := FJtiCache.ContainsKey(AJti);
  finally
    TMonitor.Exit(FJtiCacheLock);
  end;
end;

procedure TIAM4DJWTValidator.AddJtiToCache(const AJti: string);
var
  LExpiryTime: TDateTime;
begin
  if not FJtiValidationEnabled or AJti.IsEmpty then
    Exit;

  TMonitor.Enter(FJtiCacheLock);
  try
    if FJtiCache.Count >= MAX_JTI_CACHE_ENTRIES then
    begin
      CleanupExpiredJtiEntries;

      if FJtiCache.Count >= MAX_JTI_CACHE_ENTRIES then
        raise EIAM4DSecurityValidationException.CreateFmt(
          'JTI replay cache exceeded maximum capacity (%d entries). Possible DoS attack or cache TTL too long.',
          [MAX_JTI_CACHE_ENTRIES]);
    end;

    LExpiryTime := IncSecond(GetUtcNow, FJtiCacheTTL);
    FJtiCache.AddOrSetValue(AJti, LExpiryTime);
  finally
    TMonitor.Exit(FJtiCacheLock);
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