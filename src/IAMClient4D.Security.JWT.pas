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
  /// Validates signature and claims (exp/nbf/iss/aud). Supports JWKS via URL/file or provider.
  /// Security hardening: Algorithm allow-list, optional typ='JWT' check, configurable clock skew.
  /// Thread-safety: ValidateToken and JWKS fetching are thread-safe. Configuration changes
  /// during validation are not thread-safe.
  /// </remarks>
  TIAM4DJWTValidator = class(TInterfacedObject, IIAM4DJWTValidator)
  private
    FJWKS_URL: string;
    FJWKS_FilePath: string;
    FJWKSSource: TJWKSSourceType;

    FExpectedIssuer: string;
    FExpectedAudience: string;
    FExpectedAzp: string;
    FRequireAzpWhenMultipleAud: Boolean;

    FJWKS: TJSONObject;
    FLastJWKSFetchTime: TDateTime;
    FJWKSCacheDuration: TTimeSpan;
    FClockSkewSeconds: Integer;

    FSignatureVerifier: IIAM4DJWTSignatureVerifier;
    FJWKSProvider: IIAM4DJWKSProvider;
    FSSLValidator: TIAM4DSSLCertificateValidator;
    FHTTPConfig: TIAM4DHTTPClientConfig;

    FAllowedAlgs: TArray<string>; // allow-list (es. ['RS256','PS256'])
    FStrictTyp: Boolean; // se True richiede typ='JWT' nell'header

    procedure ClearJWKSCache;
    procedure FetchJWKSFromURL;
    procedure LoadJWKSFromFile;

    function FindPublicKey(const Kid, Alg: string): TJSONObject;
    function ValidateClaims(const Claims: TJSONObject; const ExpectedIssuer, ExpectedAudience: string): Boolean;
    function GetUtcNow: TDateTime;
    function InternalVerifySignature(const ASigningInput: string; const ASignatureBytes: TBytes; const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;

    function IsAlgAllowed(const AAlg: string): Boolean;
    function NormalizeIssuer(const S: string): string;
  protected
    /// <summary>
    /// Validates JWT token signature and claims, returns parsed claims if valid.
    /// </summary>
    function ValidateToken(const AToken: string; out AClaims: TJSONObject): Boolean;

    /// <summary>
    /// Configures JWKS retrieval from URL with cache duration in minutes.
    /// </summary>
    procedure ConfigureJWKSFromURL(const AJWKS_URL: string; const ACacheDurationMinutes: Integer = 5);

    /// <summary>
    /// Configures JWKS from local file path.
    /// </summary>
    procedure ConfigureJWKSFromFile(const AJWKS_FilePath: string);

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
  end;

implementation

uses
  IAMClient4D.Common.Constants,
  IAMClient4D.Security.JWT.Verifiers.Universal,
  IAMClient4D.Exceptions;

{ TIAM4DJWTValidator }

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  inherited Create;

  FSignatureVerifier := TUniversalJWTSignatureVerifier.Create;
  FJWKSProvider := nil;
  FHTTPConfig := AHTTPConfig;

  FSSLValidator := TIAM4DSSLCertificateValidator.Create;
  FSSLValidator.SetValidationMode(FHTTPConfig.SSLValidationMode);

  FExpectedIssuer := AExpectedIssuer;
  FExpectedAudience := AExpectedAudience;
  FExpectedAzp := '';
  FRequireAzpWhenMultipleAud := True;
  FClockSkewSeconds := 5;
  FJWKSCacheDuration := TTimeSpan.FromMinutes(5);

  FAllowedAlgs := FSignatureVerifier.GetSupportedAlgorithms;
  FStrictTyp := True;

  ClearJWKSCache;
  FJWKSSource := jsstNone;
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AVerifier: IIAM4DJWTSignatureVerifier;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  inherited Create;

  if not Assigned(AVerifier) then
    raise EIAM4DSecurityValidationException.Create('Custom verifier cannot be nil.');

  FSignatureVerifier := AVerifier;
  FJWKSProvider := nil;
  FHTTPConfig := AHTTPConfig;

  FSSLValidator := TIAM4DSSLCertificateValidator.Create;
  FSSLValidator.SetValidationMode(FHTTPConfig.SSLValidationMode);

  FExpectedIssuer := AExpectedIssuer;
  FExpectedAudience := AExpectedAudience;
  FExpectedAzp := '';
  FRequireAzpWhenMultipleAud := True;
  FClockSkewSeconds := 5;
  FJWKSCacheDuration := TTimeSpan.FromMinutes(5);

  FAllowedAlgs := FSignatureVerifier.GetSupportedAlgorithms;
  FStrictTyp := True;

  ClearJWKSCache;
  FJWKSSource := jsstNone;
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const ASSLValidationMode: TIAM4DSSLValidationMode);
var
  LConfig: TIAM4DHTTPClientConfig;
begin
  LConfig := TIAM4DHTTPClientConfig.Create(30000, 60000, ASSLValidationMode);
  Create(AExpectedIssuer, AExpectedAudience, LConfig);
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AVerifier: IIAM4DJWTSignatureVerifier;
  const ASSLValidationMode: TIAM4DSSLValidationMode);
var
  LConfig: TIAM4DHTTPClientConfig;
begin
  LConfig := TIAM4DHTTPClientConfig.Create(30000, 60000, ASSLValidationMode);
  Create(AExpectedIssuer, AExpectedAudience, AVerifier, LConfig);
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  Create(AExpectedIssuer, AExpectedAudience, AHTTPConfig);
  FJWKSProvider := AJWKSProvider;
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AVerifier: IIAM4DJWTSignatureVerifier;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  Create(AExpectedIssuer, AExpectedAudience, AVerifier, AHTTPConfig);
  FJWKSProvider := AJWKSProvider;
end;

constructor TIAM4DJWTValidator.Create(const AExpectedIssuer, AExpectedAudience: string;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const ASSLValidationMode: TIAM4DSSLValidationMode);
var
  LConfig: TIAM4DHTTPClientConfig;
begin
  LConfig := TIAM4DHTTPClientConfig.Create(30000, 60000, ASSLValidationMode);
  Create(AExpectedIssuer, AExpectedAudience, AJWKSProvider, LConfig);
end;

destructor TIAM4DJWTValidator.Destroy;
begin
  ClearJWKSCache;
  FreeAndNil(FSSLValidator);

  FSignatureVerifier := nil;

  inherited;
end;

procedure TIAM4DJWTValidator.ClearJWKSCache;
begin
  if Assigned(FJWKS) then
    FJWKS.Free;
  FJWKS := nil;
  FLastJWKSFetchTime := 0;
end;

procedure TIAM4DJWTValidator.ConfigureJWKSFromURL(const AJWKS_URL: string; const ACacheDurationMinutes: Integer);
begin
  ClearJWKSCache;
  FJWKSSource := jsstURL;
  FJWKS_URL := AJWKS_URL;
  FJWKSCacheDuration := TTimeSpan.FromMinutes(ACacheDurationMinutes);
end;

procedure TIAM4DJWTValidator.ConfigureJWKSFromFile(const AJWKS_FilePath: string);
begin
  ClearJWKSCache;
  FJWKSSource := jsstFile;
  FJWKS_FilePath := AJWKS_FilePath;
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

procedure TIAM4DJWTValidator.FetchJWKSFromURL;
var
  LHTTPClient: THTTPClient;
  LResponse: IHTTPResponse;
  LResponseText: string;
  LJWKSObj: TJSONObject;
  LElapsedTimeMinutes: Extended;
begin
  if Assigned(FJWKS) then
  begin
    LElapsedTimeMinutes := (GetUtcNow - FLastJWKSFetchTime) * IAM4D_SECOND_PER_DAY / 60;
    if LElapsedTimeMinutes <= FJWKSCacheDuration.TotalMinutes then
      Exit;
  end;

  if FJWKS_URL.Trim.IsEmpty then
    raise EIAM4DSecurityValidationException.Create('JWKS_URL is not configured for URL-based JWKS loading.');

  // Create local HTTP client to avoid race conditions in multi-threaded scenarios
  LHTTPClient := TIAM4DHTTPClientFactory.CreateHTTPClient(FHTTPConfig);
  try
    LResponse := TIAM4DHTTPClientFactory.GetWithRetry(LHTTPClient, FJWKS_URL, nil, 3);

    if (Integer(LResponse.StatusCode) >= 200) and (Integer(LResponse.StatusCode) <= 299) then
    begin
      LResponseText := LResponse.ContentAsString(TEncoding.UTF8);
      LJWKSObj := TIAM4DJSONUtils.SafeParseJSONObject(LResponseText, 'JWKS response from URL');

      if not Assigned(LJWKSObj.GetValue<TJSONArray>('keys')) then
      begin
        LJWKSObj.Free;
        raise EIAM4DSecurityValidationException.CreateFmt('Invalid JWKS format: "keys" array missing. Response: %s', [LResponseText]);
      end;

      ClearJWKSCache;
      FJWKS := LJWKSObj;
      FLastJWKSFetchTime := GetUtcNow;
    end
    else
      raise EIAM4DSecurityValidationException.CreateFmt('Failed to fetch JWKS from "%s": %d %s', [FJWKS_URL, LResponse.StatusCode, LResponse.StatusText]);
  finally
    LHTTPClient.Free;
  end;
end;

procedure TIAM4DJWTValidator.LoadJWKSFromFile;
var
  LFileStream: TFileStream;
  LStringStream: TStringStream;
  LJWKSObj: TJSONObject;
begin
  if FJWKS_FilePath.Trim.IsEmpty then
    raise EIAM4DSecurityValidationException.Create('JWKS file path is not configured for file-based JWKS loading.');

  if not FileExists(FJWKS_FilePath) then
    raise EIAM4DSecurityValidationException.CreateFmt('JWKS file not found at path: %s', [FJWKS_FilePath]);

  try
    LFileStream := TFileStream.Create(FJWKS_FilePath, fmOpenRead or fmShareDenyWrite);
    try
      LStringStream := TStringStream.Create('', TEncoding.UTF8);
      try
        LStringStream.CopyFrom(LFileStream, LFileStream.Size);
        LStringStream.Position := 0;

        LJWKSObj := TIAM4DJSONUtils.SafeParseJSONObject(LStringStream.DataString, Format('JWKS file %s', [FJWKS_FilePath]));

        if not Assigned(LJWKSObj.GetValue<TJSONArray>('keys')) then
        begin
          LJWKSObj.Free;
          raise EIAM4DSecurityValidationException.CreateFmt('Invalid JWKS file format: "keys" array missing in %s.', [FJWKS_FilePath]);
        end;

        ClearJWKSCache;
        FJWKS := LJWKSObj;
      finally
        if Assigned(LStringStream) then
          LStringStream.Free;
      end;
    finally
      LFileStream.Free;
    end;
  except
    on E: EIAM4DSecurityValidationException do
      raise;
    on E: Exception do
      raise EIAM4DSecurityValidationException.CreateFmt('Error loading JWKS from file "%s": %s', [FJWKS_FilePath, E.Message]);
  end;
end;

procedure TIAM4DJWTValidator.SetClockSkewSeconds(const AValue: Integer);
begin
  if AValue < 0 then
    raise EIAM4DSecurityValidationException.Create('Clock skew seconds must be >= 0');
  FClockSkewSeconds := AValue;
end;

function TIAM4DJWTValidator.FindPublicKey(const Kid, Alg: string): TJSONObject;
var
  LKeysArray: TJSONArray;
  LKey: TJSONValue;
  LKeyObj: TJSONObject;
  LKeyKid, LKeyAlg, LKeyKty, LKeyUse: string;
begin
  if not Assigned(FJWKS) then
  begin
    case FJWKSSource of
      jsstURL:
        FetchJWKSFromURL;
      jsstFile:
        LoadJWKSFromFile;
      jsstNone:
        raise EIAM4DSecurityValidationException.Create('JWKS source not configured. Call ConfigureJWKSFromURL or ConfigureJWKSFromFile first.');
    end;

    if not Assigned(FJWKS) then
      raise EIAM4DSecurityValidationException.Create('JWKS could not be loaded or fetched.');
  end;

  LKeysArray := FJWKS.GetValue<TJSONArray>('keys');
  if not Assigned(LKeysArray) then
    raise EIAM4DSecurityValidationException.Create('Invalid JWKS format: "keys" array is missing.');

  for LKey in LKeysArray do
  begin
    if (LKey <> nil) and (LKey is TJSONObject) then
    begin
      LKeyObj := LKey as TJSONObject;
      LKeyKid := LKeyObj.GetValue<string>('kid', '');
      LKeyAlg := LKeyObj.GetValue<string>('alg', '');
      LKeyKty := LKeyObj.GetValue<string>('kty', '');
      LKeyUse := LKeyObj.GetValue<string>('use', '');

      if (Alg <> '') and (LKeyKty.Equals('RSA')) and ((Alg.Equals('RS256') or Alg.Equals('PS256'))) then
      begin
        if (Kid = '') or (LKeyKid.Equals(Kid)) then
        begin
          Result := LKeyObj;
          Exit;
        end;
      end;
    end;
  end;

  raise EIAM4DSecurityValidationException.CreateFmt('Public key not found in JWKS for Kid "%s" and Alg "%s". Ensure JWKS is correct and key exists.', [Kid, Alg]);
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
  LIsMultipleAud: Boolean;
  LExpiryTimestamp: Int64;
  LNotBeforeTimestamp: Int64;
  LExpiryDateTime: TDateTime;
  LNotBeforeDateTime: TDateTime;
  LCurrentTimeUTC: TDateTime;
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

  if not SameText(LIssuer, LExpected) then
    raise EIAM4DSecurityValidationException.CreateFmt('Invalid issuer. Expected "%s", got "%s".', [LExpected, LIssuer]);

  LAudienceValue := Claims.GetValue<TJSONValue>('aud', nil);
  if not Assigned(LAudienceValue) then
    raise EIAM4DSecurityValidationException.Create('Missing audience claim (aud).');

  if LAudienceValue is TJSONString then
  begin
    LAudienceString := (LAudienceValue as TJSONString).Value;
    if LAudienceString.Trim.IsEmpty then
      raise EIAM4DSecurityValidationException.Create('Audience claim (aud) is empty.');
    if not LAudienceString.Equals(ExpectedAudience) then
      raise EIAM4DSecurityValidationException.CreateFmt('Invalid audience. Expected "%s", got "%s".', [ExpectedAudience, LAudienceString]);
  end
  else if LAudienceValue is TJSONArray then
  begin
    LIsMultipleAud := True;
    LAudienceArray := LAudienceValue as TJSONArray;
    var LFound := False;
    for var Item in LAudienceArray do
    begin
      if (Item <> nil) and (Item is TJSONString) and ((Item as TJSONString).Value.Equals(ExpectedAudience)) then
      begin
        LFound := True;
        Break;
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

    if not LAzp.Equals(FExpectedAzp) then
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

      if Assigned(FJWKSProvider) then
      begin
        LIssuer := AClaims.GetValue<string>('iss', '');
        if LIssuer.Trim.IsEmpty then
          raise EIAM4DSecurityValidationException.Create('JWT payload missing issuer (iss) claim - required for auto-discovery.');

        LIssuer := NormalizeIssuer(LIssuer);

        LPublicKeyJWK := FJWKSProvider.GetPublicKey(LIssuer, LKid);
        LMustFreePublicKey := True;

        if not Assigned(LPublicKeyJWK) then
          raise EIAM4DSecurityValidationException.CreateFmt(
            'Public key not found via JWKS provider for issuer "%s" and kid "%s"', [LIssuer, LKid]);
      end
      else
      begin
        LPublicKeyJWK := FindPublicKey(LKid, LAlg);
        LMustFreePublicKey := False;
      end;

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

end.