{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.JWT.JWKS.pas
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

unit IAMClient4D.Security.JWT.JWKS;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.DateUtils,
  System.Generics.Collections,
  System.SyncObjs,
  System.Net.HttpClient,
  System.Net.URLClient,
  System.Hash,
  IAMClient4D.Security.Core,
  IAMClient4D.Common.Security,
  IAMClient4D.Common.JSONUtils,
  IAMClient4D.Core;

type
  /// <summary>
  /// Enterprise-grade JWKS provider with automatic discovery, caching, and DoS protection.
  /// </summary>
  /// <remarks>
  /// Fetches public keys from OIDC providers via well-known discovery.
  /// Pattern: Singleton with GetInstance/ReleaseInstance (also supports direct instantiation).
  /// Discovery: Auto-discovers JWKS URI from issuer/.well-known/openid-configuration.
  /// Cache: Thread-safe caching with configurable TTL (default 3600 seconds).
  /// Negative cache: Prevents repeated fetches for non-existent kids (default 60 seconds).
  /// Key rotation: Automatic retry logic handles OIDC key rotation gracefully.
  /// Manual keys: Supports static key configuration for testing (overrides discovery).
  /// Thread-safety: All public methods are thread-safe with TLightweightMREW (Multiple Reader Exclusive Writer).
  /// SSL validation: Configurable modes (strict/self-signed/disabled).
  /// Memory: Returns cloned TJSONObject - caller must free.
  /// </remarks>
  TIAM4DJWKSProvider = class(TInterfacedObject, IIAM4DJWKSProvider)
  private
    type
      /// <summary>
      /// Cached JWKS entry with URI and fetch timestamp.
      /// </summary>
      TCachedJWKS = record
        JWKS: TJSONObject;
        JWKSUri: string;
        FetchedAt: TDateTime;
      end;
  private
    class var FInstance: IIAM4DJWKSProvider;
    class var FInstanceLock: TCriticalSection;

      FCache: TDictionary<string, TCachedJWKS>;
      FManualKeys: TDictionary<string, TJSONObject>;
      FCacheLock: TLightweightMREW;
      FCacheTTL: Integer;
      FSSLValidator: IIAM4DSSLCertificateValidator;
      FHTTPClient: THTTPClient;
      FHTTPConfig: TIAM4DHTTPClientConfig;
      FNegativeKidCache: TDictionary<string, TDateTime>;
      FNegativeTtlSec: Integer;

    function MakeNegKey(const AIssuer, AKeyId: string): string;
    function IsKidNegCached(const AIssuer, AKeyId: string): Boolean;
    procedure PutKidNegCache(const AIssuer, AKeyId: string);
    function DiscoverJWKSUri(const AIssuer: string): string;
    function FetchJWKS(const AJWKSUri: string): TJSONObject;
    function FindKeyInJWKS(const AJWKS: TJSONObject; const AKeyId: string): TJSONObject;
    function IsCacheValid(const AEntry: TCachedJWKS): Boolean;
    function GetManualKeyLookup(const AIssuer, AKeyId: string): string;
    function NormalizeIssuer(const AIssuer: string): string;
    function GetUtcNow: TDateTime;

    procedure ValidateServerCertificate(const Sender: TObject;
      const ARequest: TURLRequest; const Certificate: TCertificate;
      var Accepted: Boolean);

    // Helper methods for refactored GetPublicKey
    function TryGetFromManualKeys(const AIssuer, AKeyId: string; out AKey: TJSONObject): Boolean;
    function TryGetFromCache(const AIssuer, AKeyId: string; out AKey: TJSONObject): Boolean;
    function FetchAndCacheJWKS(const AIssuer: string; out AJWKSUri: string): TJSONObject;
    procedure UpdateCacheEntry(const AIssuer, AJWKSUri: string; AJWKS: TJSONObject);
  public
    /// <summary>
    /// Returns singleton instance (thread-safe lazy initialization).
    /// </summary>
    class function GetInstance: IIAM4DJWKSProvider;

    /// <summary>
    /// Releases singleton instance.
    /// </summary>
    class procedure ReleaseInstance;

    /// <summary>
    /// Class constructor - initializes singleton infrastructure.
    /// </summary>
    class constructor Create;

    /// <summary>
    /// Class destructor - releases singleton infrastructure.
    /// </summary>
    class destructor Destroy;

    /// <summary>
    /// Creates JWKS provider with HTTP configuration.
    /// </summary>
    constructor Create(const AHTTPConfig: TIAM4DHTTPClientConfig); overload;

    /// <summary>
    /// Creates JWKS provider with SSL validation mode (uses default timeouts).
    /// </summary>
    constructor Create(const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict); overload;

    /// <summary>
    /// Destroys provider and clears all caches.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Retrieves public key via OIDC discovery (returns cloned JWK - CALLER MUST FREE).
    /// </summary>
    /// <remarks>
    /// OWNERSHIP CONTRACT:
    ///   - Returns COPY (Clone) of cached key - caller owns and MUST free the returned object.
    ///   - Implementation guarantees: Always returns new TJSONObject instance, never cache reference.
    /// Features:
    ///   - Negative cache: Blocks repeated requests for non-existent kids (DoS protection)
    ///   - Retry logic: Handles key rotation gracefully
    ///   - Thread-safe: Read locks for cache access, write locks only for updates
    ///   - Optimized locking: Uses TLightweightMREW for concurrent reads
    /// </remarks>
    /// <exception cref="EIAM4DSecurityValidationException">
    /// Raised if discovery fails, JWKS fetch fails, or key not found.
    /// </exception>
    function GetPublicKey(const AIssuer, AKeyId: string): TJSONObject;

    /// <summary>
    /// Sets manual public key for testing (overrides discovery for issuer/kid pair).
    /// </summary>
    /// <remarks>
    /// OWNERSHIP CONTRACT:
    ///   - Takes COPY of input key - caller retains ownership and can free APublicKeyJWK after call.
    ///   - Implementation guarantees: Clones input before storing internally.
    /// </remarks>
    /// <param name="AIssuer">Issuer URL (normalized automatically)</param>
    /// <param name="AKeyId">Key ID</param>
    /// <param name="APublicKeyJWK">Public key in JWK format (will be cloned)</param>
    procedure SetManualKey(const AIssuer, AKeyId: string; const APublicKeyJWK: TJSONObject);

    /// <summary>
    /// Clears all cached JWKS entries (manual keys unaffected).
    /// </summary>
    procedure ClearCache;

    /// <summary>
    /// Sets cache time-to-live in seconds (must be >= 0).
    /// </summary>
    procedure SetCacheTTL(ASeconds: Integer);

    /// <summary>
    /// Sets SSL validation mode for JWKS and discovery endpoints.
    /// </summary>
    procedure SetSSLValidationMode(AMode: TIAM4DSSLValidationMode);

    /// <summary>
    /// Best-effort prefetch della JWKS per un issuer (riempie la cache senza eccezioni).
    /// </summary>
    procedure TryPrefetch(const AIssuer: string);

    /// <summary>
    /// Sets negative-cache TTL (seconds) for missing kid lookups (default 60).
    /// </summary>
    procedure SetNegativeKidTTLSeconds(ASeconds: Integer);
  end;

implementation

uses
  IAMClient4D.Common.Constants,
  IAMClient4D.Exceptions;

{ TIAM4DJWKSProvider }

class constructor TIAM4DJWKSProvider.Create;
begin
  FInstanceLock := TCriticalSection.Create;
  FInstance := nil;
end;

class destructor TIAM4DJWKSProvider.Destroy;
begin
  ReleaseInstance;
  FreeAndNil(FInstanceLock);
end;

class function TIAM4DJWKSProvider.GetInstance: IIAM4DJWKSProvider;
begin
  if not Assigned(FInstance) then
  begin
    FInstanceLock.Enter;
    try
      if not Assigned(FInstance) then
        FInstance := TIAM4DJWKSProvider.Create;
    finally
      FInstanceLock.Leave;
    end;
  end;
  Result := FInstance;
end;

class procedure TIAM4DJWKSProvider.ReleaseInstance;
begin
  FInstanceLock.Enter;
  try
    FInstance := nil;
  finally
    FInstanceLock.Leave;
  end;
end;

constructor TIAM4DJWKSProvider.Create(const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  inherited Create;

  FCache := TDictionary<string, TCachedJWKS>.Create;
  FManualKeys := TDictionary<string, TJSONObject>.Create;
  FNegativeKidCache := TDictionary<string, TDateTime>.Create;
  FNegativeTtlSec := 60;

  FCacheTTL := 3600;
  FSSLValidator := TIAM4DSSLCertificateValidator.Create;
  FHTTPConfig := AHTTPConfig;

  FHTTPClient := TIAM4DHTTPClientFactory.CreateHTTPClient(FHTTPConfig);

  SetSSLValidationMode(FHTTPConfig.SSLValidationMode);
end;

constructor TIAM4DJWKSProvider.Create(const ASSLValidationMode: TIAM4DSSLValidationMode);
var
  LConfig: TIAM4DHTTPClientConfig;
begin
  LConfig := TIAM4DHTTPClientConfig.Create(10000, 10000, ASSLValidationMode);
  Create(LConfig);
end;

destructor TIAM4DJWKSProvider.Destroy;
begin
  ClearCache;

  FCacheLock.BeginWrite;
  try
    for var LKey in FManualKeys.Values do
      LKey.Free;
    FManualKeys.Clear;
    FNegativeKidCache.Clear;
  finally
    FCacheLock.EndWrite;
  end;

  FreeAndNil(FCache);
  FreeAndNil(FManualKeys);
  FreeAndNil(FNegativeKidCache);
  FSSLValidator := nil;

  FreeAndNil(FHTTPClient);

  inherited;
end;

function TIAM4DJWKSProvider.GetUtcNow: TDateTime;
begin
  Result := TTimeZone.Local.ToUniversalTime(Now);
end;

function TIAM4DJWKSProvider.NormalizeIssuer(const AIssuer: string): string;
begin
  Result := AIssuer.TrimRight(['/']);
end;

procedure TIAM4DJWKSProvider.PutKidNegCache(const AIssuer, AKeyId: string);
var
  LK: string;
begin
  if AKeyId = '' then
    Exit;

  LK := MakeNegKey(AIssuer, AKeyId);
  FCacheLock.BeginWrite;
  try
    FNegativeKidCache.AddOrSetValue(LK, GetUtcNow);
  finally
    FCacheLock.EndWrite;
  end;
end;

function TIAM4DJWKSProvider.GetManualKeyLookup(const AIssuer, AKeyId: string): string;
begin
  Result := NormalizeIssuer(AIssuer) + '|' + AKeyId;
end;

function TIAM4DJWKSProvider.IsCacheValid(const AEntry: TCachedJWKS): Boolean;
var
  LElapsedSeconds: Int64;
begin
  if not Assigned(AEntry.JWKS) then
    Exit(False);

  LElapsedSeconds := SecondsBetween(GetUtcNow, AEntry.FetchedAt);
  Result := LElapsedSeconds <= FCacheTTL;
end;

function TIAM4DJWKSProvider.IsKidNegCached(const AIssuer, AKeyId: string): Boolean;
var
  LK: string;
  LTS: TDateTime;
  LNeedsRemoval: Boolean;
begin
  if AKeyId = '' then
    Exit(False);

  LK := MakeNegKey(AIssuer, AKeyId);

  FCacheLock.BeginRead;
  try
    if FNegativeKidCache.TryGetValue(LK, LTS) then
    begin
      Result := SecondsBetween(GetUtcNow, LTS) <= FNegativeTtlSec;
      LNeedsRemoval := not Result;
    end
    else
    begin
      Result := False;
      LNeedsRemoval := False;
    end;
  finally
    FCacheLock.EndRead;
  end;

  if LNeedsRemoval then
  begin
    FCacheLock.BeginWrite;
    try
      FNegativeKidCache.Remove(LK);
    finally
      FCacheLock.EndWrite;
    end;
  end;
end;

function TIAM4DJWKSProvider.MakeNegKey(const AIssuer, AKeyId: string): string;
begin
  Result := GetManualKeyLookup(NormalizeIssuer(AIssuer), AKeyId);
end;

function TIAM4DJWKSProvider.TryGetFromManualKeys(const AIssuer, AKeyId: string; out AKey: TJSONObject): Boolean;
var
  LManualKeyLookup: string;
begin
  Result := False;
  AKey := nil;

  LManualKeyLookup := GetManualKeyLookup(AIssuer, AKeyId);

  FCacheLock.BeginRead;
  try
    if FManualKeys.ContainsKey(LManualKeyLookup) then
    begin
      AKey := FManualKeys[LManualKeyLookup].Clone as TJSONObject;
      Result := True;
    end;
  finally
    FCacheLock.EndRead;
  end;
end;

function TIAM4DJWKSProvider.TryGetFromCache(const AIssuer, AKeyId: string; out AKey: TJSONObject): Boolean;
var
  LCachedEntry: TCachedJWKS;
begin
  Result := False;
  AKey := nil;

  FCacheLock.BeginRead;
  try
    if FCache.TryGetValue(AIssuer, LCachedEntry) and IsCacheValid(LCachedEntry) then
    begin
      AKey := FindKeyInJWKS(LCachedEntry.JWKS, AKeyId);
      Result := Assigned(AKey);
    end;
  finally
    FCacheLock.EndRead;
  end;
end;

procedure TIAM4DJWKSProvider.UpdateCacheEntry(const AIssuer, AJWKSUri: string; AJWKS: TJSONObject);
var
  LNewEntry, LExisting: TCachedJWKS;
begin
  FCacheLock.BeginWrite;
  try
    if FCache.TryGetValue(AIssuer, LExisting) and Assigned(LExisting.JWKS) then
      LExisting.JWKS.Free;

    LNewEntry.JWKS := AJWKS.Clone as TJSONObject;
    LNewEntry.JWKSUri := AJWKSUri;
    LNewEntry.FetchedAt := GetUtcNow;

    FCache.AddOrSetValue(AIssuer, LNewEntry);
  finally
    FCacheLock.EndWrite;
  end;
end;

function TIAM4DJWKSProvider.FetchAndCacheJWKS(const AIssuer: string; out AJWKSUri: string): TJSONObject;
begin
  AJWKSUri := DiscoverJWKSUri(AIssuer);
  Result := FetchJWKS(AJWKSUri);

  UpdateCacheEntry(AIssuer, AJWKSUri, Result);
end;

function TIAM4DJWKSProvider.DiscoverJWKSUri(const AIssuer: string): string;
var
  LDiscoveryUrl: string;
  LResponse: IHTTPResponse;
  LResponseText: string;
  LDiscoveryJSON: TJSONValue;
  LJWKSUri: string;
begin
  Result := '';

  LDiscoveryUrl := NormalizeIssuer(AIssuer) + '/.well-known/openid-configuration';

  try
    LResponse := TIAM4DHTTPClientFactory.GetWithRetry(FHTTPClient, LDiscoveryUrl, nil, 3);

    if (Integer(LResponse.StatusCode) >= 200) and (Integer(LResponse.StatusCode) <= 299) then
    begin
      LResponseText := LResponse.ContentAsString(TEncoding.UTF8);
      LDiscoveryJSON := TIAM4DJSONUtils.SafeParseJSONObject(LResponseText, 'OpenID discovery response');
      try
        LJWKSUri := (LDiscoveryJSON as TJSONObject).GetValue<string>('jwks_uri', '');
        if LJWKSUri.Trim.IsEmpty then
          raise EIAM4DSecurityValidationException.CreateFmt(
            'OpenID discovery succeeded but jwks_uri not found in response. URL: %s', [LDiscoveryUrl]);

        Result := LJWKSUri;
      finally
        if Assigned(LDiscoveryJSON) then
          LDiscoveryJSON.Free;
      end;
    end
    else
      raise EIAM4DSecurityValidationException.CreateFmt(
        'OpenID discovery failed: %d %s. URL: %s',
        [Integer(LResponse.StatusCode), LResponse.StatusText, LDiscoveryUrl]);
  except
    on E: EIAM4DSecurityValidationException do
      raise;
    on E: Exception do
      raise EIAM4DSecurityValidationException.CreateFmt(
        'Error during OpenID discovery for issuer "%s": %s', [AIssuer, E.Message]);
  end;
end;

function TIAM4DJWKSProvider.FetchJWKS(const AJWKSUri: string): TJSONObject;
var
  LResponse: IHTTPResponse;
  LResponseText: string;
begin
  try
    LResponse := TIAM4DHTTPClientFactory.GetWithRetry(FHTTPClient, AJWKSUri, nil, 3);

    if (Integer(LResponse.StatusCode) >= 200) and (Integer(LResponse.StatusCode) <= 299) then
    begin
      LResponseText := LResponse.ContentAsString(TEncoding.UTF8);
      Result := TIAM4DJSONUtils.SafeParseJSONObject(LResponseText, 'JWKS response');

      if not Assigned(Result.GetValue<TJSONArray>('keys')) then
      begin
        Result.Free;
        raise EIAM4DSecurityValidationException.CreateFmt(
          'Invalid JWKS format: "keys" array missing. URL: %s', [AJWKSUri]);
      end;
    end
    else
      raise EIAM4DSecurityValidationException.CreateFmt(
        'Failed to fetch JWKS: %d %s. URL: %s',
        [Integer(LResponse.StatusCode), LResponse.StatusText, AJWKSUri]);
  except
    on E: EIAM4DSecurityValidationException do
      raise;
    on E: Exception do
      raise EIAM4DSecurityValidationException.CreateFmt(
        'Error fetching JWKS from "%s": %s', [AJWKSUri, E.Message]);
  end;
end;

function TIAM4DJWKSProvider.FindKeyInJWKS(const AJWKS: TJSONObject;
  const AKeyId: string): TJSONObject;
var
  LKeysArray: TJSONArray;
  LKey: TJSONValue;
  LKeyObj: TJSONObject;
  LKeyKid, LKeyKty: string;
begin
  Result := nil;

  if not Assigned(AJWKS) then
    Exit;

  LKeysArray := AJWKS.GetValue<TJSONArray>('keys');
  if not Assigned(LKeysArray) then
    Exit;

  for LKey in LKeysArray do
  begin
    if (LKey <> nil) and (LKey is TJSONObject) then
    begin
      LKeyObj := LKey as TJSONObject;
      LKeyKid := LKeyObj.GetValue<string>('kid', '');
      LKeyKty := LKeyObj.GetValue<string>('kty', '');

      if (LKeyKty = 'RSA') and ((AKeyId = '') or (LKeyKid = AKeyId)) then
      begin
        Result := LKeyObj.Clone as TJSONObject;
        Exit;
      end;
    end;
  end;
end;

function TIAM4DJWKSProvider.GetPublicKey(const AIssuer, AKeyId: string): TJSONObject;
var
  LNormalizedIssuer: string;
  LJWKSUri: string;
  LJWKS: TJSONObject;
begin
  LNormalizedIssuer := NormalizeIssuer(AIssuer);

  if IsKidNegCached(LNormalizedIssuer, AKeyId) then
    raise EIAM4DSecurityValidationException.CreateFmt(
      'Public key with kid "%s" recently not found for issuer "%s" (negative cache).',
      [AKeyId, LNormalizedIssuer]);

  if TryGetFromManualKeys(LNormalizedIssuer, AKeyId, Result) then
    Exit;

  if TryGetFromCache(LNormalizedIssuer, AKeyId, Result) then
    Exit;

  LJWKS := FetchAndCacheJWKS(LNormalizedIssuer, LJWKSUri);
  try
    Result := FindKeyInJWKS(LJWKS, AKeyId);
    if Assigned(Result) then
      Exit;

    LJWKS.Free;
    LJWKS := FetchJWKS(LJWKSUri);
    UpdateCacheEntry(LNormalizedIssuer, LJWKSUri, LJWKS);

    Result := FindKeyInJWKS(LJWKS, AKeyId);
    if Assigned(Result) then
      Exit;
  finally
    LJWKS.Free;
  end;

  if not Assigned(Result) then
  begin
    PutKidNegCache(LNormalizedIssuer, AKeyId);
    raise EIAM4DSecurityValidationException.CreateFmt(
      'Public key with kid "%s" not found in JWKS for issuer "%s".',
      [AKeyId, LNormalizedIssuer]);
  end;
end;

procedure TIAM4DJWKSProvider.SetManualKey(const AIssuer, AKeyId: string;
  const APublicKeyJWK: TJSONObject);
var
  LLookup: string;
begin
  if not Assigned(APublicKeyJWK) then
    raise EIAM4DSecurityValidationException.Create('Manual key cannot be nil');

  LLookup := GetManualKeyLookup(AIssuer, AKeyId);

  FCacheLock.BeginWrite;
  try
    if FManualKeys.ContainsKey(LLookup) then
      FManualKeys[LLookup].Free;

    FManualKeys.AddOrSetValue(LLookup, APublicKeyJWK.Clone as TJSONObject);
  finally
    FCacheLock.EndWrite;
  end;
end;

procedure TIAM4DJWKSProvider.SetNegativeKidTTLSeconds(ASeconds: Integer);
begin
  if ASeconds < 0 then
    raise EIAM4DSecurityValidationException.Create('Negative kid TTL must be >= 0');
  FNegativeTtlSec := ASeconds;
end;

procedure TIAM4DJWKSProvider.ClearCache;
var
  LEntry: TCachedJWKS;
begin
  FCacheLock.BeginWrite;
  try
    for LEntry in FCache.Values do
    begin
      if Assigned(LEntry.JWKS) then
        LEntry.JWKS.Free;
    end;
    FCache.Clear;
  finally
    FCacheLock.EndWrite;
  end;
end;

procedure TIAM4DJWKSProvider.SetCacheTTL(ASeconds: Integer);
begin
  if ASeconds < 0 then
    raise EIAM4DSecurityValidationException.Create('Cache TTL must be >= 0');

  FCacheLock.BeginWrite;
  try
    FCacheTTL := ASeconds;
  finally
    FCacheLock.EndWrite;
  end;
end;

procedure TIAM4DJWKSProvider.SetSSLValidationMode(AMode: TIAM4DSSLValidationMode);
begin
  FSSLValidator.SetValidationMode(AMode);

  FCacheLock.BeginWrite;
  try
    case AMode of
      svmStrict: FHTTPClient.OnValidateServerCertificate := nil;
      svmAllowSelfSigned: FHTTPClient.OnValidateServerCertificate := ValidateServerCertificate;
    end;
  finally
    FCacheLock.EndWrite;
  end;
end;

procedure TIAM4DJWKSProvider.ValidateServerCertificate(
  const Sender: TObject;
  const ARequest: TURLRequest;
  const Certificate: TCertificate;
  var Accepted: Boolean);
begin
  Accepted := FSSLValidator.ValidateCertificate(Certificate);
end;

procedure TIAM4DJWKSProvider.TryPrefetch(const AIssuer: string);
var
  LJWKSUri: string;
  LJWKS: TJSONObject;
  LNormalizedIssuer: string;
begin
  try
    LNormalizedIssuer := NormalizeIssuer(AIssuer);
    LJWKSUri := DiscoverJWKSUri(LNormalizedIssuer);
    LJWKS := FetchJWKS(LJWKSUri);
    try
      UpdateCacheEntry(LNormalizedIssuer, LJWKSUri, LJWKS);
    finally
      LJWKS.Free;
    end;
  except
    // ignore
  end;
end;

end.