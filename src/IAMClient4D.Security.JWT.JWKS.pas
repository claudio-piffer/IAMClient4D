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
      /// Cached single JWK key with LRU tracking.
      /// </summary>
      TCachedKey = record
        Key: TJSONObject; 
        Issuer: string; 
        Kid: string; 
        JWKSUri: string;
        FetchedAt: TDateTime; 
        LastUsedAt: TDateTime; 
      end;
    const
      DEFAULT_MAX_CACHED_KEYS = 100; 
  private
    class var FInstance: IIAM4DJWKSProvider;
    class var FInstanceLock: TCriticalSection;

  private
    FKeyCache: TDictionary<string, TCachedKey>;
    FMaxCachedKeys: Integer;
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
    function GetManualKeyLookup(const AIssuer, AKeyId: string): string;
    function NormalizeIssuer(const AIssuer: string): string;
    function GetUtcNow: TDateTime;

    procedure ValidateServerCertificate(const Sender: TObject;
      const ARequest: TURLRequest; const Certificate: TCertificate;
      var Accepted: Boolean);

    function MakeKeyLookup(const AIssuer, AKid: string): string;
    function TryGetFromManualKeys(const AIssuer, AKeyId: string; out AKey: TJSONObject): Boolean;
    function TryGetKeyFromCache(const AIssuer, AKeyId: string; out AKey: TJSONObject): Boolean;
    procedure AddKeyToCache(const AIssuer, AKid, AJWKSUri: string; AKey: TJSONObject);
    procedure EvictLRUKey;
    function IsKeyExpired(const AEntry: TCachedKey): Boolean;
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

    /// <summary>
    /// Sets maximum number of cached keys (default 100). When exceeded, LRU eviction occurs.
    /// </summary>
    procedure SetMaxCachedKeys(ACount: Integer);
  end;

implementation

uses
  IAMClient4D.Common.Constants,
  IAMClient4D.Exceptions;

{ TIAM4DJWKSProvider }

class function TIAM4DJWKSProvider.GetInstance: IIAM4DJWKSProvider;
begin
  if not Assigned(FInstance) then
  begin
    if Assigned(FInstanceLock) then
    begin
      FInstanceLock.Enter;
      try
        if not Assigned(FInstance) then
          FInstance := TIAM4DJWKSProvider.Create;
      finally
        FInstanceLock.Leave;
      end;
    end;
  end;
  Result := FInstance;
end;

class procedure TIAM4DJWKSProvider.ReleaseInstance;
begin
  if not Assigned(FInstanceLock) then
  begin
    FInstance := nil;
    Exit;
  end;

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

  FKeyCache := TDictionary<string, TCachedKey>.Create;
  FMaxCachedKeys := DEFAULT_MAX_CACHED_KEYS;
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
  
  inherited Create;

  FKeyCache := TDictionary<string, TCachedKey>.Create;
  FMaxCachedKeys := DEFAULT_MAX_CACHED_KEYS;
  FManualKeys := TDictionary<string, TJSONObject>.Create;
  FNegativeKidCache := TDictionary<string, TDateTime>.Create;
  FNegativeTtlSec := 60;

  FCacheTTL := 3600;
  FSSLValidator := TIAM4DSSLCertificateValidator.Create;
  FHTTPConfig := LConfig;

  FHTTPClient := TIAM4DHTTPClientFactory.CreateHTTPClient(FHTTPConfig);

  SetSSLValidationMode(FHTTPConfig.SSLValidationMode);
end;

destructor TIAM4DJWKSProvider.Destroy;
begin
  if Assigned(FHTTPClient) then
    FHTTPClient.OnValidateServerCertificate := nil;

  if Assigned(FKeyCache) then
  begin
    for var LPair in FKeyCache do
      if Assigned(LPair.Value.Key) then
        LPair.Value.Key.Free;
    FKeyCache.Clear;
  end;

  if Assigned(FManualKeys) then
  begin
    for var LPair in FManualKeys do
      LPair.Value.Free;
    FManualKeys.Clear;
  end;

  if Assigned(FNegativeKidCache) then
    FNegativeKidCache.Clear;

  FreeAndNil(FKeyCache);
  FreeAndNil(FManualKeys);
  FreeAndNil(FNegativeKidCache);
  FreeAndNil(FHTTPClient);

  FSSLValidator := nil;

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

function TIAM4DJWKSProvider.IsKeyExpired(const AEntry: TCachedKey): Boolean;
var
  LElapsedSeconds: Int64;
begin
  if not Assigned(AEntry.Key) then
    Exit(True);

  LElapsedSeconds := SecondsBetween(GetUtcNow, AEntry.FetchedAt);
  Result := LElapsedSeconds > FCacheTTL;
end;

function TIAM4DJWKSProvider.MakeKeyLookup(const AIssuer, AKid: string): string;
begin
  Result := NormalizeIssuer(AIssuer) + '|' + AKid;
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

function TIAM4DJWKSProvider.TryGetKeyFromCache(const AIssuer, AKeyId: string; out AKey: TJSONObject): Boolean;
var
  LLookup: string;
  LEntry: TCachedKey;
begin
  Result := False;
  AKey := nil;
  LLookup := MakeKeyLookup(AIssuer, AKeyId);

  FCacheLock.BeginRead;
  try
    if FKeyCache.TryGetValue(LLookup, LEntry) then
    begin
      if not IsKeyExpired(LEntry) then
      begin
        AKey := LEntry.Key.Clone as TJSONObject;
        Result := True;
      end;
    end;
  finally
    FCacheLock.EndRead;
  end;

  if Result then
  begin
    FCacheLock.BeginWrite;
    try
      if FKeyCache.TryGetValue(LLookup, LEntry) then
      begin
        LEntry.LastUsedAt := GetUtcNow;
        FKeyCache[LLookup] := LEntry;
      end;
    finally
      FCacheLock.EndWrite;
    end;
  end;
end;

procedure TIAM4DJWKSProvider.AddKeyToCache(const AIssuer, AKid, AJWKSUri: string; AKey: TJSONObject);
var
  LEntry: TCachedKey;
  LLookup: string;
  LExisting: TCachedKey;
begin
  if not Assigned(AKey) then
    Exit;

  LLookup := MakeKeyLookup(AIssuer, AKid);

  FCacheLock.BeginWrite;
  try
    while FKeyCache.Count >= FMaxCachedKeys do
      EvictLRUKey;

    if FKeyCache.TryGetValue(LLookup, LExisting) then
      if Assigned(LExisting.Key) then
        LExisting.Key.Free;

    LEntry.Key := AKey.Clone as TJSONObject;
    LEntry.Issuer := AIssuer;
    LEntry.Kid := AKid;
    LEntry.JWKSUri := AJWKSUri;
    LEntry.FetchedAt := GetUtcNow;
    LEntry.LastUsedAt := GetUtcNow;

    FKeyCache.AddOrSetValue(LLookup, LEntry);
  finally
    FCacheLock.EndWrite;
  end;
end;

procedure TIAM4DJWKSProvider.EvictLRUKey;
var
  LOldestKey: string;
  LOldestTime: TDateTime;
  LPair: TPair<string, TCachedKey>;
  LEntry: TCachedKey;
begin
  if FKeyCache.Count = 0 then
    Exit;

  LOldestTime := MaxDateTime;
  LOldestKey := '';

  for LPair in FKeyCache do
  begin
    if LPair.Value.LastUsedAt < LOldestTime then
    begin
      LOldestTime := LPair.Value.LastUsedAt;
      LOldestKey := LPair.Key;
    end;
  end;

  if LOldestKey <> '' then
  begin
    if FKeyCache.TryGetValue(LOldestKey, LEntry) then
      if Assigned(LEntry.Key) then
        LEntry.Key.Free;
    FKeyCache.Remove(LOldestKey);
  end;
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

      if ((LKeyKty = 'RSA') or (LKeyKty = 'EC')) and ((AKeyId = '') or (LKeyKid = AKeyId)) then
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
  LFoundKey: TJSONObject;
begin
  LNormalizedIssuer := NormalizeIssuer(AIssuer);

  if IsKidNegCached(LNormalizedIssuer, AKeyId) then
    raise EIAM4DSecurityValidationException.CreateFmt(
      'Public key with kid "%s" recently not found for issuer "%s" (negative cache).',
      [AKeyId, LNormalizedIssuer]);

  if TryGetFromManualKeys(LNormalizedIssuer, AKeyId, Result) then
    Exit;

  if TryGetKeyFromCache(LNormalizedIssuer, AKeyId, Result) then
    Exit;

  LJWKSUri := DiscoverJWKSUri(LNormalizedIssuer);
  LJWKS := FetchJWKS(LJWKSUri);
  try
    LFoundKey := FindKeyInJWKS(LJWKS, AKeyId);
    if Assigned(LFoundKey) then
    begin
      AddKeyToCache(LNormalizedIssuer, AKeyId, LJWKSUri, LFoundKey);
      Result := LFoundKey;
      Exit;
    end;

    LJWKS.Free;
    LJWKS := FetchJWKS(LJWKSUri);

    LFoundKey := FindKeyInJWKS(LJWKS, AKeyId);
    if Assigned(LFoundKey) then
    begin
      AddKeyToCache(LNormalizedIssuer, AKeyId, LJWKSUri, LFoundKey);
      Result := LFoundKey;
      Exit;
    end;
  finally
    if Assigned(LJWKS) then
      LJWKS.Free;
  end;

  PutKidNegCache(LNormalizedIssuer, AKeyId);
  raise EIAM4DSecurityValidationException.CreateFmt(
    'Public key with kid "%s" not found in JWKS for issuer "%s".',
    [AKeyId, LNormalizedIssuer]);
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
  LEntry: TCachedKey;
begin
  if not Assigned(FKeyCache) then
    Exit;

  FCacheLock.BeginWrite;
  try
    for LEntry in FKeyCache.Values do
    begin
      if Assigned(LEntry.Key) then
        LEntry.Key.Free;
    end;
    FKeyCache.Clear;
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
  LKeysArray: TJSONArray;
  LKey: TJSONValue;
  LKeyObj: TJSONObject;
  LKeyKid: string;
begin
  try
    LNormalizedIssuer := NormalizeIssuer(AIssuer);
    LJWKSUri := DiscoverJWKSUri(LNormalizedIssuer);
    LJWKS := FetchJWKS(LJWKSUri);
    try
      LKeysArray := LJWKS.GetValue<TJSONArray>('keys');
      if Assigned(LKeysArray) then
      begin
        for LKey in LKeysArray do
        begin
          if (LKey <> nil) and (LKey is TJSONObject) then
          begin
            LKeyObj := LKey as TJSONObject;
            if (LKeyObj.GetValue<string>('kty', '') = 'RSA') or
               (LKeyObj.GetValue<string>('kty', '') = 'EC') then
            begin
              LKeyKid := LKeyObj.GetValue<string>('kid', '');
              AddKeyToCache(LNormalizedIssuer, LKeyKid, LJWKSUri, LKeyObj);
            end;
          end;
        end;
      end;
    finally
      LJWKS.Free;
    end;
  except
    // ignore
  end;
end;

procedure TIAM4DJWKSProvider.SetMaxCachedKeys(ACount: Integer);
begin
  if ACount < 1 then
    raise EIAM4DSecurityValidationException.Create('Max cached keys must be >= 1');

  FCacheLock.BeginWrite;
  try
    FMaxCachedKeys := ACount;
    while FKeyCache.Count > FMaxCachedKeys do
      EvictLRUKey;
  finally
    FCacheLock.EndWrite;
  end;
end;

initialization
  TIAM4DJWKSProvider.FInstanceLock := TCriticalSection.Create;
  TIAM4DJWKSProvider.FInstance := nil;

finalization
  TIAM4DJWKSProvider.ReleaseInstance;
  FreeAndNil(TIAM4DJWKSProvider.FInstanceLock);

end.

