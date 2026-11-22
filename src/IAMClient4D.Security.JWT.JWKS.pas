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
  IAMClient4D.Core,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// The keys of an issuer cannot be obtained: OIDC discovery or JWKS endpoint unreachable,
  /// failing or invalid. Not a token error: a server answers 503, not 401.
  /// </summary>
  EIAM4DJWKSUnavailableException = class(EIAM4DSecurityValidationException)
  private
    FRetryAfterSeconds: Integer;
  protected
    constructor CreateCopy(ASource: EIAM4DException); override;
  public
    constructor Create(const AMessage: string; ARetryAfterSeconds: Integer = 0);
    /// <summary>Seconds before the provider contacts the identity provider again (0 = unknown).</summary>
    property RetryAfterSeconds: Integer read FRetryAfterSeconds;
  end;

  /// <summary>
  /// Enterprise-grade JWKS provider with automatic discovery, caching, and DoS protection.
  /// </summary>
  /// <remarks>
  /// Fetches public keys from OIDC providers via well-known discovery.
  /// Pattern: Singleton with GetInstance/ReleaseInstance (also supports direct instantiation).
  /// Discovery: Auto-discovers JWKS URI from issuer/.well-known/openid-configuration; the document must
  /// carry the requested issuer (OIDC Discovery 1.0 4.3, trailing "/" ignored). SetJWKSUri skips discovery.
  /// Keys: only RSA/EC keys usable for signatures ("use" absent or "sig", "key_ops" absent or with "verify").
  /// Errors: failures to reach the identity provider raise EIAM4DJWKSUnavailableException.
  /// HTTP: one THTTPClient shared by all issuers. It does not serialize requests (a slow issuer does not
  /// delay the others) and refreshes are rare (one per issuer at a time, at most one per interval).
  /// Each discovery or JWKS request ends within the ResponseTimeout of the HTTP configuration; a timeout
  /// is not retried (TIAM4DHTTPClientFactory.GetWithRetry).
  /// Cache: Thread-safe caching with configurable TTL (default 3600 seconds).
  /// Negative cache: Prevents repeated fetches for non-existent kids (default 60 seconds, at most 1000 entries).
  /// Key rotation: an unknown kid refreshes the JWKS of its issuer, at most once per refresh interval (default 30 seconds).
  /// Single flight: one refresh per issuer at a time; the other callers wait for it or use the keys already cached.
  /// Discovery: the jwks_uri of each issuer is cached (rediscovered after the cache TTL or a failed JWKS fetch).
  /// Stale keys: when the JWKS cannot be refreshed, expired keys stay usable up to 24 hours past the cache TTL.
  /// Stale while revalidate: a cached key past its TTL is returned at once and the JWKS of its issuer is
  /// refreshed on a background thread (one per issuer, at most once per refresh interval): the request does
  /// not wait for the identity provider. The new set replaces the old one, so a kid no longer published
  /// stops validating as soon as the refresh ends. A provider not held through an interface refreshes
  /// in the request instead (the thread keeps a reference to it).
  /// Manual keys: Supports static key configuration for testing (overrides discovery).
  /// Thread-safety: All public methods are thread-safe with TLightweightMREW (Multiple Reader Exclusive Writer).
  /// SSL validation: Configurable modes (strict/self-signed/disabled).
  /// Memory: Returns cloned TJSONObject - caller must free.
  /// </remarks>
  TIAM4DJWKSProvider = class(TInterfacedObject, IIAM4DJWKSProvider, IIAM4DJWKSKeySelector)
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

      /// <summary>
      /// Discovery result and JWKS refresh state of an issuer.
      /// </summary>
      TIssuerState = record
        JWKSUri: string;
        DiscoveredAt: TDateTime;
        LastRefreshAt: TDateTime;
        LastError: string;
        RefreshInProgress: Boolean;
      end;
    const
      DEFAULT_MAX_CACHED_KEYS = 100; 
      DEFAULT_MIN_REFRESH_INTERVAL_SECONDS = 30;
      DEFAULT_MAX_NEGATIVE_KID_ENTRIES = 1000;
      MAX_ISSUER_STATES = 100;
      MAX_STALE_KEY_SECONDS = 86400;
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
    FMaxNegativeKidEntries: Integer;
    // Guarded by TMonitor on FRefreshSync (lock order: FRefreshSync, then FCacheLock)
    FIssuerStates: TDictionary<string, TIssuerState>;
    FStaticJWKSUris: TDictionary<string, string>;
    FRefreshSync: TObject;
    FMinRefreshIntervalSec: Integer;

    procedure DoInit(const AHTTPConfig: TIAM4DHTTPClientConfig; const ASSLValidator: IIAM4DSSLCertificateValidator);
    function MakeNegKey(const AIssuer, AKeyId: string): string;
    function IsKidNegCached(const AIssuer, AKeyId: string): Boolean;
    procedure PutKidNegCache(const AIssuer, AKeyId: string);
    procedure PruneNegativeKidCache(const ANow: TDateTime; AMaxEntries: Integer);
    function DiscoverJWKSUri(const AIssuer: string): string;
    function FetchJWKS(const AJWKSUri: string): TJSONObject;
    /// <summary>First signing key with AKeyId ('' = any) and, when AFamily is set, of that family</summary>
    function FindKeyInJWKS(const AJWKS: TJSONObject; const AKeyId: string; const AFamily: string = ''): TJSONObject;
    function IsSigningKey(const AKey: TJSONObject): Boolean;
    /// <summary>Key family of an algorithm: 'RSA', 'EC:P-256', 'EC:P-384', 'EC:P-521'; '' if unknown</summary>
    class function KeyFamilyOfAlg(const AAlg: string): string; static;
    /// <summary>Key family of a JWK: 'RSA' or 'EC:' + crv</summary>
    class function KeyFamilyOfKey(const AKey: TJSONObject): string; static;
    /// <summary>Cache id of a kid restricted to a family: kid + #1 + family (#1 is not in a kid)</summary>
    class function KeyLookupId(const AKeyId, AFamily: string): string; static;
    /// <summary>The kid of a lookup id, as shown in messages</summary>
    class function DisplayKeyId(const ALookupId: string): string; static;
    function GetPublicKeyFor(const AIssuer, AKeyId, AFamily: string): TJSONObject;
    function GetManualKeyLookup(const AIssuer, AKeyId: string): string;
    function NormalizeIssuer(const AIssuer: string): string;
    /// <summary>
    /// Raises when the JWKS URI is not HTTP(S), or is plain HTTP for an HTTPS issuer: the
    /// verification keys are not downloaded in clear text.
    /// </summary>
    class procedure CheckJWKSUriScheme(const AIssuer, AJWKSUri: string); static;
    function GetUtcNow: TDateTime;

    procedure ValidateServerCertificate(const Sender: TObject;
      const ARequest: TURLRequest; const Certificate: TCertificate;
      var Accepted: Boolean);

    function MakeKeyLookup(const AIssuer, AKid: string): string;
    function TryGetFromManualKeys(const AIssuer, AKeyId: string; out AKey: TJSONObject): Boolean;
    function TryGetKeyFromCache(const AIssuer, AKeyId: string; AAllowStale: Boolean; out AKey: TJSONObject): Boolean;
    procedure PutKeyInCache(const AIssuer, AKid, AJWKSUri: string; AKey: TJSONObject);
    procedure StoreIssuerKeys(const AIssuer, AJWKSUri: string; const AJWKS: TJSONObject);
    procedure EvictLRUKey;
    function IsKeyUsable(const AEntry: TCachedKey; AAllowStale: Boolean): Boolean;

    function BeginRefresh(const AIssuer, AKeyId: string; out AKey: TJSONObject; out AJWKSUri: string): Boolean;
    procedure EndRefresh(const AIssuer, AJWKSUri: string; ADiscovered: Boolean; const AError: string);
    /// <summary>RefreshKeys and EndRefresh on a thread; False when the provider has no interface reference</summary>
    function StartBackgroundRefresh(const AIssuer, AKeyId, AFamily, AJWKSUri: string): Boolean;
    function RefreshKeys(const AIssuer, AKeyId, AFamily: string; var AJWKSUri: string;
      out ADiscovered: Boolean): TJSONObject;
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
    /// Creates JWKS provider checking certificates with ASSLValidator (its pinned keys included),
    /// shared with the owner: SetSSLValidationMode changes its mode
    /// </summary>
    constructor Create(const AHTTPConfig: TIAM4DHTTPClientConfig;
      const ASSLValidator: IIAM4DSSLCertificateValidator); overload;

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
    ///   - Key rotation: an unknown kid refreshes the JWKS, at most once per refresh interval per issuer
    ///   - Single flight: concurrent callers share one refresh per issuer
    ///   - Thread-safe: Read locks for cache access, write locks only for updates
    ///   - Optimized locking: Uses TLightweightMREW for concurrent reads
    /// AIssuer is used for discovery as is: pass only configured, trusted issuers.
    /// </remarks>
    /// <exception cref="EIAM4DJWKSUnavailableException">
    /// Discovery or JWKS fetch failed and no cached key can be used.
    /// </exception>
    /// <exception cref="EIAM4DSecurityValidationException">
    /// Key not found in the JWKS of the issuer.
    /// </exception>
    function GetPublicKey(const AIssuer, AKeyId: string): TJSONObject;

    /// <summary>
    /// GetPublicKey restricted to the keys whose type fits AAlg (IIAM4DJWKSKeySelector): with
    /// keys of different types under one kid, each token gets the one of its algorithm.
    /// Manual keys (SetManualKey) are returned as they are.
    /// </summary>
    function GetPublicKeyForAlg(const AIssuer, AKeyId, AAlg: string): TJSONObject;

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
    /// Fetches the keys of AIssuer from AJWKSUri, without OIDC discovery (empty AJWKSUri: discovery again).
    /// </summary>
    /// <remarks>
    /// For identity providers without discovery, or a JWKS endpoint reachable at another address.
    /// Kept by ClearCache.
    /// </remarks>
    procedure SetJWKSUri(const AIssuer, AJWKSUri: string);

    /// <summary>
    /// Clears all cached JWKS entries (manual keys and SetJWKSUri unaffected).
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
    /// Best-effort JWKS prefetch for an issuer (fills the cache, never raises).
    /// </summary>
    procedure TryPrefetch(const AIssuer: string);

    /// <summary>
    /// Sets negative-cache TTL (seconds) for missing kid lookups (default 60).
    /// </summary>
    procedure SetNegativeKidTTLSeconds(ASeconds: Integer);

    /// <summary>
    /// Sets maximum number of negative-cache entries (default 1000). When exceeded, expired and then oldest entries are dropped.
    /// </summary>
    procedure SetMaxNegativeKidEntries(ACount: Integer);

    /// <summary>
    /// Sets the minimum interval between two JWKS refreshes of the same issuer (default 30 seconds).
    /// </summary>
    /// <remarks>
    /// Within the interval an unknown kid is rejected without network requests, and a failed refresh is not retried.
    /// 0 disables the limit (every unknown kid reaches the identity provider): not recommended.
    /// </remarks>
    procedure SetMinRefreshIntervalSeconds(ASeconds: Integer);

    /// <summary>
    /// Sets maximum number of cached keys (default 100). When exceeded, LRU eviction occurs.
    /// </summary>
    procedure SetMaxCachedKeys(ACount: Integer);

    /// <summary>
    /// Returns the number of negative-cache entries (diagnostics).
    /// </summary>
    function NegativeKidCacheCount: Integer;
  end;

  /// <summary>
  /// Process-wide JWKS providers, one per HTTP configuration (SSL validation mode and timeouts),
  /// shared by the clients without pinned public keys.
  /// </summary>
  /// <remarks>
  /// A host creating a client per login (uniGUI session, DLL, web request) reuses the keys already
  /// fetched for the realm instead of downloading the JWKS again at the first id_token of each client.
  /// Key rotation, refresh and single flight work as for one provider (TIAM4DJWKSProvider handles
  /// several issuers). A client with pinned public keys uses a provider of its own, with its validator.
  /// Enabled by default; Clear drops the providers (the clients keep the ones they hold). Thread-safe.
  /// </remarks>
  TIAM4DSharedJWKSProviders = class sealed
  private
    class var FLock: TCriticalSection;
    class var FItems: TDictionary<string, IIAM4DJWKSProvider>;
    class var FEnabled: Boolean;
    class function GetEnabled: Boolean; static;
    class procedure SetEnabled(const AValue: Boolean); static;
    class procedure Initialize; static;
    class procedure Finalize; static;
  public
    /// <summary>Key of an HTTP configuration: SSL validation mode and timeouts</summary>
    class function KeyOf(const AHTTPConfig: TIAM4DHTTPClientConfig): string; static;

    /// <summary>
    /// The provider shared by the clients with AHTTPConfig (created at first use), with the jwks_uri
    /// of AIssuer set to AJWKSUri when not empty; nil when disabled.
    /// </summary>
    class function Acquire(const AHTTPConfig: TIAM4DHTTPClientConfig; const AIssuer, AJWKSUri: string): IIAM4DJWKSProvider; static;

    /// <summary>Drops every shared provider</summary>
    class procedure Clear; static;

    /// <summary>Shared providers (diagnostics)</summary>
    class function Count: Integer; static;

    /// <summary>False: every client creates a provider of its own (shared providers dropped)</summary>
    class property Enabled: Boolean read GetEnabled write SetEnabled;
  end;

implementation

uses
  System.Math,
  IAMClient4D.Common.Constants;

{ EIAM4DJWKSUnavailableException }

constructor EIAM4DJWKSUnavailableException.Create(const AMessage: string; ARetryAfterSeconds: Integer);
begin
  inherited Create(AMessage, ecDiscoveryFailed);
  FRetryAfterSeconds := ARetryAfterSeconds;
end;

constructor EIAM4DJWKSUnavailableException.CreateCopy(ASource: EIAM4DException);
begin
  inherited;
  if ASource is EIAM4DJWKSUnavailableException then
    FRetryAfterSeconds := EIAM4DJWKSUnavailableException(ASource).FRetryAfterSeconds;
end;

{ TIAM4DJWKSProvider }

class function TIAM4DJWKSProvider.GetInstance: IIAM4DJWKSProvider;
begin
  if not Assigned(FInstanceLock) then
    raise EIAM4DSecurityValidationException.Create(
      'JWKS singleton not initialized. Unit initialization section has not executed.');

  FInstanceLock.Enter;
  try
    if not Assigned(FInstance) then
      FInstance := TIAM4DJWKSProvider.Create;
    Result := FInstance;
  finally
    FInstanceLock.Leave;
  end;
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

procedure TIAM4DJWKSProvider.DoInit(const AHTTPConfig: TIAM4DHTTPClientConfig;
  const ASSLValidator: IIAM4DSSLCertificateValidator);
begin
  FKeyCache := TDictionary<string, TCachedKey>.Create;
  FMaxCachedKeys := DEFAULT_MAX_CACHED_KEYS;
  FManualKeys := TDictionary<string, TJSONObject>.Create;
  FNegativeKidCache := TDictionary<string, TDateTime>.Create;
  FNegativeTtlSec := 60;
  FMaxNegativeKidEntries := DEFAULT_MAX_NEGATIVE_KID_ENTRIES;
  FIssuerStates := TDictionary<string, TIssuerState>.Create;
  FStaticJWKSUris := TDictionary<string, string>.Create;
  FRefreshSync := TObject.Create;
  FMinRefreshIntervalSec := DEFAULT_MIN_REFRESH_INTERVAL_SECONDS;

  FCacheTTL := 3600;
  if Assigned(ASSLValidator) then
    FSSLValidator := ASSLValidator
  else
    FSSLValidator := TIAM4DSSLCertificateValidator.Create;
  FHTTPConfig := AHTTPConfig;

  FHTTPClient := TIAM4DHTTPClientFactory.CreateHTTPClient(FHTTPConfig);

  SetSSLValidationMode(FHTTPConfig.SSLValidationMode);
end;

constructor TIAM4DJWKSProvider.Create(const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  inherited Create;
  DoInit(AHTTPConfig, nil);
end;

constructor TIAM4DJWKSProvider.Create(const AHTTPConfig: TIAM4DHTTPClientConfig;
  const ASSLValidator: IIAM4DSSLCertificateValidator);
begin
  if not Assigned(ASSLValidator) then
    raise EArgumentNilException.Create('ASSLValidator');
  inherited Create;
  DoInit(AHTTPConfig, ASSLValidator);
end;

constructor TIAM4DJWKSProvider.Create(const ASSLValidationMode: TIAM4DSSLValidationMode);
begin
  inherited Create;
  DoInit(TIAM4DHTTPClientConfig.Create(10000, 10000, ASSLValidationMode), nil);
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
  FreeAndNil(FIssuerStates);
  FreeAndNil(FStaticJWKSUris);
  FreeAndNil(FRefreshSync);
  FreeAndNil(FHTTPClient);

  FSSLValidator := nil;

  inherited;
end;

function TIAM4DJWKSProvider.GetUtcNow: TDateTime;
begin
  Result := TDateTime.NowUTC;
end;

function TIAM4DJWKSProvider.NormalizeIssuer(const AIssuer: string): string;
begin
  Result := AIssuer.TrimRight(['/']);
end;

class procedure TIAM4DJWKSProvider.CheckJWKSUriScheme(const AIssuer, AJWKSUri: string);
var
  LUri: string;
begin
  LUri := AJWKSUri.Trim.ToLower;
  if not (LUri.StartsWith('https://') or LUri.StartsWith('http://')) then
    raise EIAM4DSecurityValidationException.CreateFmt('JWKS URI "%s" is not an HTTP(S) URL.', [AJWKSUri]);
  if AIssuer.Trim.ToLower.StartsWith('https://') and not LUri.StartsWith('https://') then
    raise EIAM4DSecurityValidationException.CreateFmt(
      'JWKS URI "%s" is plain HTTP while the issuer "%s" uses HTTPS.', [AJWKSUri, AIssuer]);
end;

procedure TIAM4DJWKSProvider.PutKidNegCache(const AIssuer, AKeyId: string);
var
  LK: string;
  LNow: TDateTime;
begin
  if AKeyId = '' then
    Exit;

  LK := MakeNegKey(AIssuer, AKeyId);
  LNow := GetUtcNow;
  FCacheLock.BeginWrite;
  try
    if (FNegativeKidCache.Count >= FMaxNegativeKidEntries) and not FNegativeKidCache.ContainsKey(LK) then
      PruneNegativeKidCache(LNow, FMaxNegativeKidEntries - 1);
    FNegativeKidCache.AddOrSetValue(LK, LNow);
  finally
    FCacheLock.EndWrite;
  end;
end;

procedure TIAM4DJWKSProvider.PruneNegativeKidCache(const ANow: TDateTime; AMaxEntries: Integer);
var
  LPair: TPair<string, TDateTime>;
  LExpired: TList<string>;
  LKey, LOldestKey: string;
  LOldest: TDateTime;
begin
  // Called inside the write lock: drops expired entries, then the oldest ones down to AMaxEntries
  LExpired := TList<string>.Create;
  try
    for LPair in FNegativeKidCache do
      if SecondsBetween(ANow, LPair.Value) > FNegativeTtlSec then
        LExpired.Add(LPair.Key);
    for LKey in LExpired do
      FNegativeKidCache.Remove(LKey);
  finally
    LExpired.Free;
  end;

  while FNegativeKidCache.Count > AMaxEntries do
  begin
    LOldest := MaxDateTime;
    LOldestKey := '';
    for LPair in FNegativeKidCache do
      if LPair.Value < LOldest then
      begin
        LOldest := LPair.Value;
        LOldestKey := LPair.Key;
      end;
    if LOldestKey = '' then
      Break;
    FNegativeKidCache.Remove(LOldestKey);
  end;
end;

function TIAM4DJWKSProvider.GetManualKeyLookup(const AIssuer, AKeyId: string): string;
begin
  Result := NormalizeIssuer(AIssuer) + '|' + AKeyId;
end;

function TIAM4DJWKSProvider.IsKeyUsable(const AEntry: TCachedKey; AAllowStale: Boolean): Boolean;
var
  LElapsedSeconds: Int64;
begin
  if not Assigned(AEntry.Key) then
    Exit(False);

  LElapsedSeconds := SecondsBetween(GetUtcNow, AEntry.FetchedAt);
  if AAllowStale then
    Result := LElapsedSeconds <= Int64(FCacheTTL) + MAX_STALE_KEY_SECONDS
  else
    Result := LElapsedSeconds <= FCacheTTL;
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

function TIAM4DJWKSProvider.TryGetKeyFromCache(const AIssuer, AKeyId: string; AAllowStale: Boolean;
  out AKey: TJSONObject): Boolean;
var
  LLookup: string;
  LEntry: TCachedKey;
  LNow: TDateTime;
  LTouch: Boolean;
begin
  Result := False;
  AKey := nil;
  LTouch := False;
  LLookup := MakeKeyLookup(AIssuer, AKeyId);
  LNow := GetUtcNow;

  FCacheLock.BeginRead;
  try
    if FKeyCache.TryGetValue(LLookup, LEntry) then
    begin
      if IsKeyUsable(LEntry, AAllowStale) then
      begin
        AKey := LEntry.Key.Clone as TJSONObject;
        Result := True;
        // LRU to the second: a hit takes the exclusive lock at most once a second per key
        LTouch := MilliSecondsBetween(LNow, LEntry.LastUsedAt) >= 1000;
      end;
    end;
  finally
    FCacheLock.EndRead;
  end;

  if LTouch then
  begin
    FCacheLock.BeginWrite;
    try
      if FKeyCache.TryGetValue(LLookup, LEntry) then
      begin
        LEntry.LastUsedAt := LNow;
        FKeyCache[LLookup] := LEntry;
      end;
    finally
      FCacheLock.EndWrite;
    end;
  end;
end;

procedure TIAM4DJWKSProvider.PutKeyInCache(const AIssuer, AKid, AJWKSUri: string; AKey: TJSONObject);
var
  LEntry: TCachedKey;
  LLookup: string;
  LExisting: TCachedKey;
begin
  // Called inside the write lock
  LLookup := MakeKeyLookup(AIssuer, AKid);

  if FKeyCache.TryGetValue(LLookup, LExisting) then
  begin
    if Assigned(LExisting.Key) then
      LExisting.Key.Free;
    FKeyCache.Remove(LLookup);
  end;

  while FKeyCache.Count >= FMaxCachedKeys do
    EvictLRUKey;

  LEntry.Key := AKey.Clone as TJSONObject;
  LEntry.Issuer := AIssuer;
  LEntry.Kid := AKid;
  LEntry.JWKSUri := AJWKSUri;
  LEntry.FetchedAt := GetUtcNow;
  LEntry.LastUsedAt := LEntry.FetchedAt;

  FKeyCache.Add(LLookup, LEntry);
end;

procedure TIAM4DJWKSProvider.StoreIssuerKeys(const AIssuer, AJWKSUri: string; const AJWKS: TJSONObject);
var
  LPair: TPair<string, TCachedKey>;
  LDropped: TList<string>;
  LLookup, LKid: string;
  LKeys: TJSONArray;
  LValue: TJSONValue;
  LKey: TJSONObject;
  LFamily, LId: string;
begin
  LKeys := AJWKS.GetValue<TJSONArray>('keys', nil);

  FCacheLock.BeginWrite;
  try
    // The fetched set replaces the previous one: keys no longer published stop validating
    LDropped := TList<string>.Create;
    try
      for LPair in FKeyCache do
        if LPair.Value.Issuer = AIssuer then
          LDropped.Add(LPair.Key);
      for LLookup in LDropped do
      begin
        FKeyCache[LLookup].Key.Free;
        FKeyCache.Remove(LLookup);
      end;
    finally
      LDropped.Free;
    end;

    if not Assigned(LKeys) then
      Exit;

    for LValue in LKeys do
    begin
      if not (LValue is TJSONObject) then
        Continue;
      LKey := TJSONObject(LValue);
      if not IsSigningKey(LKey) then
        Continue;

      // The first key wins for each lookup, as in FindKeyInJWKS: kid alone, kid and key family,
      // and the same two without kid (tokens without kid)
      LKid := LKey.GetValue<string>('kid', '');
      LFamily := KeyFamilyOfKey(LKey);
      for LId in [LKid, KeyLookupId(LKid, LFamily)] do
        if not FKeyCache.ContainsKey(MakeKeyLookup(AIssuer, LId)) then
          PutKeyInCache(AIssuer, LId, AJWKSUri, LKey);
      if LKid <> '' then
        for LId in ['', KeyLookupId('', LFamily)] do
          if not FKeyCache.ContainsKey(MakeKeyLookup(AIssuer, LId)) then
            PutKeyInCache(AIssuer, LId, AJWKSUri, LKey);
    end;
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
  LDiscoveryJSON: TJSONObject;
  LIssuerValue: TJSONValue;
  LDiscoveredIssuer: string;
begin
  LDiscoveryUrl := NormalizeIssuer(AIssuer) + '/.well-known/openid-configuration';

  // Every failure here is on the identity provider side, never on the token
  try
    LResponse := TIAM4DHTTPClientFactory.GetWithRetry(FHTTPClient, LDiscoveryUrl, nil, 3);

    if (Integer(LResponse.StatusCode) < 200) or (Integer(LResponse.StatusCode) > 299) then
      raise EIAM4DJWKSUnavailableException.CreateFmt(
        'OpenID discovery failed for issuer "%s": %d %s. URL: %s',
        [AIssuer, Integer(LResponse.StatusCode), LResponse.StatusText, LDiscoveryUrl]);

    LResponseText := LResponse.ContentAsString(TEncoding.UTF8);
    LDiscoveryJSON := TIAM4DJSONUtils.SafeParseJSONObject(LResponseText, 'OpenID discovery response');
    try
      // OpenID Connect Discovery 1.0 4.3: the document must be the one of the requested issuer
      LIssuerValue := LDiscoveryJSON.Values['issuer'];
      if LIssuerValue is TJSONString then
        LDiscoveredIssuer := TJSONString(LIssuerValue).Value
      else
        LDiscoveredIssuer := '';
      if NormalizeIssuer(LDiscoveredIssuer) <> NormalizeIssuer(AIssuer) then
        raise EIAM4DJWKSUnavailableException.CreateFmt(
          'OpenID discovery document of issuer "%s" returned for issuer "%s". URL: %s',
          [LDiscoveredIssuer, AIssuer, LDiscoveryUrl]);

      Result := LDiscoveryJSON.GetValue<string>('jwks_uri', '');
      if Result.Trim.IsEmpty then
        raise EIAM4DJWKSUnavailableException.CreateFmt(
          'OpenID discovery for issuer "%s" succeeded but jwks_uri not found in response. URL: %s',
          [AIssuer, LDiscoveryUrl]);
      CheckJWKSUriScheme(AIssuer, Result);
    finally
      LDiscoveryJSON.Free;
    end;
  except
    on E: EIAM4DJWKSUnavailableException do
      raise EIAM4DJWKSUnavailableException.Create(E.Message, FMinRefreshIntervalSec);
    on E: Exception do
      raise EIAM4DJWKSUnavailableException.Create(Format(
        'Error during OpenID discovery for issuer "%s": %s', [AIssuer, E.Message]), FMinRefreshIntervalSec);
  end;
end;

function TIAM4DJWKSProvider.FetchJWKS(const AJWKSUri: string): TJSONObject;
var
  LResponse: IHTTPResponse;
  LResponseText: string;
begin
  // Every failure here is on the identity provider side, never on the token
  Result := nil;
  try
    LResponse := TIAM4DHTTPClientFactory.GetWithRetry(FHTTPClient, AJWKSUri, nil, 3);

    if (Integer(LResponse.StatusCode) < 200) or (Integer(LResponse.StatusCode) > 299) then
      raise EIAM4DJWKSUnavailableException.CreateFmt(
        'Failed to fetch JWKS: %d %s. URL: %s',
        [Integer(LResponse.StatusCode), LResponse.StatusText, AJWKSUri]);

    LResponseText := LResponse.ContentAsString(TEncoding.UTF8);
    Result := TIAM4DJSONUtils.SafeParseJSONObject(LResponseText, 'JWKS response');
    if not (Result.Values['keys'] is TJSONArray) then
      raise EIAM4DJWKSUnavailableException.CreateFmt(
        'Invalid JWKS format: "keys" array missing. URL: %s', [AJWKSUri]);
  except
    on E: Exception do
    begin
      FreeAndNil(Result);
      if E is EIAM4DJWKSUnavailableException then
        raise EIAM4DJWKSUnavailableException.Create(E.Message, FMinRefreshIntervalSec);
      raise EIAM4DJWKSUnavailableException.Create(Format(
        'Error fetching JWKS from "%s": %s', [AJWKSUri, E.Message]), FMinRefreshIntervalSec);
    end;
  end;
end;

function TIAM4DJWKSProvider.IsSigningKey(const AKey: TJSONObject): Boolean;
var
  LKty: string;
  LUse, LKeyOps, LOp: TJSONValue;
begin
  LKty := AKey.GetValue<string>('kty', '');
  if (LKty <> 'RSA') and (LKty <> 'EC') then
    Exit(False);

  // RFC 7517 4.2: a key with "use" other than "sig" is not for signatures
  LUse := AKey.Values['use'];
  if Assigned(LUse) and not ((LUse is TJSONString) and (TJSONString(LUse).Value = 'sig')) then
    Exit(False);

  // RFC 7517 4.3: with "key_ops", "verify" must be listed
  LKeyOps := AKey.Values['key_ops'];
  if not Assigned(LKeyOps) then
    Exit(True);
  if LKeyOps is TJSONArray then
    for LOp in TJSONArray(LKeyOps) do
      if (LOp is TJSONString) and (TJSONString(LOp).Value = 'verify') then
        Exit(True);
  Result := False;
end;

class function TIAM4DJWKSProvider.KeyFamilyOfAlg(const AAlg: string): string;
begin
  if AAlg.StartsWith('RS') or AAlg.StartsWith('PS') then
    Result := 'RSA'
  else if AAlg = 'ES256' then
    Result := 'EC:P-256'
  else if AAlg = 'ES384' then
    Result := 'EC:P-384'
  else if AAlg = 'ES512' then
    Result := 'EC:P-521'
  else
    Result := '';
end;

class function TIAM4DJWKSProvider.KeyFamilyOfKey(const AKey: TJSONObject): string;
begin
  Result := AKey.GetValue<string>('kty', '');
  if Result = 'EC' then
    Result := 'EC:' + AKey.GetValue<string>('crv', '');
end;

class function TIAM4DJWKSProvider.KeyLookupId(const AKeyId, AFamily: string): string;
begin
  if AFamily = '' then
    Result := AKeyId
  else
    Result := AKeyId + #1 + AFamily;
end;

class function TIAM4DJWKSProvider.DisplayKeyId(const ALookupId: string): string;
var
  LPos: Integer;
begin
  LPos := ALookupId.IndexOf(#1);
  if LPos < 0 then
    Result := ALookupId
  else
    Result := ALookupId.Substring(0, LPos);
end;

function TIAM4DJWKSProvider.FindKeyInJWKS(const AJWKS: TJSONObject;
  const AKeyId: string; const AFamily: string): TJSONObject;
var
  LKeysArray: TJSONArray;
  LKey: TJSONValue;
  LKeyObj: TJSONObject;
begin
  Result := nil;

  if not Assigned(AJWKS) then
    Exit;

  LKeysArray := AJWKS.GetValue<TJSONArray>('keys');
  if not Assigned(LKeysArray) then
    Exit;

  for LKey in LKeysArray do
  begin
    if not (LKey is TJSONObject) then
      Continue;
    LKeyObj := TJSONObject(LKey);
    if IsSigningKey(LKeyObj) and ((AKeyId = '') or (LKeyObj.GetValue<string>('kid', '') = AKeyId)) and
      ((AFamily = '') or (KeyFamilyOfKey(LKeyObj) = AFamily)) then
      Exit(LKeyObj.Clone as TJSONObject);
  end;
end;

function TIAM4DJWKSProvider.BeginRefresh(const AIssuer, AKeyId: string; out AKey: TJSONObject;
  out AJWKSUri: string): Boolean;
var
  LState: TIssuerState;
  LNow: TDateTime;
  LPair: TPair<string, TIssuerState>;
  LOldestIssuer: string;
  LOldest: TDateTime;
  LElapsedMs: Int64;
  LWaitMs, LDeadline, LNowTick: UInt64;
begin
  // True: the caller refreshes the JWKS and then calls EndRefresh. False: AKey is set.
  // Raises when the key is missing and the issuer was refreshed within the interval.
  AKey := nil;
  AJWKSUri := '';
  // A refresh is a discovery and a JWKS request, each bounded by the HTTP timeouts: the wait for
  // another thread's refresh ends with them (plus a margin) instead of never
  LWaitMs := 2 * (UInt64(Max(FHTTPConfig.ConnectionTimeout, 0)) + UInt64(Max(FHTTPConfig.ResponseTimeout, 0))) + 5000;
  LDeadline := TThread.GetTickCount64 + LWaitMs;
  TMonitor.Enter(FRefreshSync);
  try
    while True do
    begin
      if not FIssuerStates.TryGetValue(AIssuer, LState) then
        LState := Default(TIssuerState);
      if not LState.RefreshInProgress then
        Break;

      // Single flight: use the key already cached, even if expired, or wait for the refresh
      if TryGetKeyFromCache(AIssuer, AKeyId, True, AKey) then
        Exit(False);
      LNowTick := TThread.GetTickCount64;
      if LNowTick >= LDeadline then
        raise EIAM4DJWKSUnavailableException.Create(Format(
          'JWKS of issuer "%s" not available: the refresh in progress did not end within %d ms',
          [AIssuer, LWaitMs]), 1);
      TMonitor.Wait(FRefreshSync, Cardinal(LDeadline - LNowTick));
      if TryGetKeyFromCache(AIssuer, AKeyId, False, AKey) then
        Exit(False);
    end;

    LNow := GetUtcNow;
    LElapsedMs := MilliSecondsBetween(LNow, LState.LastRefreshAt);
    if (LState.LastRefreshAt <> 0) and (LElapsedMs < Int64(FMinRefreshIntervalSec) * 1000) then
    begin
      if TryGetKeyFromCache(AIssuer, AKeyId, True, AKey) then
        Exit(False);
      if LState.LastError <> '' then
        raise EIAM4DJWKSUnavailableException.Create(Format(
          'JWKS of issuer "%s" not available, next attempt within %d seconds. Last error: %s',
          [AIssuer, FMinRefreshIntervalSec, LState.LastError]),
          (Int64(FMinRefreshIntervalSec) * 1000 - LElapsedMs + 999) div 1000);
      raise EIAM4DJWKSKeyNotFoundException.CreateFmt(
        'Public key with kid "%s" not found for issuer "%s" (JWKS refreshed less than %d seconds ago).',
        [DisplayKeyId(AKeyId), AIssuer, FMinRefreshIntervalSec], ecJWKSKeyNotFound);
    end;

    // Bounded: drop the idle issuer refreshed least recently
    if (FIssuerStates.Count >= MAX_ISSUER_STATES) and not FIssuerStates.ContainsKey(AIssuer) then
    begin
      LOldestIssuer := '';
      LOldest := MaxDateTime;
      for LPair in FIssuerStates do
        if (not LPair.Value.RefreshInProgress) and (LPair.Value.LastRefreshAt < LOldest) then
        begin
          LOldest := LPair.Value.LastRefreshAt;
          LOldestIssuer := LPair.Key;
        end;
      if LOldestIssuer <> '' then
        FIssuerStates.Remove(LOldestIssuer);
    end;

    if not FStaticJWKSUris.TryGetValue(AIssuer, AJWKSUri) and
       (LState.JWKSUri <> '') and (SecondsBetween(LNow, LState.DiscoveredAt) <= FCacheTTL) then
      AJWKSUri := LState.JWKSUri;
    LState.RefreshInProgress := True;
    LState.LastRefreshAt := LNow;
    FIssuerStates.AddOrSetValue(AIssuer, LState);
    Result := True;
  finally
    TMonitor.Exit(FRefreshSync);
  end;
end;

procedure TIAM4DJWKSProvider.EndRefresh(const AIssuer, AJWKSUri: string; ADiscovered: Boolean;
  const AError: string);
var
  LState: TIssuerState;
begin
  TMonitor.Enter(FRefreshSync);
  try
    if FIssuerStates.TryGetValue(AIssuer, LState) then
    begin
      LState.RefreshInProgress := False;
      LState.LastError := AError;
      // Empty after a failure: the next refresh runs the discovery again
      LState.JWKSUri := AJWKSUri;
      if ADiscovered then
        LState.DiscoveredAt := GetUtcNow;
      FIssuerStates[AIssuer] := LState;
    end;
    TMonitor.PulseAll(FRefreshSync);
  finally
    TMonitor.Exit(FRefreshSync);
  end;
end;

function TIAM4DJWKSProvider.RefreshKeys(const AIssuer, AKeyId, AFamily: string; var AJWKSUri: string;
  out ADiscovered: Boolean): TJSONObject;
var
  LJWKS: TJSONObject;
begin
  ADiscovered := AJWKSUri = '';
  if ADiscovered then
    AJWKSUri := DiscoverJWKSUri(AIssuer);

  LJWKS := FetchJWKS(AJWKSUri);
  try
    StoreIssuerKeys(AIssuer, AJWKSUri, LJWKS);
    Result := FindKeyInJWKS(LJWKS, AKeyId, AFamily);
  finally
    LJWKS.Free;
  end;
end;

function TIAM4DJWKSProvider.GetPublicKey(const AIssuer, AKeyId: string): TJSONObject;
begin
  Result := GetPublicKeyFor(AIssuer, AKeyId, '');
end;

function TIAM4DJWKSProvider.GetPublicKeyForAlg(const AIssuer, AKeyId, AAlg: string): TJSONObject;
begin
  Result := GetPublicKeyFor(AIssuer, AKeyId, KeyFamilyOfAlg(AAlg));
end;

var
  // Background refreshes still running: the finalization waits for them (bounded)
  GBackgroundRefreshes: Integer = 0;

// A refresh started just before the end of the program: waited for at most 5 seconds
procedure WaitForBackgroundRefreshes;
var
  LWait: Integer;
begin
  for LWait := 1 to 500 do
  begin
    if TInterlocked.CompareExchange(GBackgroundRefreshes, 0, 0) = 0 then
      Exit;
    Sleep(10);
  end;
end;

function TIAM4DJWKSProvider.StartBackgroundRefresh(const AIssuer, AKeyId, AFamily, AJWKSUri: string): Boolean;
var
  LSelf: IIAM4DJWKSProvider;
begin
  // A provider used only as an object (RefCount 0) would be freed by the reference of the thread
  if RefCount = 0 then
    Exit(False);
  LSelf := Self;
  TInterlocked.Increment(GBackgroundRefreshes);
  try
    TThread.CreateAnonymousThread(
      procedure
      var
        LJWKSUri: string;
        LDiscovered: Boolean;
      begin
        try
          LJWKSUri := AJWKSUri;
          LDiscovered := False;
          try
            RefreshKeys(AIssuer, AKeyId, AFamily, LJWKSUri, LDiscovered).Free;
            EndRefresh(AIssuer, LJWKSUri, LDiscovered, '');
          except
            // Kept for the next attempt after the interval; the stale keys stay usable
            on E: Exception do
              EndRefresh(AIssuer, '', False, E.Message);
          end;
        finally
          // May free the provider: nothing of it is used afterwards
          LSelf := nil;
          TInterlocked.Decrement(GBackgroundRefreshes);
        end;
      end).Start;
  except
    TInterlocked.Decrement(GBackgroundRefreshes);
    EndRefresh(AIssuer, '', False, 'background refresh not started');
    raise;
  end;
  Result := True;
end;

function TIAM4DJWKSProvider.GetPublicKeyFor(const AIssuer, AKeyId, AFamily: string): TJSONObject;
var
  LNormalizedIssuer: string;
  LJWKSUri: string;
  LDiscovered: Boolean;
  LLookupId: string;
  LStaleKey, LOtherKey: TJSONObject;
begin
  LNormalizedIssuer := NormalizeIssuer(AIssuer);

  if TryGetFromManualKeys(LNormalizedIssuer, AKeyId, Result) then
    Exit;

  // Cache, negative cache and refresh work on the kid restricted to the family
  LLookupId := KeyLookupId(AKeyId, AFamily);

  if TryGetKeyFromCache(LNormalizedIssuer, LLookupId, False, Result) then
    Exit;

  if IsKidNegCached(LNormalizedIssuer, LLookupId) then
    raise EIAM4DJWKSKeyNotFoundException.CreateFmt(
      'Public key with kid "%s" recently not found for issuer "%s" (negative cache).',
      [DisplayKeyId(LLookupId), LNormalizedIssuer], ecJWKSKeyNotFound);

  // Known kid past the TTL: served now, the JWKS refreshed in the background. An unknown kid
  // (rotation) still waits for the refresh below
  if TryGetKeyFromCache(LNormalizedIssuer, LLookupId, True, LStaleKey) then
  begin
    try
      // False: a refresh runs or ran within the interval, the key it returns is the stale one
      if BeginRefresh(LNormalizedIssuer, LLookupId, LOtherKey, LJWKSUri) then
      begin
        if StartBackgroundRefresh(LNormalizedIssuer, AKeyId, AFamily, LJWKSUri) then
          Exit(LStaleKey);
        // No interface reference: refreshed here, the stale key still served when it fails
        LDiscovered := False;
        try
          Result := RefreshKeys(LNormalizedIssuer, AKeyId, AFamily, LJWKSUri, LDiscovered);
        except
          on E: Exception do
          begin
            EndRefresh(LNormalizedIssuer, '', False, E.Message);
            Exit(LStaleKey);
          end;
        end;
        EndRefresh(LNormalizedIssuer, LJWKSUri, LDiscovered, '');
        if Assigned(Result) then
        begin
          FreeAndNil(LStaleKey);
          Exit;
        end;
        // Refreshed, kid no longer published: refused as below
        FreeAndNil(LStaleKey);
        PutKidNegCache(LNormalizedIssuer, LLookupId);
        raise EIAM4DJWKSKeyNotFoundException.Create(DisplayKeyId(LLookupId), LNormalizedIssuer);
      end;
      LOtherKey.Free;
      Exit(LStaleKey);
    except
      LStaleKey.Free;
      raise;
    end;
  end;

  if not BeginRefresh(LNormalizedIssuer, LLookupId, Result, LJWKSUri) then
    Exit;

  LDiscovered := False;
  try
    Result := RefreshKeys(LNormalizedIssuer, AKeyId, AFamily, LJWKSUri, LDiscovered);
  except
    on E: Exception do
    begin
      EndRefresh(LNormalizedIssuer, '', False, E.Message);
      // Identity provider failing: keep using the keys fetched before
      if TryGetKeyFromCache(LNormalizedIssuer, LLookupId, True, Result) then
        Exit;
      raise;
    end;
  end;
  EndRefresh(LNormalizedIssuer, LJWKSUri, LDiscovered, '');

  if Assigned(Result) then
    Exit;

  PutKidNegCache(LNormalizedIssuer, LLookupId);
  raise EIAM4DJWKSKeyNotFoundException.Create(DisplayKeyId(LLookupId), LNormalizedIssuer);
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

procedure TIAM4DJWKSProvider.SetJWKSUri(const AIssuer, AJWKSUri: string);
var
  LIssuer: string;
begin
  LIssuer := NormalizeIssuer(AIssuer);
  if LIssuer.Trim.IsEmpty then
    raise EIAM4DSecurityValidationException.Create('JWKS URI issuer cannot be empty');

  if not AJWKSUri.Trim.IsEmpty then
    CheckJWKSUriScheme(LIssuer, AJWKSUri.Trim);

  TMonitor.Enter(FRefreshSync);
  try
    if AJWKSUri.Trim.IsEmpty then
      FStaticJWKSUris.Remove(LIssuer)
    else
      FStaticJWKSUris.AddOrSetValue(LIssuer, AJWKSUri.Trim);
  finally
    TMonitor.Exit(FRefreshSync);
  end;
end;

procedure TIAM4DJWKSProvider.SetNegativeKidTTLSeconds(ASeconds: Integer);
begin
  if ASeconds < 0 then
    raise EIAM4DSecurityValidationException.Create('Negative kid TTL must be >= 0');
  FNegativeTtlSec := ASeconds;
end;

procedure TIAM4DJWKSProvider.SetMaxNegativeKidEntries(ACount: Integer);
begin
  if ACount < 1 then
    raise EIAM4DSecurityValidationException.Create('Max negative kid entries must be >= 1');

  FCacheLock.BeginWrite;
  try
    FMaxNegativeKidEntries := ACount;
    if FNegativeKidCache.Count > FMaxNegativeKidEntries then
      PruneNegativeKidCache(GetUtcNow, FMaxNegativeKidEntries);
  finally
    FCacheLock.EndWrite;
  end;
end;

procedure TIAM4DJWKSProvider.SetMinRefreshIntervalSeconds(ASeconds: Integer);
begin
  if ASeconds < 0 then
    raise EIAM4DSecurityValidationException.Create('Min refresh interval must be >= 0');

  TMonitor.Enter(FRefreshSync);
  try
    FMinRefreshIntervalSec := ASeconds;
  finally
    TMonitor.Exit(FRefreshSync);
  end;
end;

function TIAM4DJWKSProvider.NegativeKidCacheCount: Integer;
begin
  FCacheLock.BeginRead;
  try
    Result := FNegativeKidCache.Count;
  finally
    FCacheLock.EndRead;
  end;
end;

procedure TIAM4DJWKSProvider.ClearCache;
var
  LEntry: TCachedKey;
  LPair: TPair<string, TIssuerState>;
  LIdle: TList<string>;
  LIssuer: string;
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

    if Assigned(FNegativeKidCache) then
      FNegativeKidCache.Clear;
  finally
    FCacheLock.EndWrite;
  end;

  // Discovery results and refresh intervals too: the next lookup fetches at once
  TMonitor.Enter(FRefreshSync);
  try
    LIdle := TList<string>.Create;
    try
      for LPair in FIssuerStates do
        if not LPair.Value.RefreshInProgress then
          LIdle.Add(LPair.Key);
      for LIssuer in LIdle do
        FIssuerStates.Remove(LIssuer);
    finally
      LIdle.Free;
    end;
  finally
    TMonitor.Exit(FRefreshSync);
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
    if TIAM4DHTTPClientSSLHelper.IsCallbackNeeded(AMode, FSSLValidator) then
      FHTTPClient.OnValidateServerCertificate := ValidateServerCertificate
    else
      FHTTPClient.OnValidateServerCertificate := nil;
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
  Accepted := FSSLValidator.ValidateCertificate(Certificate, Accepted);
end;

procedure TIAM4DJWKSProvider.TryPrefetch(const AIssuer: string);
begin
  // The lookup without kid refreshes the whole key set when it is not cached
  try
    GetPublicKey(AIssuer, '').Free;
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

{ TIAM4DSharedJWKSProviders }

class procedure TIAM4DSharedJWKSProviders.Initialize;
begin
  FLock := TCriticalSection.Create;
  FItems := TDictionary<string, IIAM4DJWKSProvider>.Create;
  FEnabled := True;
end;

class procedure TIAM4DSharedJWKSProviders.Finalize;
begin
  FreeAndNil(FItems);
  FreeAndNil(FLock);
end;

class function TIAM4DSharedJWKSProviders.KeyOf(const AHTTPConfig: TIAM4DHTTPClientConfig): string;
begin
  Result := Format('%d|%d|%d', [Ord(AHTTPConfig.SSLValidationMode), AHTTPConfig.ConnectionTimeout,
    AHTTPConfig.ResponseTimeout]);
end;

class function TIAM4DSharedJWKSProviders.Acquire(const AHTTPConfig: TIAM4DHTTPClientConfig;
  const AIssuer, AJWKSUri: string): IIAM4DJWKSProvider;
var
  LKey: string;
  LProvider: TIAM4DJWKSProvider;
begin
  Result := nil;
  LKey := KeyOf(AHTTPConfig);
  FLock.Acquire;
  try
    if not FEnabled then
      Exit;
    if not FItems.TryGetValue(LKey, Result) then
    begin
      Result := TIAM4DJWKSProvider.Create(AHTTPConfig);
      FItems.Add(LKey, Result);
    end;
    // jwks_uri of the discovery of the client: no second discovery request
    LProvider := Result as TIAM4DJWKSProvider;
    if not (AIssuer.Trim.IsEmpty or AJWKSUri.Trim.IsEmpty) then
      LProvider.SetJWKSUri(AIssuer, AJWKSUri);
  finally
    FLock.Release;
  end;
end;

class procedure TIAM4DSharedJWKSProviders.Clear;
begin
  FLock.Acquire;
  try
    FItems.Clear;
  finally
    FLock.Release;
  end;
end;

class function TIAM4DSharedJWKSProviders.Count: Integer;
begin
  FLock.Acquire;
  try
    Result := FItems.Count;
  finally
    FLock.Release;
  end;
end;

class function TIAM4DSharedJWKSProviders.GetEnabled: Boolean;
begin
  FLock.Acquire;
  try
    Result := FEnabled;
  finally
    FLock.Release;
  end;
end;

class procedure TIAM4DSharedJWKSProviders.SetEnabled(const AValue: Boolean);
begin
  FLock.Acquire;
  try
    FEnabled := AValue;
    if not AValue then
      FItems.Clear;
  finally
    FLock.Release;
  end;
end;

initialization
  TIAM4DJWKSProvider.FInstanceLock := TCriticalSection.Create;
  TIAM4DJWKSProvider.FInstance := nil;
  TIAM4DSharedJWKSProviders.Initialize;

finalization
  WaitForBackgroundRefreshes;
  TIAM4DSharedJWKSProviders.Finalize;
  TIAM4DJWKSProvider.ReleaseInstance;
  FreeAndNil(TIAM4DJWKSProvider.FInstanceLock);

end.

