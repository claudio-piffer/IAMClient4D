{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.DMVC.ClaimsTransformation.pas
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

unit IAMClient4D.DMVC.ClaimsTransformation;

interface

uses
  System.SysUtils,
  System.JSON,
  System.SyncObjs,
  System.Generics.Collections,
  MVCFramework;

type
  /// <summary>
  /// Claims transformation: enriches the logged user of a request after its JWT has been validated,
  /// e.g. with the application roles kept in the application database (authentication by the
  /// identity provider, authorization by the application).
  /// </summary>
  /// <remarks>
  /// Called once per request, only for a valid token, after LoggedUser has been populated from the
  /// claims (UserName, Roles, CustomData: 'sub' is the subject of SubjectClaimName).
  /// The token and its claims are not changed: Context.JWT, Context.Keycloak and the claims JSON
  /// keep what the identity provider signed; the Require*Role helpers and DMVC's RequireRoleEndpointFilter read
  /// LoggedUser.Roles. Roles are compared case-sensitively, as Keycloak names them, both by
  /// IAMClient4D and by RequireRoleEndpointFilter (Roles.Contains).
  /// Called concurrently by the server threads: the implementation must be thread-safe.
  /// An exception rejects the request with 503 (temporarily_unavailable): the token is valid, the
  /// source of the data is not available.
  /// </remarks>
  IIAM4DClaimsTransformer = interface
    ['{6B2E9C41-0D7A-4F3B-8E15-A93C27D4F086}']
    /// <param name="AContext">Current request</param>
    /// <param name="AClaims">Validated claims (read only, freed after the call)</param>
    /// <param name="AUser">Logged user to enrich (Roles, CustomData)</param>
    procedure Transform(AContext: TWebContext; const AClaims: TJSONObject; AUser: TMVCUser);
  end;

  /// <summary>
  /// Loads the application roles of a user. ASubject is LoggedUser.CustomData['sub']
  /// (claim SubjectClaimName, default 'sub'): a stable identifier, unlike email or username.
  /// A subject is unique only within its issuer (OIDC Core 2): with tokens of more than one
  /// identity provider, read the issuer from AClaims ('iss') to find the user.
  /// Returns an empty array for a user unknown to the application.
  /// </summary>
  TIAM4DRolesLoader = reference to function(const ASubject: string; const AClaims: TJSONObject): TArray<string>;

  TIAM4DRolesMode = (
    rmMerge,    // token roles + loaded roles
    rmReplace); // loaded roles only: the application is the only source of roles

  /// <summary>
  /// Claims transformer setting LoggedUser.Roles from a roles loader (e.g. a database query),
  /// with an optional in-memory cache per user (issuer and subject: the same subject from two
  /// identity providers is two users, so a transformer can be shared by several bundles).
  /// </summary>
  /// <remarks>
  /// With a cache, a role granted or revoked in the application takes effect within
  /// CacheTTLSeconds, or at once after Invalidate(Issuer, Subject), Invalidate(Subject) or Clear
  /// (a load already running then does not cache what it read).
  /// Without a subject the loader is not called: in rmReplace mode the user gets no roles.
  /// The loader is called outside the cache lock: it may be called more than once for the same
  /// subject when concurrent requests miss the cache together.
  /// </remarks>
  TIAM4DRolesClaimsTransformer = class(TInterfacedObject, IIAM4DClaimsTransformer)
  private
    type
      TCacheEntry = record
        Roles: TArray<string>;
        ExpiresAt: UInt64; // TThread.GetTickCount64
      end;
  private
    FLoader: TIAM4DRolesLoader;
    FMode: TIAM4DRolesMode;
    FCacheTTLMs: UInt64;
    FMaxCacheEntries: Integer;
    FCache: TDictionary<string, TCacheEntry>;
    FLock: TCriticalSection;
    // Grows at each Invalidate or Clear (under FLock): a load that started before one does not
    // store its roles, which may be the revoked ones
    FGeneration: UInt64;

    // Cache key: issuer + #0 + subject (#0 cannot occur in either)
    class function CacheKey(const AIssuer, ASubject: string): string; static;
    function TryGetCached(const AKey: string; out ARoles: TArray<string>; out AGeneration: UInt64): Boolean;
    procedure StoreCached(const AKey: string; const ARoles: TArray<string>; AGeneration: UInt64);
    procedure PurgeExpired(ANow: UInt64);
    procedure DropOldest(ACount: Integer);
  public
    /// <param name="ALoader">Loads the roles of a subject (required)</param>
    /// <param name="AMode">rmMerge keeps the token roles, rmReplace drops them</param>
    /// <param name="ACacheTTLSeconds">Cache duration per subject; 0 = no cache, the loader runs on every request</param>
    /// <param name="AMaxCacheEntries">Subjects kept at most: when full, expired entries are purged first, then an eighth of the oldest</param>
    constructor Create(const ALoader: TIAM4DRolesLoader; AMode: TIAM4DRolesMode = rmReplace;
      ACacheTTLSeconds: Integer = 60; AMaxCacheEntries: Integer = 10000);
    destructor Destroy; override;

    procedure Transform(AContext: TWebContext; const AClaims: TJSONObject; AUser: TMVCUser);

    /// <summary>Drops the cached roles of a subject, for every issuer: call it when its roles change.</summary>
    procedure Invalidate(const ASubject: string); overload;
    /// <summary>Drops the cached roles of the subject of one issuer (claim iss of its tokens).</summary>
    procedure Invalidate(const AIssuer, ASubject: string); overload;
    /// <summary>Drops every cached role.</summary>
    procedure Clear;
    /// <summary>Cached users, issuer and subject (expired entries included until purged).</summary>
    function CacheCount: Integer;

    property Mode: TIAM4DRolesMode read FMode;
  end;

implementation

uses
  System.Classes,
  System.Generics.Defaults,
  IAMClient4D.Exceptions;

{ TIAM4DRolesClaimsTransformer }

constructor TIAM4DRolesClaimsTransformer.Create(const ALoader: TIAM4DRolesLoader; AMode: TIAM4DRolesMode;
  ACacheTTLSeconds: Integer; AMaxCacheEntries: Integer);
begin
  inherited Create;
  if not Assigned(ALoader) then
    raise EIAM4DInvalidConfigurationException.Create('TIAM4DRolesClaimsTransformer: the roles loader is required.');
  if ACacheTTLSeconds < 0 then
    raise EIAM4DInvalidConfigurationException.Create('TIAM4DRolesClaimsTransformer: ACacheTTLSeconds must be 0 or greater.');
  if AMaxCacheEntries < 1 then
    raise EIAM4DInvalidConfigurationException.Create('TIAM4DRolesClaimsTransformer: AMaxCacheEntries must be 1 or greater.');

  FLoader := ALoader;
  FMode := AMode;
  FCacheTTLMs := UInt64(ACacheTTLSeconds) * 1000;
  FMaxCacheEntries := AMaxCacheEntries;
  FCache := TDictionary<string, TCacheEntry>.Create;
  FLock := TCriticalSection.Create;
end;

destructor TIAM4DRolesClaimsTransformer.Destroy;
begin
  FCache.Free;
  FLock.Free;
  inherited;
end;

class function TIAM4DRolesClaimsTransformer.CacheKey(const AIssuer, ASubject: string): string;
begin
  Result := AIssuer + #0 + ASubject;
end;

function TIAM4DRolesClaimsTransformer.TryGetCached(const AKey: string; out ARoles: TArray<string>;
  out AGeneration: UInt64): Boolean;
var
  LEntry: TCacheEntry;
begin
  Result := False;
  ARoles := nil;
  AGeneration := 0;
  if FCacheTTLMs = 0 then
    Exit;

  FLock.Enter;
  try
    AGeneration := FGeneration;
    if FCache.TryGetValue(AKey, LEntry) then
    begin
      if TThread.GetTickCount64 < LEntry.ExpiresAt then
      begin
        ARoles := LEntry.Roles;
        Result := True;
      end
      else
        FCache.Remove(AKey);
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TIAM4DRolesClaimsTransformer.PurgeExpired(ANow: UInt64);
var
  LExpired: TList<string>;
  LPair: TPair<string, TCacheEntry>;
  LSubject: string;
begin
  // Caller holds FLock
  LExpired := TList<string>.Create;
  try
    for LPair in FCache do
      if ANow >= LPair.Value.ExpiresAt then
        LExpired.Add(LPair.Key);
    for LSubject in LExpired do
      FCache.Remove(LSubject);
  finally
    LExpired.Free;
  end;
end;

procedure TIAM4DRolesClaimsTransformer.DropOldest(ACount: Integer);
var
  LPairs: TArray<TPair<string, TCacheEntry>>;
  I: Integer;
begin
  // Caller holds FLock
  LPairs := FCache.ToArray;
  TArray.Sort<TPair<string, TCacheEntry>>(LPairs, TComparer<TPair<string, TCacheEntry>>.Construct(
    function(const A, B: TPair<string, TCacheEntry>): Integer
    begin
      if A.Value.ExpiresAt < B.Value.ExpiresAt then
        Result := -1
      else if A.Value.ExpiresAt > B.Value.ExpiresAt then
        Result := 1
      else
        Result := 0;
    end));
  for I := 0 to ACount - 1 do
  begin
    if I > High(LPairs) then
      Break;
    FCache.Remove(LPairs[I].Key);
  end;
end;

procedure TIAM4DRolesClaimsTransformer.StoreCached(const AKey: string; const ARoles: TArray<string>;
  AGeneration: UInt64);
var
  LEntry: TCacheEntry;
  LNow: UInt64;
begin
  if FCacheTTLMs = 0 then
    Exit;

  LNow := TThread.GetTickCount64;
  LEntry.Roles := Copy(ARoles);
  LEntry.ExpiresAt := LNow + FCacheTTLMs;

  FLock.Enter;
  try
    // Invalidated or cleared during the load: these roles may be stale, the next request reloads
    if FGeneration <> AGeneration then
      Exit;
    if (FCache.Count >= FMaxCacheEntries) and not FCache.ContainsKey(AKey) then
    begin
      PurgeExpired(LNow);
      // Still full: an eighth of the entries, the ones closest to expiry (one TTL for all: the
      // oldest), so one full scan per Max/8 new subjects and the recent ones stay cached
      if FCache.Count >= FMaxCacheEntries then
        DropOldest(FCache.Count - FMaxCacheEntries + 1 + FMaxCacheEntries div 8);
    end;
    FCache.AddOrSetValue(AKey, LEntry);
  finally
    FLock.Leave;
  end;
end;

procedure TIAM4DRolesClaimsTransformer.Transform(AContext: TWebContext; const AClaims: TJSONObject; AUser: TMVCUser);
var
  LSubject, LIssuer, LKey, LRole, LTrimmed, LExisting: string;
  LRoles: TArray<string>;
  LFound: Boolean;
  LGeneration: UInt64;
begin
  LSubject := '';
  LIssuer := '';
  if Assigned(AUser.CustomData) then
  begin
    if not AUser.CustomData.TryGetValue('sub', LSubject) then
      LSubject := '';
    if not AUser.CustomData.TryGetValue('iss', LIssuer) then
      LIssuer := '';
  end;

  if FMode = rmReplace then
    AUser.Roles.Clear;

  if LSubject.IsEmpty then
    Exit;

  // A subject is unique only within its issuer (OIDC Core 2): the key carries both
  LKey := CacheKey(LIssuer, LSubject);
  if not TryGetCached(LKey, LRoles, LGeneration) then
  begin
    // Outside the lock: a slow database must not serialize the other requests
    LRoles := FLoader(LSubject, AClaims);
    StoreCached(LKey, LRoles, LGeneration);
  end;

  // Case-sensitive, as PopulateContext, the Require*Role helpers and RequireRoleEndpointFilter
  for LRole in LRoles do
  begin
    LTrimmed := LRole.Trim;
    if LTrimmed.IsEmpty then
      Continue;
    LFound := False;
    for LExisting in AUser.Roles do
      if LExisting = LTrimmed then
      begin
        LFound := True;
        Break;
      end;
    if not LFound then
      AUser.Roles.Add(LTrimmed);
  end;
end;

procedure TIAM4DRolesClaimsTransformer.Invalidate(const ASubject: string);
var
  LSuffix, LKey: string;
  LKeys: TArray<string>;
begin
  // Every issuer: the keys ending with #0 + subject
  LSuffix := #0 + ASubject;
  FLock.Enter;
  try
    Inc(FGeneration);
    LKeys := FCache.Keys.ToArray;
    for LKey in LKeys do
      if LKey.EndsWith(LSuffix) then
        FCache.Remove(LKey);
  finally
    FLock.Leave;
  end;
end;

procedure TIAM4DRolesClaimsTransformer.Invalidate(const AIssuer, ASubject: string);
begin
  FLock.Enter;
  try
    Inc(FGeneration);
    FCache.Remove(CacheKey(AIssuer, ASubject));
  finally
    FLock.Leave;
  end;
end;

procedure TIAM4DRolesClaimsTransformer.Clear;
begin
  FLock.Enter;
  try
    Inc(FGeneration);
    FCache.Clear;
  finally
    FLock.Leave;
  end;
end;

function TIAM4DRolesClaimsTransformer.CacheCount: Integer;
begin
  FLock.Enter;
  try
    Result := FCache.Count;
  finally
    FLock.Leave;
  end;
end;

end.
