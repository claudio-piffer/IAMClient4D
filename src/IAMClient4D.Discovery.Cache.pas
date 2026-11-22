{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Discovery.Cache.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2026 Claudio Piffer
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

  Process-wide cache of the OIDC discovery documents read by the Keycloak client.

  Every Build, BuildAsync and ConfigureAsync fetched the discovery document of the
  realm: a host that creates a client per login (e.g. a DLL validating users) paid a
  blocking HTTP round trip each time. The endpoints of a realm do not change while the
  server runs, so a successful discovery is reused for TimeToLiveSeconds.
}

unit IAMClient4D.Discovery.Cache;

interface

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Generics.Collections,
  IAMClient4D.Core,
  IAMClient4D.Common.Security;

type
  /// <summary>
  /// Process-wide cache of discovery results (well-known endpoints) by realm URL.
  /// </summary>
  /// <remarks>
  /// Enabled by default; only successful discoveries are stored, for TimeToLiveSeconds
  /// (default 3600). The key holds the SSL validation mode, so a strict client never reuses
  /// a document fetched by a client accepting self-signed certificates; a client with pinned
  /// public keys bypasses the cache. Clear forgets every entry (e.g. after moving a realm).
  /// Thread-safe.
  /// </remarks>
  TIAM4DDiscoveryCache = class sealed
  private
    type
      TEntry = record
        Endpoints: TIAM4DWellKnownEndpoints;
        ExpiresAt: UInt64;
      end;
    class var FLock: TCriticalSection;
    class var FItems: TDictionary<string, TEntry>;
    class var FEnabled: Boolean;
    class var FTimeToLiveSeconds: Integer;
    class constructor Create;
    class destructor Destroy;
    class function GetEnabled: Boolean; static;
    class procedure SetEnabled(const AValue: Boolean); static;
    class function GetTimeToLiveSeconds: Integer; static;
    class procedure SetTimeToLiveSeconds(const AValue: Integer); static;
  public
    const
      DEFAULT_TIME_TO_LIVE_SECONDS = 3600;

    /// <summary>Cache key of a realm: realm URL and SSL validation mode</summary>
    class function KeyOf(const ARealmURL: string; ASSLValidationMode: TIAM4DSSLValidationMode): string; static;

    /// <summary>Endpoints stored for AKey and not expired; False when disabled</summary>
    class function TryGet(const AKey: string; out AEndpoints: TIAM4DWellKnownEndpoints): Boolean; static;

    /// <summary>Stores the endpoints of a successful discovery (nothing when disabled)</summary>
    class procedure Put(const AKey: string; const AEndpoints: TIAM4DWellKnownEndpoints); static;

    /// <summary>Forgets every entry</summary>
    class procedure Clear; static;

    /// <summary>Entries stored, expired ones included (diagnostics)</summary>
    class function Count: Integer; static;

    /// <summary>False: every client fetches the discovery document again (entries cleared)</summary>
    class property Enabled: Boolean read GetEnabled write SetEnabled;

    /// <summary>Lifetime of an entry in seconds (greater than 0)</summary>
    class property TimeToLiveSeconds: Integer read GetTimeToLiveSeconds write SetTimeToLiveSeconds;
  end;

implementation

{ TIAM4DDiscoveryCache }

class constructor TIAM4DDiscoveryCache.Create;
begin
  FLock := TCriticalSection.Create;
  FItems := TDictionary<string, TEntry>.Create;
  FEnabled := True;
  FTimeToLiveSeconds := DEFAULT_TIME_TO_LIVE_SECONDS;
end;

class destructor TIAM4DDiscoveryCache.Destroy;
begin
  FItems.Free;
  FLock.Free;
end;

class function TIAM4DDiscoveryCache.KeyOf(const ARealmURL: string;
  ASSLValidationMode: TIAM4DSSLValidationMode): string;
begin
  Result := ARealmURL.TrimRight(['/']) + '|' + IntToStr(Ord(ASSLValidationMode));
end;

class function TIAM4DDiscoveryCache.TryGet(const AKey: string; out AEndpoints: TIAM4DWellKnownEndpoints): Boolean;
var
  LEntry: TEntry;
begin
  Result := False;
  AEndpoints := Default(TIAM4DWellKnownEndpoints);
  FLock.Acquire;
  try
    if not FEnabled or not FItems.TryGetValue(AKey, LEntry) then
      Exit;
    if TThread.GetTickCount64 >= LEntry.ExpiresAt then
    begin
      FItems.Remove(AKey);
      Exit;
    end;
    AEndpoints := LEntry.Endpoints;
    Result := True;
  finally
    FLock.Release;
  end;
end;

class procedure TIAM4DDiscoveryCache.Put(const AKey: string; const AEndpoints: TIAM4DWellKnownEndpoints);
var
  LEntry: TEntry;
begin
  FLock.Acquire;
  try
    if not FEnabled then
      Exit;
    LEntry.Endpoints := AEndpoints;
    LEntry.ExpiresAt := TThread.GetTickCount64 + UInt64(FTimeToLiveSeconds) * 1000;
    FItems.AddOrSetValue(AKey, LEntry);
  finally
    FLock.Release;
  end;
end;

class procedure TIAM4DDiscoveryCache.Clear;
begin
  FLock.Acquire;
  try
    FItems.Clear;
  finally
    FLock.Release;
  end;
end;

class function TIAM4DDiscoveryCache.Count: Integer;
begin
  FLock.Acquire;
  try
    Result := FItems.Count;
  finally
    FLock.Release;
  end;
end;

class function TIAM4DDiscoveryCache.GetEnabled: Boolean;
begin
  FLock.Acquire;
  try
    Result := FEnabled;
  finally
    FLock.Release;
  end;
end;

class procedure TIAM4DDiscoveryCache.SetEnabled(const AValue: Boolean);
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

class function TIAM4DDiscoveryCache.GetTimeToLiveSeconds: Integer;
begin
  FLock.Acquire;
  try
    Result := FTimeToLiveSeconds;
  finally
    FLock.Release;
  end;
end;

class procedure TIAM4DDiscoveryCache.SetTimeToLiveSeconds(const AValue: Integer);
begin
  if AValue <= 0 then
    raise EArgumentOutOfRangeException.Create('Discovery cache time to live must be > 0');
  FLock.Acquire;
  try
    FTimeToLiveSeconds := AValue;
  finally
    FLock.Release;
  end;
end;

end.
