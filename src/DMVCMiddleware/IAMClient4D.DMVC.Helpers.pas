{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.DMVC.Helpers.pas
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

unit IAMClient4D.DMVC.Helpers;

interface

uses
  System.SysUtils,
  System.DateUtils,
  System.JSON,
  System.Generics.Collections,
  MVCFramework,
  IAMClient4D.DMVC.DTO;

type
  /// <summary>
  /// Class helper for TWebContext providing JWT claims access in DMVC controllers.
  /// THREAD-SAFETY: Each HTTP request has its own TWebContext instance.
  /// The Context.Data dictionary is isolated per-request and does not require synchronization.
  /// </summary>
  TIAM4DJWTHelper = class helper for TWebContext
  private
    /// <summary>
    /// Executes a procedure with parsed JWT claims object.
    /// Memory-safe: automatically frees TJSONObject after procedure execution.
    /// </summary>
    procedure ExecuteWithClaims(const AProc: TProc<TJSONObject>);
  public
    /// <summary>
    /// Returns JWT claims from current request context.
    /// THREAD-SAFETY: Each HTTP request has its own TWebContext instance.
    /// The Context.Data dictionary is isolated per-request and does not require synchronization.
    /// Cache keys (CACHE_KEY, KC_CACHE_KEY) are stored in the same Context.Data and are
    /// therefore request-scoped and thread-safe.
    /// </summary>
    function JWT: TIAM4DJWTClaims;

    /// <summary>
    /// Checks if the current request has valid JWT authentication.
    /// </summary>
    function IsAuthenticated: Boolean;

    /// <summary>
    /// Gets custom claim value from JWT payload. Returns empty string if not found.
    /// </summary>
    function GetCustomClaim(const AClaimName: string): string; overload;

    /// <summary>
    /// Gets custom claim value from JWT payload with default fallback.
    /// </summary>
    function GetCustomClaim(const AClaimName, ADefault: string): string; overload;

    /// <summary>
    /// Tries to get custom claim value. Returns True if found, False otherwise.
    /// </summary>
    function TryGetCustomClaim(const AClaimName: string; out AValue: string): Boolean;

    /// <summary>
    /// Gets custom claim as integer with default fallback.
    /// </summary>
    function GetCustomClaimAsInteger(const AClaimName: string; ADefault: Integer = 0): Integer;

    /// <summary>
    /// Gets custom claim as boolean with default fallback.
    /// </summary>
    function GetCustomClaimAsBoolean(const AClaimName: string; ADefault: Boolean = False): Boolean;

    /// <summary>
    /// Gets custom claim as TDateTime (expects Unix timestamp in claim).
    /// Returns 0 if claim not found or invalid.
    /// </summary>
    function GetCustomClaimAsDateTime(const AClaimName: string): TDateTime;

    /// <summary>
    /// Throws HTTP 401 if user is not authenticated.
    /// </summary>
    procedure RequireAuthentication;

    /// <summary>
    /// Throws HTTP 403 if user doesn't have at least one of the specified roles.
    /// </summary>
    procedure RequireAnyRole(const ARoles: TArray<string>);

    /// <summary>
    /// Throws HTTP 403 if user doesn't have all of the specified roles.
    /// </summary>
    procedure RequireAllRoles(const ARoles: TArray<string>);

    /// <summary>
    /// Throws HTTP 403 if user doesn't have the specified scope.
    /// </summary>
    procedure RequireScope(const AScope: string);

    /// <summary>
    /// Returns Keycloak-specific claims (realm_access, resource_access, groups).
    /// THREAD-SAFETY: Same as JWT() method - request-scoped and thread-safe.
    /// </summary>
    function Keycloak: TIAM4DKeycloakClaims;

    /// <summary>
    /// Throws HTTP 403 if user doesn't have the specified Keycloak realm role.
    /// </summary>
    procedure RequireRealmRole(const ARole: string);

    /// <summary>
    /// Throws HTTP 403 if user doesn't have at least one of the specified Keycloak realm roles.
    /// </summary>
    procedure RequireAnyRealmRole(const ARoles: TArray<string>);

    /// <summary>
    /// Throws HTTP 403 if user doesn't belong to the specified Keycloak group.
    /// </summary>
    procedure RequireGroup(const AGroup: string);
  end;

implementation

uses
  System.Hash,
  MVCFramework.Commons,
  IAMClient4D.DMVC.Common;

{ TIAM4DJWTHelper }

/// <summary>
/// Memory-safe helper: Executes a procedure with parsed JWT claims object.
/// Automatically handles TJSONObject lifecycle - no manual Free() required by caller.
/// </summary>
procedure TIAM4DJWTHelper.ExecuteWithClaims(const AProc: TProc<TJSONObject>);
var
  LClaimsJSON: string;
  LJsonObj: TJSONObject;
begin
  if not Self.Data.ContainsKey(CONTEXT_KEY_JWT_CLAIMS) then
    Exit;

  LClaimsJSON := Self.Data[CONTEXT_KEY_JWT_CLAIMS];
  if LClaimsJSON.IsEmpty then
    Exit;

  LJsonObj := TJSONObject.ParseJSONValue(LClaimsJSON) as TJSONObject;
  if not Assigned(LJsonObj) then
    Exit;

  try
    AProc(LJsonObj);
  finally
    LJsonObj.Free;
  end;
end;

function TIAM4DJWTHelper.JWT: TIAM4DJWTClaims;
var
  LCurrentHash: Integer;
  LCachedHash: Integer;
  LJsonObj: TJSONObject;
  LClaims: TIAM4DJWTClaims;
begin
  LClaims := TIAM4DJWTClaims.Empty;

  if Self.Data.ContainsKey(CONTEXT_KEY_JWT_CLAIMS) then
  begin
    LCurrentHash := THashBobJenkins.GetHashValue(Self.Data[CONTEXT_KEY_JWT_CLAIMS]);

    if Self.Data.ContainsKey(CACHE_KEY) and
      TryStrToInt(Self.Data[CACHE_KEY], LCachedHash) and
      (LCurrentHash = LCachedHash) then
    begin
      if Self.Data.ContainsKey(CONTEXT_KEY_STD_JSON) then
      begin
        LJsonObj := TJSONObject.ParseJSONValue(Self.Data[CONTEXT_KEY_STD_JSON]) as TJSONObject;
        if Assigned(LJsonObj) then
          try
            Result := TIAM4DJWTClaims.ParseFromPayload(LJsonObj);
            Exit;
          finally
            LJsonObj.Free;
          end;
      end;
    end;
  end;

  ExecuteWithClaims(
    procedure(LJsonObj: TJSONObject)
    begin
      LClaims := TIAM4DJWTClaims.ParseFromPayload(LJsonObj);

      if Self.Data.ContainsKey(CONTEXT_KEY_JWT_TOKEN) then
        LClaims.RawToken := Self.Data[CONTEXT_KEY_JWT_TOKEN];

      if Self.Data.ContainsKey(CONTEXT_KEY_JWT_CLAIMS) then
        Self.Data[CACHE_KEY] := LCurrentHash.ToString;
    end);

  if not Self.Data.ContainsKey(CONTEXT_KEY_JWT_CLAIMS) then
    Self.Data.Remove(CACHE_KEY);

  Result := LClaims;
end;

function TIAM4DJWTHelper.IsAuthenticated: Boolean;
begin
  Result := Self.Data.ContainsKey(CONTEXT_KEY_JWT_CLAIMS) and
    (Self.Data[CONTEXT_KEY_JWT_CLAIMS] <> '');
end;

function TIAM4DJWTHelper.GetCustomClaim(const AClaimName: string): string;
begin
  Result := GetCustomClaim(AClaimName, '');
end;

function TIAM4DJWTHelper.GetCustomClaim(const AClaimName, ADefault: string): string;
var
  LValue: string;
begin
  LValue := ADefault;
  ExecuteWithClaims(
    procedure(LJsonObj: TJSONObject)
    begin
      if not LJsonObj.TryGetValue<string>(AClaimName, LValue) then
        LValue := ADefault;
    end);
  Result := LValue;
end;

function TIAM4DJWTHelper.TryGetCustomClaim(const AClaimName: string; out AValue: string): Boolean;
var
  LFound: Boolean;
  LValue: string;
begin
  LFound := False;
  LValue := '';
  ExecuteWithClaims(
    procedure(LJsonObj: TJSONObject)
    begin
      LFound := LJsonObj.TryGetValue<string>(AClaimName, LValue);
    end);
  Result := LFound;
  AValue := LValue;
end;

function TIAM4DJWTHelper.GetCustomClaimAsInteger(const AClaimName: string; ADefault: Integer): Integer;
var
  LValue: Integer;
begin
  LValue := ADefault;
  ExecuteWithClaims(
    procedure(LJsonObj: TJSONObject)
    begin
      if not LJsonObj.TryGetValue<Integer>(AClaimName, LValue) then
        LValue := ADefault;
    end);
  Result := LValue;
end;

function TIAM4DJWTHelper.GetCustomClaimAsBoolean(const AClaimName: string; ADefault: Boolean): Boolean;
var
  LValue: Boolean;
begin
  LValue := ADefault;
  ExecuteWithClaims(
    procedure(LJsonObj: TJSONObject)
    begin
      if not LJsonObj.TryGetValue<Boolean>(AClaimName, LValue) then
        LValue := ADefault;
    end);
  Result := LValue;
end;

function TIAM4DJWTHelper.GetCustomClaimAsDateTime(const AClaimName: string): TDateTime;
var
  LUnixTime: Int64;
  LValue: TDateTime;
begin
  LValue := 0;
  ExecuteWithClaims(
    procedure(LJsonObj: TJSONObject)
    begin
      if LJsonObj.TryGetValue<Int64>(AClaimName, LUnixTime) then
        LValue := UnixToDateTime(LUnixTime, True);
    end);
  Result := LValue;
end;

function TIAM4DJWTHelper.Keycloak: TIAM4DKeycloakClaims;
var
  LCurrentHash: Integer;
  LCachedHash: Integer;
  LJsonObj: TJSONObject;
  LClaims: TIAM4DKeycloakClaims;
begin
  LClaims := TIAM4DKeycloakClaims.Empty;

  if Self.Data.ContainsKey(CONTEXT_KEY_JWT_CLAIMS) then
  begin
    LCurrentHash := THashBobJenkins.GetHashValue(Self.Data[CONTEXT_KEY_JWT_CLAIMS]);

    if Self.Data.ContainsKey(KC_CACHE_KEY) and
      TryStrToInt(Self.Data[KC_CACHE_KEY], LCachedHash) and
      (LCurrentHash = LCachedHash) then
    begin
      if Self.Data.ContainsKey(CONTEXT_KEY_KC_JSON) then
      begin
        LJsonObj := TJSONObject.ParseJSONValue(Self.Data[CONTEXT_KEY_KC_JSON]) as TJSONObject;
        if Assigned(LJsonObj) then
          try
            Result := TIAM4DKeycloakClaims.ParseFromPayload(LJsonObj);
            Exit;
          finally
            LJsonObj.Free;
          end;
      end;
    end;
  end;

  ExecuteWithClaims(
    procedure(LJsonObj: TJSONObject)
    begin
      LClaims := TIAM4DKeycloakClaims.ParseFromPayload(LJsonObj);

      if Self.Data.ContainsKey(CONTEXT_KEY_JWT_CLAIMS) then
        Self.Data[KC_CACHE_KEY] := LCurrentHash.ToString;
    end);

  if not Self.Data.ContainsKey(CONTEXT_KEY_JWT_CLAIMS) then
    Self.Data.Remove(KC_CACHE_KEY);

  Result := LClaims;
end;

procedure TIAM4DJWTHelper.RequireAuthentication;
begin
  if not IsAuthenticated then
    raise EMVCException.Create(HTTP_STATUS.Unauthorized, 'Authentication required');
end;

procedure TIAM4DJWTHelper.RequireAnyRole(const ARoles: TArray<string>);
var
  LClaims: TIAM4DJWTClaims;
  LRolesList: string;
begin
  RequireAuthentication;
  LClaims := JWT;
  if not LClaims.HasAnyRole(ARoles) then
  begin
    LRolesList := string.Join(', ', ARoles);
    raise EMVCException.Create(HTTP_STATUS.Forbidden,
      Format('Insufficient permissions: user must have at least one of these roles: [%s]', [LRolesList]));
  end;
end;

procedure TIAM4DJWTHelper.RequireAllRoles(const ARoles: TArray<string>);
var
  LClaims: TIAM4DJWTClaims;
  LRolesList: string;
begin
  RequireAuthentication;
  LClaims := JWT;
  if not LClaims.HasAllRoles(ARoles) then
  begin
    LRolesList := string.Join(', ', ARoles);
    raise EMVCException.Create(HTTP_STATUS.Forbidden,
      Format('Insufficient permissions: user must have all of these roles: [%s]', [LRolesList]));
  end;
end;

procedure TIAM4DJWTHelper.RequireScope(const AScope: string);
var
  LClaims: TIAM4DJWTClaims;
begin
  RequireAuthentication;
  LClaims := JWT;
  if not LClaims.HasScope(AScope) then
    raise EMVCException.Create(HTTP_STATUS.Forbidden,
      Format('Insufficient permissions: required scope "%s" not found', [AScope]));
end;

procedure TIAM4DJWTHelper.RequireRealmRole(const ARole: string);
var
  LKeycloak: TIAM4DKeycloakClaims;
begin
  RequireAuthentication;

  LKeycloak := Keycloak;
  if not LKeycloak.RealmAccess.HasRole(ARole) then
    raise EMVCException.Create(HTTP_STATUS.Forbidden,
      Format('Insufficient permissions: required realm role "%s" not found', [ARole]));
end;

procedure TIAM4DJWTHelper.RequireAnyRealmRole(const ARoles: TArray<string>);
var
  LKeycloak: TIAM4DKeycloakClaims;
  LRolesList: string;
begin
  RequireAuthentication;

  LKeycloak := Keycloak;
  if not LKeycloak.RealmAccess.HasAnyRole(ARoles) then
  begin
    LRolesList := string.Join(', ', ARoles);
    raise EMVCException.Create(HTTP_STATUS.Forbidden,
      Format('Insufficient permissions: user must have at least one of these realm roles: [%s]', [LRolesList]));
  end;
end;

procedure TIAM4DJWTHelper.RequireGroup(const AGroup: string);
var
  LKeycloak: TIAM4DKeycloakClaims;
begin
  RequireAuthentication;

  LKeycloak := Keycloak;
  if not LKeycloak.HasGroup(AGroup) then
    raise EMVCException.Create(HTTP_STATUS.Forbidden,
      Format('Insufficient permissions: required group membership "%s" not found', [AGroup]));
end;

end.