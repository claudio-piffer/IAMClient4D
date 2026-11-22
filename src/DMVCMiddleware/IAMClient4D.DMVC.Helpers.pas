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
    /// Each call parses the claims of the request: keep the result in a local variable.
    /// THREAD-SAFETY: Each HTTP request has its own TWebContext instance.
    /// The Context.Data dictionary is isolated per-request and does not require synchronization.
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
    /// Throws HTTP 401 if user is not authenticated, with a WWW-Authenticate Bearer challenge
    /// (error="invalid_token" when a token was sent), or 503 with Retry-After when the token
    /// could not be validated because the identity provider is unavailable.
    /// </summary>
    procedure RequireAuthentication;

    /// <summary>
    /// Throws HTTP 403 if user doesn't have at least one of the specified roles.
    /// Checks LoggedUser.Roles: RolesClaimName claim, Keycloak realm roles and client roles of Audience/ExpectedAzp.
    /// Roles are compared case-sensitively, as Keycloak names them, and as DMVC's
    /// RequireRoleEndpointFilter does on the same LoggedUser.Roles.
    /// Every 403 of these helpers carries WWW-Authenticate: Bearer error="insufficient_scope" (RFC 6750 3.1)
    /// and the message "Insufficient permissions": the roles, groups or scope required are logged
    /// (warning), never sent to the client. RequireScope keeps the scope in the challenge (RFC 6750 3).
    /// </summary>
    procedure RequireAnyRole(const ARoles: TArray<string>);

    /// <summary>
    /// Throws HTTP 403 if user doesn't have all of the specified roles (same roles as RequireAnyRole).
    /// </summary>
    procedure RequireAllRoles(const ARoles: TArray<string>);

    /// <summary>
    /// Throws HTTP 403 if user doesn't have the specified scope (challenge with scope="AScope").
    /// </summary>
    procedure RequireScope(const AScope: string);

    /// <summary>
    /// Returns Keycloak-specific claims (realm_access, resource_access, groups).
    /// Each call parses the claims of the request: keep the result in a local variable.
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

    /// <summary>
    /// Returns True if the current request was not authenticated (no token or invalid token),
    /// typically indicating a public endpoint. Useful for logging and debugging.
    /// </summary>
    function IsPublicEndpoint: Boolean;
  end;

implementation

uses
  MVCFramework.Commons,
  MVCFramework.Logger,
  IAMClient4D.DMVC.Common;

const
  // The only text of a 403 the client gets: the required roles, groups and scopes are the
  // access policy of the API (logged, not sent)
  FORBIDDEN_MESSAGE = 'Insufficient permissions';

type
  TClaimReader = record
    // A claim name is a key, not a JSON path: TJSONObject.TryGetValue<T>(Path) splits it on '.' and '['
    // (e.g. https://app.example.com/tenant, the custom claims of Auth0 and Okta)
    class function TryGet<T>(AClaims: TJSONObject; const AName: string; out AValue: T): Boolean; static;
  end;

class function TClaimReader.TryGet<T>(AClaims: TJSONObject; const AName: string; out AValue: T): Boolean;
var
  LValue: TJSONValue;
begin
  LValue := AClaims.Values[AName];
  Result := Assigned(LValue) and LValue.TryGetValue<T>(AValue);
end;

function HasUserRole(AContext: TWebContext; const ARole: string): Boolean;
var
  LRole: string;
begin
  for LRole in AContext.LoggedUser.Roles do
    if LRole = ARole then
      Exit(True);
  Result := False;
end;

// RFC 6750 3.1: 403 for a valid token lacking the privileges.
// ADetail (what was required) goes to the log only; the scope stays in the challenge (RFC 6750 3)
procedure RaiseForbidden(AContext: TWebContext; const ADetail: string; const AScope: string = '');
begin
  LogW('403 for "' + SanitizeLogText(AContext.LoggedUser.UserName) + '" [' +
    SanitizeLogText(AContext.Request.HTTPMethodAsString + ' ' + AContext.Request.PathInfo) + ']: ' +
    SanitizeLogText(ADetail));
  AContext.Response.SetCustomHeader('WWW-Authenticate',
    BearerChallenge(AContext.Data[CONTEXT_KEY_REALM], 'insufficient_scope', FORBIDDEN_MESSAGE, AScope));
  raise EMVCException.Create(HTTP_STATUS.Forbidden, FORBIDDEN_MESSAGE);
end;

{ TIAM4DJWTHelper }

/// <summary>
/// Memory-safe helper: Executes a procedure with parsed JWT claims object.
/// Automatically handles TJSONObject lifecycle - no manual Free() required by caller.
/// </summary>
procedure TIAM4DJWTHelper.ExecuteWithClaims(const AProc: TProc<TJSONObject>);
var
  LClaimsJSON: string;
  LJsonValue: TJSONValue;
begin
  if not Self.Data.ContainsKey(CONTEXT_KEY_JWT_CLAIMS) then
    Exit;

  LClaimsJSON := Self.Data[CONTEXT_KEY_JWT_CLAIMS];
  if LClaimsJSON.IsEmpty then
    Exit;

  // nil when the text is not JSON; "as TJSONObject" would raise on a JSON value that is not an object
  LJsonValue := TJSONObject.ParseJSONValue(LClaimsJSON);
  try
    if LJsonValue is TJSONObject then
      AProc(TJSONObject(LJsonValue));
  finally
    LJsonValue.Free;
  end;
end;

function TIAM4DJWTHelper.JWT: TIAM4DJWTClaims;
var
  LClaims: TIAM4DJWTClaims;
begin
  LClaims := TIAM4DJWTClaims.Empty;
  ExecuteWithClaims(
    procedure(LJsonObj: TJSONObject)
    begin
      LClaims := TIAM4DJWTClaims.ParseFromPayload(LJsonObj);
      LClaims.RawToken := Self.Data[CONTEXT_KEY_JWT_TOKEN];
    end);
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
      if not TClaimReader.TryGet<string>(LJsonObj, AClaimName, LValue) then
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
      LFound := TClaimReader.TryGet<string>(LJsonObj, AClaimName, LValue);
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
      if not TClaimReader.TryGet<Integer>(LJsonObj, AClaimName, LValue) then
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
      if not TClaimReader.TryGet<Boolean>(LJsonObj, AClaimName, LValue) then
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
      if TClaimReader.TryGet<Int64>(LJsonObj, AClaimName, LUnixTime) then
        LValue := UnixToDateTime(LUnixTime, True);
    end);
  Result := LValue;
end;

function TIAM4DJWTHelper.Keycloak: TIAM4DKeycloakClaims;
var
  LClaims: TIAM4DKeycloakClaims;
begin
  LClaims := TIAM4DKeycloakClaims.Empty;
  ExecuteWithClaims(
    procedure(LJsonObj: TJSONObject)
    begin
      LClaims := TIAM4DKeycloakClaims.ParseFromPayload(LJsonObj);
    end);
  Result := LClaims;
end;

procedure TIAM4DJWTHelper.RequireAuthentication;
var
  LStatus: string;
begin
  if IsAuthenticated then
    Exit;

  LStatus := Self.Data[CONTEXT_KEY_AUTH_STATUS];
  // Token not judged: the identity provider could not be reached
  if LStatus = AUTH_STATUS_UNAVAILABLE then
  begin
    if Self.Data[CONTEXT_KEY_RETRY_AFTER] <> '' then
      Self.Response.SetCustomHeader('Retry-After', Self.Data[CONTEXT_KEY_RETRY_AFTER]);
    raise EMVCException.Create(HTTP_STATUS.ServiceUnavailable, 'Token validation temporarily unavailable');
  end;

  // RFC 6750 3.1: error code only when a token was sent
  if LStatus = AUTH_STATUS_INVALID_TOKEN then
    Self.Response.SetCustomHeader('WWW-Authenticate',
      BearerChallenge(Self.Data[CONTEXT_KEY_REALM], 'invalid_token', 'Invalid or expired JWT token'))
  else
    Self.Response.SetCustomHeader('WWW-Authenticate', BearerChallenge(Self.Data[CONTEXT_KEY_REALM], '', ''));
  raise EMVCException.Create(HTTP_STATUS.Unauthorized, 'Authentication required');
end;

procedure TIAM4DJWTHelper.RequireAnyRole(const ARoles: TArray<string>);
var
  LRole: string;
begin
  RequireAuthentication;
  // LoggedUser.Roles, as DMVC's RequireRoleEndpointFilter (which is case-sensitive, this is not):
  // Keycloak does not emit a top-level "roles" claim by default
  for LRole in ARoles do
    if HasUserRole(Self, LRole) then
      Exit;

  RaiseForbidden(Self, Format('Insufficient permissions: user must have at least one of these roles: [%s]',
    [string.Join(', ', ARoles)]));
end;

procedure TIAM4DJWTHelper.RequireAllRoles(const ARoles: TArray<string>);
var
  LRole: string;
begin
  RequireAuthentication;
  for LRole in ARoles do
    if not HasUserRole(Self, LRole) then
      RaiseForbidden(Self, Format('Insufficient permissions: user must have all of these roles: [%s]',
        [string.Join(', ', ARoles)]));
end;

procedure TIAM4DJWTHelper.RequireScope(const AScope: string);
var
  LClaims: TIAM4DJWTClaims;
begin
  RequireAuthentication;
  LClaims := JWT;
  if not LClaims.HasScope(AScope) then
    RaiseForbidden(Self, Format('Insufficient permissions: required scope "%s" not found', [AScope]), AScope);
end;

procedure TIAM4DJWTHelper.RequireRealmRole(const ARole: string);
var
  LKeycloak: TIAM4DKeycloakClaims;
begin
  RequireAuthentication;

  LKeycloak := Keycloak;
  if not LKeycloak.RealmAccess.HasRole(ARole) then
    RaiseForbidden(Self, Format('Insufficient permissions: required realm role "%s" not found', [ARole]));
end;

procedure TIAM4DJWTHelper.RequireAnyRealmRole(const ARoles: TArray<string>);
var
  LKeycloak: TIAM4DKeycloakClaims;
begin
  RequireAuthentication;

  LKeycloak := Keycloak;
  if not LKeycloak.RealmAccess.HasAnyRole(ARoles) then
    RaiseForbidden(Self, Format('Insufficient permissions: user must have at least one of these realm roles: [%s]',
      [string.Join(', ', ARoles)]));
end;

procedure TIAM4DJWTHelper.RequireGroup(const AGroup: string);
var
  LKeycloak: TIAM4DKeycloakClaims;
begin
  RequireAuthentication;

  LKeycloak := Keycloak;
  if not LKeycloak.HasGroup(AGroup) then
    RaiseForbidden(Self, Format('Insufficient permissions: required group membership "%s" not found', [AGroup]));
end;

function TIAM4DJWTHelper.IsPublicEndpoint: Boolean;
begin
  Result := not IsAuthenticated;
end;

end.
