{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.DMVC.DTO.pas
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

unit IAMClient4D.DMVC.DTO;

interface

uses
  System.SysUtils,
  System.DateUtils,
  System.JSON;

type
  /// <summary>
  /// DTO record for standard JWT claims (RFC 7519).
  /// Memory-safe: No manual Free() required.
  /// </summary>
  TIAM4DJWTClaims = record
    /// <summary>
    /// Subject (sub) - unique identifier for the user.
    /// </summary>
    Subject: string;

    /// <summary>
    /// Issuer (iss) - who issued the token.
    /// </summary>
    Issuer: string;

    /// <summary>
    /// Audience (aud) - intended recipient(s).
    /// Always normalized to array.
    /// </summary>
    Audience: TArray<string>;

    /// <summary>
    /// Expiration time (exp) as TDateTime (UTC).
    /// </summary>
    ExpirationTime: TDateTime;

    /// <summary>
    /// Issued at time (iat) as TDateTime (UTC).
    /// </summary>
    IssuedAtTime: TDateTime;

    /// <summary>
    /// Not before time (nbf) as TDateTime (UTC).
    /// </summary>
    NotBeforeTime: TDateTime;

    /// <summary>
    /// JWT ID (jti) - unique token identifier.
    /// </summary>
    JwtId: string;

    /// <summary>
    /// Authorized Party (azp) - OAuth2/OIDC client identifier.
    /// </summary>
    AuthorizedParty: string;

    /// <summary>
    /// Authentication Context Class Reference (acr) - OIDC authentication strength.
    /// </summary>
    Acr: string;

    /// <summary>
    /// Authentication Time (auth_time) as TDateTime (UTC).
    /// </summary>
    AuthTime: TDateTime;

    /// <summary>
    /// Token Type (typ) - Usually "Bearer".
    /// </summary>
    TokenType: string;

    /// <summary>
    /// Session ID (sid) - OIDC session identifier.
    /// </summary>
    SessionId: string;

    /// <summary>
    /// Email address (OpenID Connect standard).
    /// </summary>
    Email: string;

    /// <summary>
    /// Email verified flag (OpenID Connect standard).
    /// </summary>
    EmailVerified: Boolean;

    /// <summary>
    /// Preferred username (OpenID Connect / Keycloak).
    /// </summary>
    PreferredUsername: string;

    /// <summary>
    /// Given name / first name (OpenID Connect standard).
    /// </summary>
    GivenName: string;

    /// <summary>
    /// Family name / last name (OpenID Connect standard).
    /// </summary>
    FamilyName: string;

    /// <summary>
    /// Full name (OpenID Connect standard).
    /// </summary>
    Name: string;

    /// <summary>
    /// Roles array from 'roles' claim (custom/non-standard).
    /// </summary>
    Roles: TArray<string>;

    /// <summary>
    /// Scopes array normalized from 'scope' (OAuth2 standard).
    /// </summary>
    Scopes: TArray<string>;

    /// <summary>
    /// Authentication Methods References (amr) - RFC 8176.
    /// Array of identifiers for authentication methods used.
    /// Common values: "pwd" (password), "user" (user presence/passkey),
    ///   "pin", "fpt" (fingerprint), "hwk" (hardware key), "swk" (software key),
    ///   "otp", "mfa", "sms", "kba" (knowledge-based auth).
    /// </summary>
    Amr: TArray<string>;

    /// <summary>
    /// Raw JWT token string.
    /// </summary>
    RawToken: string;

    /// <summary>
    /// Checks if token is expired based on current time.
    /// </summary>
    function IsExpired: Boolean;

    /// <summary>
    /// Checks if token is not yet valid (nbf > now).
    /// </summary>
    function IsNotYetValid: Boolean;

    /// <summary>
    /// Checks if user has specific role (case-insensitive).
    /// </summary>
    function HasRole(const ARole: string): Boolean;

    /// <summary>
    /// Checks if user has ANY of the specified roles (case-insensitive).
    /// </summary>
    function HasAnyRole(const ARoles: TArray<string>): Boolean;

    /// <summary>
    /// Checks if user has ALL of the specified roles (case-insensitive).
    /// </summary>
    function HasAllRoles(const ARoles: TArray<string>): Boolean;

    /// <summary>
    /// Checks if user has specific scope (case-insensitive).
    /// </summary>
    function HasScope(const AScope: string): Boolean;

    /// <summary>
    /// Checks if specific authentication method was used (case-insensitive).
    /// Use RFC 8176 values: 'pwd', 'user', 'hwk', 'swk', 'otp', 'mfa', etc.
    /// </summary>
    function HasAuthMethod(const AMethod: string): Boolean;

    /// <summary>
    /// Checks if passkey/WebAuthn was used for authentication.
    /// Returns True if AMR contains "user", "hwk", or "swk" (RFC 8176).
    /// </summary>
    function WasPasskeyUsed: Boolean;

    /// <summary>
    /// Checks if multi-factor authentication was used.
    /// Returns True if AMR contains "mfa".
    /// </summary>
    function WasMfaUsed: Boolean;

    /// <summary>
    /// Converts claims to JSON object (aud always array, times ISO-8601 UTC).
    /// Caller must free the returned object.
    /// </summary>
    function ToJSON: TJSONObject;

    /// <summary>
    /// Returns empty/default claims record.
    /// </summary>
    class function Empty: TIAM4DJWTClaims; static;

    /// <summary>
    /// Safe parse from JWT payload (decoded JSON). Missing fields are tolerated.
    /// Times parsed as UTC.
    /// </summary>
    class function ParseFromPayload(const Payload: TJSONObject): TIAM4DJWTClaims; static;
  end;

  /// <summary>
  /// DTO record for Keycloak realm access structure.
  /// Represents realm_access.roles from Keycloak JWT.
  /// </summary>
  TIAM4DKeycloakRealmAccess = record
    Roles: TArray<string>;
    function HasRole(const ARole: string): Boolean;
    function HasAnyRole(const ARoles: TArray<string>): Boolean;
    function ToJSON: TJSONObject;
  end;

  /// <summary>
  /// DTO record for Keycloak client-specific access.
  /// Represents resource_access.{client_id} from Keycloak JWT.
  /// </summary>
  TIAM4DKeycloakClientAccess = record
    ClientID: string;
    Roles: TArray<string>;
    function HasRole(const ARole: string): Boolean;
    function HasAnyRole(const ARoles: TArray<string>): Boolean;
    function ToJSON: TJSONObject;
  end;

  /// <summary>
  /// DTO record for Keycloak-specific JWT structure.
  /// Memory-safe: No manual Free() required.
  /// </summary>
  TIAM4DKeycloakClaims = record
    RealmAccess: TIAM4DKeycloakRealmAccess;
    ResourceAccess: TArray<TIAM4DKeycloakClientAccess>;
    Groups: TArray<string>; // optional
    AllowedOrigins: TArray<string>; // optional

    function GetClientAccess(const AClientID: string): TIAM4DKeycloakClientAccess;
    function HasGroup(const AGroup: string): Boolean;
    function GetAllRoles: TArray<string>; overload;
    function GetAllRoles(const AClientID: string): TArray<string>; overload;
    function ToJSON: TJSONObject;

    class function Empty: TIAM4DKeycloakClaims; static;
    class function ParseFromPayload(const Payload: TJSONObject): TIAM4DKeycloakClaims; static;
  end;

implementation

uses
  System.Generics.Collections,
  IAMClient4D.DMVC.Common;

function JsonGetObject(const Obj: TJSONObject; const Name: string): TJSONObject;
var
  LValue: TJSONValue;
begin
  Result := nil;
  if not Assigned(Obj) then
    Exit;
  LValue := Obj.Values[Name];
  if Assigned(LValue) and (LValue is TJSONObject) then
    Result := TJSONObject(LValue);
end;

function JsonGetArray(const Obj: TJSONObject; const Name: string): TJSONArray;
var
  LValue: TJSONValue;
begin
  Result := nil;
  if not Assigned(Obj) then
    Exit;
  LValue := Obj.Values[Name];
  if Assigned(LValue) and (LValue is TJSONArray) then
    Result := TJSONArray(LValue);
end;

function JsonGetArrayOfStrings(const Obj: TJSONObject; const Name: string): TArray<string>;
var
  LArray: TJSONArray;
  LIndex: Integer;
begin
  SetLength(Result, 0);
  LArray := JsonGetArray(Obj, Name);
  if not Assigned(LArray) then
    Exit;
  SetLength(Result, LArray.Count);
  for LIndex := 0 to LArray.Count - 1 do
    Result[LIndex] := LArray.Items[LIndex].Value;
end;

function JsonGetString(const Obj: TJSONObject; const Name: string; const Default: string = ''): string;
var
  LValue: TJSONValue;
begin
  Result := Default;
  if not Assigned(Obj) then
    Exit;
  LValue := Obj.Values[Name];
  if Assigned(LValue) then
    Result := LValue.Value;
end;

function JsonGetBoolean(const Obj: TJSONObject; const Name: string; const Default: Boolean = False): Boolean;
var
  LValue: TJSONValue;
  LBoolValue: TJSONBool;
begin
  Result := Default;
  if not Assigned(Obj) then
    Exit;
  LValue := Obj.Values[Name];
  if not Assigned(LValue) then
    Exit;

  if LValue is TJSONBool then
  begin
    LBoolValue := TJSONBool(LValue);
    Exit(LBoolValue.AsBoolean);
  end;

  Result := SameText(LValue.Value, 'true') or SameText(LValue.Value, '1');
end;

function JsonGetInt64(const Obj: TJSONObject; const Name: string; const Default: Int64 = 0): Int64;
var
  LValue: TJSONValue;
begin
  Result := Default;
  if not Assigned(Obj) then
    Exit;
  LValue := Obj.Values[Name];
  if not Assigned(LValue) then
    Exit;
  Result := StrToInt64Def(LValue.Value, Default);
end;

function UnixToUTCDateTime(const Secs: Int64): TDateTime;
begin
  if Secs <= 0 then
    Exit(0);

  Result := UnixToDateTime(Secs, True);
end;

function DateTimeToISO8601UTC(const DT: TDateTime): string;
begin
  Result := DateToISO8601(DT, True);
end;

function SplitScopes(const Scope: string): TArray<string>;
var
  LString: string;
begin
  LString := Trim(Scope);
  if LString = '' then
  begin
    SetLength(Result, 0);
    Exit;
  end;
  Result := LString.Split([' '], TStringSplitOptions.ExcludeEmpty);
end;

function TIAM4DJWTClaims.IsExpired: Boolean;
var
  LNowUTC: TDateTime;
begin
  if ExpirationTime <= 0 then
    Exit(False);

  LNowUTC := TTimeZone.Local.ToUniversalTime(Now);
  Result := LNowUTC > ExpirationTime;
end;

function TIAM4DJWTClaims.IsNotYetValid: Boolean;
var
  LNowUTC: TDateTime;
begin
  if NotBeforeTime <= 0 then
    Exit(False);

  LNowUTC := TTimeZone.Local.ToUniversalTime(Now);
  Result := LNowUTC < NotBeforeTime;
end;

function TIAM4DJWTClaims.HasRole(const ARole: string): Boolean;
var
  LIndex: Integer;
begin
  if Length(Roles) = 0 then
    Exit(False);

  for LIndex := 0 to High(Roles) do
  begin
    if CompareText(Roles[LIndex], ARole) = 0 then
      Exit(True);
  end;

  Result := False;
end;

function TIAM4DJWTClaims.HasAnyRole(const ARoles: TArray<string>): Boolean;
var
  LIndexA, LIndexB: Integer;
begin
  if (Length(Roles) = 0) or (Length(ARoles) = 0) then
    Exit(False);

  for LIndexA := 0 to High(ARoles) do
  begin
    for LIndexB := 0 to High(Roles) do
    begin
      if CompareText(Roles[LIndexB], ARoles[LIndexA]) = 0 then
        Exit(True);
    end;
  end;

  Result := False;
end;

function TIAM4DJWTClaims.HasAllRoles(const ARoles: TArray<string>): Boolean;
var
  LIndexA, LIndexB: Integer;
  LFound: Boolean;
begin
  if Length(ARoles) = 0 then
    Exit(True);

  if Length(Roles) = 0 then
    Exit(False);

  for LIndexA := 0 to High(ARoles) do
  begin
    LFound := False;

    for LIndexB := 0 to High(Roles) do
    begin
      if CompareText(Roles[LIndexB], ARoles[LIndexA]) = 0 then
      begin
        LFound := True;
        Break;
      end;
    end;

    if not LFound then
      Exit(False);
  end;

  Result := True;
end;

function TIAM4DJWTClaims.HasScope(const AScope: string): Boolean;
var
  LIndex: Integer;
begin
  if Length(Scopes) = 0 then
    Exit(False);

  for LIndex := 0 to High(Scopes) do
  begin
    if CompareText(Scopes[LIndex], AScope) = 0 then
      Exit(True);
  end;

  Result := False;
end;

function TIAM4DJWTClaims.HasAuthMethod(const AMethod: string): Boolean;
var
  LIndex: Integer;
begin
  if Length(Amr) = 0 then
    Exit(False);

  for LIndex := 0 to High(Amr) do
  begin
    if CompareText(Amr[LIndex], AMethod) = 0 then
      Exit(True);
  end;

  Result := False;
end;

function TIAM4DJWTClaims.WasPasskeyUsed: Boolean;
const
  PASSKEY_AMR_VALUES: array[0..2] of string = ('user', 'hwk', 'swk');
var
  LMethod, LPasskeyMethod: string;
begin
  Result := False;

  if Length(Amr) = 0 then
    Exit;

  for LMethod in Amr do
    for LPasskeyMethod in PASSKEY_AMR_VALUES do
      if CompareText(LMethod, LPasskeyMethod) = 0 then
        Exit(True);
end;

function TIAM4DJWTClaims.WasMfaUsed: Boolean;
begin
  Result := HasAuthMethod('mfa');
end;

function TIAM4DJWTClaims.ToJSON: TJSONObject;
var
  LIndex: Integer;
  LJArr: TJSONArray;
begin
  Result := TJSONObject.Create;

  if not Subject.IsEmpty then
    Result.AddPair('subject', Subject);
  if not Issuer.IsEmpty then
    Result.AddPair('issuer', Issuer);

  if Length(Audience) > 0 then
  begin
    LJArr := TJSONArray.Create;
    for LIndex := 0 to High(Audience) do
      LJArr.Add(Audience[LIndex]);
    Result.AddPair('audience', LJArr);
  end;

  if not JwtId.IsEmpty then
    Result.AddPair('jti', JwtId);
  if not AuthorizedParty.IsEmpty then
    Result.AddPair('azp', AuthorizedParty);
  if not Acr.IsEmpty then
    Result.AddPair('acr', Acr);
  if not TokenType.IsEmpty then
    Result.AddPair('typ', TokenType);
  if not SessionId.IsEmpty then
    Result.AddPair('sid', SessionId);

  if ExpirationTime > 0 then
    Result.AddPair('exp', DateTimeToISO8601UTC(ExpirationTime));
  if IssuedAtTime > 0 then
    Result.AddPair('iat', DateTimeToISO8601UTC(IssuedAtTime));
  if NotBeforeTime > 0 then
    Result.AddPair('nbf', DateTimeToISO8601UTC(NotBeforeTime));
  if AuthTime > 0 then
    Result.AddPair('auth_time', DateTimeToISO8601UTC(AuthTime));

  if not Email.IsEmpty then
    Result.AddPair('email', Email);
  Result.AddPair('email_verified', TJSONBool.Create(EmailVerified));
  if not PreferredUsername.IsEmpty then
    Result.AddPair('preferred_username', PreferredUsername);
  if not GivenName.IsEmpty then
    Result.AddPair('given_name', GivenName);
  if not FamilyName.IsEmpty then
    Result.AddPair('family_name', FamilyName);
  if not Name.IsEmpty then
    Result.AddPair('name', Name);

  if Length(Roles) > 0 then
  begin
    LJArr := TJSONArray.Create;
    for LIndex := 0 to High(Roles) do
      LJArr.Add(Roles[LIndex]);
    Result.AddPair('roles', LJArr);
  end;

  if Length(Scopes) > 0 then
  begin
    LJArr := TJSONArray.Create;
    for LIndex := 0 to High(Scopes) do
      LJArr.Add(Scopes[LIndex]);
    Result.AddPair('scopes', LJArr);
  end;

  if Length(Amr) > 0 then
  begin
    LJArr := TJSONArray.Create;
    for LIndex := 0 to High(Amr) do
      LJArr.Add(Amr[LIndex]);
    Result.AddPair('amr', LJArr);
  end;
end;

class function TIAM4DJWTClaims.Empty: TIAM4DJWTClaims;
begin
  Result := Default(TIAM4DJWTClaims);
end;

class function TIAM4DJWTClaims.ParseFromPayload(const Payload: TJSONObject): TIAM4DJWTClaims;
var
  LAudArr: TJSONArray;
  LAudVal: TJSONValue;
  LIndex: Integer;
  LScopeStr: string;
begin
  Result := TIAM4DJWTClaims.Empty;
  if not Assigned(Payload) then
    Exit;

  Result.Subject := JsonGetString(Payload, 'sub');
  Result.Issuer := JsonGetString(Payload, 'iss');
  Result.JwtId := JsonGetString(Payload, 'jti');
  Result.TokenType := JsonGetString(Payload, 'typ');
  Result.AuthorizedParty := JsonGetString(Payload, 'azp');
  Result.Acr := JsonGetString(Payload, 'acr');
  Result.SessionId := JsonGetString(Payload, 'sid');

  Result.ExpirationTime := UnixToUTCDateTime(JsonGetInt64(Payload, 'exp'));
  Result.IssuedAtTime := UnixToUTCDateTime(JsonGetInt64(Payload, 'iat'));
  Result.NotBeforeTime := UnixToUTCDateTime(JsonGetInt64(Payload, 'nbf'));
  Result.AuthTime := UnixToUTCDateTime(JsonGetInt64(Payload, 'auth_time'));

  Result.Email := JsonGetString(Payload, 'email');
  Result.EmailVerified := JsonGetBoolean(Payload, 'email_verified', False);
  Result.PreferredUsername := JsonGetString(Payload, 'preferred_username');
  Result.GivenName := JsonGetString(Payload, 'given_name');
  Result.FamilyName := JsonGetString(Payload, 'family_name');
  Result.Name := JsonGetString(Payload, 'name');

  SetLength(Result.Audience, 0);
  LAudArr := JsonGetArray(Payload, 'aud');
  if Assigned(LAudArr) then
  begin
    SetLength(Result.Audience, LAudArr.Count);
    for LIndex := 0 to LAudArr.Count - 1 do
      Result.Audience[LIndex] := LAudArr.Items[LIndex].Value;
  end
  else
  begin
    LAudVal := Payload.Values['aud'];
    if Assigned(LAudVal) then
      Result.Audience := TArray<string>.Create(LAudVal.Value);
  end;

  Result.Roles := JsonGetArrayOfStrings(Payload, 'roles');

  LScopeStr := JsonGetString(Payload, 'scope');
  if not LScopeStr.IsEmpty then
    Result.Scopes := SplitScopes(LScopeStr)
  else
    Result.Scopes := JsonGetArrayOfStrings(Payload, 'scope');

  Result.Amr := JsonGetArrayOfStrings(Payload, 'amr');
end;

function TIAM4DKeycloakRealmAccess.HasRole(const ARole: string): Boolean;
var
  LIndex: Integer;
begin
  if Length(Roles) = 0 then
    Exit(False);

  for LIndex := 0 to High(Roles) do
  begin
    if CompareText(Roles[LIndex], ARole) = 0 then
      Exit(True);
  end;

  Result := False;
end;

function TIAM4DKeycloakRealmAccess.HasAnyRole(const ARoles: TArray<string>): Boolean;
var
  LIndexA, LindexB: Integer;
begin
  if (Length(Roles) = 0) or (Length(ARoles) = 0) then
    Exit(False);

  for LIndexA := 0 to High(ARoles) do
  begin
    for LindexB := 0 to High(Roles) do
    begin
      if CompareText(Roles[LindexB], ARoles[LIndexA]) = 0 then
        Exit(True);
    end;
  end;

  Result := False;
end;

function TIAM4DKeycloakRealmAccess.ToJSON: TJSONObject;
var
  LJArr: TJSONArray;
  LRole: string;
begin
  Result := TJSONObject.Create;

  if Length(Roles) > 0 then
  begin
    LJArr := TJSONArray.Create;
    for LRole in Roles do
      LJArr.Add(LRole);
    Result.AddPair('roles', LJArr);
  end;
end;

function TIAM4DKeycloakClientAccess.HasRole(const ARole: string): Boolean;
var
  LIndex: Integer;
begin
  if Length(Roles) = 0 then
    Exit(False);

  for LIndex := 0 to High(Roles) do
  begin
    if CompareText(Roles[LIndex], ARole) = 0 then
      Exit(True);
  end;

  Result := False;
end;

function TIAM4DKeycloakClientAccess.HasAnyRole(const ARoles: TArray<string>): Boolean;
var
  LIndexA, LIndexB: Integer;
begin
  if (Length(Roles) = 0) or (Length(ARoles) = 0) then
    Exit(False);

  for LIndexA := 0 to High(ARoles) do
  begin
    for LIndexB := 0 to High(Roles) do
    begin
      if CompareText(Roles[LIndexB], ARoles[LIndexA]) = 0 then
        Exit(True);
    end;
  end;

  Result := False;
end;

function TIAM4DKeycloakClientAccess.ToJSON: TJSONObject;
var
  LJArr: TJSONArray;
  LRole: string;
begin
  Result := TJSONObject.Create;

  if not ClientID.IsEmpty then
    Result.AddPair('client_id', ClientID);

  if Length(Roles) > 0 then
  begin
    LJArr := TJSONArray.Create;
    for LRole in Roles do
      LJArr.Add(LRole);
    Result.AddPair('roles', LJArr);
  end;
end;

function TIAM4DKeycloakClaims.GetClientAccess(const AClientID: string): TIAM4DKeycloakClientAccess;
var
  LIndex: Integer;
begin
  if Length(ResourceAccess) = 0 then
  begin
    Result.ClientID := AClientID;
    SetLength(Result.Roles, 0);
    Exit;
  end;

  for LIndex := 0 to High(ResourceAccess) do
  begin
    if CompareText(ResourceAccess[LIndex].ClientID, AClientID) = 0 then
      Exit(ResourceAccess[LIndex]);
  end;

  Result.ClientID := AClientID;
  SetLength(Result.Roles, 0);
end;

function TIAM4DKeycloakClaims.HasGroup(const AGroup: string): Boolean;
var
  LIndex: Integer;
begin
  if Length(Groups) = 0 then
    Exit(False);

  for LIndex := 0 to High(Groups) do
  begin
    if CompareText(Groups[LIndex], AGroup) = 0 then
      Exit(True);
  end;

  Result := False;
end;

function TIAM4DKeycloakClaims.GetAllRoles: TArray<string>;
var
  LRoleSet: TDictionary<string, Boolean>;
  LRole: string;
  LAccess: TIAM4DKeycloakClientAccess;
begin
  LRoleSet := TDictionary<string, Boolean>.Create(CaseInsensitiveComparer);
  try
    for LRole in RealmAccess.Roles do
      if not LRoleSet.ContainsKey(LRole) then
        LRoleSet.Add(LRole, True);

    for LAccess in ResourceAccess do
      for LRole in LAccess.Roles do
        if not LRoleSet.ContainsKey(LRole) then
          LRoleSet.Add(LRole, True);

    Result := LRoleSet.Keys.ToArray;
  finally
    LRoleSet.Free;
  end;
end;

function TIAM4DKeycloakClaims.GetAllRoles(const AClientID: string): TArray<string>;
var
  LRoleSet: TDictionary<string, Boolean>;
  LRole: string;
  LClientAccess: TIAM4DKeycloakClientAccess;
begin
  LRoleSet := TDictionary<string, Boolean>.Create(CaseInsensitiveComparer);
  try
    for LRole in RealmAccess.Roles do
      if not LRoleSet.ContainsKey(LRole) then
        LRoleSet.Add(LRole, True);

    LClientAccess := GetClientAccess(AClientID);
    for LRole in LClientAccess.Roles do
      if not LRoleSet.ContainsKey(LRole) then
        LRoleSet.Add(LRole, True);

    Result := LRoleSet.Keys.ToArray;
  finally
    LRoleSet.Free;
  end;
end;

function TIAM4DKeycloakClaims.ToJSON: TJSONObject;
var
  LIndexA, LIndexB: Integer;
  LRealmRolesArray: TJSONArray;
  LResourceAccessObj: TJSONObject;
  LClientObj: TJSONObject;
  LClientRolesArray: TJSONArray;
  LGroupsArray: TJSONArray;
  LOriginsArray: TJSONArray;
begin
  Result := TJSONObject.Create;

  if Length(RealmAccess.Roles) > 0 then
  begin
    LRealmRolesArray := TJSONArray.Create;
    for LIndexA := 0 to High(RealmAccess.Roles) do
      LRealmRolesArray.Add(RealmAccess.Roles[LIndexA]);

    Result.AddPair('realm_roles', LRealmRolesArray);
  end;

  if Length(ResourceAccess) > 0 then
  begin
    LResourceAccessObj := TJSONObject.Create;

    for LIndexA := 0 to High(ResourceAccess) do
    begin
      if Length(ResourceAccess[LIndexA].Roles) > 0 then
      begin
        LClientRolesArray := TJSONArray.Create;
        for LIndexB := 0 to High(ResourceAccess[LIndexA].Roles) do
          LClientRolesArray.Add(ResourceAccess[LIndexA].Roles[LIndexB]);

        LClientObj := TJSONObject.Create;
        LClientObj.AddPair('roles', LClientRolesArray);

        LResourceAccessObj.AddPair(ResourceAccess[LIndexA].ClientID, LClientObj);
      end;
    end;

    Result.AddPair('resource_access', LResourceAccessObj);
  end;

  if Length(Groups) > 0 then
  begin
    LGroupsArray := TJSONArray.Create;
    for LIndexA := 0 to High(Groups) do
      LGroupsArray.Add(Groups[LIndexA]);
    Result.AddPair('groups', LGroupsArray);
  end;

  if Length(AllowedOrigins) > 0 then
  begin
    LOriginsArray := TJSONArray.Create;
    for LIndexA := 0 to High(AllowedOrigins) do
      LOriginsArray.Add(AllowedOrigins[LIndexA]);
    Result.AddPair('allowed_origins', LOriginsArray);
  end;
end;

class function TIAM4DKeycloakClaims.Empty: TIAM4DKeycloakClaims;
begin
  Result := Default(TIAM4DKeycloakClaims);
end;

class function TIAM4DKeycloakClaims.ParseFromPayload(const Payload: TJSONObject): TIAM4DKeycloakClaims;
var
  LRealmObj, LResObj, LClientObj: TJSONObject;
  LPair: TJSONPair;
  LAccess: TIAM4DKeycloakClientAccess;
  LRoles: TArray<string>;
begin
  Result := TIAM4DKeycloakClaims.Empty;
  if not Assigned(Payload) then
    Exit;

  LRealmObj := JsonGetObject(Payload, 'realm_access');
  if Assigned(LRealmObj) then
    Result.RealmAccess.Roles := JsonGetArrayOfStrings(LRealmObj, 'roles');

  LResObj := JsonGetObject(Payload, 'resource_access');
  if Assigned(LResObj) then
  begin
    for LPair in LResObj do
    begin
      LClientObj := LPair.JsonValue as TJSONObject;
      if not Assigned(LClientObj) then
        Continue;

      LRoles := JsonGetArrayOfStrings(LClientObj, 'roles');
      if Length(LRoles) = 0 then
        Continue;

      LAccess.ClientID := LPair.JsonString.Value;
      LAccess.Roles := LRoles;
      Result.ResourceAccess := Result.ResourceAccess + [LAccess];
    end;
  end;

  Result.Groups := JsonGetArrayOfStrings(Payload, 'groups');

  Result.AllowedOrigins := JsonGetArrayOfStrings(Payload, 'allowed-origins');
end;

end.