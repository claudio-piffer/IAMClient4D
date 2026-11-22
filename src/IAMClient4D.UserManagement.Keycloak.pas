{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.UserManagement.Keycloak.pas
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

unit IAMClient4D.UserManagement.Keycloak;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Generics.Collections,
  System.Net.URLClient,
  System.Net.HttpClient,
  System.NetEncoding,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.UserManagement.Core,
  IAMClient4D.UserManagement.Constants,
  IAMClient4D.UserManagement.Validation,
  IAMClient4D.UserManagement.Helpers,
  IAMClient4D.Common.JSONUtils,
  IAMClient4D.Exceptions,
  IAMClient4D.Admin.Keycloak.Base;

type
  // Moved to IAMClient4D.Admin.Keycloak.Base: aliases keep existing code compiling
  IKeycloakAuthProvider = IAMClient4D.Admin.Keycloak.Base.IKeycloakAuthProvider;
  TClientBasedAuthProvider = IAMClient4D.Admin.Keycloak.Base.TClientBasedAuthProvider;
  TTokenBasedAuthProvider = IAMClient4D.Admin.Keycloak.Base.TTokenBasedAuthProvider;

  /// <summary>
  /// Keycloak Admin API implementation for user management (synchronous).
  /// </summary>
  /// <remarks>
  /// API: Keycloak Admin REST API (/admin/realms/{realm}).
  /// Authentication: Uses access token with admin permissions via auth provider.
  /// HTTP: a pool of HTTP clients per instance (TIAM4DKeycloakAdminBase): connections are reused.
  /// JSON: Automatic serialization/deserialization of Keycloak entities.
  /// Sync: All operations execute synchronously and block until completion.
  /// Use case: Server-side (REST API) where the request is already on a worker thread.
  /// </remarks>
  TIAM4DKeycloakUserManager = class(TIAM4DKeycloakAdminBase, IIAM4DUserManager)
  private
    function GetUsersURL: string;
    function GetUserURL(const AUserID: string): string;
    function GetRealmRolesURL: string;
    function GetGroupsURL: string;

    /// <summary>
    /// Keycloak representation of AUser. AForUpdate: the record is the new state of the profile,
    /// email, first and last name and required actions are sent also when empty (they are cleared);
    /// an empty username is not sent (unchanged). For a create the empty fields are left out.
    /// </summary>
    function UserToJSON(const AUser: TIAM4DUser; const AIncludeCredentials: Boolean = False;
      const AForUpdate: Boolean = False): TJSONObject;
    function JSONToUser(const AJSON: TJSONObject): TIAM4DUser;
    function JSONToRole(const AJSON: TJSONObject): TIAM4DRole; overload;
    function JSONToRole(const AJSON: TJSONObject; const AContainerID: string; const AClientID: string): TIAM4DRole; overload;
    function JSONToGroup(const AJSON: TJSONObject): TIAM4DGroup;
    function JSONToFederatedIdentity(const AJSON: TJSONObject): TIAM4DFederatedIdentity;
    function JSONToUserSession(const AJSON: TJSONObject): TIAM4DUserSession;
    function JSONToRealmClient(const AJSON: TJSONObject): TIAM4DRealmClient;
    function RoleToJSON(const ARole: TIAM4DRole): TJSONObject;

    function ParseAttributesFromJSON(const AJSON: TJSONObject): TArray<TIAM4DUserAttribute>;
    procedure AddAttributesToJSON(const ATargetJSON: TJSONObject; const AAttributes: TArray<TIAM4DUserAttribute>);
    /// <summary>
    /// Internal: GET /admin/realms/{realm}/group-by-path/{path}, one encoded segment per level.
    /// False on 404 or when Keycloak returns a group with another path (e.g. a case-insensitive
    /// database collation).
    /// </summary>
    function TryFetchGroupByPath(const AHTTPClient: THTTPClient; const AGroupPath: string; out AGroup: TIAM4DGroup): Boolean;
    /// <summary>
    /// Internal: adds the groups of AGroups and all their descendants: inline subGroups (Keycloak < 23)
    /// or GET /groups/{id}/children, paged (Keycloak 23+ returns subGroupCount only).
    /// </summary>
    procedure CollectGroups(const AHTTPClient: THTTPClient; const AGroups: TJSONArray; const AList: TList<TIAM4DGroup>);
    procedure CollectChildGroups(const AHTTPClient: THTTPClient; const AGroupID: string; const AList: TList<TIAM4DGroup>);

    /// <summary>
    /// Validates batch operation array size.
    /// Raises EIAM4DException if array is empty or exceeds maximum size.
    /// </summary>
    /// <param name="ACount">Number of items in the batch</param>
    /// <param name="AOperationName">Name of the operation (for error message)</param>
    procedure ValidateBatchSize(const ACount: Integer; const AOperationName: string);

    // ========================================================================
    // Internal Helper Methods - ID-based operations (not exposed in interface)
    // ========================================================================

    /// <summary>
    /// Internal: Retrieves the internal Keycloak client UUID by logical clientId.
    /// </summary>
    function GetClientUUIDByClientID(const AHTTPClient: THTTPClient; const AClientID: string): string;

    /// <summary>
    /// Internal: group ID by path (TryFetchGroupByPath), '' when there is no such group.
    /// </summary>
    function GetGroupIDByPath(const AHTTPClient: THTTPClient; const AGroupPath: string): string;

    /// <summary>
    /// Internal: Retrieves all client roles via GET /admin/realms/{realm}/clients/{id}/roles.
    /// </summary>
    /// <remarks>
    /// Populates ContainerID and ClientID in returned roles for automatic routing in assignment methods.
    /// </remarks>
    function GetClientRoles(const AHTTPClient: THTTPClient; const AContainerID: string; const AClientID: string = ''): TArray<TIAM4DRole>;
    /// <summary>
    /// Realm role ARoleName read by name (one request, not the list of the realm); same name, same
    /// case, or EIAM4DRoleNotFoundException
    /// </summary>
    function FindRealmRole(const ARoleName: string): TIAM4DRole;
    /// <summary>Client role ARoleName of AClientID read by name, as FindRealmRole</summary>
    function FindClientRole(const AClientID, ARoleName: string): TIAM4DRole;

    /// <summary>
    /// Internal: Retrieves client roles assigned to user via GET /admin/realms/{realm}/users/{id}/role-mappings/clients/{id}.
    /// </summary>
    function GetUserClientRoles(const AHTTPClient: THTTPClient; const AUserID: string; const AContainerID: string; const AClientID: string = ''): TArray<TIAM4DRole>;

    /// <summary>
    /// Internal: Assigns client roles to user via POST to role-mappings endpoint.
    /// </summary>
    procedure AssignClientRolesToUser(const AHTTPClient: THTTPClient; const AUserID: string; const AContainerID: string; const ARoles: TArray<TIAM4DRole>); overload;

    /// <summary>
    /// Internal: raises EIAM4DInvalidConfigurationException for the first role without ID, ContainerID
    /// or ClientID (roles not read from Keycloak: the role mapping would answer 404).
    /// </summary>
    class procedure CheckClientRoles(const ARoles: TArray<TIAM4DRole>); static;

    /// <summary>
    /// Internal: one role-mapping POST per client of ARoles (checked by CheckClientRoles), in the order
    /// of their first role.
    /// </summary>
    procedure AssignClientRolesByContainer(const AHTTPClient: THTTPClient; const AUserID: string;
      const ARoles: TArray<TIAM4DRole>);

    /// <summary>
    /// Internal: Removes client roles from user via DELETE to role-mappings endpoint.
    /// </summary>
    procedure RemoveClientRolesFromUser(const AHTTPClient: THTTPClient; const AUserID: string; const AContainerID: string; const ARoles: TArray<TIAM4DRole>);

    /// <summary>
    /// Internal: Checks if user has a specific client role.
    /// </summary>
    function HasClientRole(const AHTTPClient: THTTPClient; const AUserID: string; const AContainerID: string; const ARoleName: string): Boolean;

    /// <summary>
    /// Internal: Adds user to group via PUT to groups endpoint.
    /// </summary>
    procedure AddUserToGroup(const AHTTPClient: THTTPClient; const AUserID: string; const AGroupID: string);

    /// <summary>
    /// Internal: Removes user from group via DELETE to groups endpoint.
    /// </summary>
    procedure RemoveUserFromGroup(const AHTTPClient: THTTPClient; const AUserID: string; const AGroupID: string);

    /// <summary>
    /// Internal: Retrieves users in group via GET /admin/realms/{realm}/groups/{id}/members.
    /// </summary>
    function GetUsersInGroup(const AHTTPClient: THTTPClient; const AGroupID: string; const AFirstResult: Integer = 0; const AMaxResults: Integer = 100): TArray<TIAM4DUser>;

  protected
    // IIAM4DUserManager sync interface implementation
    function CreateUser(const AUser: TIAM4DUser): string;
    function CreateUsers(const AUsers: TArray<TIAM4DUser>; const ACancellationToken: IAsyncOperation = nil): TArray<TIAM4DUsersCreateResult>;
    function GetUser(const AUserID: string): TIAM4DUser;
    function GetUserByUsername(const AUsername: string): TIAM4DUser;
    function TryGetUserByUsername(const AUsername: string): TIAM4DUserTryResult;
    function GetUserByEmail(const AEmail: string): TIAM4DUser;
    function TryGetUserByEmail(const AEmail: string): TIAM4DUserTryResult;
    function GetUsersByIDs(const AUserIDs: TArray<string>; const ACancellationToken: IAsyncOperation = nil): TArray<TIAM4DUserGetResult>;
    procedure UpdateUser(const AUser: TIAM4DUser);
    function UpdateUsers(const AUsers: TArray<TIAM4DUser>; const ACancellationToken: IAsyncOperation = nil): TArray<TIAM4DOperationResult>;
    procedure DeleteUser(const AUserID: string);
    function DeleteUsers(const AUserIDs: TArray<string>; const ACancellationToken: IAsyncOperation = nil): TArray<TIAM4DOperationResult>;
    function SearchUsers(const ACriteria: TIAM4DUserSearchCriteria): TArray<TIAM4DUser>;
    function GetUsersCount: Integer;
    procedure SetPassword(const AUserID: string; const APassword: string; const ATemporary: Boolean = False);
    function SetPasswords(const APasswordResets: TArray<TIAM4DPasswordReset>; const ACancellationToken: IAsyncOperation = nil): TArray<TIAM4DOperationResult>;
    procedure SendPasswordResetEmail(const AUserID: string);
    procedure SendVerifyEmail(const AUserID: string);
    function GetRealmRoles: TArray<TIAM4DRole>;
    function GetUserRoles(const AUserID: string): TArray<TIAM4DRole>;
    procedure AssignRolesToUser(const AUserID: string; const ARoles: TArray<TIAM4DRole>);
    function AssignRolesToUsers(const ARoleAssignments: TArray<TIAM4DRoleAssignment>; const ACancellationToken: IAsyncOperation = nil): TArray<TIAM4DOperationResult>;
    procedure RemoveRolesFromUser(const AUserID: string; const ARoles: TArray<TIAM4DRole>);
    procedure AssignRoleByName(const AUserID: string; const ARoleName: string);
    procedure RemoveRoleByName(const AUserID: string; const ARoleName: string);
    procedure AssignClientRoleByClientID(const AUserID: string; const AClientID: string; const ARoleName: string);
    procedure RemoveClientRoleByClientID(const AUserID: string; const AClientID: string; const ARoleName: string);
    function GetGroups: TArray<TIAM4DGroup>;
    function GetUserGroups(const AUserID: string): TArray<TIAM4DGroup>;
    procedure AddUserToGroupByPath(const AUserID: string; const AGroupPath: string);
    procedure RemoveUserFromGroupByPath(const AUserID: string; const AGroupPath: string);
    procedure LogoutUser(const AUserID: string);
    function GetUserSessions(const AUserID: string): TArray<TIAM4DUserSession>;
    function GetUserSessionCount(const AUserID: string): Integer;
    procedure RevokeUserSession(const AUserID: string; const ASessionID: string);
    function GetUserFederatedIdentities(const AUserID: string): TArray<TIAM4DFederatedIdentity>;
    function IsUserFederated(const AUserID: string): Boolean;
    procedure LinkFederatedIdentity(const AUserID: string; const AFederatedIdentity: TIAM4DFederatedIdentity);
    procedure UnlinkFederatedIdentity(const AUserID: string; const AIdentityProvider: string);
    function GetUserRequiredActions(const AUserID: string): TArray<TIAM4DRequiredAction>;
    procedure SetUserRequiredActions(const AUserID: string; const AActions: TArray<TIAM4DRequiredAction>);
    procedure RemoveUserRequiredActions(const AUserID: string; const AActions: TArray<TIAM4DRequiredAction>);
    function IsUserLocked(const AUserID: string): Boolean;
    procedure UnlockUser(const AUserID: string);
    procedure DisableUser(const AUserID: string);
    procedure EnableUser(const AUserID: string);
    function GetRoleByName(const ARoleName: string): TIAM4DRole;
    function TryGetRoleByName(const ARoleName: string): TIAM4DRoleTryResult;
    function HasRole(const AUserID: string; const ARoleName: string): Boolean;
    function GetUsersWithRole(const ARoleName: string; const AFirstResult: Integer = 0; const AMaxResults: Integer = 100): TArray<TIAM4DUser>;
    function GetGroupByPath(const APath: string): TIAM4DGroup;
    function TryGetGroupByPath(const APath: string): TIAM4DGroupTryResult;
    function IsMemberOfGroup(const AUserID: string; const AGroupPath: string): Boolean;
    function GetUsersInGroupByPath(const AGroupPath: string; const AFirstResult: Integer = 0; const AMaxResults: Integer = 100): TArray<TIAM4DUser>;
    function GetClientRolesByClientID(const AClientID: string): TArray<TIAM4DRole>;
    function GetUserClientRolesByClientID(const AUserID: string; const AClientID: string): TArray<TIAM4DRole>;
    procedure AssignClientRolesToUser(const AUserID: string; const ARoles: TArray<TIAM4DRole>); overload;
    function AssignClientRolesToUsers(const ARoleAssignments: TArray<TIAM4DRoleAssignment>; const ACancellationToken: IAsyncOperation = nil): TArray<TIAM4DOperationResult>;
    procedure RemoveClientRolesFromUserByClientID(const AUserID: string; const AClientID: string; const ARoles: TArray<TIAM4DRole>);
    function HasClientRoleByClientID(const AUserID: string; const AClientID: string; const ARoleName: string): Boolean;
    function GetClients: TIAM4DRealmClientArray; overload;
    function GetClientByClientID(const AClientID: string): TIAM4DRealmClient;
    // Internal helper
    procedure SetUserEnabledState(const AUserID: string; const AEnabled: Boolean);

  end;

implementation

uses
  System.NetConsts,
  System.StrUtils,
  IAMClient4D.Common.Constants;

procedure RaiseAmbiguousEmail(const AEmail: string; ACount: Integer);
begin
  raise EIAM4DInvalidUserDataException.Create(Format(
    '%d users have the email %s (realm with duplicate emails allowed): search by username or ID', [ACount, AEmail]));
end;

{ TIAM4DKeycloakUserManager }

function TIAM4DKeycloakUserManager.GetUsersURL: string;
begin
  Result := GetAdminURL + '/users';
end;

function TIAM4DKeycloakUserManager.GetUserURL(const AUserID: string): string;
begin
  Result := GetUsersURL + '/' + EncodePathSegment(AUserID);
end;

function TIAM4DKeycloakUserManager.GetRealmRolesURL: string;
begin
  Result := GetAdminURL + '/roles';
end;

function TIAM4DKeycloakUserManager.GetGroupsURL: string;
begin
  Result := GetAdminURL + '/groups';
end;

// Client lookup by clientId found nothing: a 404 like the other "not found" errors
function ClientNotFound(const AClientID: string): EIAM4DHTTPNotFoundException;
begin
  Result := EIAM4DHTTPNotFoundException.CreateFromResponse(IAM4D_HTTP_STATUS_NOT_FOUND, '',
    Format('Client "%s" not found', [AClientID]));
end;

{ JSON Mapping }

function TIAM4DKeycloakUserManager.UserToJSON(const AUser: TIAM4DUser; const AIncludeCredentials: Boolean;
  const AForUpdate: Boolean): TJSONObject;
var
  LCredentials: TJSONArray;
  LCredential: TJSONObject;
  LActionsArray: TJSONArray;
  LAction: TIAM4DRequiredAction;
  LOther: string;
begin
  Result := TJSONObject.Create;
  try
    if not AUser.ID.IsEmpty then
      Result.AddPair('id', AUser.ID);

    if not (AForUpdate and AUser.Username.IsEmpty) then
      Result.AddPair('username', AUser.Username);

    if AForUpdate or not AUser.Email.IsEmpty then
      Result.AddPair('email', AUser.Email);

    if AForUpdate or not AUser.FirstName.IsEmpty then
      Result.AddPair('firstName', AUser.FirstName);

    if AForUpdate or not AUser.LastName.IsEmpty then
      Result.AddPair('lastName', AUser.LastName);

    Result.AddPair('enabled', TJSONBool.Create(AUser.Enabled));
    Result.AddPair('emailVerified', TJSONBool.Create(AUser.EmailVerified));

    if AUser.CreatedTimestamp > 0 then
      Result.AddPair('createdTimestamp', TJSONNumber.Create(AUser.CreatedTimestamp));

    if AIncludeCredentials and (not AUser.TemporaryPassword.IsEmpty) then
    begin
      LCredentials := TJSONArray.Create;
      LCredential := TJSONObject.Create;
      LCredential.AddPair('type', 'password');
      LCredential.AddPair('value', AUser.TemporaryPassword);
      LCredential.AddPair('temporary', TJSONBool.Create(AUser.RequirePasswordChange));
      LCredentials.Add(LCredential);
      Result.AddPair('credentials', LCredentials);
    end;

    // The actions not in TIAM4DRequiredAction too: an update must not drop them
    if AForUpdate or (Length(AUser.RequiredActions) > 0) or (Length(AUser.OtherRequiredActions) > 0) then
    begin
      LActionsArray := TJSONArray.Create;
      for LAction in AUser.RequiredActions do
        LActionsArray.Add(LAction.ToString);
      for LOther in AUser.OtherRequiredActions do
        LActionsArray.Add(LOther);
      Result.AddPair('requiredActions', LActionsArray);
    end;

    AddAttributesToJSON(Result, AUser.AllAttributes);
  except
    Result.Free;
    raise;
  end;
end;

function TIAM4DKeycloakUserManager.JSONToUser(const AJSON: TJSONObject): TIAM4DUser;
var
  LActionsArray: TJSONArray;
  LActionsList: TList<TIAM4DRequiredAction>;
  LOtherList: TList<string>;
  LActionStr: string;
  LAction: TIAM4DRequiredAction;
begin
  Result.ID := AJSON.GetValue<string>('id', '');
  Result.Username := AJSON.GetValue<string>('username', '');
  Result.Email := AJSON.GetValue<string>('email', '');
  Result.FirstName := AJSON.GetValue<string>('firstName', '');
  Result.LastName := AJSON.GetValue<string>('lastName', '');
  Result.Enabled := AJSON.GetValue<Boolean>('enabled', False);
  Result.EmailVerified := AJSON.GetValue<Boolean>('emailVerified', False);
  Result.CreatedTimestamp := AJSON.GetValue<Int64>('createdTimestamp', 0);
  Result.FederationLink := AJSON.GetValue<string>('federationLink', '');

  Result.AllAttributes := ParseAttributesFromJSON(AJSON);

  // An action not in TIAM4DRequiredAction (Keycloak 24+ VERIFY_PROFILE, webauthn-register, a
  // custom one) goes to OtherRequiredActions: reading the user must not fail
  Result.RequiredActions := nil;
  Result.OtherRequiredActions := nil;
  LActionsArray := TIAM4DJSONHelper.GetArray(AJSON, 'requiredActions');
  if LActionsArray <> nil then
  begin
    LActionsList := TList<TIAM4DRequiredAction>.Create;
    LOtherList := TList<string>.Create;
    try
      for var LIndex := 0 to LActionsArray.Count - 1 do
      begin
        LActionStr := LActionsArray.Items[LIndex].Value;
        if TIAM4DRequiredAction.TryFromString(LActionStr, LAction) then
          LActionsList.Add(LAction)
        else
          LOtherList.Add(LActionStr);
      end;
      Result.RequiredActions := LActionsList.ToArray;
      Result.OtherRequiredActions := LOtherList.ToArray;
    finally
      LOtherList.Free;
      LActionsList.Free;
    end;
  end;
end;

function TIAM4DKeycloakUserManager.JSONToRole(const AJSON: TJSONObject): TIAM4DRole;
begin
  Result.ID := AJSON.GetValue<string>('id', '');
  Result.Name := AJSON.GetValue<string>('name', '');
  Result.Description := AJSON.GetValue<string>('description', '');
  Result.Composite := AJSON.GetValue<Boolean>('composite', False);
  Result.ContainerID := '';
  Result.ClientID := '';
end;

function TIAM4DKeycloakUserManager.JSONToRole(const AJSON: TJSONObject; const AContainerID: string; const AClientID: string): TIAM4DRole;
begin
  Result.ID := AJSON.GetValue<string>('id', '');
  Result.Name := AJSON.GetValue<string>('name', '');
  Result.Description := AJSON.GetValue<string>('description', '');
  Result.Composite := AJSON.GetValue<Boolean>('composite', False);
  Result.ContainerID := AContainerID;
  Result.ClientID := AClientID;
end;

function TIAM4DKeycloakUserManager.JSONToGroup(const AJSON: TJSONObject): TIAM4DGroup;
begin
  Result.ID := AJSON.GetValue<string>('id', '');
  Result.Name := AJSON.GetValue<string>('name', '');
  Result.Path := AJSON.GetValue<string>('path', '');
end;

function TIAM4DKeycloakUserManager.JSONToFederatedIdentity(const AJSON: TJSONObject): TIAM4DFederatedIdentity;
begin
  Result.IdentityProvider := AJSON.GetValue<string>('identityProvider', '');
  Result.UserID := AJSON.GetValue<string>('userId', '');
  Result.UserName := AJSON.GetValue<string>('userName', '');
end;

function TIAM4DKeycloakUserManager.JSONToRealmClient(const AJSON: TJSONObject): TIAM4DRealmClient;
begin
  Result.ID := AJSON.GetValue<string>('id', '');
  Result.ClientID := AJSON.GetValue<string>('clientId', '');
  Result.Name := AJSON.GetValue<string>('name', '');
  Result.Description := AJSON.GetValue<string>('description', '');
  Result.Enabled := AJSON.GetValue<Boolean>('enabled', False);
end;

function TIAM4DKeycloakUserManager.ParseAttributesFromJSON(
  const AJSON: TJSONObject): TArray<TIAM4DUserAttribute>;
var
  LAttributesJSON: TJSONObject;
  LPair: TJSONPair;
  LArray: TJSONArray;
  LValues: TArray<string>;
  LAttrCount: Integer;
  LValue: TJSONValue;
begin
  Result := nil;

  if not AJSON.TryGetValue<TJSONValue>('attributes', LValue) then
    Exit;

  if not (LValue is TJSONObject) then
    Exit;

  LAttributesJSON := LValue as TJSONObject;

  LAttrCount := 0;
  for LPair in LAttributesJSON do
  begin
    if LPair.JsonValue is TJSONArray then
    begin
      LArray := TJSONArray(LPair.JsonValue);

      LValues := TIAM4DJSONHelper.MapArray<string>(LArray,
        function(AValue: TJSONValue): string
        begin
          if AValue is TJSONString then
            Result := AValue.Value
          else
            Result := AValue.ToString;
        end);

      SetLength(Result, LAttrCount + 1);
      Result[LAttrCount].Name := LPair.JsonString.Value;
      Result[LAttrCount].Values := LValues;
      Inc(LAttrCount);
    end;
  end;
end;

procedure TIAM4DKeycloakUserManager.AddAttributesToJSON(
  const ATargetJSON: TJSONObject;
  const AAttributes: TArray<TIAM4DUserAttribute>);
var
  LAttributesJSON: TJSONObject;
  LAttr: TIAM4DUserAttribute;
  LArray: TJSONArray;
  LValue: string;
begin
  if Length(AAttributes) = 0 then
    Exit;

  LAttributesJSON := TJSONObject.Create;
  try
    for LAttr in AAttributes do
    begin
      LArray := TJSONArray.Create;
      for LValue in LAttr.Values do
        LArray.Add(LValue);

      LAttributesJSON.AddPair(LAttr.Name, LArray);
    end;

    ATargetJSON.AddPair('attributes', LAttributesJSON);
  except
    LAttributesJSON.Free;
    raise;
  end;
end;

function TIAM4DKeycloakUserManager.TryFetchGroupByPath(const AHTTPClient: THTTPClient; const AGroupPath: string;
  out AGroup: TIAM4DGroup): Boolean;
var
  LPath, LURL, LSegment: string;
  LResponse: IHTTPResponse;
  LGroupObj: TJSONObject;
begin
  AGroup := Default(TIAM4DGroup);
  LPath := AGroupPath;
  if not LPath.StartsWith('/') then
    LPath := '/' + LPath;

  // Segments encoded one by one, '/' kept as the separator (a '/' inside a name is '~/' in Keycloak 24+)
  LURL := GetAdminURL + '/group-by-path';
  for LSegment in LPath.Substring(1).Split(['/']) do
    LURL := LURL + '/' + EncodePathSegment(LSegment);

  LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
  if LResponse.StatusCode = IAM4D_HTTP_STATUS_NOT_FOUND then
    Exit(False);
  EnsureResponseSuccess(LResponse, 'Get group by path');

  LGroupObj := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'group response');
  try
    AGroup := JSONToGroup(LGroupObj);
  finally
    LGroupObj.Free;
  end;
  // Group paths are case-sensitive in Keycloak
  Result := SameStr(AGroup.Path, LPath);
  if not Result then
    AGroup := Default(TIAM4DGroup);
end;

procedure TIAM4DKeycloakUserManager.CollectGroups(const AHTTPClient: THTTPClient; const AGroups: TJSONArray;
  const AList: TList<TIAM4DGroup>);
var
  LGroupObj: TJSONObject;
  LSubGroups: TJSONValue;
begin
  for var LIndex := 0 to AGroups.Count - 1 do
  begin
    if not (AGroups.Items[LIndex] is TJSONObject) then
      Continue;
    LGroupObj := TJSONObject(AGroups.Items[LIndex]);
    AList.Add(JSONToGroup(LGroupObj));

    LSubGroups := LGroupObj.Values['subGroups'];
    if (LSubGroups is TJSONArray) and (TJSONArray(LSubGroups).Count > 0) then
      CollectGroups(AHTTPClient, TJSONArray(LSubGroups), AList)
    else if LGroupObj.GetValue<Integer>('subGroupCount', 0) > 0 then
      CollectChildGroups(AHTTPClient, LGroupObj.GetValue<string>('id', ''), AList);
  end;
end;

procedure TIAM4DKeycloakUserManager.CollectChildGroups(const AHTTPClient: THTTPClient; const AGroupID: string;
  const AList: TList<TIAM4DGroup>);
var
  LFirst, LCount: Integer;
  LResponse: IHTTPResponse;
  LJSONArray: TJSONArray;
begin
  // The children endpoint returns 10 groups unless max is set
  LFirst := 0;
  repeat
    LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet,
      Format('%s/%s/children?first=%d&max=%d', [GetGroupsURL, EncodePathSegment(AGroupID), LFirst, IAM4D_DEFAULT_PAGE_SIZE]));
    EnsureResponseSuccess(LResponse, 'Get child groups');

    LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
    try
      LCount := LJSONArray.Count;
      CollectGroups(AHTTPClient, LJSONArray, AList);
    finally
      LJSONArray.Free;
    end;
    Inc(LFirst, LCount);
  until LCount < IAM4D_DEFAULT_PAGE_SIZE;
end;

function TIAM4DKeycloakUserManager.RoleToJSON(const ARole: TIAM4DRole): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('id', ARole.ID);
    Result.AddPair('name', ARole.Name);
    if not ARole.Description.IsEmpty then
      Result.AddPair('description', ARole.Description);
  except
    Result.Free;
    raise;
  end;
end;

{ Helper Methods }

procedure TIAM4DKeycloakUserManager.ValidateBatchSize(const ACount: Integer; const AOperationName: string);
begin
  if ACount < IAM4D_MIN_BATCH_SIZE then
    raise EIAM4DException.CreateFmt(
      '%s: Batch operation requires at least %d item (provided: %d)',
      [AOperationName, IAM4D_MIN_BATCH_SIZE, ACount]);

  if ACount > IAM4D_MAX_BATCH_SIZE then
    raise EIAM4DException.CreateFmt(
      '%s: Batch operation exceeds maximum size of %d items (provided: %d). ' +
      'Please split into smaller batches for optimal performance.',
      [AOperationName, IAM4D_MAX_BATCH_SIZE, ACount]);
end;

function TIAM4DKeycloakUserManager.CreateUser(const AUser: TIAM4DUser): string;
var
  LUserJSON: TJSONObject;
begin
  // Same rules as SetPassword
  if not AUser.TemporaryPassword.IsEmpty then
    TIAM4DUserManagementValidator.ValidatePassword(AUser.TemporaryPassword);

  Result := ExecuteWithAuth<string>(
    function(AHTTPClient: THTTPClient): string
    begin
      LUserJSON := UserToJSON(AUser, True);
      try
        try
          Result := ExecuteJSONRequestWithLocation(AHTTPClient, GetUsersURL, LUserJSON, 'Create user');
        except
          on E: EIAM4DHTTPConflictException do
            raise EIAM4DUserAlreadyExistsException.CreateFromConflict(E, AUser.Username, AUser.Email);
        end;
      finally
        LUserJSON.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUser(const AUserID: string): TIAM4DUser;
begin
  Result := ExecuteWithAuth<TIAM4DUser>(
    function(AHTTPClient: THTTPClient): TIAM4DUser
    var
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, GetUserURL(AUserID));
      EnsureResponseSuccess(LResponse, 'Get user');

      LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'user response');
      try
        Result := JSONToUser(LJSONValue as TJSONObject);
      finally
        LJSONValue.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserByUsername(const AUsername: string): TIAM4DUser;
var
  LURL: string;
begin
  TIAM4DUserManagementValidator.ValidateUsernameLookup(AUsername);

  LURL := GetUsersURL + '?username=' + TNetEncoding.URL.Encode(AUsername) + '&exact=true';

  Result := ExecuteWithAuth<TIAM4DUser>(
    function(AHTTPClient: THTTPClient): TIAM4DUser
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse, 'Get user by username', LURL, IAM4D_HTTP_METHOD_GET);

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
      try
        if LJSONArray.Count = 0 then
          raise EIAM4DUserNotFoundException.Create(AUsername)
        else
          Result := JSONToUser(LJSONArray.Items[0] as TJSONObject);
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.TryGetUserByUsername(const AUsername: string): TIAM4DUserTryResult;
var
  LURL: string;
  LFound: Boolean;
  LUser: TIAM4DUser;
begin
  TIAM4DUserManagementValidator.ValidateUsernameLookup(AUsername);

  LURL := GetUsersURL + '?username=' + TNetEncoding.URL.Encode(AUsername) + '&exact=true';

  LFound := False;
  LUser := Default(TIAM4DUser);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse, 'Try get user by username', LURL, IAM4D_HTTP_METHOD_GET);

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
      try
        if LJSONArray.Count > 0 then
        begin
          LFound := True;
          LUser := JSONToUser(LJSONArray.Items[0] as TJSONObject);
        end;
      finally
        LJSONArray.Free;
      end;
    end);

  Result.Found := LFound;
  Result.User := LUser;
end;

procedure TIAM4DKeycloakUserManager.UpdateUser(const AUser: TIAM4DUser);
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUser.ID);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LUserJSON: TJSONObject;
    begin
      LUserJSON := UserToJSON(AUser, False, True);
      try
        ExecuteJSONRequest(AHTTPClient, GetUserURL(AUser.ID), IAM4D_HTTP_METHOD_PUT, LUserJSON, 'Update user');
      finally
        LUserJSON.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.UpdateUsers(const AUsers: TArray<TIAM4DUser>;
  const ACancellationToken: IAsyncOperation): TArray<TIAM4DOperationResult>;
var
  LResults: TArray<TIAM4DOperationResult>;
begin
  ValidateBatchSize(Length(AUsers), 'UpdateUsers');

  SetLength(LResults, Length(AUsers));

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LIdx: Integer;
      LUserJSON: TJSONObject;
      LUser: TIAM4DUser;
    begin
      for LIdx := 0 to High(AUsers) do
      begin
        if Assigned(ACancellationToken) and ACancellationToken.IsCancellationRequested then
        begin
          for var J := LIdx to High(AUsers) do
          begin
            LResults[J].Identifier := AUsers[J].Username;
            LResults[J].Success := False;
            LResults[J].ErrorMessage := IAM4D_OPERATION_CANCELLED;
          end;
          Break;
        end;

        LUser := AUsers[LIdx];
        LResults[LIdx].Identifier := LUser.Username;
        LResults[LIdx].Success := False;
        LResults[LIdx].ErrorMessage := '';

        try
          RenewAuthorization(AHTTPClient);
          if LUser.ID.IsEmpty then
            raise EIAM4DInvalidConfigurationException.Create(Format('User %d: ID is required for update', [LIdx + 1]));

          LUserJSON := UserToJSON(LUser, False, True);
          try
            ExecuteJSONRequest(
              AHTTPClient,
              GetUserURL(LUser.ID),
              'PUT',
              LUserJSON,
              Format('Update user %d/%d', [LIdx + 1, Length(AUsers)]));

            LResults[LIdx].Success := True;
          finally
            LUserJSON.Free;
          end;
        except
          on E: Exception do
          begin
            LResults[LIdx].Success := False;
            LResults[LIdx].ErrorMessage := Format('User %d/%d (%s): %s',
              [LIdx + 1, Length(AUsers), LUser.Username, E.Message]);
          end;
        end;
      end;
    end);

  Result := LResults;
end;

procedure TIAM4DKeycloakUserManager.DeleteUser(const AUserID: string);
begin
  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodDelete, GetUserURL(AUserID));
      EnsureResponseSuccess(LResponse, 'Delete user');
    end);
end;

function TIAM4DKeycloakUserManager.CreateUsers(const AUsers: TArray<TIAM4DUser>;
  const ACancellationToken: IAsyncOperation): TArray<TIAM4DUsersCreateResult>;
var
  LResults: TArray<TIAM4DUsersCreateResult>;
begin
  ValidateBatchSize(Length(AUsers), 'CreateUsers');

  SetLength(LResults, Length(AUsers));

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LIdx: Integer;
      LUserJSON: TJSONObject;
      LUserID: string;
    begin
      for LIdx := 0 to High(AUsers) do
      begin
        if Assigned(ACancellationToken) and ACancellationToken.IsCancellationRequested then
        begin
          for var J := LIdx to High(AUsers) do
          begin
            LResults[J].Username := AUsers[J].Username;
            LResults[J].ID := '';
            LResults[J].ErrorMessage := IAM4D_OPERATION_CANCELLED;
          end;
          Break;
        end;

        LResults[LIdx].Username := AUsers[LIdx].Username;
        LResults[LIdx].ID := '';
        LResults[LIdx].ErrorMessage := '';

        LUserJSON := UserToJSON(AUsers[LIdx], True);
        try
          try
            // Same rules as SetPasswords: a refused password is the error of its item
            if not AUsers[LIdx].TemporaryPassword.IsEmpty then
              TIAM4DUserManagementValidator.ValidatePassword(AUsers[LIdx].TemporaryPassword);
            RenewAuthorization(AHTTPClient);
            LUserID := ExecuteJSONRequestWithLocation(
              AHTTPClient,
              GetUsersURL,
              LUserJSON,
              Format('Create user %d/%d', [LIdx + 1, Length(AUsers)]));

            LResults[LIdx].ID := LUserID;
          except
            on E: Exception do
            begin
              LResults[LIdx].ErrorMessage := Format('User %d/%d (%s): %s',
                [LIdx + 1, Length(AUsers), AUsers[LIdx].Username, E.Message]);
            end;
          end;
        finally
          LUserJSON.Free;
        end;
      end;
    end);

  Result := LResults;
end;

function TIAM4DKeycloakUserManager.DeleteUsers(const AUserIDs: TArray<string>;
  const ACancellationToken: IAsyncOperation): TArray<TIAM4DOperationResult>;
var
  LResults: TArray<TIAM4DOperationResult>;
begin
  ValidateBatchSize(Length(AUserIDs), 'DeleteUsers');

  SetLength(LResults, Length(AUserIDs));

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LIdx: Integer;
      LResponse: IHTTPResponse;
      LUserID: string;
    begin
      for LIdx := 0 to High(AUserIDs) do
      begin
        if Assigned(ACancellationToken) and ACancellationToken.IsCancellationRequested then
        begin
          for var J := LIdx to High(AUserIDs) do
          begin
            LResults[J].Identifier := AUserIDs[J];
            LResults[J].Success := False;
            LResults[J].ErrorMessage := IAM4D_OPERATION_CANCELLED;
          end;
          Break;
        end;

        LUserID := AUserIDs[LIdx];
        LResults[LIdx].Identifier := LUserID;
        LResults[LIdx].Success := False;
        LResults[LIdx].ErrorMessage := '';

        try
          RenewAuthorization(AHTTPClient);
          LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodDelete, GetUserURL(LUserID));
          EnsureResponseSuccess(LResponse, Format('Delete user %d/%d', [LIdx + 1, Length(AUserIDs)]));
          LResults[LIdx].Success := True;
        except
          on E: Exception do
          begin
            LResults[LIdx].Success := False;
            LResults[LIdx].ErrorMessage := Format('User %d/%d (ID: %s): %s',
              [LIdx + 1, Length(AUserIDs), LUserID, E.Message]);
          end;
        end;
      end;
    end);

  Result := LResults;
end;

function TIAM4DKeycloakUserManager.SearchUsers(
  const ACriteria: TIAM4DUserSearchCriteria): TArray<TIAM4DUser>;
var
  LURL: string;
  LParams: TStringList;
begin
  TIAM4DUserManagementValidator.ValidatePaging(ACriteria.FirstResult, ACriteria.MaxResults);

  LParams := TStringList.Create;
  try
    if not ACriteria.Username.IsEmpty then
      LParams.Add('username=' + TNetEncoding.URL.Encode(ACriteria.Username));
    if not ACriteria.Email.IsEmpty then
      LParams.Add('email=' + TNetEncoding.URL.Encode(ACriteria.Email));
    if not ACriteria.FirstName.IsEmpty then
      LParams.Add('firstName=' + TNetEncoding.URL.Encode(ACriteria.FirstName));
    if not ACriteria.LastName.IsEmpty then
      LParams.Add('lastName=' + TNetEncoding.URL.Encode(ACriteria.LastName));
    if not ACriteria.Search.IsEmpty then
      LParams.Add('search=' + TNetEncoding.URL.Encode(ACriteria.Search));
    if ACriteria.FilterByEnabled then
      LParams.Add('enabled=' + IfThen(ACriteria.Enabled, 'true', 'false'));

    LParams.Add('first=' + ACriteria.FirstResult.ToString);
    LParams.Add('max=' + ACriteria.MaxResults.ToString);

    LURL := GetUsersURL;
    if LParams.Count > 0 then
      LURL := LURL + '?' + string.Join('&', LParams.ToStringArray);

    Result := ExecuteWithAuth < TArray<TIAM4DUser> > (
      function(AHTTPClient: THTTPClient): TArray<TIAM4DUser>
      var
        LIdx: Integer;
        LResponse: IHTTPResponse;
        LJSONArray: TJSONArray;
        LUsersList: TList<TIAM4DUser>;
      begin
        LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
        EnsureResponseSuccess(LResponse, 'Search users');

        LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
        try
          LUsersList := TList<TIAM4DUser>.Create;
          try
            for LIdx := 0 to LJSONArray.Count - 1 do
              if LJSONArray.Items[LIdx] is TJSONObject then
                LUsersList.Add(JSONToUser(LJSONArray.Items[LIdx] as TJSONObject));
            Result := LUsersList.ToArray;
          finally
            LUsersList.Free;
          end;
        finally
          LJSONArray.Free;
        end;
      end);
  finally
    LParams.Free;
  end;
end;

function TIAM4DKeycloakUserManager.GetUsersCount: Integer;
begin
  Result := ExecuteWithAuth<Integer>(
    function(AHTTPClient: THTTPClient): Integer
    var
      LResponse: IHTTPResponse;
      LCountText: string;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, GetUsersURL + '/count');
      EnsureResponseSuccess(LResponse, 'Get users count');
      LCountText := LResponse.ContentAsString.Trim;
      if not TryStrToInt(LCountText, Result) then
        raise EIAM4DException.CreateFmt(
          'Get users count failed: invalid numeric response "%s"',
          [LResponse.ContentAsString]);
    end);
end;

procedure TIAM4DKeycloakUserManager.SetPassword(
  const AUserID: string;
  const APassword: string;
  const ATemporary: Boolean);
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);
  TIAM4DUserManagementValidator.ValidatePassword(APassword);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LPasswordJSON: TJSONObject;
    begin
      LPasswordJSON := TJSONObject.Create;
      try
        LPasswordJSON.AddPair('type', 'password');
        LPasswordJSON.AddPair('value', APassword);
        LPasswordJSON.AddPair('temporary', TJSONBool.Create(ATemporary));

        ExecuteJSONRequest(AHTTPClient, GetUserURL(AUserID) + '/reset-password', 'PUT', LPasswordJSON, 'Set password');
      finally
        LPasswordJSON.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.SetPasswords(
  const APasswordResets: TArray<TIAM4DPasswordReset>;
  const ACancellationToken: IAsyncOperation): TArray<TIAM4DOperationResult>;
var
  LResult: TArray<TIAM4DOperationResult>;
begin
  ValidateBatchSize(Length(APasswordResets), 'SetPasswords');

  SetLength(LResult, Length(APasswordResets));

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LPasswordJSON: TJSONObject;
      LReset: TIAM4DPasswordReset;
    begin
      for var LIndex := 0 to High(APasswordResets) do
      begin
        if Assigned(ACancellationToken) and ACancellationToken.IsCancellationRequested then
        begin
          for var J := LIndex to High(APasswordResets) do
          begin
            LResult[J].Identifier := APasswordResets[J].UserID;
            LResult[J].Success := False;
            LResult[J].ErrorMessage := IAM4D_OPERATION_CANCELLED;
          end;
          Break;
        end;

        LReset := APasswordResets[LIndex];
        LResult[LIndex].Identifier := LReset.UserID;
        LResult[LIndex].Success := False;
        LResult[LIndex].ErrorMessage := '';

        try
          RenewAuthorization(AHTTPClient);
          TIAM4DUserManagementValidator.ValidateUserID(LReset.UserID);
          TIAM4DUserManagementValidator.ValidatePassword(LReset.Password);

          LPasswordJSON := TJSONObject.Create;
          try
            LPasswordJSON.AddPair('type', 'password');
            LPasswordJSON.AddPair('value', LReset.Password);
            LPasswordJSON.AddPair('temporary', TJSONBool.Create(LReset.Temporary));

            ExecuteJSONRequest(
              AHTTPClient,
              GetUserURL(LReset.UserID) + '/reset-password',
              IAM4D_HTTP_METHOD_PUT,
              LPasswordJSON,
              Format('Set password %d/%d', [LIndex + 1, Length(APasswordResets)]));

            LResult[LIndex].Success := True;
          finally
            LPasswordJSON.Free;
          end;
        except
          on E: Exception do
          begin
            LResult[LIndex].Success := False;
            LResult[LIndex].ErrorMessage := Format('Password %d/%d (UserID: %s): %s',
              [LIndex + 1, Length(APasswordResets), LReset.UserID, E.Message]);
          end;
        end;
      end;
    end);

  Result := LResult;
end;

procedure TIAM4DKeycloakUserManager.SendPasswordResetEmail(const AUserID: string);
begin
  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LActions: TJSONArray;
    begin
      LActions := TJSONArray.Create;
      try
        LActions.Add('UPDATE_PASSWORD');
        ExecuteJSONArrayRequest(AHTTPClient, GetUserURL(AUserID) + '/execute-actions-email', 'PUT', LActions, 'Send password reset email');
      finally
        LActions.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.SendVerifyEmail(const AUserID: string);
begin
  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LContent: TStringStream;
      LResponse: IHTTPResponse;
    begin
      LContent := TStringStream.Create('', TEncoding.UTF8);
      try
        LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodPut,
          GetUserURL(AUserID) + '/send-verify-email', LContent);
        EnsureResponseSuccess(LResponse, 'Send verify email');
      finally
        LContent.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetRealmRoles: TArray<TIAM4DRole>;
begin
  Result := ExecuteWithAuth < TArray<TIAM4DRole> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DRole>
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LRolesList: TList<TIAM4DRole>;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, GetRealmRolesURL);
      EnsureResponseSuccess(LResponse, 'Get realm roles');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'roles array response');
      try
        LRolesList := TList<TIAM4DRole>.Create;
        try
          for var LIndex := 0 to LJSONArray.Count - 1 do
            if LJSONArray.Items[LIndex] is TJSONObject then
              LRolesList.Add(JSONToRole(LJSONArray.Items[LIndex] as TJSONObject));
          Result := LRolesList.ToArray;
        finally
          LRolesList.Free;
        end;
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserRoles(const AUserID: string): TArray<TIAM4DRole>;
begin
  Result := ExecuteWithAuth < TArray<TIAM4DRole> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DRole>
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LRolesList: TList<TIAM4DRole>;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet,
        GetUserURL(AUserID) + '/role-mappings/realm');
      EnsureResponseSuccess(LResponse, 'Get user roles');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'roles array response');
      try
        LRolesList := TList<TIAM4DRole>.Create;
        try
          for var LIndex := 0 to LJSONArray.Count - 1 do
            if LJSONArray.Items[LIndex] is TJSONObject then
              LRolesList.Add(JSONToRole(LJSONArray.Items[LIndex] as TJSONObject));
          Result := LRolesList.ToArray;
        finally
          LRolesList.Free;
        end;
      finally
        LJSONArray.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.AssignRolesToUser(
  const AUserID: string;
  const ARoles: TArray<TIAM4DRole>);
begin
  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LRolesArray: TJSONArray;
    begin
      LRolesArray := TJSONArray.Create;
      try
        for var LRole in ARoles do
          LRolesArray.Add(RoleToJSON(LRole));

        ExecuteJSONArrayRequest(AHTTPClient, GetUserURL(AUserID) + '/role-mappings/realm', 'POST', LRolesArray, 'Assign roles to user');
      finally
        LRolesArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.AssignRolesToUsers(
  const ARoleAssignments: TArray<TIAM4DRoleAssignment>;
  const ACancellationToken: IAsyncOperation): TArray<TIAM4DOperationResult>;
var
  LResult: TArray<TIAM4DOperationResult>;
begin
  ValidateBatchSize(Length(ARoleAssignments), 'AssignRolesToUsers');

  SetLength(LResult, Length(ARoleAssignments));

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LRolesArray: TJSONArray;
      LAssignment: TIAM4DRoleAssignment;
    begin
      for var LIndex := 0 to High(ARoleAssignments) do
      begin
        if Assigned(ACancellationToken) and ACancellationToken.IsCancellationRequested then
        begin
          for var J := LIndex to High(ARoleAssignments) do
          begin
            LResult[J].Identifier := ARoleAssignments[J].UserID;
            LResult[J].Success := False;
            LResult[J].ErrorMessage := IAM4D_OPERATION_CANCELLED;
          end;
          Break;
        end;

        LAssignment := ARoleAssignments[LIndex];
        LResult[LIndex].Identifier := LAssignment.UserID;
        LResult[LIndex].Success := False;
        LResult[LIndex].ErrorMessage := '';

        if Length(LAssignment.Roles) = 0 then
        begin
          LResult[LIndex].Success := True;
          Continue;
        end;

        try
          RenewAuthorization(AHTTPClient);
          LRolesArray := TJSONArray.Create;
          try
            for var LRole in LAssignment.Roles do
              LRolesArray.Add(RoleToJSON(LRole));

            ExecuteJSONArrayRequest(
              AHTTPClient,
              GetUserURL(LAssignment.UserID) + '/role-mappings/realm',
              'POST',
              LRolesArray,
              Format('Assign roles to user %d/%d', [LIndex + 1, Length(ARoleAssignments)]));

            LResult[LIndex].Success := True;
          finally
            LRolesArray.Free;
          end;
        except
          on E: Exception do
          begin
            LResult[LIndex].Success := False;
            LResult[LIndex].ErrorMessage := Format('Assignment %d/%d (UserID: %s, %d roles): %s',
              [LIndex + 1, Length(ARoleAssignments), LAssignment.UserID, Length(LAssignment.Roles), E.Message]);
          end;
        end;
      end;
    end);

  Result := LResult;
end;

procedure TIAM4DKeycloakUserManager.RemoveRolesFromUser(
  const AUserID: string;
  const ARoles: TArray<TIAM4DRole>);
begin
  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LRolesArray: TJSONArray;
    begin
      LRolesArray := TJSONArray.Create;
      try
        for var LRole in ARoles do
          LRolesArray.Add(RoleToJSON(LRole));

        ExecuteJSONArrayRequest(AHTTPClient, GetUserURL(AUserID) + '/role-mappings/realm', 'DELETE', LRolesArray, 'Remove roles from user');
      finally
        LRolesArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.FindRealmRole(const ARoleName: string): TIAM4DRole;
begin
  Result := GetRoleByName(ARoleName);
  // A database with a case-insensitive collation finds "Admin" for "admin": another role here
  if not SameStr(Result.Name, ARoleName) then
    raise EIAM4DRoleNotFoundException.Create(ARoleName);
end;

function TIAM4DKeycloakUserManager.FindClientRole(const AClientID, ARoleName: string): TIAM4DRole;
begin
  TIAM4DUserManagementValidator.ValidateClientID(AClientID);
  TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);

  Result := ExecuteWithAuth<TIAM4DRole>(
    function(AHTTPClient: THTTPClient): TIAM4DRole
    var
      LClientUUID: string;
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
    begin
      LClientUUID := GetClientUUIDByClientID(AHTTPClient, AClientID);
      if LClientUUID.IsEmpty then
        raise ClientNotFound(AClientID);

      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet,
        GetAdminURL + '/clients/' + EncodePathSegment(LClientUUID) + '/roles/' + EncodePathSegment(ARoleName));
      if LResponse.StatusCode = IAM4D_HTTP_STATUS_NOT_FOUND then
        raise EIAM4DRoleNotFoundException.Create(ARoleName, AClientID);
      EnsureResponseSuccess(LResponse, 'Get client role by name');
      LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'client role response');
      try
        Result := JSONToRole(LJSONValue as TJSONObject, LClientUUID, AClientID);
      finally
        LJSONValue.Free;
      end;
      if not SameStr(Result.Name, ARoleName) then
        raise EIAM4DRoleNotFoundException.Create(ARoleName, AClientID);
    end);
end;

procedure TIAM4DKeycloakUserManager.AssignRoleByName(
  const AUserID: string;
  const ARoleName: string);
begin
  AssignRolesToUser(AUserID, [FindRealmRole(ARoleName)]);
end;

procedure TIAM4DKeycloakUserManager.RemoveRoleByName(
  const AUserID: string;
  const ARoleName: string);
begin
  RemoveRolesFromUser(AUserID, [FindRealmRole(ARoleName)]);
end;

procedure TIAM4DKeycloakUserManager.AssignClientRoleByClientID(
  const AUserID: string;
  const AClientID: string;
  const ARoleName: string);
begin
  AssignClientRolesToUser(AUserID, [FindClientRole(AClientID, ARoleName)]);
end;

procedure TIAM4DKeycloakUserManager.RemoveClientRoleByClientID(
  const AUserID: string;
  const AClientID: string;
  const ARoleName: string);
begin
  RemoveClientRolesFromUserByClientID(AUserID, AClientID, [FindClientRole(AClientID, ARoleName)]);
end;

function TIAM4DKeycloakUserManager.GetGroups: TArray<TIAM4DGroup>;
begin
  Result := ExecuteWithAuth < TArray<TIAM4DGroup> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DGroup>
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LGroupsList: TList<TIAM4DGroup>;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, GetGroupsURL);
      EnsureResponseSuccess(LResponse, 'Get groups');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
      try
        LGroupsList := TList<TIAM4DGroup>.Create;
        try
          CollectGroups(AHTTPClient, LJSONArray, LGroupsList);
          Result := LGroupsList.ToArray;
        finally
          LGroupsList.Free;
        end;
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserGroups(const AUserID: string): TArray<TIAM4DGroup>;
begin
  Result := ExecuteWithAuth < TArray<TIAM4DGroup> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DGroup>
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LGroupsList: TList<TIAM4DGroup>;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, GetUserURL(AUserID) + '/groups');
      EnsureResponseSuccess(LResponse, 'Get user groups');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
      try
        LGroupsList := TList<TIAM4DGroup>.Create;
        try
          for var LIndex := 0 to LJSONArray.Count - 1 do
            if LJSONArray.Items[LIndex] is TJSONObject then
              LGroupsList.Add(JSONToGroup(LJSONArray.Items[LIndex] as TJSONObject));
          Result := LGroupsList.ToArray;
        finally
          LGroupsList.Free;
        end;
      finally
        LJSONArray.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.AddUserToGroup(
  const AHTTPClient: THTTPClient;
  const AUserID: string;
  const AGroupID: string);
var
  LContent: TStringStream;
  LResponse: IHTTPResponse;
begin
  LContent := TStringStream.Create('', TEncoding.UTF8);
  try
    LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodPut,
      GetUserURL(AUserID) + '/groups/' + EncodePathSegment(AGroupID), LContent);
    EnsureResponseSuccess(LResponse, 'Add user to group');
  finally
    LContent.Free;
  end;
end;

procedure TIAM4DKeycloakUserManager.RemoveUserFromGroup(
  const AHTTPClient: THTTPClient;
  const AUserID: string;
  const AGroupID: string);
var
  LResponse: IHTTPResponse;
begin
  LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodDelete,
    GetUserURL(AUserID) + '/groups/' + EncodePathSegment(AGroupID));
  EnsureResponseSuccess(LResponse, 'Remove user from group');
end;

procedure TIAM4DKeycloakUserManager.LogoutUser(const AUserID: string);
begin
  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LContent: TStringStream;
      LResponse: IHTTPResponse;
    begin
      LContent := TStringStream.Create('', TEncoding.UTF8);
      try
        LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodPost,
          GetUserURL(AUserID) + '/logout', LContent);
        EnsureResponseSuccess(LResponse, 'Logout user');
      finally
        LContent.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserFederatedIdentities(
  const AUserID: string): TArray<TIAM4DFederatedIdentity>;
begin
  Result := ExecuteWithAuth < TArray<TIAM4DFederatedIdentity> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DFederatedIdentity>
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LIdentitiesList: TList<TIAM4DFederatedIdentity>;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet,
        GetUserURL(AUserID) + '/federated-identity');
      EnsureResponseSuccess(LResponse, 'Get user federated identities');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'federated identities array response');
      try
        LIdentitiesList := TList<TIAM4DFederatedIdentity>.Create;
        try
          for var LIndex := 0 to LJSONArray.Count - 1 do
            if LJSONArray.Items[LIndex] is TJSONObject then
              LIdentitiesList.Add(JSONToFederatedIdentity(LJSONArray.Items[LIndex] as TJSONObject));
          Result := LIdentitiesList.ToArray;
        finally
          LIdentitiesList.Free;
        end;
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.IsUserFederated(const AUserID: string): Boolean;
begin
  Result := ExecuteWithAuth<Boolean>(
    function(AHTTPClient: THTTPClient): Boolean
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet,
        GetUserURL(AUserID) + '/federated-identity');
      EnsureResponseSuccess(LResponse, 'Check if user is federated');

      if TIAM4DJSONUtils.TryParseJSONArray(LResponse.ContentAsString, LJSONArray) then
        try
          Result := LJSONArray.Count > 0;
        finally
          LJSONArray.Free;
        end
      else
        Result := False;
    end);
end;

procedure TIAM4DKeycloakUserManager.LinkFederatedIdentity(const AUserID: string;
  const AFederatedIdentity: TIAM4DFederatedIdentity);
var
  LError: string;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);
  if not AFederatedIdentity.IsValid(LError) then
    raise EIAM4DInvalidConfigurationException.Create('Federated identity: ' + LError);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LJSON: TJSONObject;
    begin
      LJSON := AFederatedIdentity.ToJSON;
      try
        ExecuteJSONRequest(AHTTPClient,
          GetUserURL(AUserID) + '/federated-identity/' + EncodePathSegment(AFederatedIdentity.IdentityProvider),
          IAM4D_HTTP_METHOD_POST, LJSON,
          Format('Link user to identity provider "%s"', [AFederatedIdentity.IdentityProvider]));
      finally
        LJSON.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.UnlinkFederatedIdentity(const AUserID: string; const AIdentityProvider: string);
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);
  if AIdentityProvider.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Identity provider alias cannot be empty');

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LURL: string;
    begin
      LURL := GetUserURL(AUserID) + '/federated-identity/' + EncodePathSegment(AIdentityProvider);
      EnsureResponseSuccess(TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodDelete, LURL),
        Format('Unlink user from identity provider "%s"', [AIdentityProvider]), LURL, IAM4D_HTTP_METHOD_DELETE);
    end);
end;

function TIAM4DKeycloakUserManager.GetUserRequiredActions(
  const AUserID: string): TArray<TIAM4DRequiredAction>;
begin
  Result := ExecuteWithAuth < TArray<TIAM4DRequiredAction> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DRequiredAction>
    var
      LUser: TIAM4DUser;
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, GetUserURL(AUserID));
      EnsureResponseSuccess(LResponse, 'Get user required actions');

      LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'user response');
      try
        LUser := JSONToUser(LJSONValue as TJSONObject);
        Result := LUser.RequiredActions;
      finally
        LJSONValue.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.SetUserRequiredActions(
  const AUserID: string;
  const AActions: TArray<TIAM4DRequiredAction>);
begin
  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LActionsArray: TJSONArray;
      LUpdateJSON: TJSONObject;
    begin
      // LUpdateJSON owns LActionsArray: freeing both was a double free (EInvalidPointer)
      LUpdateJSON := TJSONObject.Create;
      try
        LActionsArray := TJSONArray.Create;
        LUpdateJSON.AddPair('requiredActions', LActionsArray);
        for var LAction in AActions do
          LActionsArray.Add(LAction.ToString);
        ExecuteJSONRequest(AHTTPClient, GetUserURL(AUserID), 'PUT', LUpdateJSON, 'Set user required actions');
      finally
        LUpdateJSON.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.RemoveUserRequiredActions(
  const AUserID: string;
  const AActions: TArray<TIAM4DRequiredAction>);
begin
  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
      LUser: TIAM4DUser;
      LCurrentActions: TArray<TIAM4DRequiredAction>;
      LOtherActions: TArray<string>;
      LNewActions: TList<TIAM4DRequiredAction>;
      LShouldRemove: Boolean;
      LActionsArray: TJSONArray;
      LUpdateJSON: TJSONObject;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, GetUserURL(AUserID));
      EnsureResponseSuccess(LResponse, 'Get user for removing required actions');

      LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'user response');
      try
        LUser := JSONToUser(LJSONValue as TJSONObject);
        LCurrentActions := LUser.RequiredActions;
        LOtherActions := LUser.OtherRequiredActions;
      finally
        LJSONValue.Free;
      end;

      LNewActions := TList<TIAM4DRequiredAction>.Create;
      try
        for var LCurrentAction in LCurrentActions do
        begin
          LShouldRemove := False;
          for var LActionToRemove in AActions do
          begin
            if LCurrentAction = LActionToRemove then
            begin
              LShouldRemove := True;
              Break;
            end;
          end;

          if not LShouldRemove then
            LNewActions.Add(LCurrentAction);
        end;

        // LUpdateJSON owns LActionsArray: freeing both was a double free (EInvalidPointer)
        LUpdateJSON := TJSONObject.Create;
        try
          LActionsArray := TJSONArray.Create;
          LUpdateJSON.AddPair('requiredActions', LActionsArray);
          for var LCurrentAction in LNewActions.ToArray do
            LActionsArray.Add(LCurrentAction.ToString);
          // The PUT replaces the whole list: keep the actions not in TIAM4DRequiredAction
          for var LOtherAction in LOtherActions do
            LActionsArray.Add(LOtherAction);
          ExecuteJSONRequest(AHTTPClient, GetUserURL(AUserID), 'PUT', LUpdateJSON, 'Remove user required actions');
        finally
          LUpdateJSON.Free;
        end;
      finally
        LNewActions.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserByEmail(const AEmail: string): TIAM4DUser;
var
  LURL: string;
begin
  TIAM4DUserManagementValidator.ValidateEmail(AEmail);

  LURL := GetUsersURL + '?email=' + TNetEncoding.URL.Encode(AEmail) + '&exact=true';

  Result := ExecuteWithAuth<TIAM4DUser>(
    function(AHTTPClient: THTTPClient): TIAM4DUser
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse, 'Get user by email');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
      try
        if LJSONArray.Count = 0 then
          raise EIAM4DUserNotFoundException.Create(AEmail);
        // Realm with duplicateEmailsAllowed: the email does not identify one user
        if LJSONArray.Count > 1 then
          RaiseAmbiguousEmail(AEmail, LJSONArray.Count);
        Result := JSONToUser(LJSONArray.Items[0] as TJSONObject);
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.TryGetUserByEmail(const AEmail: string): TIAM4DUserTryResult;
var
  LURL: string;
  LResult: TIAM4DUserTryResult;
begin
  TIAM4DUserManagementValidator.ValidateEmail(AEmail);

  LURL := GetUsersURL + '?email=' + TNetEncoding.URL.Encode(AEmail) + '&exact=true';

  LResult.Found := False;
  LResult.User := Default(TIAM4DUser);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse, 'Try get user by email');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
      try
        // Not found is a result, an email shared by several users an error (as GetUserByEmail)
        if LJSONArray.Count > 1 then
          RaiseAmbiguousEmail(AEmail, LJSONArray.Count);
        if LJSONArray.Count = 1 then
        begin
          LResult.Found := True;
          LResult.User := JSONToUser(LJSONArray.Items[0] as TJSONObject);
        end;
      finally
        LJSONArray.Free;
      end;
    end);

  Result := LResult;
end;

function TIAM4DKeycloakUserManager.GetUsersByIDs(const AUserIDs: TArray<string>;
  const ACancellationToken: IAsyncOperation): TArray<TIAM4DUserGetResult>;
var
  LResults: TList<TIAM4DUserGetResult>;
begin
  ValidateBatchSize(Length(AUserIDs), 'GetUsersByIDs');

  LResults := TList<TIAM4DUserGetResult>.Create;
  try
    ExecuteWithAuthVoid(
      procedure(AHTTPClient: THTTPClient)
      var
        LResponse: IHTTPResponse;
        LJSONValue: TJSONValue;
        LUserID: string;
        LResult: TIAM4DUserGetResult;
      begin
        for var LIndex := 0 to High(AUserIDs) do
        begin
          if Assigned(ACancellationToken) and ACancellationToken.IsCancellationRequested then
          begin
            for var J := LIndex to High(AUserIDs) do
            begin
              var LCancelledResult: TIAM4DUserGetResult;
              LCancelledResult.UserID := AUserIDs[J];
              LCancelledResult.ErrorMessage := IAM4D_OPERATION_CANCELLED;
              LCancelledResult.User := TIAM4DUser.Create(IAM4D_EMPTY_USER_ID, IAM4D_EMPTY_USER_ID, IAM4D_EMPTY_USER_ID, IAM4D_EMPTY_USER_ID, False);
              LCancelledResult.User.ID := IAM4D_EMPTY_USER_ID;
              LResults.Add(LCancelledResult);
            end;
            Break;
          end;

          LUserID := AUserIDs[LIndex];
          LResult.UserID := LUserID;
          LResult.ErrorMessage := '';
          LResult.User := TIAM4DUser.Create(IAM4D_EMPTY_USER_ID, IAM4D_EMPTY_USER_ID, IAM4D_EMPTY_USER_ID, IAM4D_EMPTY_USER_ID, False);
          LResult.User.ID := IAM4D_EMPTY_USER_ID;

          try
            RenewAuthorization(AHTTPClient);
            LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, GetUserURL(LUserID));

            if LResponse.StatusCode = IAM4D_HTTP_STATUS_OK then
            begin
              LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'user response');
              try
                LResult.User := JSONToUser(LJSONValue as TJSONObject);
              finally
                LJSONValue.Free;
              end;
            end
            else if LResponse.StatusCode = IAM4D_HTTP_STATUS_NOT_FOUND then
            begin
              LResult.ErrorMessage := Format('User not found: %s', [LUserID]);
            end
            else
            begin
              LResult.ErrorMessage := Format('HTTP %d: %s', [LResponse.StatusCode, LResponse.StatusText]);
            end;
          except
            on E: Exception do
            begin
              LResult.ErrorMessage := Format('%s: %s', [E.ClassName, E.Message]);
            end;
          end;

          LResults.Add(LResult);
        end;
      end);

    Result := LResults.ToArray;
  finally
    LResults.Free;
  end;
end;

function TIAM4DKeycloakUserManager.IsUserLocked(const AUserID: string): Boolean;
var
  LURL: string;
begin
  LURL := GetAdminURL + '/attack-detection/brute-force/users/' + EncodePathSegment(AUserID);

  Result := ExecuteWithAuth<Boolean>(
    function(AHTTPClient: THTTPClient): Boolean
    var
      LResponse: IHTTPResponse;
      LJSON: TJSONObject;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      // No brute force record: not locked. Any other error (403, 5xx) is not an answer
      if LResponse.StatusCode = IAM4D_HTTP_STATUS_NOT_FOUND then
        Exit(False);
      EnsureResponseSuccess(LResponse, 'Get brute force status', LURL, IAM4D_HTTP_METHOD_GET);

      LJSON := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'brute force status response');
      try
        Result := LJSON.GetValue<Boolean>('disabled', False);
      finally
        LJSON.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.UnlockUser(const AUserID: string);
var
  LURL: string;
begin
  LURL := GetAdminURL + '/attack-detection/brute-force/users/' + EncodePathSegment(AUserID);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodDelete, LURL);
      EnsureResponseSuccess(LResponse, 'Unlock user');
    end);
end;

function TIAM4DKeycloakUserManager.JSONToUserSession(const AJSON: TJSONObject): TIAM4DUserSession;
var
  LClientsJSON: TJSONObject;
  LClientsList: TList<string>;
  LPair: TJSONPair;
begin
  Result.SessionID := AJSON.GetValue<string>('id', '');
  Result.IPAddress := AJSON.GetValue<string>('ipAddress', '');
  Result.UserAgent := AJSON.GetValue<string>('userAgent', '');
  Result.Started := AJSON.GetValue<Int64>('start', 0);
  Result.LastAccess := AJSON.GetValue<Int64>('lastAccess', 0);

  if AJSON.TryGetValue<TJSONObject>('clients', LClientsJSON) and Assigned(LClientsJSON) then
  begin
    LClientsList := TList<string>.Create;
    try
      for LPair in LClientsJSON do
        LClientsList.Add(LPair.JsonString.Value);
      Result.Clients := LClientsList.ToArray;
    finally
      LClientsList.Free;
    end;
  end
  else
    Result.Clients := nil;
end;

function TIAM4DKeycloakUserManager.GetUserSessions(const AUserID: string): TArray<TIAM4DUserSession>;
var
  LURL: string;
begin
  LURL := GetUserURL(AUserID) + '/sessions';

  Result := ExecuteWithAuth < TArray<TIAM4DUserSession> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DUserSession>
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LSessionsList: TList<TIAM4DUserSession>;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse, 'Get user sessions');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'sessions array response');
      try
        LSessionsList := TList<TIAM4DUserSession>.Create;
        try
          for var LIndex := 0 to LJSONArray.Count - 1 do
            if LJSONArray.Items[LIndex] is TJSONObject then
              LSessionsList.Add(JSONToUserSession(LJSONArray.Items[LIndex] as TJSONObject));
          Result := LSessionsList.ToArray;
        finally
          LSessionsList.Free;
        end;
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserSessionCount(const AUserID: string): Integer;
var
  LURL: string;
begin
  LURL := GetUserURL(AUserID) + '/sessions';

  Result := ExecuteWithAuth<Integer>(
    function(AHTTPClient: THTTPClient): Integer
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse, 'Get user session count');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'sessions array response');
      try
        Result := LJSONArray.Count;
      finally
        LJSONArray.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.RevokeUserSession(const AUserID: string; const ASessionID: string);
var
  LURL: string;
  LSession: TIAM4DUserSession;
  LOwned: Boolean;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);
  TIAM4DUserManagementValidator.ValidateSessionID(ASessionID);

  // DELETE /sessions/{id} ends any session of the realm: only one of AUserID is revoked
  LOwned := False;
  for LSession in GetUserSessions(AUserID) do
    if LSession.SessionID = ASessionID then
    begin
      LOwned := True;
      Break;
    end;
  if not LOwned then
    raise EIAM4DHTTPNotFoundException.CreateFromResponse(IAM4D_HTTP_STATUS_NOT_FOUND, '',
      Format('Session "%s" not found among the sessions of user "%s"', [ASessionID, AUserID]));

  LURL := GetAdminURL + '/sessions/' + EncodePathSegment(ASessionID);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodDelete, LURL);
      EnsureResponseSuccess(LResponse, 'Revoke user session');
    end);
end;

procedure TIAM4DKeycloakUserManager.SetUserEnabledState(const AUserID: string; const AEnabled: Boolean);
var
  LContext: string;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);

  LContext := IfThen(AEnabled, 'Enable user', 'Disable user');

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LUpdateJSON: TJSONObject;
    begin
      LUpdateJSON := TJSONObject.Create;
      try
        LUpdateJSON.AddPair('enabled', TJSONBool.Create(AEnabled));
        ExecuteJSONRequest(AHTTPClient, GetUserURL(AUserID), 'PUT', LUpdateJSON, LContext);
      finally
        LUpdateJSON.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.DisableUser(const AUserID: string);
begin
  SetUserEnabledState(AUserID, False);
end;

procedure TIAM4DKeycloakUserManager.EnableUser(const AUserID: string);
begin
  SetUserEnabledState(AUserID, True);
end;

function TIAM4DKeycloakUserManager.GetRoleByName(const ARoleName: string): TIAM4DRole;
var
  LURL: string;
begin
  TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);

  LURL := GetRealmRolesURL + '/' + EncodePathSegment(ARoleName);

  Result := ExecuteWithAuth<TIAM4DRole>(
    function(AHTTPClient: THTTPClient): TIAM4DRole
    var
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);

      if LResponse.StatusCode = IAM4D_HTTP_STATUS_NOT_FOUND then
        raise EIAM4DRoleNotFoundException.Create(ARoleName);

      EnsureResponseSuccess(LResponse, 'Get role by name');
      LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'role response');
      try
        Result := JSONToRole(LJSONValue as TJSONObject);
      finally
        LJSONValue.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.TryGetRoleByName(const ARoleName: string): TIAM4DRoleTryResult;
var
  LURL: string;
  LResult: TIAM4DRoleTryResult;
begin
  TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);

  LURL := GetRealmRolesURL + '/' + EncodePathSegment(ARoleName);

  LResult.Found := False;
  LResult.Role := Default(TIAM4DRole);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);

      if LResponse.StatusCode = IAM4D_HTTP_STATUS_NOT_FOUND then
      begin
        LResult.Found := False;
      end
      else
      begin
        EnsureResponseSuccess(LResponse, 'Try get role by name');
        LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'role response');
        try
          LResult.Found := True;
          LResult.Role := JSONToRole(LJSONValue as TJSONObject);
        finally
          LJSONValue.Free;
        end;
      end;
    end);

  Result := LResult;
end;

function TIAM4DKeycloakUserManager.HasRole(const AUserID: string; const ARoleName: string): Boolean;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);
  TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);

  Result := ExecuteWithAuth<Boolean>(
    function(AHTTPClient: THTTPClient): Boolean
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LRoleName: string;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet,
        GetUserURL(AUserID) + '/role-mappings/realm');
      EnsureResponseSuccess(LResponse, 'Get user roles for HasRole check');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'roles array response');
      try
        Result := False;
        for var LIndex := 0 to LJSONArray.Count - 1 do
        begin
          if LJSONArray.Items[LIndex] is TJSONObject then
          begin
            LRoleName := (LJSONArray.Items[LIndex] as TJSONObject).GetValue<string>('name', '');
            if SameStr(LRoleName, ARoleName) then
            begin
              Result := True;
              Break;
            end;
          end;
        end;
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUsersWithRole(const ARoleName: string; const AFirstResult: Integer; const AMaxResults: Integer): TArray<TIAM4DUser>;
var
  LURL: string;
begin
  TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);
  TIAM4DUserManagementValidator.ValidatePaging(AFirstResult, AMaxResults);

  LURL := GetRealmRolesURL + '/' + EncodePathSegment(ARoleName) + '/users';
  LURL := LURL + '?first=' + AFirstResult.ToString + '&max=' + AMaxResults.ToString;

  Result := ExecuteWithAuth < TArray<TIAM4DUser> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DUser>
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LUsersList: TList<TIAM4DUser>;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse, 'Get users with role');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
      try
        LUsersList := TList<TIAM4DUser>.Create;
        try
          for var LIndex := 0 to LJSONArray.Count - 1 do
            if LJSONArray.Items[LIndex] is TJSONObject then
              LUsersList.Add(JSONToUser(LJSONArray.Items[LIndex] as TJSONObject));
          Result := LUsersList.ToArray;
        finally
          LUsersList.Free;
        end;
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetGroupByPath(const APath: string): TIAM4DGroup;
begin
  if APath.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Group path cannot be empty');

  Result := ExecuteWithAuth<TIAM4DGroup>(
    function(AHTTPClient: THTTPClient): TIAM4DGroup
    begin
      if not TryFetchGroupByPath(AHTTPClient, APath, Result) then
        raise EIAM4DGroupNotFoundException.Create(APath);
    end);
end;

function TIAM4DKeycloakUserManager.TryGetGroupByPath(const APath: string): TIAM4DGroupTryResult;
var
  LResult: TIAM4DGroupTryResult;
begin
  if APath.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Group path cannot be empty');

  LResult.Found := False;
  LResult.Group := Default(TIAM4DGroup);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    begin
      LResult.Found := TryFetchGroupByPath(AHTTPClient, APath, LResult.Group);
    end);

  Result := LResult;
end;

function TIAM4DKeycloakUserManager.IsMemberOfGroup(const AUserID: string; const AGroupPath: string): Boolean;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);
  TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

  Result := ExecuteWithAuth<Boolean>(
    function(AHTTPClient: THTTPClient): Boolean
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LPath: string;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, GetUserURL(AUserID) + '/groups');
      EnsureResponseSuccess(LResponse, 'Get user groups for membership check');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
      try
        Result := False;
        for var LIndex := 0 to LJSONArray.Count - 1 do
        begin
          if LJSONArray.Items[LIndex] is TJSONObject then
          begin
            LPath := (LJSONArray.Items[LIndex] as TJSONObject).GetValue<string>('path', '');
            if SameStr(LPath, AGroupPath) then
            begin
              Result := True;
              Break;
            end;
          end;
        end;
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUsersInGroup(const AHTTPClient: THTTPClient; const AGroupID: string; const AFirstResult: Integer; const AMaxResults: Integer): TArray<TIAM4DUser>;
var
  LResponse: IHTTPResponse;
  LURL: string;
  LJSONArray: TJSONArray;
  LUsersList: TList<TIAM4DUser>;
begin
  TIAM4DUserManagementValidator.ValidateGroupID(AGroupID);
  TIAM4DUserManagementValidator.ValidatePaging(AFirstResult, AMaxResults);

  LURL := GetGroupsURL + '/' + EncodePathSegment(AGroupID) + '/members';
  LURL := LURL + '?first=' + AFirstResult.ToString + '&max=' + AMaxResults.ToString;

  LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
  EnsureResponseSuccess(LResponse, 'Get users in group');

  LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
  try
    LUsersList := TList<TIAM4DUser>.Create;
    try
      for var LIndex := 0 to LJSONArray.Count - 1 do
        if LJSONArray.Items[LIndex] is TJSONObject then
          LUsersList.Add(JSONToUser(LJSONArray.Items[LIndex] as TJSONObject));
      Result := LUsersList.ToArray;
    finally
      LUsersList.Free;
    end;
  finally
    LJSONArray.Free;
  end;
end;

function TIAM4DKeycloakUserManager.GetClientRoles(const AHTTPClient: THTTPClient; const AContainerID: string; const AClientID: string = ''): TArray<TIAM4DRole>;
var
  LResponse: IHTTPResponse;
  LURL: string;
  LJSONArray: TJSONArray;
  LRolesList: TList<TIAM4DRole>;
begin
  TIAM4DUserManagementValidator.ValidateContainerID(AContainerID);

  LURL := GetAdminURL + '/clients/' + EncodePathSegment(AContainerID) + '/roles';

  LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
  EnsureResponseSuccess(LResponse, 'Get client roles');

  LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'client roles array response');
  try
    LRolesList := TList<TIAM4DRole>.Create;
    try
      for var LIndex := 0 to LJSONArray.Count - 1 do
        if LJSONArray.Items[LIndex] is TJSONObject then
          LRolesList.Add(JSONToRole(LJSONArray.Items[LIndex] as TJSONObject, AContainerID, AClientID));
      Result := LRolesList.ToArray;
    finally
      LRolesList.Free;
    end;
  finally
    LJSONArray.Free;
  end;
end;

function TIAM4DKeycloakUserManager.GetUserClientRoles(const AHTTPClient: THTTPClient; const AUserID: string; const AContainerID: string; const AClientID: string = ''): TArray<TIAM4DRole>;
var
  LResponse: IHTTPResponse;
  LURL: string;
  LJSONArray: TJSONArray;
  LRolesList: TList<TIAM4DRole>;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);

  TIAM4DUserManagementValidator.ValidateContainerID(AContainerID);

  LURL := GetUserURL(AUserID) + '/role-mappings/clients/' + EncodePathSegment(AContainerID);

  LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
  EnsureResponseSuccess(LResponse, 'Get user client roles');

  LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'user client roles array response');
  try
    LRolesList := TList<TIAM4DRole>.Create;
    try
      for var LIndex := 0 to LJSONArray.Count - 1 do
        if LJSONArray.Items[LIndex] is TJSONObject then
          LRolesList.Add(JSONToRole(LJSONArray.Items[LIndex] as TJSONObject, AContainerID, AClientID));
      Result := LRolesList.ToArray;
    finally
      LRolesList.Free;
    end;
  finally
    LJSONArray.Free;
  end;
end;

procedure TIAM4DKeycloakUserManager.AssignClientRolesToUser(
  const AHTTPClient: THTTPClient;
  const AUserID: string;
  const AContainerID: string;
  const ARoles: TArray<TIAM4DRole>);
var
  LRolesArray: TJSONArray;
  LRole: TIAM4DRole;
  LURL: string;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);

  TIAM4DUserManagementValidator.ValidateContainerID(AContainerID);

  TIAM4DUserManagementValidator.ValidateRolesArray(Length(ARoles));

  LURL := GetUserURL(AUserID) + '/role-mappings/clients/' + EncodePathSegment(AContainerID);

  LRolesArray := TJSONArray.Create;
  try
    for LRole in ARoles do
      LRolesArray.AddElement(RoleToJSON(LRole));

    ExecuteJSONArrayRequest(AHTTPClient, LURL, 'POST', LRolesArray, 'Assign client roles to user');
  finally
    LRolesArray.Free;
  end;
end;

class procedure TIAM4DKeycloakUserManager.CheckClientRoles(const ARoles: TArray<TIAM4DRole>);
var
  LRole: TIAM4DRole;
begin
  for LRole in ARoles do
    if LRole.ID.IsEmpty or LRole.ContainerID.IsEmpty or LRole.ClientID.IsEmpty then
      raise EIAM4DInvalidConfigurationException.Create(Format(
        'Role "%s" is missing ID, ContainerID or ClientID. Use GetClientRolesByClientID to retrieve roles ' +
        'with complete client information.', [LRole.Name]));
end;

procedure TIAM4DKeycloakUserManager.AssignClientRolesByContainer(const AHTTPClient: THTTPClient;
  const AUserID: string; const ARoles: TArray<TIAM4DRole>);
var
  LContainers: TList<string>;
  LContainer: string;
  LGroup: TArray<TIAM4DRole>;
  LRole: TIAM4DRole;
begin
  LContainers := TList<string>.Create;
  try
    for LRole in ARoles do
      if not LContainers.Contains(LRole.ContainerID) then
        LContainers.Add(LRole.ContainerID);
    for LContainer in LContainers do
    begin
      LGroup := nil;
      for LRole in ARoles do
        if LRole.ContainerID = LContainer then
          LGroup := LGroup + [LRole];
      AssignClientRolesToUser(AHTTPClient, AUserID, LContainer, LGroup);
    end;
  finally
    LContainers.Free;
  end;
end;

procedure TIAM4DKeycloakUserManager.RemoveClientRolesFromUser(
  const AHTTPClient: THTTPClient;
  const AUserID: string;
  const AContainerID: string;
  const ARoles: TArray<TIAM4DRole>);
var
  LRolesArray: TJSONArray;
  LRole: TIAM4DRole;
  LURL: string;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);

  TIAM4DUserManagementValidator.ValidateContainerID(AContainerID);

  TIAM4DUserManagementValidator.ValidateRolesArray(Length(ARoles));

  LURL := GetUserURL(AUserID) + '/role-mappings/clients/' + EncodePathSegment(AContainerID);

  LRolesArray := TJSONArray.Create;
  try
    for LRole in ARoles do
      LRolesArray.AddElement(RoleToJSON(LRole));

    ExecuteJSONArrayRequest(AHTTPClient, LURL, 'DELETE', LRolesArray, 'Remove client roles from user');
  finally
    LRolesArray.Free;
  end;
end;

function TIAM4DKeycloakUserManager.HasClientRole(
  const AHTTPClient: THTTPClient;
  const AUserID: string;
  const AContainerID: string;
  const ARoleName: string): Boolean;
var
  LRoles: TArray<TIAM4DRole>;
  LRole: TIAM4DRole;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);

  TIAM4DUserManagementValidator.ValidateContainerID(AContainerID);

  TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);

  LRoles := GetUserClientRoles(AHTTPClient, AUserID, AContainerID);

  for LRole in LRoles do
    if SameStr(LRole.Name, ARoleName) then
      Exit(True);

  Result := False;
end;

function TIAM4DKeycloakUserManager.GetClientUUIDByClientID(const AHTTPClient: THTTPClient; const AClientID: string): string;
var
  LResponse: IHTTPResponse;
  LURL: string;
  LJSONArray: TJSONArray;
  LClientObj: TJSONObject;
begin
  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  LURL := GetAdminURL + '/clients?clientId=' + TNetEncoding.URL.Encode(AClientID);

  LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
  EnsureResponseSuccess(LResponse, 'Get client by clientId');

  LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'clients array response');
  try
    if (LJSONArray.Count > 0) and (LJSONArray.Items[0] is TJSONObject) then
    begin
      LClientObj := LJSONArray.Items[0] as TJSONObject;
      Result := LClientObj.GetValue<string>('id', '');
    end
    else
      Result := '';
  finally
    LJSONArray.Free;
  end;
end;

function TIAM4DKeycloakUserManager.GetGroupIDByPath(const AHTTPClient: THTTPClient; const AGroupPath: string): string;
var
  LGroup: TIAM4DGroup;
begin
  TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

  if TryFetchGroupByPath(AHTTPClient, AGroupPath, LGroup) then
    Result := LGroup.ID
  else
    Result := '';
end;

function TIAM4DKeycloakUserManager.GetClientRolesByClientID(const AClientID: string): TArray<TIAM4DRole>;
begin
  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  Result := ExecuteWithAuth < TArray<TIAM4DRole> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DRole>
    var
      LClientUUID: string;
    begin
      LClientUUID := GetClientUUIDByClientID(AHTTPClient, AClientID);

      if LClientUUID.IsEmpty then
        raise ClientNotFound(AClientID);

      Result := GetClientRoles(AHTTPClient, LClientUUID, AClientID);
    end);
end;

function TIAM4DKeycloakUserManager.GetUserClientRolesByClientID(
  const AUserID: string;
  const AClientID: string): TArray<TIAM4DRole>;
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  Result := ExecuteWithAuth < TArray<TIAM4DRole> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DRole>
    var
      LClientUUID: string;
    begin
      LClientUUID := GetClientUUIDByClientID(AHTTPClient, AClientID);

      if LClientUUID.IsEmpty then
        raise ClientNotFound(AClientID);

      Result := GetUserClientRoles(AHTTPClient, AUserID, LClientUUID, AClientID);
    end);
end;

procedure TIAM4DKeycloakUserManager.AssignClientRolesToUser(
  const AUserID: string;
  const ARoles: TArray<TIAM4DRole>);
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

  TIAM4DUserManagementValidator.ValidateRolesArray(Length(ARoles));

  // Every role, before any request: roles of several clients go each to its own client
  CheckClientRoles(ARoles);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    begin
      AssignClientRolesByContainer(AHTTPClient, AUserID, ARoles);
    end);
end;

function TIAM4DKeycloakUserManager.AssignClientRolesToUsers(
  const ARoleAssignments: TArray<TIAM4DRoleAssignment>;
  const ACancellationToken: IAsyncOperation): TArray<TIAM4DOperationResult>;
var
  LResults: TArray<TIAM4DOperationResult>;
begin
  ValidateBatchSize(Length(ARoleAssignments), 'AssignClientRolesToUsers');

  SetLength(LResults, Length(ARoleAssignments));

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LIdx: Integer;
      LAssignment: TIAM4DRoleAssignment;
    begin
      for LIdx := 0 to High(ARoleAssignments) do
      begin
        if Assigned(ACancellationToken) and ACancellationToken.IsCancellationRequested then
        begin
          for var J := LIdx to High(ARoleAssignments) do
          begin
            LResults[J].Identifier := ARoleAssignments[J].UserID;
            LResults[J].Success := False;
            LResults[J].ErrorMessage := IAM4D_OPERATION_CANCELLED;
          end;
          Break;
        end;

        LAssignment := ARoleAssignments[LIdx];
        LResults[LIdx].Identifier := LAssignment.UserID;
        LResults[LIdx].Success := False;
        LResults[LIdx].ErrorMessage := '';

        if Length(LAssignment.Roles) = 0 then
        begin
          LResults[LIdx].Success := True;
          Continue;
        end;

        try
          CheckClientRoles(LAssignment.Roles);
          RenewAuthorization(AHTTPClient);
          AssignClientRolesByContainer(AHTTPClient, LAssignment.UserID, LAssignment.Roles);
          LResults[LIdx].Success := True;
        except
          on E: Exception do
          begin
            LResults[LIdx].Success := False;
            LResults[LIdx].ErrorMessage := Format('Client role assignment %d/%d (UserID: %s): %s',
              [LIdx + 1, Length(ARoleAssignments), LAssignment.UserID, E.Message]);
          end;
        end;
      end;
    end);

  Result := LResults;
end;

procedure TIAM4DKeycloakUserManager.RemoveClientRolesFromUserByClientID(
  const AUserID: string;
  const AClientID: string;
  const ARoles: TArray<TIAM4DRole>);
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  TIAM4DUserManagementValidator.ValidateRolesArray(Length(ARoles));

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LClientUUID: string;
    begin
      LClientUUID := GetClientUUIDByClientID(AHTTPClient, AClientID);

      if LClientUUID.IsEmpty then
        raise ClientNotFound(AClientID);

      RemoveClientRolesFromUser(AHTTPClient, AUserID, LClientUUID, ARoles);
    end);
end;

function TIAM4DKeycloakUserManager.HasClientRoleByClientID(
  const AUserID: string;
  const AClientID: string;
  const ARoleName: string): Boolean;
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  if ARoleName.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('RoleName cannot be empty');

  Result := ExecuteWithAuth<Boolean>(
    function(AHTTPClient: THTTPClient): Boolean
    var
      LClientUUID: string;
    begin
      LClientUUID := GetClientUUIDByClientID(AHTTPClient, AClientID);

      if LClientUUID.IsEmpty then
        raise ClientNotFound(AClientID);

      Result := HasClientRole(AHTTPClient, AUserID, LClientUUID, ARoleName);
    end);
end;

function TIAM4DKeycloakUserManager.GetClients: TIAM4DRealmClientArray;
var
  LURL: string;
begin
  LURL := GetAdminURL + '/clients';

  Result := ExecuteWithAuth<TIAM4DRealmClientArray>(
    function(AHTTPClient: THTTPClient): TIAM4DRealmClientArray
    var
      LIdx: Integer;
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LClientsList: TList<TIAM4DRealmClient>;
      LClient: TIAM4DRealmClient;
      LRoles: TArray<TIAM4DRole>;
    begin
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse, 'Get clients');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'clients array response');
      try
        LClientsList := TList<TIAM4DRealmClient>.Create;
        try
          for LIdx := 0 to LJSONArray.Count - 1 do
          begin
            if LJSONArray.Items[LIdx] is TJSONObject then
            begin
              LClient := JSONToRealmClient(LJSONArray.Items[LIdx] as TJSONObject);
              LRoles := GetClientRoles(AHTTPClient, LClient.ID, LClient.ClientID);
              LClient.Roles := LRoles;

              LClientsList.Add(LClient);
            end;
          end;

          Result := LClientsList.ToArray;
        finally
          LClientsList.Free;
        end;
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetClientByClientID(const AClientID: string): TIAM4DRealmClient;
begin
  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  Result := ExecuteWithAuth<TIAM4DRealmClient>(
    function(AHTTPClient: THTTPClient): TIAM4DRealmClient
    var
      LJSONValue: TJSONValue;
      LClientUUID: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LRoles: TArray<TIAM4DRole>;
    begin
      LClientUUID := GetClientUUIDByClientID(AHTTPClient, AClientID);

      if LClientUUID.IsEmpty then
        raise ClientNotFound(AClientID);

      LURL := GetAdminURL + '/clients/' + EncodePathSegment(LClientUUID);
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse, 'Get client details');

      LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'client response');
      try
        Result := JSONToRealmClient(LJSONValue as TJSONObject);
        LRoles := GetClientRoles(AHTTPClient, LClientUUID, AClientID);
        Result.Roles := LRoles;
      finally
        LJSONValue.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.AddUserToGroupByPath(
  const AUserID: string;
  const AGroupPath: string);
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

  TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LGroupID: string;
    begin
      LGroupID := GetGroupIDByPath(AHTTPClient, AGroupPath);

      if LGroupID.IsEmpty then
        raise EIAM4DGroupNotFoundException.Create(AGroupPath);

      AddUserToGroup(AHTTPClient, AUserID, LGroupID);
    end);
end;

procedure TIAM4DKeycloakUserManager.RemoveUserFromGroupByPath(
  const AUserID: string;
  const AGroupPath: string);
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

  TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LGroupID: string;
    begin
      LGroupID := GetGroupIDByPath(AHTTPClient, AGroupPath);

      if LGroupID.IsEmpty then
        raise EIAM4DGroupNotFoundException.Create(AGroupPath);

      RemoveUserFromGroup(AHTTPClient, AUserID, LGroupID);
    end);
end;

function TIAM4DKeycloakUserManager.GetUsersInGroupByPath(
  const AGroupPath: string;
  const AFirstResult: Integer;
  const AMaxResults: Integer): TArray<TIAM4DUser>;
begin
  TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);
  // Before the group lookup: no request for a call that cannot succeed
  TIAM4DUserManagementValidator.ValidatePaging(AFirstResult, AMaxResults);

  Result := ExecuteWithAuth < TArray<TIAM4DUser> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DUser>
    var
      LGroupID: string;
    begin
      LGroupID := GetGroupIDByPath(AHTTPClient, AGroupPath);

      if LGroupID.IsEmpty then
        raise EIAM4DGroupNotFoundException.Create(AGroupPath);

      Result := GetUsersInGroup(AHTTPClient, LGroupID, AFirstResult, AMaxResults);
    end);
end;

end.
