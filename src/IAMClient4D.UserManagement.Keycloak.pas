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
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// Authentication provider interface for Keycloak Admin API access.
  /// </summary>
  IKeycloakAuthProvider = interface
    ['{8AFF271E-1A31-42CD-992E-7FCE62325685}']
    /// <summary>
    /// Returns access token for Admin API authentication.
    /// </summary>
    function GetAccessToken: string;
    /// <summary>
    /// Creates configured HTTP client for API calls.
    /// </summary>
    function CreateHTTPClient: THTTPClient;
  end;

  /// <summary>
  /// Auth provider using IAM4D client for token management.
  /// </summary>
  /// <remarks>
  /// Token source: Retrieved from IAM4D client (automatic refresh handling).
  /// Use case: When using OAuth2 client for authentication.
  /// </remarks>
  TClientBasedAuthProvider = class(TInterfacedObject, IKeycloakAuthProvider)
  private
    FClient: IIAM4DClient;
  protected
    /// <summary>
  /// Returns access token from client.
  /// </summary>
    function GetAccessToken: string;
    /// <summary>
    /// Creates HTTP client from client configuration.
    /// </summary>
    function CreateHTTPClient: THTTPClient;
  public
    /// <summary>
    /// Creates provider with IAM4D client.
    /// </summary>
    constructor Create(const AClient: IIAM4DClient);
  end;

  /// <summary>
  /// Auth provider using static access token.
  /// </summary>
  /// <remarks>
  /// Token source: Provided directly (no automatic refresh).
  /// Use case: Service accounts, external token management, testing.
  /// </remarks>
  TTokenBasedAuthProvider = class(TInterfacedObject, IKeycloakAuthProvider)
  private
    FAccessToken: string;
    FHTTPConfig: TIAM4DHTTPClientConfig;
  protected
    /// <summary>
    /// Returns the static access token.
    /// </summary>
    function GetAccessToken: string;
    /// <summary>
    /// Creates HTTP client with configured settings.
    /// </summary>
    function CreateHTTPClient: THTTPClient;
  public
    /// <summary>
    /// Creates provider with access token and HTTP configuration.
    /// </summary>
    constructor Create(const AAccessToken: string; const AHTTPConfig: TIAM4DHTTPClientConfig); overload;

    /// <summary>
    /// Creates provider with access token and default HTTP configuration.
    /// </summary>
    constructor Create(const AAccessToken: string); overload;
  end;

  /// <summary>
  /// Keycloak Admin API implementation for user management (synchronous).
  /// </summary>
  /// <remarks>
  /// API: Keycloak Admin REST API (/admin/realms/{realm}).
  /// Authentication: Uses access token with admin permissions via auth provider.
  /// HTTP: Creates new HTTP client for each operation (no connection pooling).
  /// JSON: Automatic serialization/deserialization of Keycloak entities.
  /// Sync: All operations execute synchronously and block until completion.
  /// Use case: Server-side (REST API) where the request is already on a worker thread.
  /// </remarks>
  TIAM4DKeycloakUserManager = class(TInterfacedObject, IIAM4DUserManager)
  private
    FAuthProvider: IKeycloakAuthProvider;
    FBaseURL: string;
    FRealm: string;

    function GetAdminURL: string;
    function GetUsersURL: string;
    function GetUserURL(const AUserID: string): string;
    function GetRealmRolesURL: string;
    function GetGroupsURL: string;
    function GetAccessToken: string;

    procedure EnsureResponseSuccess(const AResponse: IHTTPResponse; const AContext: string); overload;
    procedure EnsureResponseSuccess(const AResponse: IHTTPResponse; const AContext: string; const AURL: string; const AMethod: string); overload;
    function ExtractLocationID(const AResponse: IHTTPResponse): string;

    function UserToJSON(const AUser: TIAM4DUser; const AIncludeCredentials: Boolean = False): TJSONObject;
    function JSONToUser(const AJSON: TJSONObject): TIAM4DUser;
    function JSONToRole(const AJSON: TJSONObject): TIAM4DRole; overload;
    function JSONToRole(const AJSON: TJSONObject; const AClientID: string; const AClientName: string): TIAM4DRole; overload;
    function JSONToGroup(const AJSON: TJSONObject): TIAM4DGroup;
    function JSONToFederatedIdentity(const AJSON: TJSONObject): TIAM4DFederatedIdentity;
    function JSONToUserSession(const AJSON: TJSONObject): TIAM4DUserSession;
    function JSONToRealmClient(const AJSON: TJSONObject): TIAM4DRealmClient;
    function RoleToJSON(const ARole: TIAM4DRole): TJSONObject;

    function ParseAttributesFromJSON(const AJSON: TJSONObject): TArray<TIAM4DUserAttribute>;
    procedure AddAttributesToJSON(const ATargetJSON: TJSONObject; const AAttributes: TArray<TIAM4DUserAttribute>);

    /// <summary>
    /// Helper: Executes HTTP request with JSON body and validates response.
    /// </summary>
    function ExecuteJSONRequest(
      const AHTTPClient: THTTPClient;
      const AURL: string;
      const AMethod: string;
      const AJSON: TJSONObject;
      const AContext: string): IHTTPResponse;

    /// <summary>
    /// Helper: Executes POST request with JSON body and extracts Location header ID.
    /// </summary>
    function ExecuteJSONRequestWithLocation(
      const AHTTPClient: THTTPClient;
      const AURL: string;
      const AJSON: TJSONObject;
      const AContext: string): string;

    /// <summary>
    /// Helper: Executes HTTP request with JSON array body and validates response.
    /// </summary>
    function ExecuteJSONArrayRequest(
      const AHTTPClient: THTTPClient;
      const AURL: string;
      const AMethod: string;
      const AJSONArray: TJSONArray;
      const AContext: string): IHTTPResponse;

    /// <summary>
    /// Helper: Executes an operation with authenticated HTTP client.
    /// Handles token retrieval, client creation, auth header setup, and cleanup.
    /// </summary>
    function ExecuteWithAuth<T>(const AOperation: TFunc<THTTPClient, T>): T;

    /// <summary>
    /// Helper: Executes a void operation with authenticated HTTP client.
    /// Handles token retrieval, client creation, auth header setup, and cleanup.
    /// </summary>
    procedure ExecuteWithAuthVoid(const AOperation: TProc<THTTPClient>);

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
    /// Internal: Retrieves client ID by client name via GET /admin/realms/{realm}/clients?clientId={name}.
    /// </summary>
    function GetClientIDByName(const AHTTPClient: THTTPClient; const AClientName: string): string;

    /// <summary>
    /// Internal: Retrieves group ID by group path via GET /admin/realms/{realm}/groups (filtered by path).
    /// </summary>
    function GetGroupIDByPath(const AHTTPClient: THTTPClient; const AGroupPath: string): string;

    /// <summary>
    /// Internal: Retrieves all client roles via GET /admin/realms/{realm}/clients/{clientId}/roles.
    /// </summary>
    /// <remarks>
    /// Populates ClientID and ClientName in returned roles for automatic routing in assignment methods.
    /// </remarks>
    function GetClientRoles(const AHTTPClient: THTTPClient; const AClientID: string; const AClientName: string = ''): TArray<TIAM4DRole>;

    /// <summary>
    /// Internal: Retrieves client roles assigned to user via GET /admin/realms/{realm}/users/{id}/role-mappings/clients/{clientId}.
    /// </summary>
    function GetUserClientRoles(const AHTTPClient: THTTPClient; const AUserID: string; const AClientID: string): TArray<TIAM4DRole>;

    /// <summary>
    /// Internal: Assigns client roles to user via POST to role-mappings endpoint.
    /// </summary>
    procedure AssignClientRolesToUser(const AHTTPClient: THTTPClient; const AUserID: string; const AClientID: string; const ARoles: TArray<TIAM4DRole>); overload;

    /// <summary>
    /// Internal: Removes client roles from user via DELETE to role-mappings endpoint.
    /// </summary>
    procedure RemoveClientRolesFromUser(const AHTTPClient: THTTPClient; const AUserID: string; const AClientID: string; const ARoles: TArray<TIAM4DRole>);

    /// <summary>
    /// Internal: Checks if user has a specific client role.
    /// </summary>
    function HasClientRole(const AHTTPClient: THTTPClient; const AUserID: string; const AClientID: string; const ARoleName: string): Boolean;

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
    procedure AssignClientRoleByName(const AUserID: string; const AClientName: string; const ARoleName: string);
    procedure RemoveClientRoleByName(const AUserID: string; const AClientName: string; const ARoleName: string);
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
    function GetClientRolesByName(const AClientName: string): TArray<TIAM4DRole>;
    function GetUserClientRolesByName(const AUserID: string; const AClientName: string): TArray<TIAM4DRole>;
    procedure AssignClientRolesToUser(const AUserID: string; const ARoles: TArray<TIAM4DRole>); overload;
    function AssignClientRolesToUsers(const ARoleAssignments: TArray<TIAM4DRoleAssignment>; const ACancellationToken: IAsyncOperation = nil): TArray<TIAM4DOperationResult>;
    procedure RemoveClientRolesFromUserByName(const AUserID: string; const AClientName: string; const ARoles: TArray<TIAM4DRole>);
    function HasClientRoleByName(const AUserID: string; const AClientName: string; const ARoleName: string): Boolean;
    function GetClients: TIAM4DRealmClientArray; overload;
    function GetClients(const AClientName: string): TIAM4DRealmClient; overload;
    // Internal helper
    procedure SetUserEnabledState(const AUserID: string; const AEnabled: Boolean);

  public
    /// <summary>
    /// Creates manager with custom auth provider.
    /// </summary>
    constructor Create(const AAuthProvider: IKeycloakAuthProvider; const ABaseURL: string; const ARealm: string); overload;

    /// <summary>
    /// Creates manager with IAM4D client (auto-extracts base URL and realm from issuer if not provided).
    /// </summary>
    constructor Create(const AClient: IIAM4DClient; const ABaseURL: string = ''; const ARealm: string = ''); overload;

    /// <summary>
    /// Creates manager with static access token and custom HTTP configuration.
    /// </summary>
    constructor Create(const AAccessToken: string; const ABaseURL: string; const ARealm: string; const AHTTPConfig: TIAM4DHTTPClientConfig); overload;

    /// <summary>
    /// Creates manager with static access token and default HTTP configuration.
    /// </summary>
    constructor Create(const AAccessToken: string; const ABaseURL: string; const ARealm: string); overload;
  end;

implementation

uses
  System.NetConsts,
  System.StrUtils,
  IAMClient4D.Common.Constants;

{ TClientBasedAuthProvider }

constructor TClientBasedAuthProvider.Create(const AClient: IIAM4DClient);
begin
  inherited Create;
  if not Assigned(AClient) then
    raise EIAM4DInvalidConfigurationException.Create('Client cannot be nil');
  FClient := AClient;
end;

function TClientBasedAuthProvider.GetAccessToken: string;
begin
  Result := FClient.GetAccessTokenAsync.Run.WaitForResult();
end;

function TClientBasedAuthProvider.CreateHTTPClient: THTTPClient;
begin
  Result := FClient.CreateHTTPClient;
end;

{ TTokenBasedAuthProvider }

constructor TTokenBasedAuthProvider.Create(
  const AAccessToken: string;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  inherited Create;
  if AAccessToken.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Access token cannot be empty');
  FAccessToken := AAccessToken;
  FHTTPConfig := AHTTPConfig;
end;

constructor TTokenBasedAuthProvider.Create(const AAccessToken: string);
begin
  Create(AAccessToken, TIAM4DHTTPClientConfig.Default);
end;

function TTokenBasedAuthProvider.GetAccessToken: string;
begin
  Result := FAccessToken;
end;

function TTokenBasedAuthProvider.CreateHTTPClient: THTTPClient;
begin
  Result := TIAM4DHTTPClientFactory.CreateHTTPClient(FHTTPConfig);
end;

{ TIAM4DKeycloakUserManager }

constructor TIAM4DKeycloakUserManager.Create(
  const AAuthProvider: IKeycloakAuthProvider;
  const ABaseURL: string;
  const ARealm: string);
begin
  inherited Create;

  if not Assigned(AAuthProvider) then
    raise EIAM4DInvalidConfigurationException.Create('AuthProvider cannot be nil');

  if ABaseURL.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('BaseURL cannot be empty');

  if ARealm.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Realm cannot be empty');

  FAuthProvider := AAuthProvider;
  FBaseURL := ABaseURL.TrimRight(['/']);
  FRealm := ARealm;
end;

constructor TIAM4DKeycloakUserManager.Create(
  const AClient: IIAM4DClient;
  const ABaseURL: string;
  const ARealm: string);
var
  LAuthProvider: IKeycloakAuthProvider;
  LBaseURL, LRealm: string;
begin
  if not Assigned(AClient) then
    raise EIAM4DInvalidConfigurationException.Create('Client cannot be nil');

  LBaseURL := ABaseURL;
  LRealm := ARealm;

  if LBaseURL.IsEmpty or LRealm.IsEmpty then
  begin
    var LIssuer := AClient.Issuer;
    if LIssuer.IsEmpty then
      raise EIAM4DInvalidConfigurationException.Create('Client not configured. Call Configure first.');

    var LRealmsPos := LIssuer.IndexOf('/realms/');
    if LRealmsPos < 0 then
      raise EIAM4DInvalidConfigurationException.Create('Invalid issuer format. Expected: {baseURL}/realms/{realm}');

    LBaseURL := LIssuer.Substring(0, LRealmsPos);
    LRealm := LIssuer.Substring(LRealmsPos + 8);
  end;

  LAuthProvider := TClientBasedAuthProvider.Create(AClient);

  Create(LAuthProvider, LBaseURL, LRealm);
end;

constructor TIAM4DKeycloakUserManager.Create(
  const AAccessToken: string;
  const ABaseURL: string;
  const ARealm: string;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
var
  LAuthProvider: IKeycloakAuthProvider;
begin
  LAuthProvider := TTokenBasedAuthProvider.Create(AAccessToken, AHTTPConfig);
  Create(LAuthProvider, ABaseURL, ARealm);
end;

constructor TIAM4DKeycloakUserManager.Create(
  const AAccessToken: string;
  const ABaseURL: string;
  const ARealm: string);
var
  LAuthProvider: IKeycloakAuthProvider;
begin
  LAuthProvider := TTokenBasedAuthProvider.Create(AAccessToken);
  Create(LAuthProvider, ABaseURL, ARealm);
end;

function TIAM4DKeycloakUserManager.GetAdminURL: string;
begin
  Result := FBaseURL + '/admin/realms/' + FRealm;
end;

function TIAM4DKeycloakUserManager.GetUsersURL: string;
begin
  Result := GetAdminURL + '/users';
end;

function TIAM4DKeycloakUserManager.GetUserURL(const AUserID: string): string;
begin
  Result := GetUsersURL + '/' + TNetEncoding.URL.Encode(AUserID);
end;

function TIAM4DKeycloakUserManager.GetRealmRolesURL: string;
begin
  Result := GetAdminURL + '/roles';
end;

function TIAM4DKeycloakUserManager.GetGroupsURL: string;
begin
  Result := GetAdminURL + '/groups';
end;

function TIAM4DKeycloakUserManager.GetAccessToken: string;
begin
  Result := FAuthProvider.GetAccessToken;
end;

procedure TIAM4DKeycloakUserManager.EnsureResponseSuccess(
  const AResponse: IHTTPResponse;
  const AContext: string);
var
  LErrorMsg: string;
begin
  if AResponse.StatusCode in [IAM4D_HTTP_STATUS_OK, IAM4D_HTTP_STATUS_CREATED, IAM4D_HTTP_STATUS_NO_CONTENT] then
    Exit;

  if not AResponse.ContentAsString.Trim.IsEmpty then
    LErrorMsg := AResponse.ContentAsString
  else
    LErrorMsg := AResponse.StatusText;

  raise EIAM4DInvalidConfigurationException.CreateFmt(
    '%s failed: %d - %s',
    [AContext, AResponse.StatusCode, LErrorMsg]);
end;

procedure TIAM4DKeycloakUserManager.EnsureResponseSuccess(
  const AResponse: IHTTPResponse;
  const AContext: string;
  const AURL: string;
  const AMethod: string);
var
  LErrorMsg: string;
  LResponsePreview: string;
begin
  if AResponse.StatusCode in [IAM4D_HTTP_STATUS_OK, IAM4D_HTTP_STATUS_CREATED, IAM4D_HTTP_STATUS_NO_CONTENT] then
    Exit;

  if not AResponse.ContentAsString.Trim.IsEmpty then
  begin
    if AResponse.ContentAsString.Length > IAM4D_MAX_ERROR_PREVIEW_LENGTH then
      LResponsePreview := AResponse.ContentAsString.Substring(0, IAM4D_MAX_ERROR_PREVIEW_LENGTH) + '...'
    else
      LResponsePreview := AResponse.ContentAsString;
  end
  else
    LResponsePreview := AResponse.StatusText;

  LErrorMsg := Format(
    '%s failed'#13#10 +
    'Request: %s %s'#13#10 +
    'Status: %d %s'#13#10 +
    'Response: %s',
    [AContext, AMethod, AURL, AResponse.StatusCode, AResponse.StatusText, LResponsePreview]);

  raise EIAM4DInvalidConfigurationException.Create(LErrorMsg);
end;

function TIAM4DKeycloakUserManager.ExtractLocationID(const AResponse: IHTTPResponse): string;
var
  LLocation: string;
  LLastSlashPos: Integer;
begin
  LLocation := AResponse.HeaderValue['Location'];
  if LLocation.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Location header missing from create response');

  LLastSlashPos := LLocation.LastIndexOf('/');
  if LLastSlashPos < 0 then
    raise EIAM4DInvalidConfigurationException.Create('Invalid Location header format');

  Result := LLocation.Substring(LLastSlashPos + 1);
end;

{ JSON Mapping }

function TIAM4DKeycloakUserManager.UserToJSON(const AUser: TIAM4DUser; const AIncludeCredentials: Boolean = False): TJSONObject;
var
  LCredentials: TJSONArray;
  LCredential: TJSONObject;
  LActionsArray: TJSONArray;
  LAction: TIAM4DRequiredAction;
begin
  Result := TJSONObject.Create;
  try
    if not AUser.ID.IsEmpty then
      Result.AddPair('id', AUser.ID);

    Result.AddPair('username', AUser.Username);

    if not AUser.Email.IsEmpty then
      Result.AddPair('email', AUser.Email);

    if not AUser.FirstName.IsEmpty then
      Result.AddPair('firstName', AUser.FirstName);

    if not AUser.LastName.IsEmpty then
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

    if Length(AUser.RequiredActions) > 0 then
    begin
      LActionsArray := TJSONArray.Create;
      for LAction in AUser.RequiredActions do
        LActionsArray.Add(LAction.ToString);
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
  LActionStr: string;
begin
  Result.ID := AJSON.GetValue<string>('id', '');
  Result.Username := AJSON.GetValue<string>('username', '');
  Result.Email := AJSON.GetValue<string>('email', '');
  Result.FirstName := AJSON.GetValue<string>('firstName', '');
  Result.LastName := AJSON.GetValue<string>('lastName', '');
  Result.Enabled := AJSON.GetValue<Boolean>('enabled', False);
  Result.EmailVerified := AJSON.GetValue<Boolean>('emailVerified', False);
  Result.CreatedTimestamp := AJSON.GetValue<Int64>('createdTimestamp', 0);

  Result.AllAttributes := ParseAttributesFromJSON(AJSON);

  LActionsArray := TIAM4DJSONHelper.GetArray(AJSON, 'requiredActions');
  if LActionsArray <> nil then
  begin
    LActionsList := TList<TIAM4DRequiredAction>.Create;
    try
      for var LIndex := 0 to LActionsArray.Count - 1 do
      begin
        LActionStr := LActionsArray.Items[LIndex].Value;
        try
          LActionsList.Add(TIAM4DRequiredAction.FromString(LActionStr));
        except
          on E: EArgumentException do
          begin
            raise EIAM4DUnknownRequiredActionException.Create(LActionStr, Result.ID);
          end;
        end;
      end;
      Result.RequiredActions := LActionsList.ToArray;
    finally
      LActionsList.Free;
    end;
  end
  else
    Result.RequiredActions := nil;
end;

function TIAM4DKeycloakUserManager.JSONToRole(const AJSON: TJSONObject): TIAM4DRole;
begin
  Result.ID := AJSON.GetValue<string>('id', '');
  Result.Name := AJSON.GetValue<string>('name', '');
  Result.Description := AJSON.GetValue<string>('description', '');
  Result.Composite := AJSON.GetValue<Boolean>('composite', False);
  Result.ClientID := '';
  Result.ClientName := '';
end;

function TIAM4DKeycloakUserManager.JSONToRole(const AJSON: TJSONObject; const AClientID: string; const AClientName: string): TIAM4DRole;
begin
  Result.ID := AJSON.GetValue<string>('id', '');
  Result.Name := AJSON.GetValue<string>('name', '');
  Result.Description := AJSON.GetValue<string>('description', '');
  Result.Composite := AJSON.GetValue<Boolean>('composite', False);
  Result.ClientID := AClientID;
  Result.ClientName := AClientName;
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

function TIAM4DKeycloakUserManager.ExecuteJSONRequest(
  const AHTTPClient: THTTPClient;
  const AURL: string;
  const AMethod: string;
  const AJSON: TJSONObject;
  const AContext: string): IHTTPResponse;
var
  LContent: TStringStream;
begin
  AHTTPClient.ContentType := IAM4D_CONTENT_TYPE_JSON;

  LContent := TStringStream.Create(AJSON.ToString, TEncoding.UTF8);
  try
    if SameText(AMethod, IAM4D_HTTP_METHOD_POST) then
      Result := AHTTPClient.Post(AURL, LContent)
    else if SameText(AMethod, IAM4D_HTTP_METHOD_PUT) then
      Result := AHTTPClient.Put(AURL, LContent)
    else if SameText(AMethod, IAM4D_HTTP_METHOD_DELETE) then
      Result := AHTTPClient.Delete(AURL, LContent)
    else
      raise EIAM4DInvalidConfigurationException.CreateFmt('Unsupported HTTP method: %s', [AMethod]);

    EnsureResponseSuccess(Result, AContext, AURL, AMethod);
  finally
    LContent.Free;
  end;
end;

function TIAM4DKeycloakUserManager.ExecuteJSONRequestWithLocation(
  const AHTTPClient: THTTPClient;
  const AURL: string;
  const AJSON: TJSONObject;
  const AContext: string): string;
var
  LResponse: IHTTPResponse;
begin
  LResponse := ExecuteJSONRequest(AHTTPClient, AURL, IAM4D_HTTP_METHOD_POST, AJSON, AContext);
  Result := ExtractLocationID(LResponse);
end;

function TIAM4DKeycloakUserManager.ExecuteJSONArrayRequest(
  const AHTTPClient: THTTPClient;
  const AURL: string;
  const AMethod: string;
  const AJSONArray: TJSONArray;
  const AContext: string): IHTTPResponse;
var
  LContent: TStringStream;
begin
  AHTTPClient.ContentType := IAM4D_CONTENT_TYPE_JSON;

  LContent := TStringStream.Create(AJSONArray.ToString, TEncoding.UTF8);
  try
    if SameText(AMethod, IAM4D_HTTP_METHOD_POST) then
      Result := AHTTPClient.Post(AURL, LContent)
    else if SameText(AMethod, IAM4D_HTTP_METHOD_PUT) then
      Result := AHTTPClient.Put(AURL, LContent)
    else if SameText(AMethod, IAM4D_HTTP_METHOD_DELETE) then
      Result := AHTTPClient.Delete(AURL, LContent)
    else
      raise EIAM4DInvalidConfigurationException.CreateFmt('Unsupported HTTP method: %s', [AMethod]);

    EnsureResponseSuccess(Result, AContext, AURL, AMethod);
  finally
    LContent.Free;
  end;
end;

function TIAM4DKeycloakUserManager.ExecuteWithAuth<T>(const AOperation: TFunc<THTTPClient, T>): T;
var
  LToken: string;
  LHTTPClient: THTTPClient;
begin
  LToken := GetAccessToken;
  LHTTPClient := FAuthProvider.CreateHTTPClient;
  try
    LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;
    Result := AOperation(LHTTPClient);
  finally
    LHTTPClient.Free;
  end;
end;

procedure TIAM4DKeycloakUserManager.ExecuteWithAuthVoid(const AOperation: TProc<THTTPClient>);
var
  LToken: string;
  LHTTPClient: THTTPClient;
begin
  LToken := GetAccessToken;
  LHTTPClient := FAuthProvider.CreateHTTPClient;
  try
    LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;
    AOperation(LHTTPClient);
  finally
    LHTTPClient.Free;
  end;
end;

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
  Result := ExecuteWithAuth<string>(
    function(AHTTPClient: THTTPClient): string
    begin
      LUserJSON := UserToJSON(AUser, True);
      try
        Result := ExecuteJSONRequestWithLocation(AHTTPClient, GetUsersURL, LUserJSON, 'Create user');
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
      LResponse := AHTTPClient.Get(GetUserURL(AUserID));
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
  TIAM4DUserManagementValidator.ValidateUsername(AUsername);

  LURL := GetUsersURL + '?username=' + TNetEncoding.URL.Encode(AUsername) + '&exact=true';

  Result := ExecuteWithAuth<TIAM4DUser>(
    function(AHTTPClient: THTTPClient): TIAM4DUser
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
    begin
      LResponse := AHTTPClient.Get(LURL);
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
  TIAM4DUserManagementValidator.ValidateUsername(AUsername);

  LURL := GetUsersURL + '?username=' + TNetEncoding.URL.Encode(AUsername) + '&exact=true';

  LFound := False;
  LUser := Default(TIAM4DUser);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
    begin
      LResponse := AHTTPClient.Get(LURL);
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
      LUserJSON := UserToJSON(AUser, False);
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
          if LUser.ID.IsEmpty then
            raise EIAM4DInvalidConfigurationException.CreateFmt('User %d: ID is required for update', [LIdx + 1]);

          LUserJSON := UserToJSON(LUser, False);
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
      LResponse := AHTTPClient.Delete(GetUserURL(AUserID));
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
          LResponse := AHTTPClient.Delete(GetUserURL(LUserID));
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
        LResponse := AHTTPClient.Get(LURL);
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
    begin
      LResponse := AHTTPClient.Get(GetUsersURL + '/count');
      EnsureResponseSuccess(LResponse, 'Get users count');
      Result := StrToIntDef(LResponse.ContentAsString, 0);
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
        LResponse := AHTTPClient.Put(GetUserURL(AUserID) + '/send-verify-email', LContent);
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
      LResponse := AHTTPClient.Get(GetRealmRolesURL);
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
      LResponse := AHTTPClient.Get(GetUserURL(AUserID) + '/role-mappings/realm');
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

procedure TIAM4DKeycloakUserManager.AssignRoleByName(
  const AUserID: string;
  const ARoleName: string);
var
  LRealmRoles: TArray<TIAM4DRole>;
  LRole: TIAM4DRole;
  LFound: Boolean;
begin
  LRealmRoles := GetRealmRoles;

  LFound := False;
  for LRole in LRealmRoles do
  begin
    if SameText(LRole.Name, ARoleName) then
    begin
      LFound := True;
      Break;
    end;
  end;

  if not LFound then
    raise EIAM4DException.CreateFmt('Realm role "%s" not found', [ARoleName]);

  AssignRolesToUser(AUserID, [LRole]);
end;

procedure TIAM4DKeycloakUserManager.RemoveRoleByName(
  const AUserID: string;
  const ARoleName: string);
var
  LRealmRoles: TArray<TIAM4DRole>;
  LRole: TIAM4DRole;
  LFound: Boolean;
begin
  LRealmRoles := GetRealmRoles;

  LFound := False;
  for LRole in LRealmRoles do
  begin
    if SameText(LRole.Name, ARoleName) then
    begin
      LFound := True;
      Break;
    end;
  end;

  if not LFound then
    raise EIAM4DException.CreateFmt('Realm role "%s" not found', [ARoleName]);

  RemoveRolesFromUser(AUserID, [LRole]);
end;

procedure TIAM4DKeycloakUserManager.AssignClientRoleByName(
  const AUserID: string;
  const AClientName: string;
  const ARoleName: string);
var
  LClientRoles: TArray<TIAM4DRole>;
  LRole: TIAM4DRole;
  LFound: Boolean;
begin
  LClientRoles := GetClientRolesByName(AClientName);

  LFound := False;
  for LRole in LClientRoles do
  begin
    if SameText(LRole.Name, ARoleName) then
    begin
      LFound := True;
      Break;
    end;
  end;

  if not LFound then
    raise EIAM4DException.CreateFmt('Client role "%s" not found in client "%s"', [ARoleName, AClientName]);

  AssignClientRolesToUser(AUserID, [LRole]);
end;

procedure TIAM4DKeycloakUserManager.RemoveClientRoleByName(
  const AUserID: string;
  const AClientName: string;
  const ARoleName: string);
var
  LClientRoles: TArray<TIAM4DRole>;
  LRole: TIAM4DRole;
  LFound: Boolean;
begin
  LClientRoles := GetClientRolesByName(AClientName);

  LFound := False;
  for LRole in LClientRoles do
  begin
    if SameText(LRole.Name, ARoleName) then
    begin
      LFound := True;
      Break;
    end;
  end;

  if not LFound then
    raise EIAM4DException.CreateFmt('Client role "%s" not found in client "%s"', [ARoleName, AClientName]);

  RemoveClientRolesFromUserByName(AUserID, AClientName, [LRole]);
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
      LResponse := AHTTPClient.Get(GetGroupsURL);
      EnsureResponseSuccess(LResponse, 'Get groups');

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

function TIAM4DKeycloakUserManager.GetUserGroups(const AUserID: string): TArray<TIAM4DGroup>;
begin
  Result := ExecuteWithAuth < TArray<TIAM4DGroup> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DGroup>
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LGroupsList: TList<TIAM4DGroup>;
    begin
      LResponse := AHTTPClient.Get(GetUserURL(AUserID) + '/groups');
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
    LResponse := AHTTPClient.Put(GetUserURL(AUserID) + '/groups/' + TNetEncoding.URL.Encode(AGroupID), LContent);
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
  LResponse := AHTTPClient.Delete(GetUserURL(AUserID) + '/groups/' + TNetEncoding.URL.Encode(AGroupID));
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
        LResponse := AHTTPClient.Post(GetUserURL(AUserID) + '/logout', LContent);
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
      LResponse := AHTTPClient.Get(GetUserURL(AUserID) + '/federated-identity');
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
      LResponse := AHTTPClient.Get(GetUserURL(AUserID) + '/federated-identity');
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
      LResponse := AHTTPClient.Get(GetUserURL(AUserID));
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
      LActionsArray := TJSONArray.Create;
      try
        for var LAction in AActions do
          LActionsArray.Add(LAction.ToString);

        LUpdateJSON := TJSONObject.Create;
        try
          LUpdateJSON.AddPair('requiredActions', LActionsArray);
          ExecuteJSONRequest(AHTTPClient, GetUserURL(AUserID), 'PUT', LUpdateJSON, 'Set user required actions');
        finally
          LUpdateJSON.Free;
        end;
      finally
        LActionsArray.Free;
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
      LNewActions: TList<TIAM4DRequiredAction>;
      LShouldRemove: Boolean;
      LActionsArray: TJSONArray;
      LUpdateJSON: TJSONObject;
    begin
      LResponse := AHTTPClient.Get(GetUserURL(AUserID));
      EnsureResponseSuccess(LResponse, 'Get user for removing required actions');

      LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'user response');
      try
        LUser := JSONToUser(LJSONValue as TJSONObject);
        LCurrentActions := LUser.RequiredActions;
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

        LActionsArray := TJSONArray.Create;
        try
          for var LCurrentAction in LNewActions.ToArray do
            LActionsArray.Add(LCurrentAction.ToString);

          LUpdateJSON := TJSONObject.Create;
          try
            LUpdateJSON.AddPair('requiredActions', LActionsArray);
            ExecuteJSONRequest(AHTTPClient, GetUserURL(AUserID), 'PUT', LUpdateJSON, 'Remove user required actions');
          finally
            LUpdateJSON.Free;
          end;
        finally
          LActionsArray.Free;
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
      LURL: string;
      LJSONArray: TJSONArray;
    begin
      LResponse := AHTTPClient.Get(LURL);
      EnsureResponseSuccess(LResponse, 'Get user by email');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
      try
        if LJSONArray.Count = 0 then
          raise EIAM4DUserNotFoundException.Create(AEmail)
        else
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
      LURL: string;
      LJSONArray: TJSONArray;
      LResult: TIAM4DUserTryResult;
    begin
      LResponse := AHTTPClient.Get(LURL);
      EnsureResponseSuccess(LResponse, 'Try get user by email');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
      try
        if LJSONArray.Count > 0 then
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
            LResponse := AHTTPClient.Get(GetUserURL(LUserID));

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
  LURL := GetAdminURL + '/attack-detection/brute-force/users/' + TNetEncoding.URL.Encode(AUserID);

  Result := ExecuteWithAuth<Boolean>(
    function(AHTTPClient: THTTPClient): Boolean
    var
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONValue: TJSONValue;
      LJSONObj: TJSONObject;
    begin
      try
        LResponse := AHTTPClient.Get(LURL);

        if LResponse.StatusCode = IAM4D_HTTP_STATUS_OK then
        begin
          LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'brute force status response');
          try
            LJSONObj := LJSONValue as TJSONObject;
            Result := LJSONObj.GetValue<Boolean>('disabled', False);
          finally
            LJSONValue.Free;
          end;
        end
        else
          Result := False;
      except
        Result := False;
      end;
    end);
end;

procedure TIAM4DKeycloakUserManager.UnlockUser(const AUserID: string);
var
  LURL: string;
begin
  LURL := GetAdminURL + '/attack-detection/brute-force/users/' + TNetEncoding.URL.Encode(AUserID);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
    begin
      LResponse := AHTTPClient.Delete(LURL);
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
      LResponse := AHTTPClient.Get(LURL);
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
      LResponse := AHTTPClient.Get(LURL);
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
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);
  TIAM4DUserManagementValidator.ValidateSessionID(ASessionID);

  LURL := GetAdminURL + '/sessions/' + TNetEncoding.URL.Encode(ASessionID);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
    begin
      LResponse := AHTTPClient.Delete(LURL);
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

  LURL := GetRealmRolesURL + '/' + TNetEncoding.URL.Encode(ARoleName);

  Result := ExecuteWithAuth<TIAM4DRole>(
    function(AHTTPClient: THTTPClient): TIAM4DRole
    var
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
    begin
      LResponse := AHTTPClient.Get(LURL);

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

  LURL := GetRealmRolesURL + '/' + TNetEncoding.URL.Encode(ARoleName);

  LResult.Found := False;
  LResult.Role := Default(TIAM4DRole);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
    begin
      LResponse := AHTTPClient.Get(LURL);

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
      LResponse := AHTTPClient.Get(GetUserURL(AUserID) + '/role-mappings/realm');
      EnsureResponseSuccess(LResponse, 'Get user roles for HasRole check');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'roles array response');
      try
        Result := False;
        for var LIndex := 0 to LJSONArray.Count - 1 do
        begin
          if LJSONArray.Items[LIndex] is TJSONObject then
          begin
            LRoleName := (LJSONArray.Items[LIndex] as TJSONObject).GetValue<string>('name', '');
            if SameText(LRoleName, ARoleName) then
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

  LURL := GetRealmRolesURL + '/' + TNetEncoding.URL.Encode(ARoleName) + '/users';
  LURL := LURL + '?first=' + AFirstResult.ToString + '&max=' + AMaxResults.ToString;

  Result := ExecuteWithAuth < TArray<TIAM4DUser> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DUser>
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LUsersList: TList<TIAM4DUser>;
    begin
      LResponse := AHTTPClient.Get(LURL);
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
var
  LURL: string;
begin
  if APath.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Group path cannot be empty');

  LURL := GetGroupsURL;

  Result := ExecuteWithAuth<TIAM4DGroup>(
    function(AHTTPClient: THTTPClient): TIAM4DGroup
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LGroupPath: string;
    begin
      LResponse := AHTTPClient.Get(LURL);
      EnsureResponseSuccess(LResponse, 'Get groups for path search');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
      try
        Result.ID := IAM4D_EMPTY_USER_ID;

        for var LIndex := 0 to LJSONArray.Count - 1 do
        begin
          if LJSONArray.Items[LIndex] is TJSONObject then
          begin
            LGroupPath := (LJSONArray.Items[LIndex] as TJSONObject).GetValue<string>('path', IAM4D_EMPTY_USER_ID);
            if SameText(LGroupPath, APath) then
            begin
              Result := JSONToGroup(LJSONArray.Items[LIndex] as TJSONObject);
              Break;
            end;
          end;
        end;

        if Result.ID = IAM4D_EMPTY_USER_ID then
          raise EIAM4DGroupNotFoundException.Create(APath);
      finally
        LJSONArray.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.TryGetGroupByPath(const APath: string): TIAM4DGroupTryResult;
var
  LURL: string;
  LResult: TIAM4DGroupTryResult;
begin
  if APath.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Group path cannot be empty');

  LURL := GetGroupsURL;

  LResult.Found := False;
  LResult.Group := Default(TIAM4DGroup);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      LGroupPath: string;
    begin
      LResponse := AHTTPClient.Get(LURL);
      EnsureResponseSuccess(LResponse, 'Try get group by path');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
      try
        for var LIndex := 0 to LJSONArray.Count - 1 do
        begin
          if LJSONArray.Items[LIndex] is TJSONObject then
          begin
            LGroupPath := (LJSONArray.Items[LIndex] as TJSONObject).GetValue<string>('path', IAM4D_EMPTY_USER_ID);
            if SameText(LGroupPath, APath) then
            begin
              LResult.Found := True;
              LResult.Group := JSONToGroup(LJSONArray.Items[LIndex] as TJSONObject);
              Break;
            end;
          end;
        end;
      finally
        LJSONArray.Free;
      end;
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
      LResponse := AHTTPClient.Get(GetUserURL(AUserID) + '/groups');
      EnsureResponseSuccess(LResponse, 'Get user groups for membership check');

      LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
      try
        Result := False;
        for var LIndex := 0 to LJSONArray.Count - 1 do
        begin
          if LJSONArray.Items[LIndex] is TJSONObject then
          begin
            LPath := (LJSONArray.Items[LIndex] as TJSONObject).GetValue<string>('path', '');
            if SameText(LPath, AGroupPath) then
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

  LURL := GetGroupsURL + '/' + TNetEncoding.URL.Encode(AGroupID) + '/members';
  LURL := LURL + '?first=' + AFirstResult.ToString + '&max=' + AMaxResults.ToString;

  LResponse := AHTTPClient.Get(LURL);
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

function TIAM4DKeycloakUserManager.GetClientRoles(const AHTTPClient: THTTPClient; const AClientID: string; const AClientName: string = ''): TArray<TIAM4DRole>;
var
  LResponse: IHTTPResponse;
  LURL: string;
  LJSONArray: TJSONArray;
  LRolesList: TList<TIAM4DRole>;
begin
  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  LURL := GetAdminURL + '/clients/' + TNetEncoding.URL.Encode(AClientID) + '/roles';

  LResponse := AHTTPClient.Get(LURL);
  EnsureResponseSuccess(LResponse, 'Get client roles');

  LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'client roles array response');
  try
    LRolesList := TList<TIAM4DRole>.Create;
    try
      for var LIndex := 0 to LJSONArray.Count - 1 do
        if LJSONArray.Items[LIndex] is TJSONObject then
          LRolesList.Add(JSONToRole(LJSONArray.Items[LIndex] as TJSONObject, AClientID, AClientName));
      Result := LRolesList.ToArray;
    finally
      LRolesList.Free;
    end;
  finally
    LJSONArray.Free;
  end;
end;

function TIAM4DKeycloakUserManager.GetUserClientRoles(const AHTTPClient: THTTPClient; const AUserID: string; const AClientID: string): TArray<TIAM4DRole>;
var
  LResponse: IHTTPResponse;
  LURL: string;
  LJSONArray: TJSONArray;
  LRolesList: TList<TIAM4DRole>;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);

  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  LURL := GetUserURL(AUserID) + '/role-mappings/clients/' + TNetEncoding.URL.Encode(AClientID);

  LResponse := AHTTPClient.Get(LURL);
  EnsureResponseSuccess(LResponse, 'Get user client roles');

  LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'user client roles array response');
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
end;

procedure TIAM4DKeycloakUserManager.AssignClientRolesToUser(
  const AHTTPClient: THTTPClient;
  const AUserID: string;
  const AClientID: string;
  const ARoles: TArray<TIAM4DRole>);
var
  LRolesArray: TJSONArray;
  LRole: TIAM4DRole;
  LURL: string;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);

  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  TIAM4DUserManagementValidator.ValidateRolesArray(Length(ARoles));

  LURL := GetUserURL(AUserID) + '/role-mappings/clients/' + TNetEncoding.URL.Encode(AClientID);

  LRolesArray := TJSONArray.Create;
  try
    for LRole in ARoles do
      LRolesArray.AddElement(RoleToJSON(LRole));

    ExecuteJSONArrayRequest(AHTTPClient, LURL, 'POST', LRolesArray, 'Assign client roles to user');
  finally
    LRolesArray.Free;
  end;
end;

procedure TIAM4DKeycloakUserManager.RemoveClientRolesFromUser(
  const AHTTPClient: THTTPClient;
  const AUserID: string;
  const AClientID: string;
  const ARoles: TArray<TIAM4DRole>);
var
  LRolesArray: TJSONArray;
  LRole: TIAM4DRole;
  LURL: string;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);

  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  TIAM4DUserManagementValidator.ValidateRolesArray(Length(ARoles));

  LURL := GetUserURL(AUserID) + '/role-mappings/clients/' + TNetEncoding.URL.Encode(AClientID);

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
  const AClientID: string;
  const ARoleName: string): Boolean;
var
  LRoles: TArray<TIAM4DRole>;
  LRole: TIAM4DRole;
begin
  TIAM4DUserManagementValidator.ValidateUserID(AUserID);

  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);

  LRoles := GetUserClientRoles(AHTTPClient, AUserID, AClientID);

  for LRole in LRoles do
    if SameText(LRole.Name, ARoleName) then
      Exit(True);

  Result := False;
end;

function TIAM4DKeycloakUserManager.GetClientIDByName(const AHTTPClient: THTTPClient; const AClientName: string): string;
var
  LResponse: IHTTPResponse;
  LURL: string;
  LJSONArray: TJSONArray;
  LClientObj: TJSONObject;
begin
  TIAM4DUserManagementValidator.ValidateClientName(AClientName);

  LURL := GetAdminURL + '/clients?clientId=' + TNetEncoding.URL.Encode(AClientName);

  LResponse := AHTTPClient.Get(LURL);
  EnsureResponseSuccess(LResponse, 'Get client by name');

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
  LResponse: IHTTPResponse;
  LURL: string;
  LJSONArray: TJSONArray;
  LGroupObj: TJSONObject;
  LPath: string;
begin
  TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

  LURL := GetGroupsURL;

  LResponse := AHTTPClient.Get(LURL);
  EnsureResponseSuccess(LResponse, 'Get groups for path lookup');

  LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
  try
    Result := '';

    for var LIndex := 0 to LJSONArray.Count - 1 do
    begin
      if LJSONArray.Items[LIndex] is TJSONObject then
      begin
        LGroupObj := LJSONArray.Items[LIndex] as TJSONObject;
        LPath := LGroupObj.GetValue<string>('path', '');
        if SameText(LPath, AGroupPath) then
        begin
          Result := LGroupObj.GetValue<string>('id', '');
          Exit;
        end;
      end;
    end;
  finally
    LJSONArray.Free;
  end;
end;

function TIAM4DKeycloakUserManager.GetClientRolesByName(const AClientName: string): TArray<TIAM4DRole>;
begin
  TIAM4DUserManagementValidator.ValidateClientName(AClientName);

  Result := ExecuteWithAuth < TArray<TIAM4DRole> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DRole>
    var
      LClientID: string;
    begin
      LClientID := GetClientIDByName(AHTTPClient, AClientName);

      if LClientID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.CreateFmt('Client "%s" not found', [AClientName]);

      Result := GetClientRoles(AHTTPClient, LClientID, AClientName);
    end);
end;

function TIAM4DKeycloakUserManager.GetUserClientRolesByName(
  const AUserID: string;
  const AClientName: string): TArray<TIAM4DRole>;
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

  TIAM4DUserManagementValidator.ValidateClientName(AClientName);

  Result := ExecuteWithAuth < TArray<TIAM4DRole> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DRole>
    var
      LClientID: string;
    begin
      LClientID := GetClientIDByName(AHTTPClient, AClientName);

      if LClientID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.CreateFmt('Client "%s" not found', [AClientName]);

      Result := GetUserClientRoles(AHTTPClient, AUserID, LClientID);
    end);
end;

procedure TIAM4DKeycloakUserManager.AssignClientRolesToUser(
  const AUserID: string;
  const ARoles: TArray<TIAM4DRole>);
var
  LClientID: string;
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

  TIAM4DUserManagementValidator.ValidateRolesArray(Length(ARoles));

  if (Length(ARoles) > 0) and (ARoles[0].ClientID.IsEmpty or ARoles[0].ClientName.IsEmpty) then
    raise EIAM4DInvalidConfigurationException.CreateFmt(
      'Role "%s" is missing ClientID or ClientName. Use GetClientRolesByName to retrieve roles with complete client information.',
      [ARoles[0].Name]);

  LClientID := ARoles[0].ClientID;

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    begin
      AssignClientRolesToUser(AHTTPClient, AUserID, LClientID, ARoles);
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
      LClientID: string;
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

        if LAssignment.Roles[0].ClientID.IsEmpty or LAssignment.Roles[0].ClientName.IsEmpty then
        begin
          LResults[LIdx].ErrorMessage := Format('Role "%s" is missing ClientID or ClientName', [LAssignment.Roles[0].Name]);
          Continue;
        end;

        try
          LClientID := LAssignment.Roles[0].ClientID;
          AssignClientRolesToUser(AHTTPClient, LAssignment.UserID, LClientID, LAssignment.Roles);
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

procedure TIAM4DKeycloakUserManager.RemoveClientRolesFromUserByName(
  const AUserID: string;
  const AClientName: string;
  const ARoles: TArray<TIAM4DRole>);
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

  TIAM4DUserManagementValidator.ValidateClientName(AClientName);

  TIAM4DUserManagementValidator.ValidateRolesArray(Length(ARoles));

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LClientID: string;
    begin
      LClientID := GetClientIDByName(AHTTPClient, AClientName);

      if LClientID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.CreateFmt('Client "%s" not found', [AClientName]);

      RemoveClientRolesFromUser(AHTTPClient, AUserID, LClientID, ARoles);
    end);
end;

function TIAM4DKeycloakUserManager.HasClientRoleByName(
  const AUserID: string;
  const AClientName: string;
  const ARoleName: string): Boolean;
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

  TIAM4DUserManagementValidator.ValidateClientName(AClientName);

  if ARoleName.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('RoleName cannot be empty');

  Result := ExecuteWithAuth<Boolean>(
    function(AHTTPClient: THTTPClient): Boolean
    var
      LClientID: string;
    begin
      LClientID := GetClientIDByName(AHTTPClient, AClientName);

      if LClientID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.CreateFmt('Client "%s" not found', [AClientName]);

      Result := HasClientRole(AHTTPClient, AUserID, LClientID, ARoleName);
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
      LResponse := AHTTPClient.Get(LURL);
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

              try
                LRoles := GetClientRoles(AHTTPClient, LClient.ID, LClient.ClientID);
                LClient.Roles := LRoles;
              except
                LClient.Roles := nil;
              end;

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

function TIAM4DKeycloakUserManager.GetClients(const AClientName: string): TIAM4DRealmClient;
begin
  TIAM4DUserManagementValidator.ValidateClientName(AClientName);

  Result := ExecuteWithAuth<TIAM4DRealmClient>(
    function(AHTTPClient: THTTPClient): TIAM4DRealmClient
    var
      LJSONValue: TJSONValue;
      LClientID: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LRoles: TArray<TIAM4DRole>;
    begin
      LClientID := GetClientIDByName(AHTTPClient, AClientName);

      if LClientID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.CreateFmt('Client "%s" not found', [AClientName]);

      LURL := GetAdminURL + '/clients/' + TNetEncoding.URL.Encode(LClientID);
      LResponse := AHTTPClient.Get(LURL);
      EnsureResponseSuccess(LResponse, 'Get client details');

      LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'client response');
      try
        Result := JSONToRealmClient(LJSONValue as TJSONObject);

        try
          LRoles := GetClientRoles(AHTTPClient, LClientID, AClientName);
          Result.Roles := LRoles;
        except
          Result.Roles := nil;
        end;
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
        raise EIAM4DInvalidConfigurationException.CreateFmt('Group "%s" not found', [AGroupPath]);

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
        raise EIAM4DInvalidConfigurationException.CreateFmt('Group "%s" not found', [AGroupPath]);

      RemoveUserFromGroup(AHTTPClient, AUserID, LGroupID);
    end);
end;

function TIAM4DKeycloakUserManager.GetUsersInGroupByPath(
  const AGroupPath: string;
  const AFirstResult: Integer;
  const AMaxResults: Integer): TArray<TIAM4DUser>;
begin
  TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

  Result := ExecuteWithAuth < TArray<TIAM4DUser> > (
    function(AHTTPClient: THTTPClient): TArray<TIAM4DUser>
    var
      LGroupID: string;
    begin
      LGroupID := GetGroupIDByPath(AHTTPClient, AGroupPath);

      if LGroupID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.CreateFmt('Group "%s" not found', [AGroupPath]);

      Result := GetUsersInGroup(AHTTPClient, LGroupID, AFirstResult, AMaxResults);
    end);
end;

end.