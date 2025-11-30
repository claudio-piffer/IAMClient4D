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
  /// Keycloak Admin API implementation for user management.
  /// </summary>
  /// <remarks>
  /// API: Keycloak Admin REST API (/admin/realms/{realm}).
  /// Authentication: Uses access token with admin permissions via auth provider.
  /// HTTP: Creates new HTTP client for each operation (no connection pooling).
  /// JSON: Automatic serialization/deserialization of Keycloak entities.
  /// Async: All operations return promises for non-blocking execution.
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
    procedure AssignClientRolesToUser(const AHTTPClient: THTTPClient; const AUserID: string; const AClientID: string; const ARoles: TArray<TIAM4DRole>);

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
    /// <summary>
    /// Creates user via Admin API and returns user ID.
    /// </summary>
    function CreateUserAsync(const AUser: TIAM4DUser): IAsyncPromise<string>;

    /// <summary>
    /// Retrieves user by ID via GET /admin/realms/{realm}/users/{id}.
    /// </summary>
    function GetUserAsync(const AUserID: string): IAsyncPromise<TIAM4DUser>;

    /// <summary>
    /// Retrieves user by username via GET /admin/realms/{realm}/users?username={username}&exact=true.
    /// </summary>
    function GetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUser>;
    function TryGetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUserTryResult>;

    /// <summary>
    /// Updates user via PUT /admin/realms/{realm}/users/{id}.
    /// User.ID must be set.
    /// </summary>
    function UpdateUserAsync(const AUser: TIAM4DUser): IAsyncVoidPromise;

    /// <summary>
    /// Updates multiple users in batch using single HTTP connection.
    /// Each user's ID must be set.
    /// Returns an array of operation results with details for each user.
    /// </summary>
    function UpdateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Deletes user via DELETE /admin/realms/{realm}/users/{id}.
    /// </summary>
    function DeleteUserAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Creates multiple users in batch using single HTTP connection.
    /// </summary>
    function CreateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DUsersCreateResult>>;

    /// <summary>
    /// Deletes multiple users in batch using single HTTP connection.
    /// Returns an array of operation results with details for each user.
    /// </summary>
    function DeleteUsersAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Searches users with criteria and pagination.
    /// </summary>
    function SearchUsersAsync(const ACriteria: TIAM4DUserSearchCriteria): IAsyncPromise<TArray<TIAM4DUser>>;

    /// <summary>
    /// Returns total user count via GET /admin/realms/{realm}/users/count.
    /// </summary>
    function GetUsersCountAsync: IAsyncPromise<Integer>;

    /// <summary>
    /// Sets user password via PUT /admin/realms/{realm}/users/{id}/reset-password.
    /// </summary>
    function SetPasswordAsync(const AUserID: string; const APassword: string; const ATemporary: Boolean = False): IAsyncVoidPromise;

    /// <summary>
    /// Sets passwords for multiple users in batch using single HTTP connection.
    /// Returns an array of operation results with details for each password reset.
    /// </summary>
    function SetPasswordsAsync(const APasswordResets: TArray<TIAM4DPasswordReset>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Sends password reset email via execute-actions-email endpoint.
    /// </summary>
    function SendPasswordResetEmailAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Sends email verification link via send-verify-email endpoint.
    /// </summary>
    function SendVerifyEmailAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Returns all realm-level roles.
    /// </summary>
    function GetRealmRolesAsync: IAsyncPromise<TArray<TIAM4DRole>>;

    /// <summary>
    /// Returns realm roles assigned to user.
    /// </summary>
    function GetUserRolesAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DRole>>;

    /// <summary>
    /// Assigns realm roles to user via POST to role-mappings endpoint.
    /// </summary>
    function AssignRolesToUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;

    /// <summary>
    /// Assigns roles to multiple users in batch using single HTTP connection.
    /// Each assignment can have different roles for different users.
    /// Returns an array of operation results with details for each role assignment.
    /// </summary>
    function AssignRolesToUsersAsync(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Removes realm roles from user via DELETE to role-mappings endpoint.
    /// </summary>
    function RemoveRolesFromUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;

    /// <summary>
    /// Assigns a single realm role to a user by role name (convenience method).
    /// </summary>
    function AssignRoleByNameAsync(const AUserID: string; const ARoleName: string): IAsyncVoidPromise;

    /// <summary>
    /// Removes a single realm role from a user by role name (convenience method).
    /// </summary>
    function RemoveRoleByNameAsync(const AUserID: string; const ARoleName: string): IAsyncVoidPromise;

    /// <summary>
    /// Assigns a single client role to a user by client and role names (convenience method).
    /// </summary>
    function AssignClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncVoidPromise;

    /// <summary>
    /// Removes a single client role from a user by client and role names (convenience method).
    /// </summary>
    function RemoveClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncVoidPromise;

    /// <summary>
    /// Returns all groups in realm.
    /// </summary>
    function GetGroupsAsync: IAsyncPromise<TArray<TIAM4DGroup>>;

    /// <summary>
    /// Returns groups user is member of.
    /// </summary>
    function GetUserGroupsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DGroup>>;
    /// <summary>
    /// Adds user to group using group path (public API).
    /// </summary>
    function AddUserToGroupByPathAsync(const AUserID: string; const AGroupPath: string): IAsyncVoidPromise;

    /// <summary>
    /// Removes user from group using group path (public API).
    /// </summary>
    function RemoveUserFromGroupByPathAsync(const AUserID: string; const AGroupPath: string): IAsyncVoidPromise;

    /// <summary>
    /// Logs out user by revoking all sessions via POST to logout endpoint.
    /// </summary>
    function LogoutUserAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Returns federated identity links for user.
    /// </summary>
    function GetUserFederatedIdentitiesAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DFederatedIdentity>>;

    /// <summary>
    /// Checks if user has any federated identity links.
    /// </summary>
    function IsUserFederatedAsync(const AUserID: string): IAsyncPromise<Boolean>;

    /// <summary>
    /// Returns required actions from user profile.
    /// </summary>
    function GetUserRequiredActionsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DRequiredAction>>;

    /// <summary>
    /// Sets required actions by updating user profile (replaces existing).
    /// </summary>
    function SetUserRequiredActionsAsync(const AUserID: string; const AActions: TArray<TIAM4DRequiredAction>): IAsyncVoidPromise;

    /// <summary>
    /// Removes specified actions from user's required actions list.
    /// </summary>
    function RemoveUserRequiredActionsAsync(const AUserID: string; const AActions: TArray<TIAM4DRequiredAction>): IAsyncVoidPromise;

    /// <summary>
    /// Retrieves user by email via GET /admin/realms/{realm}/users?email={email}&exact=true.
    /// </summary>
    function GetUserByEmailAsync(const AEmail: string): IAsyncPromise<TIAM4DUser>;
    function TryGetUserByEmailAsync(const AEmail: string): IAsyncPromise<TIAM4DUserTryResult>;

    /// <summary>
    /// Retrieves multiple users by their IDs in batch.
    /// Returns detailed results showing success/failure for each user ID.
    /// </summary>
    function GetUsersByIDsAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DUserGetResult>>;

    /// <summary>
    /// Checks if user is locked via GET /admin/realms/{realm}/attack-detection/brute-force/users/{id}.
    /// </summary>
    function IsUserLockedAsync(const AUserID: string): IAsyncPromise<Boolean>;

    /// <summary>
    /// Unlocks user via DELETE /admin/realms/{realm}/attack-detection/brute-force/users/{id}.
    /// </summary>
    function UnlockUserAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Retrieves active sessions for user via GET /admin/realms/{realm}/users/{id}/sessions.
    /// </summary>
    function GetUserSessionsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DUserSession>>;

    /// <summary>
    /// Returns count of active user sessions.
    /// </summary>
    function GetUserSessionCountAsync(const AUserID: string): IAsyncPromise<Integer>;

    /// <summary>
    /// Revokes a specific user session via DELETE /admin/realms/{realm}/sessions/{sessionId}.
    /// </summary>
    function RevokeUserSessionAsync(const AUserID: string; const ASessionID: string): IAsyncVoidPromise;

    /// <summary>
    /// Disables a user account via PUT /admin/realms/{realm}/users/{id} with enabled=false.
    /// </summary>
    function DisableUserAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Enables a user account via PUT /admin/realms/{realm}/users/{id} with enabled=true.
    /// </summary>
    function EnableUserAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Retrieves role by name via GET /admin/realms/{realm}/roles/{role-name}.
    /// </summary>
    function GetRoleByNameAsync(const ARoleName: string): IAsyncPromise<TIAM4DRole>;
    function TryGetRoleByNameAsync(const ARoleName: string): IAsyncPromise<TIAM4DRoleTryResult>;

    /// <summary>
    /// Checks if user has a specific role.
    /// </summary>
    function HasRoleAsync(const AUserID: string; const ARoleName: string): IAsyncPromise<Boolean>;

    /// <summary>
    /// Retrieves users with a specific role via GET /admin/realms/{realm}/roles/{role-name}/users.
    /// </summary>
    function GetUsersWithRoleAsync(const ARoleName: string; const AFirstResult: Integer = 0; const AMaxResults: Integer = 100): IAsyncPromise<TArray<TIAM4DUser>>;

    /// <summary>
    /// Retrieves group by path via GET /admin/realms/{realm}/groups (filtered by path).
    /// </summary>
    function GetGroupByPathAsync(const APath: string): IAsyncPromise<TIAM4DGroup>;
    function TryGetGroupByPathAsync(const APath: string): IAsyncPromise<TIAM4DGroupTryResult>;

    /// <summary>
    /// Checks if user is member of a specific group.
    /// </summary>
    function IsMemberOfGroupAsync(const AUserID: string; const AGroupPath: string): IAsyncPromise<Boolean>;

    /// <summary>
    /// Retrieves users in group using group path (public API).
    /// </summary>
    function GetUsersInGroupByPathAsync(const AGroupPath: string; const AFirstResult: Integer = 0; const AMaxResults: Integer = 100): IAsyncPromise<TArray<TIAM4DUser>>;

    /// <summary>
    /// Sets user enabled state (shared implementation for Enable/Disable).
    /// </summary>
    function SetUserEnabledStateAsync(const AUserID: string; const AEnabled: Boolean): IAsyncVoidPromise;

    /// <summary>
    /// Retrieves all client roles using client name (public API).
    /// </summary>
    function GetClientRolesByNameAsync(const AClientName: string): IAsyncPromise<TArray<TIAM4DRole>>;

    /// <summary>
    /// Retrieves client roles assigned to user using client name (public API).
    /// </summary>
    function GetUserClientRolesByNameAsync(const AUserID: string; const AClientName: string): IAsyncPromise<TArray<TIAM4DRole>>;

    /// <summary>
    /// Assigns client roles to user (automatically extracts client from roles).
    /// </summary>
    function AssignClientRolesToUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;

    /// <summary>
    /// Assigns client roles to multiple users in batch (automatically extracts client from roles).
    /// </summary>
    function AssignClientRolesToUsersAsync(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Removes client roles from user using client name (public API).
    /// </summary>
    function RemoveClientRolesFromUserByNameAsync(const AUserID: string; const AClientName: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;

    /// <summary>
    /// Checks if user has a specific client role using client name (public API).
    /// </summary>
    function HasClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncPromise<Boolean>;

    /// <summary>
    /// Retrieves all client applications registered in the realm with their roles.
    /// </summary>
    function GetClientsAsync: IAsyncPromise<TArray<TIAM4DRealmClient>>; overload;

    /// <summary>
    /// Retrieves a specific client application by name with all its roles.
    /// </summary>
    function GetClientsAsync(const AClientName: string): IAsyncPromise<TIAM4DRealmClient>; overload;

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
  I: Integer;
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
      for I := 0 to LActionsArray.Count - 1 do
      begin
        LActionStr := LActionsArray.Items[I].Value;
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

function TIAM4DKeycloakUserManager.CreateUserAsync(const AUser: TIAM4DUser): IAsyncPromise<string>;
begin
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    var
      LToken: string;
      LUserJSON: TJSONObject;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LUserJSON := UserToJSON(AUser, True);
        try
          Result := ExecuteJSONRequestWithLocation(LHTTPClient, GetUsersURL, LUserJSON, 'Create user');
        finally
          LUserJSON.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserAsync(const AUserID: string): IAsyncPromise<TIAM4DUser>;
begin
  Result := TAsyncCore.New<TIAM4DUser>(
    function(const AOperation: IAsyncOperation): TIAM4DUser
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetUserURL(AUserID));
        EnsureResponseSuccess(LResponse, 'Get user');

        LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'user response');
        try
          Result := JSONToUser(LJSONValue as TJSONObject);
        finally
          LJSONValue.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUser>;
begin
  Result := TAsyncCore.New<TIAM4DUser>(
    function(const AOperation: IAsyncOperation): TIAM4DUser
    var
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONArray: TJSONArray;
    begin
      TIAM4DUserManagementValidator.ValidateUsername(AUsername);

      LURL := GetUsersURL + '?username=' + TNetEncoding.URL.Encode(AUsername) + '&exact=true';

      Result := ExecuteWithAuth<TIAM4DUser>(
        function(AHTTPClient: THTTPClient): TIAM4DUser
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
    end);
end;

function TIAM4DKeycloakUserManager.TryGetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUserTryResult>;
begin
  Result := TAsyncCore.New<TIAM4DUserTryResult>(
    function(const AOperation: IAsyncOperation): TIAM4DUserTryResult
    var
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONArray: TJSONArray;
      LTryResult: TIAM4DUserTryResult;
    begin
      TIAM4DUserManagementValidator.ValidateUsername(AUsername);

      LURL := GetUsersURL + '?username=' + TNetEncoding.URL.Encode(AUsername) + '&exact=true';

      LTryResult.Found := False;
      LTryResult.User := Default(TIAM4DUser);

      ExecuteWithAuthVoid(
        procedure(AHTTPClient: THTTPClient)
        begin
          LResponse := AHTTPClient.Get(LURL);
          EnsureResponseSuccess(LResponse, 'Try get user by username', LURL, IAM4D_HTTP_METHOD_GET);

          LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
          try
            if LJSONArray.Count > 0 then
            begin
              LTryResult.Found := True;
              LTryResult.User := JSONToUser(LJSONArray.Items[0] as TJSONObject);
            end;
          finally
            LJSONArray.Free;
          end;
        end);

      Result := LTryResult;
    end);
end;

function TIAM4DKeycloakUserManager.UpdateUserAsync(const AUser: TIAM4DUser): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LUserJSON: TJSONObject;
    begin
      TIAM4DUserManagementValidator.ValidateUserID(AUser.ID);

      ExecuteWithAuthVoid(
        procedure(AHTTPClient: THTTPClient)
        begin
          LUserJSON := UserToJSON(AUser, False);
          try
            ExecuteJSONRequest(AHTTPClient, GetUserURL(AUser.ID), IAM4D_HTTP_METHOD_PUT, LUserJSON, 'Update user');
          finally
            LUserJSON.Free;
          end;
        end);
    end);
end;

function TIAM4DKeycloakUserManager.UpdateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  ValidateBatchSize(Length(AUsers), 'UpdateUsersAsync');

  Result := TAsyncCore.New < TArray<TIAM4DOperationResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DOperationResult>
    var
      LToken: string;
      LUserJSON: TJSONObject;
      LUser: TIAM4DUser;
      LIndex: Integer;
      LResults: TArray<TIAM4DOperationResult>;
    begin
      SetLength(LResults, Length(AUsers));

      LToken := GetAccessToken;
      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        for LIndex := 0 to High(AUsers) do
        begin
          LUser := AUsers[LIndex];
          LResults[LIndex].Identifier := LUser.Username;
          LResults[LIndex].Success := False;
          LResults[LIndex].ErrorMessage := '';

          try
            if LUser.ID.IsEmpty then
              raise EIAM4DInvalidConfigurationException.CreateFmt('User %d: ID is required for update', [LIndex + 1]);

            LUserJSON := UserToJSON(LUser, False);
            try
              ExecuteJSONRequest(
                LHTTPClient,
                GetUserURL(LUser.ID),
                'PUT',
                LUserJSON,
                Format('Update user %d/%d', [LIndex + 1, Length(AUsers)]));

              LResults[LIndex].Success := True;
            finally
              LUserJSON.Free;
            end;
          except
            on E: Exception do
            begin
              LResults[LIndex].Success := False;
              LResults[LIndex].ErrorMessage := Format('User %d/%d (%s): %s',
                [LIndex + 1, Length(AUsers), LUser.Username, E.Message]);
            end;
          end;
        end;

        Result := LResults;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.DeleteUserAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LResponse: IHTTPResponse;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Delete(GetUserURL(AUserID));
        EnsureResponseSuccess(LResponse, 'Delete user');
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.CreateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DUsersCreateResult>>;
begin
  ValidateBatchSize(Length(AUsers), 'CreateUsersAsync');

  Result := TAsyncCore.New < TArray<TIAM4DUsersCreateResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUsersCreateResult>
    var
      LToken: string;
      LResults: TArray<TIAM4DUsersCreateResult>;
      LUserJSON: TJSONObject;
      LUserID: string;
      I: Integer;
    begin
      SetLength(LResults, Length(AUsers));

      LToken := GetAccessToken;
      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        for I := 0 to High(AUsers) do
        begin
          LResults[I].Username := AUsers[I].Username;
          LResults[I].ID := '';
          LResults[I].ErrorMessage := '';

          LUserJSON := UserToJSON(AUsers[I], True);
          try
            try
              LUserID := ExecuteJSONRequestWithLocation(
                LHTTPClient,
                GetUsersURL,
                LUserJSON,
                Format('Create user %d/%d', [I + 1, Length(AUsers)]));

              LResults[I].ID := LUserID;
            except
              on E: Exception do
              begin
                LResults[I].ErrorMessage := Format('User %d/%d (%s): %s',
                  [I + 1, Length(AUsers), AUsers[I].Username, E.Message]);
              end;
            end;
          finally
            LUserJSON.Free;
          end;
        end;

        Result := LResults;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.DeleteUsersAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  ValidateBatchSize(Length(AUserIDs), 'DeleteUsersAsync');

  Result := TAsyncCore.New < TArray<TIAM4DOperationResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DOperationResult>
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LUserID: string;
      LIndex: Integer;
      LResults: TArray<TIAM4DOperationResult>;
    begin
      SetLength(LResults, Length(AUserIDs));

      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        for LIndex := 0 to High(AUserIDs) do
        begin
          LUserID := AUserIDs[LIndex];
          LResults[LIndex].Identifier := LUserID;
          LResults[LIndex].Success := False;
          LResults[LIndex].ErrorMessage := '';

          try
            LResponse := LHTTPClient.Delete(GetUserURL(LUserID));
            EnsureResponseSuccess(LResponse, Format('Delete user %d/%d', [LIndex + 1, Length(AUserIDs)]));
            LResults[LIndex].Success := True;
          except
            on E: Exception do
            begin
              LResults[LIndex].Success := False;
              LResults[LIndex].ErrorMessage := Format('User %d/%d (ID: %s): %s',
                [LIndex + 1, Length(AUserIDs), LUserID, E.Message]);
            end;
          end;
        end;

        Result := LResults;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.SearchUsersAsync(
  const ACriteria: TIAM4DUserSearchCriteria): IAsyncPromise<TArray<TIAM4DUser>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DUser> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUser>
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LParams: TStringList;
    begin
      LToken := GetAccessToken;

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

        var LHTTPClient := FAuthProvider.CreateHTTPClient;
        try
          LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

          LResponse := LHTTPClient.Get(LURL);
          EnsureResponseSuccess(LResponse, 'Search users');

          var LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
          try
            var LUsersList := TList<TIAM4DUser>.Create;
            try
              for var I := 0 to LJSONArray.Count - 1 do
                if LJSONArray.Items[I] is TJSONObject then
                  LUsersList.Add(JSONToUser(LJSONArray.Items[I] as TJSONObject));
              Result := LUsersList.ToArray;
            finally
              LUsersList.Free;
            end;
          finally
            LJSONArray.Free;
          end;
        finally
          LHTTPClient.Free;
        end;
      finally
        LParams.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUsersCountAsync: IAsyncPromise<Integer>;
begin
  Result := TAsyncCore.New<Integer>(
    function(const AOperation: IAsyncOperation): Integer
    var
      LToken: string;
      LResponse: IHTTPResponse;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetUsersURL + '/count');
        EnsureResponseSuccess(LResponse, 'Get users count');
        Result := StrToIntDef(LResponse.ContentAsString, 0);
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.SetPasswordAsync(
  const AUserID: string;
  const APassword: string;
  const ATemporary: Boolean): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LPasswordJSON: TJSONObject;
    begin
      TIAM4DUserManagementValidator.ValidateUserID(AUserID);
      TIAM4DUserManagementValidator.ValidatePassword(APassword);

      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LPasswordJSON := TJSONObject.Create;
        try
          LPasswordJSON.AddPair('type', 'password');
          LPasswordJSON.AddPair('value', APassword);
          LPasswordJSON.AddPair('temporary', TJSONBool.Create(ATemporary));

          ExecuteJSONRequest(LHTTPClient, GetUserURL(AUserID) + '/reset-password', 'PUT', LPasswordJSON, 'Set password');
        finally
          LPasswordJSON.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.SetPasswordsAsync(
  const APasswordResets: TArray<TIAM4DPasswordReset>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  ValidateBatchSize(Length(APasswordResets), 'SetPasswordsAsync');

  Result := TAsyncCore.New < TArray<TIAM4DOperationResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DOperationResult>
    var
      LToken: string;
      LPasswordJSON: TJSONObject;
      LReset: TIAM4DPasswordReset;
      I: Integer;
      LResults: TArray<TIAM4DOperationResult>;
    begin
      SetLength(LResults, Length(APasswordResets));

      LToken := GetAccessToken;
      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        for I := 0 to High(APasswordResets) do
        begin
          LReset := APasswordResets[I];
          LResults[I].Identifier := LReset.UserID;
          LResults[I].Success := False;
          LResults[I].ErrorMessage := '';

          try
            TIAM4DUserManagementValidator.ValidateUserID(LReset.UserID);
            TIAM4DUserManagementValidator.ValidatePassword(LReset.Password);

            LPasswordJSON := TJSONObject.Create;
            try
              LPasswordJSON.AddPair('type', 'password');
              LPasswordJSON.AddPair('value', LReset.Password);
              LPasswordJSON.AddPair('temporary', TJSONBool.Create(LReset.Temporary));

              ExecuteJSONRequest(
                LHTTPClient,
                GetUserURL(LReset.UserID) + '/reset-password',
                IAM4D_HTTP_METHOD_PUT,
                LPasswordJSON,
                Format('Set password %d/%d', [I + 1, Length(APasswordResets)]));

              LResults[I].Success := True;
            finally
              LPasswordJSON.Free;
            end;
          except
            on E: Exception do
            begin
              LResults[I].Success := False;
              LResults[I].ErrorMessage := Format('Password %d/%d (UserID: %s): %s',
                [I + 1, Length(APasswordResets), LReset.UserID, E.Message]);
            end;
          end;
        end;

        Result := LResults;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.SendPasswordResetEmailAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LActions: TJSONArray;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LActions := TJSONArray.Create;
        try
          LActions.Add('UPDATE_PASSWORD');
          ExecuteJSONArrayRequest(LHTTPClient, GetUserURL(AUserID) + '/execute-actions-email', 'PUT', LActions, 'Send password reset email');
        finally
          LActions.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.SendVerifyEmailAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LContent: TStringStream;
      LResponse: IHTTPResponse;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LContent := TStringStream.Create('', TEncoding.UTF8);
        try
          LResponse := LHTTPClient.Put(GetUserURL(AUserID) + '/send-verify-email', LContent);
          EnsureResponseSuccess(LResponse, 'Send verify email');
        finally
          LContent.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetRealmRolesAsync: IAsyncPromise<TArray<TIAM4DRole>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRole> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRole>
    var
      LToken: string;
      LResponse: IHTTPResponse;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetRealmRolesURL);
        EnsureResponseSuccess(LResponse, 'Get realm roles');

        var LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'roles array response');
        try
          var LRolesList := TList<TIAM4DRole>.Create;
          try
            for var I := 0 to LJSONArray.Count - 1 do
              if LJSONArray.Items[I] is TJSONObject then
                LRolesList.Add(JSONToRole(LJSONArray.Items[I] as TJSONObject));
            Result := LRolesList.ToArray;
          finally
            LRolesList.Free;
          end;
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserRolesAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DRole>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRole> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRole>
    var
      LToken: string;
      LResponse: IHTTPResponse;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetUserURL(AUserID) + '/role-mappings/realm');
        EnsureResponseSuccess(LResponse, 'Get user roles');

        var LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'roles array response');
        try
          var LRolesList := TList<TIAM4DRole>.Create;
          try
            for var I := 0 to LJSONArray.Count - 1 do
              if LJSONArray.Items[I] is TJSONObject then
                LRolesList.Add(JSONToRole(LJSONArray.Items[I] as TJSONObject));
            Result := LRolesList.ToArray;
          finally
            LRolesList.Free;
          end;
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.AssignRolesToUserAsync(
  const AUserID: string;
  const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LRolesArray: TJSONArray;
      LRole: TIAM4DRole;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LRolesArray := TJSONArray.Create;
        try
          for LRole in ARoles do
            LRolesArray.Add(RoleToJSON(LRole));

          ExecuteJSONArrayRequest(LHTTPClient, GetUserURL(AUserID) + '/role-mappings/realm', 'POST', LRolesArray, 'Assign roles to user');
        finally
          LRolesArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.AssignRolesToUsersAsync(
  const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  ValidateBatchSize(Length(ARoleAssignments), 'AssignRolesToUsersAsync');

  Result := TAsyncCore.New < TArray<TIAM4DOperationResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DOperationResult>
    var
      LToken: string;
      LRolesArray: TJSONArray;
      LRole: TIAM4DRole;
      LAssignment: TIAM4DRoleAssignment;
      I: Integer;
      LResults: TArray<TIAM4DOperationResult>;
    begin
      SetLength(LResults, Length(ARoleAssignments));

      LToken := GetAccessToken;
      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        for I := 0 to High(ARoleAssignments) do
        begin
          LAssignment := ARoleAssignments[I];
          LResults[I].Identifier := LAssignment.UserID;
          LResults[I].Success := False;
          LResults[I].ErrorMessage := '';

          if Length(LAssignment.Roles) = 0 then
          begin
            LResults[I].Success := True;
            Continue;
          end;

          try
            LRolesArray := TJSONArray.Create;
            try
              for LRole in LAssignment.Roles do
                LRolesArray.Add(RoleToJSON(LRole));

              ExecuteJSONArrayRequest(
                LHTTPClient,
                GetUserURL(LAssignment.UserID) + '/role-mappings/realm',
                'POST',
                LRolesArray,
                Format('Assign roles to user %d/%d', [I + 1, Length(ARoleAssignments)]));

              LResults[I].Success := True;
            finally
              LRolesArray.Free;
            end;
          except
            on E: Exception do
            begin
              LResults[I].Success := False;
              LResults[I].ErrorMessage := Format('Assignment %d/%d (UserID: %s, %d roles): %s',
                [I + 1, Length(ARoleAssignments), LAssignment.UserID, Length(LAssignment.Roles), E.Message]);
            end;
          end;
        end;

        Result := LResults;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.RemoveRolesFromUserAsync(
  const AUserID: string;
  const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LRolesArray: TJSONArray;
      LRole: TIAM4DRole;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LRolesArray := TJSONArray.Create;
        try
          for LRole in ARoles do
            LRolesArray.Add(RoleToJSON(LRole));

          ExecuteJSONArrayRequest(LHTTPClient, GetUserURL(AUserID) + '/role-mappings/realm', 'DELETE', LRolesArray, 'Remove roles from user');
        finally
          LRolesArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.AssignRoleByNameAsync(
  const AUserID: string;
  const ARoleName: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LRealmRoles: TArray<TIAM4DRole>;
      LRole: TIAM4DRole;
      LFound: Boolean;
    begin
      LRealmRoles := GetRealmRolesAsync.Run.WaitForResult();

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

      AssignRolesToUserAsync(AUserID, [LRole]).Run.WaitForCompletion();
    end);
end;

function TIAM4DKeycloakUserManager.RemoveRoleByNameAsync(
  const AUserID: string;
  const ARoleName: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LRealmRoles: TArray<TIAM4DRole>;
      LRole: TIAM4DRole;
      LFound: Boolean;
    begin
      LRealmRoles := GetRealmRolesAsync.Run.WaitForResult();

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

      RemoveRolesFromUserAsync(AUserID, [LRole]).Run.WaitForCompletion();
    end);
end;

function TIAM4DKeycloakUserManager.AssignClientRoleByNameAsync(
  const AUserID: string;
  const AClientName: string;
  const ARoleName: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LClientRoles: TArray<TIAM4DRole>;
      LRole: TIAM4DRole;
      LFound: Boolean;
    begin
      LClientRoles := GetClientRolesByNameAsync(AClientName).Run.WaitForResult();

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

      AssignClientRolesToUserAsync(AUserID, [LRole]).Run.WaitForCompletion();
    end);
end;

function TIAM4DKeycloakUserManager.RemoveClientRoleByNameAsync(
  const AUserID: string;
  const AClientName: string;
  const ARoleName: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LClientRoles: TArray<TIAM4DRole>;
      LRole: TIAM4DRole;
      LFound: Boolean;
    begin
      LClientRoles := GetClientRolesByNameAsync(AClientName).Run.WaitForResult();

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

      RemoveClientRolesFromUserByNameAsync(AUserID, AClientName, [LRole]).Run.WaitForCompletion();
    end);
end;

function TIAM4DKeycloakUserManager.GetGroupsAsync: IAsyncPromise<TArray<TIAM4DGroup>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DGroup> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DGroup>
    var
      LToken: string;
      LResponse: IHTTPResponse;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetGroupsURL);
        EnsureResponseSuccess(LResponse, 'Get groups');

        var LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
        try
          var LGroupsList := TList<TIAM4DGroup>.Create;
          try
            for var I := 0 to LJSONArray.Count - 1 do
              if LJSONArray.Items[I] is TJSONObject then
                LGroupsList.Add(JSONToGroup(LJSONArray.Items[I] as TJSONObject));
            Result := LGroupsList.ToArray;
          finally
            LGroupsList.Free;
          end;
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserGroupsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DGroup>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DGroup> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DGroup>
    var
      LToken: string;
      LResponse: IHTTPResponse;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetUserURL(AUserID) + '/groups');
        EnsureResponseSuccess(LResponse, 'Get user groups');

        var LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
        try
          var LGroupsList := TList<TIAM4DGroup>.Create;
          try
            for var I := 0 to LJSONArray.Count - 1 do
              if LJSONArray.Items[I] is TJSONObject then
                LGroupsList.Add(JSONToGroup(LJSONArray.Items[I] as TJSONObject));
            Result := LGroupsList.ToArray;
          finally
            LGroupsList.Free;
          end;
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
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

function TIAM4DKeycloakUserManager.LogoutUserAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LContent: TStringStream;
      LResponse: IHTTPResponse;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LContent := TStringStream.Create('', TEncoding.UTF8);
        try
          LResponse := LHTTPClient.Post(GetUserURL(AUserID) + '/logout', LContent);
          EnsureResponseSuccess(LResponse, 'Logout user');
        finally
          LContent.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserFederatedIdentitiesAsync(
  const AUserID: string): IAsyncPromise<TArray<TIAM4DFederatedIdentity>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DFederatedIdentity> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DFederatedIdentity>
    var
      LToken: string;
      LResponse: IHTTPResponse;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetUserURL(AUserID) + '/federated-identity');
        EnsureResponseSuccess(LResponse, 'Get user federated identities');

        var LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'federated identities array response');
        try
          var LIdentitiesList := TList<TIAM4DFederatedIdentity>.Create;
          try
            for var I := 0 to LJSONArray.Count - 1 do
              if LJSONArray.Items[I] is TJSONObject then
                LIdentitiesList.Add(JSONToFederatedIdentity(LJSONArray.Items[I] as TJSONObject));
            Result := LIdentitiesList.ToArray;
          finally
            LIdentitiesList.Free;
          end;
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.IsUserFederatedAsync(const AUserID: string): IAsyncPromise<Boolean>;
begin
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetUserURL(AUserID) + '/federated-identity');
        EnsureResponseSuccess(LResponse, 'Check if user is federated');

        if TIAM4DJSONUtils.TryParseJSONArray(LResponse.ContentAsString, LJSONArray) then
          try
            Result := LJSONArray.Count > 0;
          finally
            LJSONArray.Free;
          end
        else
          Result := False;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserRequiredActionsAsync(
  const AUserID: string): IAsyncPromise<TArray<TIAM4DRequiredAction>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRequiredAction> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRequiredAction>
    var
      LUser: TIAM4DUser;
      LToken: string;
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetUserURL(AUserID));
        EnsureResponseSuccess(LResponse, 'Get user required actions');

        LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'user response');
        try
          LUser := JSONToUser(LJSONValue as TJSONObject);
          Result := LUser.RequiredActions;
        finally
          LJSONValue.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.SetUserRequiredActionsAsync(
  const AUserID: string;
  const AActions: TArray<TIAM4DRequiredAction>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LActionsArray: TJSONArray;
      LAction: TIAM4DRequiredAction;
      LUpdateJSON: TJSONObject;
    begin
      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LActionsArray := TJSONArray.Create;
        try
          for LAction in AActions do
            LActionsArray.Add(LAction.ToString);

          LUpdateJSON := TJSONObject.Create;
          try
            LUpdateJSON.AddPair('requiredActions', LActionsArray);
            ExecuteJSONRequest(LHTTPClient, GetUserURL(AUserID), 'PUT', LUpdateJSON, 'Set user required actions');
          finally
            LUpdateJSON.Free;
          end;
        finally
          LActionsArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.RemoveUserRequiredActionsAsync(
  const AUserID: string;
  const AActions: TArray<TIAM4DRequiredAction>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
      LUser: TIAM4DUser;
      LCurrentActions: TArray<TIAM4DRequiredAction>;
      LNewActions: TList<TIAM4DRequiredAction>;
      LCurrentAction: TIAM4DRequiredAction;
      LActionToRemove: TIAM4DRequiredAction;
      LShouldRemove: Boolean;
      LActionsArray: TJSONArray;
      LUpdateJSON: TJSONObject;
      LHTTPClient: THTTPClient;
    begin
      LToken := GetAccessToken;

      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetUserURL(AUserID));
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
          for LCurrentAction in LCurrentActions do
          begin
            LShouldRemove := False;
            for LActionToRemove in AActions do
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
            for LCurrentAction in LNewActions.ToArray do
              LActionsArray.Add(LCurrentAction.ToString);

            LUpdateJSON := TJSONObject.Create;
            try
              LUpdateJSON.AddPair('requiredActions', LActionsArray);
              ExecuteJSONRequest(LHTTPClient, GetUserURL(AUserID), 'PUT', LUpdateJSON, 'Remove user required actions');
            finally
              LUpdateJSON.Free;
            end;
          finally
            LActionsArray.Free;
          end;
        finally
          LNewActions.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserByEmailAsync(const AEmail: string): IAsyncPromise<TIAM4DUser>;
begin
  Result := TAsyncCore.New<TIAM4DUser>(
    function(const AOperation: IAsyncOperation): TIAM4DUser
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONArray: TJSONArray;
    begin
      TIAM4DUserManagementValidator.ValidateEmail(AEmail);

      LToken := GetAccessToken;

      LURL := GetUsersURL + '?email=' + TNetEncoding.URL.Encode(AEmail) + '&exact=true';

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(LURL);
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
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.TryGetUserByEmailAsync(const AEmail: string): IAsyncPromise<TIAM4DUserTryResult>;
begin
  Result := TAsyncCore.New<TIAM4DUserTryResult>(
    function(const AOperation: IAsyncOperation): TIAM4DUserTryResult
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONArray: TJSONArray;
    begin
      TIAM4DUserManagementValidator.ValidateEmail(AEmail);

      LToken := GetAccessToken;
      LURL := GetUsersURL + '?email=' + TNetEncoding.URL.Encode(AEmail) + '&exact=true';

      Result.Found := False;
      Result.User := Default(TIAM4DUser);

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(LURL);
        EnsureResponseSuccess(LResponse, 'Try get user by email');

        LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
        try
          if LJSONArray.Count > 0 then
          begin
            Result.Found := True;
            Result.User := JSONToUser(LJSONArray.Items[0] as TJSONObject);
          end;
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUsersByIDsAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DUserGetResult>>;
begin
  ValidateBatchSize(Length(AUserIDs), 'GetUsersByIDsAsync');

  Result := TAsyncCore.New < TArray<TIAM4DUserGetResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUserGetResult>
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LJSONValue: TJSONValue;
      LUserID: string;
      LResults: TList<TIAM4DUserGetResult>;
      LResult: TIAM4DUserGetResult;
      I: Integer;
    begin

      LToken := GetAccessToken;
      LResults := TList<TIAM4DUserGetResult>.Create;
      try
        var LHTTPClient := FAuthProvider.CreateHTTPClient;
        try
          LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

          for I := 0 to High(AUserIDs) do
          begin
            LUserID := AUserIDs[I];
            LResult.UserID := LUserID;
            LResult.ErrorMessage := '';
            LResult.User := TIAM4DUser.Create(IAM4D_EMPTY_USER_ID, IAM4D_EMPTY_USER_ID, IAM4D_EMPTY_USER_ID, IAM4D_EMPTY_USER_ID, False);
            LResult.User.ID := IAM4D_EMPTY_USER_ID;

            try
              LResponse := LHTTPClient.Get(GetUserURL(LUserID));

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

          Result := LResults.ToArray;
        finally
          LHTTPClient.Free;
        end;
      finally
        LResults.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.IsUserLockedAsync(const AUserID: string): IAsyncPromise<Boolean>;
begin
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONValue: TJSONValue;
      LJSONObj: TJSONObject;
    begin
      LToken := GetAccessToken;

      LURL := GetAdminURL + '/attack-detection/brute-force/users/' + TNetEncoding.URL.Encode(AUserID);

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        try
          LResponse := LHTTPClient.Get(LURL);

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
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.UnlockUserAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
    begin
      LToken := GetAccessToken;

      LURL := GetAdminURL + '/attack-detection/brute-force/users/' + TNetEncoding.URL.Encode(AUserID);

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Delete(LURL);
        EnsureResponseSuccess(LResponse, 'Unlock user');
      finally
        LHTTPClient.Free;
      end;
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

function TIAM4DKeycloakUserManager.GetUserSessionsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DUserSession>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DUserSession> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUserSession>
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONArray: TJSONArray;
      LSessionsList: TList<TIAM4DUserSession>;
      I: Integer;
    begin
      LToken := GetAccessToken;

      LURL := GetUserURL(AUserID) + '/sessions';

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(LURL);
        EnsureResponseSuccess(LResponse, 'Get user sessions');

        LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'sessions array response');
        try
          LSessionsList := TList<TIAM4DUserSession>.Create;
          try
            for I := 0 to LJSONArray.Count - 1 do
              if LJSONArray.Items[I] is TJSONObject then
                LSessionsList.Add(JSONToUserSession(LJSONArray.Items[I] as TJSONObject));
            Result := LSessionsList.ToArray;
          finally
            LSessionsList.Free;
          end;
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserSessionCountAsync(const AUserID: string): IAsyncPromise<Integer>;
begin
  Result := TAsyncCore.New<Integer>(
    function(const AOperation: IAsyncOperation): Integer
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONArray: TJSONArray;
    begin
      LToken := GetAccessToken;

      LURL := GetUserURL(AUserID) + '/sessions';

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(LURL);
        EnsureResponseSuccess(LResponse, 'Get user session count');

        LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'sessions array response');
        try
          Result := LJSONArray.Count;
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.RevokeUserSessionAsync(const AUserID: string; const ASessionID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
    begin
      TIAM4DUserManagementValidator.ValidateUserID(AUserID);
      TIAM4DUserManagementValidator.ValidateSessionID(ASessionID);

      LToken := GetAccessToken;

      LURL := GetAdminURL + '/sessions/' + TNetEncoding.URL.Encode(ASessionID);

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Delete(LURL);
        EnsureResponseSuccess(LResponse, 'Revoke user session');
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.SetUserEnabledStateAsync(const AUserID: string; const AEnabled: Boolean): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LUpdateJSON: TJSONObject;
      LContext: string;
    begin
      TIAM4DUserManagementValidator.ValidateUserID(AUserID);

      LToken := GetAccessToken;
      LContext := IfThen(AEnabled, 'Enable user', 'Disable user');

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LUpdateJSON := TJSONObject.Create;
        try
          LUpdateJSON.AddPair('enabled', TJSONBool.Create(AEnabled));
          ExecuteJSONRequest(LHTTPClient, GetUserURL(AUserID), 'PUT', LUpdateJSON, LContext);
        finally
          LUpdateJSON.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.DisableUserAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := SetUserEnabledStateAsync(AUserID, False);
end;

function TIAM4DKeycloakUserManager.EnableUserAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := SetUserEnabledStateAsync(AUserID, True);
end;

function TIAM4DKeycloakUserManager.GetRoleByNameAsync(const ARoleName: string): IAsyncPromise<TIAM4DRole>;
begin
  Result := TAsyncCore.New<TIAM4DRole>(
    function(const AOperation: IAsyncOperation): TIAM4DRole
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONValue: TJSONValue;
    begin
      TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);

      LToken := GetAccessToken;

      LURL := GetRealmRolesURL + '/' + TNetEncoding.URL.Encode(ARoleName);

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(LURL);

        if LResponse.StatusCode = IAM4D_HTTP_STATUS_NOT_FOUND then
          raise EIAM4DRoleNotFoundException.Create(ARoleName);

        EnsureResponseSuccess(LResponse, 'Get role by name');
        LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'role response');
        try
          Result := JSONToRole(LJSONValue as TJSONObject);
        finally
          LJSONValue.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.TryGetRoleByNameAsync(const ARoleName: string): IAsyncPromise<TIAM4DRoleTryResult>;
begin
  Result := TAsyncCore.New<TIAM4DRoleTryResult>(
    function(const AOperation: IAsyncOperation): TIAM4DRoleTryResult
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONValue: TJSONValue;
    begin
      TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);

      LToken := GetAccessToken;
      LURL := GetRealmRolesURL + '/' + TNetEncoding.URL.Encode(ARoleName);

      Result.Found := False;
      Result.Role := Default(TIAM4DRole);

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(LURL);

        if LResponse.StatusCode = IAM4D_HTTP_STATUS_NOT_FOUND then
        begin
          Result.Found := False;
        end
        else
        begin
          EnsureResponseSuccess(LResponse, 'Try get role by name');
          LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'role response');
          try
            Result.Found := True;
            Result.Role := JSONToRole(LJSONValue as TJSONObject);
          finally
            LJSONValue.Free;
          end;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.HasRoleAsync(const AUserID: string; const ARoleName: string): IAsyncPromise<Boolean>;
begin
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      I: Integer;
      LRoleName: string;
    begin
      TIAM4DUserManagementValidator.ValidateUserID(AUserID);
      TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);

      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetUserURL(AUserID) + '/role-mappings/realm');
        EnsureResponseSuccess(LResponse, 'Get user roles for HasRole check');

        LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'roles array response');
        try
          Result := False;
          for I := 0 to LJSONArray.Count - 1 do
          begin
            if LJSONArray.Items[I] is TJSONObject then
            begin
              LRoleName := (LJSONArray.Items[I] as TJSONObject).GetValue<string>('name', '');
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
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUsersWithRoleAsync(const ARoleName: string; const AFirstResult: Integer; const AMaxResults: Integer): IAsyncPromise<TArray<TIAM4DUser>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DUser> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUser>
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONArray: TJSONArray;
      LUsersList: TList<TIAM4DUser>;
      I: Integer;
    begin
      TIAM4DUserManagementValidator.ValidateRoleName(ARoleName);

      LToken := GetAccessToken;

      LURL := GetRealmRolesURL + '/' + TNetEncoding.URL.Encode(ARoleName) + '/users';
      LURL := LURL + '?first=' + AFirstResult.ToString + '&max=' + AMaxResults.ToString;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(LURL);
        EnsureResponseSuccess(LResponse, 'Get users with role');

        LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'users array response');
        try
          LUsersList := TList<TIAM4DUser>.Create;
          try
            for I := 0 to LJSONArray.Count - 1 do
              if LJSONArray.Items[I] is TJSONObject then
                LUsersList.Add(JSONToUser(LJSONArray.Items[I] as TJSONObject));
            Result := LUsersList.ToArray;
          finally
            LUsersList.Free;
          end;
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetGroupByPathAsync(const APath: string): IAsyncPromise<TIAM4DGroup>;
begin
  Result := TAsyncCore.New<TIAM4DGroup>(
    function(const AOperation: IAsyncOperation): TIAM4DGroup
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONArray: TJSONArray;
      I: Integer;
      LGroupPath: string;
    begin
      if APath.IsEmpty then
        raise EIAM4DInvalidConfigurationException.Create('Group path cannot be empty');

      LToken := GetAccessToken;

      LURL := GetGroupsURL;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(LURL);
        EnsureResponseSuccess(LResponse, 'Get groups for path search');

        LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
        try
          Result.ID := IAM4D_EMPTY_USER_ID;

          for I := 0 to LJSONArray.Count - 1 do
          begin
            if LJSONArray.Items[I] is TJSONObject then
            begin
              LGroupPath := (LJSONArray.Items[I] as TJSONObject).GetValue<string>('path', IAM4D_EMPTY_USER_ID);
              if SameText(LGroupPath, APath) then
              begin
                Result := JSONToGroup(LJSONArray.Items[I] as TJSONObject);
                Break;
              end;
            end;
          end;

          if Result.ID = IAM4D_EMPTY_USER_ID then
            raise EIAM4DGroupNotFoundException.Create(APath);
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.TryGetGroupByPathAsync(const APath: string): IAsyncPromise<TIAM4DGroupTryResult>;
begin
  Result := TAsyncCore.New<TIAM4DGroupTryResult>(
    function(const AOperation: IAsyncOperation): TIAM4DGroupTryResult
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONArray: TJSONArray;
      I: Integer;
      LGroupPath: string;
    begin
      if APath.IsEmpty then
        raise EIAM4DInvalidConfigurationException.Create('Group path cannot be empty');

      LToken := GetAccessToken;
      LURL := GetGroupsURL;

      Result.Found := False;
      Result.Group := Default(TIAM4DGroup);

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(LURL);
        EnsureResponseSuccess(LResponse, 'Try get group by path');

        LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
        try
          for I := 0 to LJSONArray.Count - 1 do
          begin
            if LJSONArray.Items[I] is TJSONObject then
            begin
              LGroupPath := (LJSONArray.Items[I] as TJSONObject).GetValue<string>('path', IAM4D_EMPTY_USER_ID);
              if SameText(LGroupPath, APath) then
              begin
                Result.Found := True;
                Result.Group := JSONToGroup(LJSONArray.Items[I] as TJSONObject);
                Break;
              end;
            end;
          end;
        finally
          LJSONArray.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.IsMemberOfGroupAsync(const AUserID: string; const AGroupPath: string): IAsyncPromise<Boolean>;
begin
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LJSONArray: TJSONArray;
      I: Integer;
      LPath: string;
    begin
      TIAM4DUserManagementValidator.ValidateUserID(AUserID);
      TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

      LToken := GetAccessToken;

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(GetUserURL(AUserID) + '/groups');
        EnsureResponseSuccess(LResponse, 'Get user groups for membership check');

        LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
        try
          Result := False;
          for I := 0 to LJSONArray.Count - 1 do
          begin
            if LJSONArray.Items[I] is TJSONObject then
            begin
              LPath := (LJSONArray.Items[I] as TJSONObject).GetValue<string>('path', '');
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
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUsersInGroup(const AHTTPClient: THTTPClient; const AGroupID: string; const AFirstResult: Integer; const AMaxResults: Integer): TArray<TIAM4DUser>;
var
  LResponse: IHTTPResponse;
  LURL: string;
  LJSONArray: TJSONArray;
  LUsersList: TList<TIAM4DUser>;
  I: Integer;
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
      for I := 0 to LJSONArray.Count - 1 do
        if LJSONArray.Items[I] is TJSONObject then
          LUsersList.Add(JSONToUser(LJSONArray.Items[I] as TJSONObject));
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
  I: Integer;
begin
  TIAM4DUserManagementValidator.ValidateClientID(AClientID);

  LURL := GetAdminURL + '/clients/' + TNetEncoding.URL.Encode(AClientID) + '/roles';

  LResponse := AHTTPClient.Get(LURL);
  EnsureResponseSuccess(LResponse, 'Get client roles');

  LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'client roles array response');
  try
    LRolesList := TList<TIAM4DRole>.Create;
    try
      for I := 0 to LJSONArray.Count - 1 do
        if LJSONArray.Items[I] is TJSONObject then
          LRolesList.Add(JSONToRole(LJSONArray.Items[I] as TJSONObject, AClientID, AClientName));
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
  I: Integer;
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
      for I := 0 to LJSONArray.Count - 1 do
        if LJSONArray.Items[I] is TJSONObject then
          LRolesList.Add(JSONToRole(LJSONArray.Items[I] as TJSONObject));
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
  I: Integer;
  LPath: string;
begin
  TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

  LURL := GetGroupsURL;

  LResponse := AHTTPClient.Get(LURL);
  EnsureResponseSuccess(LResponse, 'Get groups for path lookup');

  LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'groups array response');
  try
    Result := '';

    for I := 0 to LJSONArray.Count - 1 do
    begin
      if LJSONArray.Items[I] is TJSONObject then
      begin
        LGroupObj := LJSONArray.Items[I] as TJSONObject;
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

function TIAM4DKeycloakUserManager.GetClientRolesByNameAsync(const AClientName: string): IAsyncPromise<TArray<TIAM4DRole>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRole> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRole>
    var
      LToken: string;
      LClientID: string;
      LHTTPClient: THTTPClient;
    begin
      TIAM4DUserManagementValidator.ValidateClientName(AClientName);

      LToken := GetAccessToken;

      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LClientID := GetClientIDByName(LHTTPClient, AClientName);

        if LClientID.IsEmpty then
          raise EIAM4DInvalidConfigurationException.CreateFmt('Client "%s" not found', [AClientName]);

        Result := GetClientRoles(LHTTPClient, LClientID, AClientName);
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUserClientRolesByNameAsync(
  const AUserID: string;
  const AClientName: string): IAsyncPromise<TArray<TIAM4DRole>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRole> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRole>
    var
      LToken: string;
      LClientID: string;
      LHTTPClient: THTTPClient;
    begin
      if AUserID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

      TIAM4DUserManagementValidator.ValidateClientName(AClientName);

      LToken := GetAccessToken;

      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LClientID := GetClientIDByName(LHTTPClient, AClientName);

        if LClientID.IsEmpty then
          raise EIAM4DInvalidConfigurationException.CreateFmt('Client "%s" not found', [AClientName]);

        Result := GetUserClientRoles(LHTTPClient, AUserID, LClientID);
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.AssignClientRolesToUserAsync(
  const AUserID: string;
  const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LClientID: string;
      LHTTPClient: THTTPClient;
    begin
      if AUserID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

      TIAM4DUserManagementValidator.ValidateRolesArray(Length(ARoles));

      if (Length(ARoles) > 0) and (ARoles[0].ClientID.IsEmpty or ARoles[0].ClientName.IsEmpty) then
        raise EIAM4DInvalidConfigurationException.CreateFmt(
          'Role "%s" is missing ClientID or ClientName. Use GetClientRolesByNameAsync to retrieve roles with complete client information.',
          [ARoles[0].Name]);

      LToken := GetAccessToken;

      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LClientID := ARoles[0].ClientID;

        AssignClientRolesToUser(LHTTPClient, AUserID, LClientID, ARoles);
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.AssignClientRolesToUsersAsync(
  const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  ValidateBatchSize(Length(ARoleAssignments), 'AssignClientRolesToUsersAsync');

  Result := TAsyncCore.New < TArray<TIAM4DOperationResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DOperationResult>
    type
      TClientAssignments = record
        ClientID: string;
        ClientName: string;
        Users: TList<Integer>;
      end;
      var
      LToken: string;
      LHTTPClient: THTTPClient;
      LAssignment: TIAM4DRoleAssignment;
      LClientGroups: TDictionary<string, TClientAssignments>;
      LClientKey: string;
      LClientGroup: TClientAssignments;
      LUserIndex: Integer;
      I: Integer;
      LResults: TArray<TIAM4DOperationResult>;
    begin
      SetLength(LResults, Length(ARoleAssignments));

      LToken := GetAccessToken;
      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LClientGroups := TDictionary<string, TClientAssignments>.Create;
        try
          for I := 0 to High(ARoleAssignments) do
          begin
            LAssignment := ARoleAssignments[I];
            LResults[I].Identifier := LAssignment.UserID;
            LResults[I].Success := False;
            LResults[I].ErrorMessage := '';

            if Length(LAssignment.Roles) = 0 then
            begin
              LResults[I].Success := True;
              Continue;
            end;

            if LAssignment.Roles[0].ClientID.IsEmpty or LAssignment.Roles[0].ClientName.IsEmpty then
              raise EIAM4DInvalidConfigurationException.CreateFmt(
                'Role "%s" is missing ClientID or ClientName. Use GetClientRolesByNameAsync to retrieve roles with complete client information.',
                [LAssignment.Roles[0].Name]);

            LClientKey := LAssignment.Roles[0].ClientID;

            if not LClientGroups.TryGetValue(LClientKey, LClientGroup) then
            begin
              LClientGroup.ClientID := LAssignment.Roles[0].ClientID;
              LClientGroup.ClientName := LAssignment.Roles[0].ClientName;
              LClientGroup.Users := TList<Integer>.Create;
              LClientGroups.Add(LClientKey, LClientGroup);
            end;

            LClientGroup.Users.Add(I);
          end;

          for LClientKey in LClientGroups.Keys do
          begin
            LClientGroup := LClientGroups[LClientKey];

            for LUserIndex in LClientGroup.Users do
            begin
              try
                AssignClientRolesToUser(
                  LHTTPClient,
                  ARoleAssignments[LUserIndex].UserID,
                  LClientGroup.ClientID,
                  ARoleAssignments[LUserIndex].Roles);
                LResults[LUserIndex].Success := True;
              except
                on E: Exception do
                begin
                  LResults[LUserIndex].Success := False;
                  LResults[LUserIndex].ErrorMessage := Format('Client role assignment %d/%d (UserID: %s, Client: %s, %d roles): %s',
                    [LUserIndex + 1, Length(ARoleAssignments), ARoleAssignments[LUserIndex].UserID,
                      LClientGroup.ClientName, Length(ARoleAssignments[LUserIndex].Roles), E.Message]);
                end;
              end;
            end;
          end;

        finally
          for LClientKey in LClientGroups.Keys do
          begin
            LClientGroup := LClientGroups[LClientKey];
            LClientGroup.Users.Free;
          end;
          LClientGroups.Free;
        end;

        Result := LResults;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.RemoveClientRolesFromUserByNameAsync(
  const AUserID: string;
  const AClientName: string;
  const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LClientID: string;
      LHTTPClient: THTTPClient;
    begin
      if AUserID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

      TIAM4DUserManagementValidator.ValidateClientName(AClientName);

      TIAM4DUserManagementValidator.ValidateRolesArray(Length(ARoles));

      LToken := GetAccessToken;

      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LClientID := GetClientIDByName(LHTTPClient, AClientName);

        if LClientID.IsEmpty then
          raise EIAM4DInvalidConfigurationException.CreateFmt('Client "%s" not found', [AClientName]);

        RemoveClientRolesFromUser(LHTTPClient, AUserID, LClientID, ARoles);
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.HasClientRoleByNameAsync(
  const AUserID: string;
  const AClientName: string;
  const ARoleName: string): IAsyncPromise<Boolean>;
begin
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    var
      LToken: string;
      LClientID: string;
      LHTTPClient: THTTPClient;
    begin
      if AUserID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

      TIAM4DUserManagementValidator.ValidateClientName(AClientName);

      if ARoleName.IsEmpty then
        raise EIAM4DInvalidConfigurationException.Create('RoleName cannot be empty');

      LToken := GetAccessToken;

      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LClientID := GetClientIDByName(LHTTPClient, AClientName);

        if LClientID.IsEmpty then
          raise EIAM4DInvalidConfigurationException.CreateFmt('Client "%s" not found', [AClientName]);

        Result := HasClientRole(LHTTPClient, AUserID, LClientID, ARoleName);
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetClientsAsync: IAsyncPromise<TArray<TIAM4DRealmClient>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRealmClient> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRealmClient>
    var
      LToken: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LJSONArray: TJSONArray;
      LClientsList: TList<TIAM4DRealmClient>;
      I: Integer;
      LClient: TIAM4DRealmClient;
      LRoles: TArray<TIAM4DRole>;
    begin
      LToken := GetAccessToken;
      LURL := GetAdminURL + '/clients';

      var LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LResponse := LHTTPClient.Get(LURL);
        EnsureResponseSuccess(LResponse, 'Get clients');

        LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(LResponse.ContentAsString, 'clients array response');
        try
          LClientsList := TList<TIAM4DRealmClient>.Create;
          try
            for I := 0 to LJSONArray.Count - 1 do
            begin
              if LJSONArray.Items[I] is TJSONObject then
              begin
                LClient := JSONToRealmClient(LJSONArray.Items[I] as TJSONObject);

                try
                  LRoles := GetClientRoles(LHTTPClient, LClient.ID, LClient.ClientID);
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
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetClientsAsync(const AClientName: string): IAsyncPromise<TIAM4DRealmClient>;
begin
  Result := TAsyncCore.New<TIAM4DRealmClient>(
    function(const AOperation: IAsyncOperation): TIAM4DRealmClient
    var
      LToken: string;
      LHTTPClient: THTTPClient;
      LClientID: string;
      LResponse: IHTTPResponse;
      LURL: string;
      LRoles: TArray<TIAM4DRole>;
    begin
      TIAM4DUserManagementValidator.ValidateClientName(AClientName);

      LToken := GetAccessToken;

      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LClientID := GetClientIDByName(LHTTPClient, AClientName);

        if LClientID.IsEmpty then
          raise EIAM4DInvalidConfigurationException.CreateFmt('Client "%s" not found', [AClientName]);

        LURL := GetAdminURL + '/clients/' + TNetEncoding.URL.Encode(LClientID);
        LResponse := LHTTPClient.Get(LURL);
        EnsureResponseSuccess(LResponse, 'Get client details');

        var LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'client response');
        try
          Result := JSONToRealmClient(LJSONValue as TJSONObject);

          try
            LRoles := GetClientRoles(LHTTPClient, LClientID, AClientName);
            Result.Roles := LRoles;
          except
            Result.Roles := nil;
          end;
        finally
          LJSONValue.Free;
        end;
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.AddUserToGroupByPathAsync(
  const AUserID: string;
  const AGroupPath: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LGroupID: string;
      LHTTPClient: THTTPClient;
    begin
      if AUserID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

      TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

      LToken := GetAccessToken;

      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LGroupID := GetGroupIDByPath(LHTTPClient, AGroupPath);

        if LGroupID.IsEmpty then
          raise EIAM4DInvalidConfigurationException.CreateFmt('Group "%s" not found', [AGroupPath]);

        AddUserToGroup(LHTTPClient, AUserID, LGroupID);
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.RemoveUserFromGroupByPathAsync(
  const AUserID: string;
  const AGroupPath: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    var
      LToken: string;
      LGroupID: string;
      LHTTPClient: THTTPClient;
    begin
      if AUserID.IsEmpty then
        raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');

      TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

      LToken := GetAccessToken;

      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LGroupID := GetGroupIDByPath(LHTTPClient, AGroupPath);

        if LGroupID.IsEmpty then
          raise EIAM4DInvalidConfigurationException.CreateFmt('Group "%s" not found', [AGroupPath]);

        RemoveUserFromGroup(LHTTPClient, AUserID, LGroupID);
      finally
        LHTTPClient.Free;
      end;
    end);
end;

function TIAM4DKeycloakUserManager.GetUsersInGroupByPathAsync(
  const AGroupPath: string;
  const AFirstResult: Integer;
  const AMaxResults: Integer): IAsyncPromise<TArray<TIAM4DUser>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DUser> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUser>
    var
      LToken: string;
      LGroupID: string;
      LHTTPClient: THTTPClient;
    begin
      TIAM4DUserManagementValidator.ValidateGroupPath(AGroupPath);

      LToken := GetAccessToken;

      LHTTPClient := FAuthProvider.CreateHTTPClient;
      try
        LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;

        LGroupID := GetGroupIDByPath(LHTTPClient, AGroupPath);

        if LGroupID.IsEmpty then
          raise EIAM4DInvalidConfigurationException.CreateFmt('Group "%s" not found', [AGroupPath]);

        Result := GetUsersInGroup(LHTTPClient, LGroupID, AFirstResult, AMaxResults);
      finally
        LHTTPClient.Free;
      end;
    end);
end;

end.