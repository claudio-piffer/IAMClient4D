{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.UserManagement.Keycloak.Async.pas
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

  Async wrapper for Keycloak User Manager.

  This unit provides TIAM4DKeycloakUserManagerAsync which implements
  IIAM4DUserManagerAsync by wrapping the synchronous TIAM4DKeycloakUserManager
  methods using TAsyncCore.New<T>.

  Architecture:
    IIAM4DUserManagerAsync (async interface)
           |
           v
    TIAM4DKeycloakUserManagerAsync (async wrapper - this class)
           |
           v
    IIAM4DUserManager / TIAM4DKeycloakUserManager (sync implementation)

  Usage:
    var ASyncManager := TIAM4DKeycloakUserManagerAsync.Create(SyncManager);

  ---------------------------------------------------------------------------
}

unit IAMClient4D.UserManagement.Keycloak.Async;

interface

uses
  System.SysUtils,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.UserManagement.Core,
  IAMClient4D.UserManagement.Keycloak;

type
  /// <summary>
  /// Async wrapper for TIAM4DKeycloakUserManager.
  /// Implements IIAM4DUserManagerAsync by wrapping sync methods with TAsyncCore.New.
  /// </summary>
  /// <remarks>
  /// <para><b>Architecture:</b> This class wraps the synchronous IIAM4DUserManager implementation,
  /// executing each operation on a background thread via TAsyncCore. Callbacks (OnSuccess,
  /// OnError, OnFinally) execute on the main thread by default.</para>
  ///
  /// <para><b>When to use:</b> VCL/FMX desktop applications where UI responsiveness is required.
  /// For REST services, use IIAM4DUserManager directly - async adds unnecessary overhead.</para>
  ///
  /// <para><b>Thread safety:</b> Each operation creates a new HTTP client internally. The
  /// wrapper itself is thread-safe for concurrent async operations.</para>
  ///
  /// <para><b>Cancellation:</b> Batch operations (CreateUsersAsync, UpdateUsersAsync, etc.)
  /// run atomically. For fine-grained cancellation, use individual operations in a loop.</para>
  /// </remarks>
  /// <seealso cref="IIAM4DUserManagerAsync"/>
  /// <seealso cref="IIAM4DUserManager"/>
  TIAM4DKeycloakUserManagerAsync = class(TInterfacedObject, IIAM4DUserManagerAsync)
  private
    FSyncManager: IIAM4DUserManager;
  public
    constructor Create(const ASyncManager: IIAM4DUserManager); overload;
    constructor Create(const AClient: IIAM4DClient; const ABaseURL: string = ''; const ARealm: string = ''); overload;
    constructor Create(const AAccessToken: string; const ABaseURL: string; const ARealm: string); overload;

    // ========================================================================
    // User CRUD Operations
    // ========================================================================
    function CreateUserAsync(const AUser: TIAM4DUser): IAsyncPromise<string>;
    function CreateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DUsersCreateResult>>;
    function GetUserAsync(const AUserID: string): IAsyncPromise<TIAM4DUser>;
    function GetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUser>;
    function TryGetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUserTryResult>;
    function GetUserByEmailAsync(const AEmail: string): IAsyncPromise<TIAM4DUser>;
    function TryGetUserByEmailAsync(const AEmail: string): IAsyncPromise<TIAM4DUserTryResult>;
    function GetUsersByIDsAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DUserGetResult>>;
    function UpdateUserAsync(const AUser: TIAM4DUser): IAsyncVoidPromise;
    function UpdateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
    function DeleteUserAsync(const AUserID: string): IAsyncVoidPromise;
    function DeleteUsersAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
    function SearchUsersAsync(const ACriteria: TIAM4DUserSearchCriteria): IAsyncPromise<TArray<TIAM4DUser>>;
    function GetUsersCountAsync: IAsyncPromise<Integer>;

    // ========================================================================
    // Password Management
    // ========================================================================
    function SetPasswordAsync(const AUserID: string; const APassword: string; const ATemporary: Boolean = False): IAsyncVoidPromise;
    function SetPasswordsAsync(const APasswordResets: TArray<TIAM4DPasswordReset>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
    function SendPasswordResetEmailAsync(const AUserID: string): IAsyncVoidPromise;
    function SendVerifyEmailAsync(const AUserID: string): IAsyncVoidPromise;

    // ========================================================================
    // Role Management
    // ========================================================================
    function GetRealmRolesAsync: IAsyncPromise<TArray<TIAM4DRole>>;
    function GetUserRolesAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DRole>>;
    function AssignRolesToUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
    function AssignRolesToUsersAsync(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
    function RemoveRolesFromUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
    function AssignRoleByNameAsync(const AUserID: string; const ARoleName: string): IAsyncVoidPromise;
    function RemoveRoleByNameAsync(const AUserID: string; const ARoleName: string): IAsyncVoidPromise;
    function AssignClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncVoidPromise;
    function RemoveClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncVoidPromise;

    // ========================================================================
    // Group Management
    // ========================================================================
    function GetGroupsAsync: IAsyncPromise<TArray<TIAM4DGroup>>;
    function GetUserGroupsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DGroup>>;
    function AddUserToGroupByPathAsync(const AUserID: string; const AGroupPath: string): IAsyncVoidPromise;
    function RemoveUserFromGroupByPathAsync(const AUserID: string; const AGroupPath: string): IAsyncVoidPromise;

    // ========================================================================
    // Session Management
    // ========================================================================
    function LogoutUserAsync(const AUserID: string): IAsyncVoidPromise;
    function GetUserSessionsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DUserSession>>;
    function GetUserSessionCountAsync(const AUserID: string): IAsyncPromise<Integer>;
    function RevokeUserSessionAsync(const AUserID: string; const ASessionID: string): IAsyncVoidPromise;

    // ========================================================================
    // Federated Identity Management
    // ========================================================================
    function GetUserFederatedIdentitiesAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DFederatedIdentity>>;
    function IsUserFederatedAsync(const AUserID: string): IAsyncPromise<Boolean>;

    // ========================================================================
    // Required Actions Management
    // ========================================================================
    function GetUserRequiredActionsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DRequiredAction>>;
    function SetUserRequiredActionsAsync(const AUserID: string; const AActions: TArray<TIAM4DRequiredAction>): IAsyncVoidPromise;
    function RemoveUserRequiredActionsAsync(const AUserID: string; const AActions: TArray<TIAM4DRequiredAction>): IAsyncVoidPromise;

    // ========================================================================
    // Account Security
    // ========================================================================
    function IsUserLockedAsync(const AUserID: string): IAsyncPromise<Boolean>;
    function UnlockUserAsync(const AUserID: string): IAsyncVoidPromise;

    // ========================================================================
    // User State Management
    // ========================================================================
    function DisableUserAsync(const AUserID: string): IAsyncVoidPromise;
    function EnableUserAsync(const AUserID: string): IAsyncVoidPromise;

    // ========================================================================
    // Advanced Role Queries
    // ========================================================================
    function GetRoleByNameAsync(const ARoleName: string): IAsyncPromise<TIAM4DRole>;
    function TryGetRoleByNameAsync(const ARoleName: string): IAsyncPromise<TIAM4DRoleTryResult>;
    function HasRoleAsync(const AUserID: string; const ARoleName: string): IAsyncPromise<Boolean>;
    function GetUsersWithRoleAsync(const ARoleName: string; const AFirstResult: Integer = 0; const AMaxResults: Integer = 100): IAsyncPromise<TArray<TIAM4DUser>>;

    // ========================================================================
    // Advanced Group Queries
    // ========================================================================
    function GetGroupByPathAsync(const APath: string): IAsyncPromise<TIAM4DGroup>;
    function TryGetGroupByPathAsync(const APath: string): IAsyncPromise<TIAM4DGroupTryResult>;
    function IsMemberOfGroupAsync(const AUserID: string; const AGroupPath: string): IAsyncPromise<Boolean>;
    function GetUsersInGroupByPathAsync(const AGroupPath: string; const AFirstResult: Integer = 0; const AMaxResults: Integer = 100): IAsyncPromise<TArray<TIAM4DUser>>;

    // ========================================================================
    // Client Role Management
    // ========================================================================
    function GetClientRolesByNameAsync(const AClientName: string): IAsyncPromise<TArray<TIAM4DRole>>;
    function GetUserClientRolesByNameAsync(const AUserID: string; const AClientName: string): IAsyncPromise<TArray<TIAM4DRole>>;
    function AssignClientRolesToUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
    function AssignClientRolesToUsersAsync(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
    function RemoveClientRolesFromUserByNameAsync(const AUserID: string; const AClientName: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
    function HasClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncPromise<Boolean>;
    function GetClientsAsync: IAsyncPromise<TIAM4DRealmClientArray>; overload;
    function GetClientsAsync(const AClientName: string): IAsyncPromise<TIAM4DRealmClient>; overload;
  end;

implementation

{ TIAM4DKeycloakUserManagerAsync }

constructor TIAM4DKeycloakUserManagerAsync.Create(const ASyncManager: IIAM4DUserManager);
begin
  inherited Create;
  FSyncManager := ASyncManager;
end;

constructor TIAM4DKeycloakUserManagerAsync.Create(const AClient: IIAM4DClient; const ABaseURL: string; const ARealm: string);
begin
  Create(TIAM4DKeycloakUserManager.Create(AClient, ABaseURL, ARealm) as IIAM4DUserManager);
end;

constructor TIAM4DKeycloakUserManagerAsync.Create(const AAccessToken: string; const ABaseURL: string; const ARealm: string);
begin
  Create(TIAM4DKeycloakUserManager.Create(AAccessToken, ABaseURL, ARealm) as IIAM4DUserManager);
end;

// ============================================================================
// User CRUD Operations
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.CreateUserAsync(const AUser: TIAM4DUser): IAsyncPromise<string>;
begin
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := FSyncManager.CreateUser(AUser);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.CreateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DUsersCreateResult>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DUsersCreateResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUsersCreateResult>
    begin
      Result := FSyncManager.CreateUsers(AUsers, AOperation);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUserAsync(const AUserID: string): IAsyncPromise<TIAM4DUser>;
begin
  Result := TAsyncCore.New<TIAM4DUser>(
    function(const AOperation: IAsyncOperation): TIAM4DUser
    begin
      Result := FSyncManager.GetUser(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUser>;
begin
  Result := TAsyncCore.New<TIAM4DUser>(
    function(const AOperation: IAsyncOperation): TIAM4DUser
    begin
      Result := FSyncManager.GetUserByUsername(AUsername);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.TryGetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUserTryResult>;
begin
  Result := TAsyncCore.New<TIAM4DUserTryResult>(
    function(const AOperation: IAsyncOperation): TIAM4DUserTryResult
    begin
      Result := FSyncManager.TryGetUserByUsername(AUsername);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUserByEmailAsync(const AEmail: string): IAsyncPromise<TIAM4DUser>;
begin
  Result := TAsyncCore.New<TIAM4DUser>(
    function(const AOperation: IAsyncOperation): TIAM4DUser
    begin
      Result := FSyncManager.GetUserByEmail(AEmail);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.TryGetUserByEmailAsync(const AEmail: string): IAsyncPromise<TIAM4DUserTryResult>;
begin
  Result := TAsyncCore.New<TIAM4DUserTryResult>(
    function(const AOperation: IAsyncOperation): TIAM4DUserTryResult
    begin
      Result := FSyncManager.TryGetUserByEmail(AEmail);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUsersByIDsAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DUserGetResult>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DUserGetResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUserGetResult>
    begin
      Result := FSyncManager.GetUsersByIDs(AUserIDs, AOperation);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.UpdateUserAsync(const AUser: TIAM4DUser): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.UpdateUser(AUser);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.UpdateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DOperationResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DOperationResult>
    begin
      Result := FSyncManager.UpdateUsers(AUsers, AOperation);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.DeleteUserAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.DeleteUser(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.DeleteUsersAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DOperationResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DOperationResult>
    begin
      Result := FSyncManager.DeleteUsers(AUserIDs, AOperation);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.SearchUsersAsync(const ACriteria: TIAM4DUserSearchCriteria): IAsyncPromise<TArray<TIAM4DUser>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DUser> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUser>
    begin
      Result := FSyncManager.SearchUsers(ACriteria);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUsersCountAsync: IAsyncPromise<Integer>;
begin
  Result := TAsyncCore.New<Integer>(
    function(const AOperation: IAsyncOperation): Integer
    begin
      Result := FSyncManager.GetUsersCount;
    end);
end;

// ============================================================================
// Password Management
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.SetPasswordAsync(const AUserID: string; const APassword: string; const ATemporary: Boolean): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.SetPassword(AUserID, APassword, ATemporary);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.SetPasswordsAsync(const APasswordResets: TArray<TIAM4DPasswordReset>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DOperationResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DOperationResult>
    begin
      Result := FSyncManager.SetPasswords(APasswordResets, AOperation);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.SendPasswordResetEmailAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.SendPasswordResetEmail(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.SendVerifyEmailAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.SendVerifyEmail(AUserID);
    end);
end;

// ============================================================================
// Role Management
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.GetRealmRolesAsync: IAsyncPromise<TArray<TIAM4DRole>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRole> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRole>
    begin
      Result := FSyncManager.GetRealmRoles;
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUserRolesAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DRole>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRole> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRole>
    begin
      Result := FSyncManager.GetUserRoles(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.AssignRolesToUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.AssignRolesToUser(AUserID, ARoles);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.AssignRolesToUsersAsync(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DOperationResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DOperationResult>
    begin
      Result := FSyncManager.AssignRolesToUsers(ARoleAssignments, AOperation);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.RemoveRolesFromUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.RemoveRolesFromUser(AUserID, ARoles);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.AssignRoleByNameAsync(const AUserID: string; const ARoleName: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.AssignRoleByName(AUserID, ARoleName);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.RemoveRoleByNameAsync(const AUserID: string; const ARoleName: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.RemoveRoleByName(AUserID, ARoleName);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.AssignClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.AssignClientRoleByName(AUserID, AClientName, ARoleName);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.RemoveClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.RemoveClientRoleByName(AUserID, AClientName, ARoleName);
    end);
end;

// ============================================================================
// Group Management
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.GetGroupsAsync: IAsyncPromise<TArray<TIAM4DGroup>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DGroup> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DGroup>
    begin
      Result := FSyncManager.GetGroups;
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUserGroupsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DGroup>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DGroup> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DGroup>
    begin
      Result := FSyncManager.GetUserGroups(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.AddUserToGroupByPathAsync(const AUserID: string; const AGroupPath: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.AddUserToGroupByPath(AUserID, AGroupPath);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.RemoveUserFromGroupByPathAsync(const AUserID: string; const AGroupPath: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.RemoveUserFromGroupByPath(AUserID, AGroupPath);
    end);
end;

// ============================================================================
// Session Management
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.LogoutUserAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.LogoutUser(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUserSessionsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DUserSession>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DUserSession> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUserSession>
    begin
      Result := FSyncManager.GetUserSessions(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUserSessionCountAsync(const AUserID: string): IAsyncPromise<Integer>;
begin
  Result := TAsyncCore.New<Integer>(
    function(const AOperation: IAsyncOperation): Integer
    begin
      Result := FSyncManager.GetUserSessionCount(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.RevokeUserSessionAsync(const AUserID: string; const ASessionID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.RevokeUserSession(AUserID, ASessionID);
    end);
end;

// ============================================================================
// Federated Identity Management
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.GetUserFederatedIdentitiesAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DFederatedIdentity>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DFederatedIdentity> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DFederatedIdentity>
    begin
      Result := FSyncManager.GetUserFederatedIdentities(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.IsUserFederatedAsync(const AUserID: string): IAsyncPromise<Boolean>;
begin
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    begin
      Result := FSyncManager.IsUserFederated(AUserID);
    end);
end;

// ============================================================================
// Required Actions Management
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.GetUserRequiredActionsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DRequiredAction>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRequiredAction> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRequiredAction>
    begin
      Result := FSyncManager.GetUserRequiredActions(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.SetUserRequiredActionsAsync(const AUserID: string; const AActions: TArray<TIAM4DRequiredAction>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.SetUserRequiredActions(AUserID, AActions);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.RemoveUserRequiredActionsAsync(const AUserID: string; const AActions: TArray<TIAM4DRequiredAction>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.RemoveUserRequiredActions(AUserID, AActions);
    end);
end;

// ============================================================================
// Account Security
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.IsUserLockedAsync(const AUserID: string): IAsyncPromise<Boolean>;
begin
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    begin
      Result := FSyncManager.IsUserLocked(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.UnlockUserAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.UnlockUser(AUserID);
    end);
end;

// ============================================================================
// User State Management
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.DisableUserAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.DisableUser(AUserID);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.EnableUserAsync(const AUserID: string): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.EnableUser(AUserID);
    end);
end;

// ============================================================================
// Advanced Role Queries
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.GetRoleByNameAsync(const ARoleName: string): IAsyncPromise<TIAM4DRole>;
begin
  Result := TAsyncCore.New<TIAM4DRole>(
    function(const AOperation: IAsyncOperation): TIAM4DRole
    begin
      Result := FSyncManager.GetRoleByName(ARoleName);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.TryGetRoleByNameAsync(const ARoleName: string): IAsyncPromise<TIAM4DRoleTryResult>;
begin
  Result := TAsyncCore.New<TIAM4DRoleTryResult>(
    function(const AOperation: IAsyncOperation): TIAM4DRoleTryResult
    begin
      Result := FSyncManager.TryGetRoleByName(ARoleName);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.HasRoleAsync(const AUserID: string; const ARoleName: string): IAsyncPromise<Boolean>;
begin
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    begin
      Result := FSyncManager.HasRole(AUserID, ARoleName);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUsersWithRoleAsync(const ARoleName: string; const AFirstResult: Integer; const AMaxResults: Integer): IAsyncPromise<TArray<TIAM4DUser>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DUser> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUser>
    begin
      Result := FSyncManager.GetUsersWithRole(ARoleName, AFirstResult, AMaxResults);
    end);
end;

// ============================================================================
// Advanced Group Queries
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.GetGroupByPathAsync(const APath: string): IAsyncPromise<TIAM4DGroup>;
begin
  Result := TAsyncCore.New<TIAM4DGroup>(
    function(const AOperation: IAsyncOperation): TIAM4DGroup
    begin
      Result := FSyncManager.GetGroupByPath(APath);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.TryGetGroupByPathAsync(const APath: string): IAsyncPromise<TIAM4DGroupTryResult>;
begin
  Result := TAsyncCore.New<TIAM4DGroupTryResult>(
    function(const AOperation: IAsyncOperation): TIAM4DGroupTryResult
    begin
      Result := FSyncManager.TryGetGroupByPath(APath);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.IsMemberOfGroupAsync(const AUserID: string; const AGroupPath: string): IAsyncPromise<Boolean>;
begin
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    begin
      Result := FSyncManager.IsMemberOfGroup(AUserID, AGroupPath);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUsersInGroupByPathAsync(const AGroupPath: string; const AFirstResult: Integer; const AMaxResults: Integer): IAsyncPromise<TArray<TIAM4DUser>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DUser> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DUser>
    begin
      Result := FSyncManager.GetUsersInGroupByPath(AGroupPath, AFirstResult, AMaxResults);
    end);
end;

// ============================================================================
// Client Role Management
// ============================================================================

function TIAM4DKeycloakUserManagerAsync.GetClientRolesByNameAsync(const AClientName: string): IAsyncPromise<TArray<TIAM4DRole>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRole> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRole>
    begin
      Result := FSyncManager.GetClientRolesByName(AClientName);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetUserClientRolesByNameAsync(const AUserID: string; const AClientName: string): IAsyncPromise<TArray<TIAM4DRole>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DRole> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DRole>
    begin
      Result := FSyncManager.GetUserClientRolesByName(AUserID, AClientName);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.AssignClientRolesToUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.AssignClientRolesToUser(AUserID, ARoles);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.AssignClientRolesToUsersAsync(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  Result := TAsyncCore.New < TArray<TIAM4DOperationResult> > (
    function(const AOperation: IAsyncOperation): TArray<TIAM4DOperationResult>
    begin
      Result := FSyncManager.AssignClientRolesToUsers(ARoleAssignments, AOperation);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.RemoveClientRolesFromUserByNameAsync(const AUserID: string; const AClientName: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      FSyncManager.RemoveClientRolesFromUserByName(AUserID, AClientName, ARoles);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.HasClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncPromise<Boolean>;
begin
  Result := TAsyncCore.New<Boolean>(
    function(const AOperation: IAsyncOperation): Boolean
    begin
      Result := FSyncManager.HasClientRoleByName(AUserID, AClientName, ARoleName);
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetClientsAsync: IAsyncPromise<TIAM4DRealmClientArray>;
begin
  Result := TAsyncCore.New<TIAM4DRealmClientArray>(
    function(const AOperation: IAsyncOperation): TIAM4DRealmClientArray
    begin
      Result := FSyncManager.GetClients;
    end);
end;

function TIAM4DKeycloakUserManagerAsync.GetClientsAsync(const AClientName: string): IAsyncPromise<TIAM4DRealmClient>;
begin
  Result := TAsyncCore.New<TIAM4DRealmClient>(
    function(const AOperation: IAsyncOperation): TIAM4DRealmClient
    begin
      Result := FSyncManager.GetClients(AClientName);
    end);
end;

end.