unit UserManagement;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.UserManagement.Core,
  IAMClient4D.UserManagement.Keycloak.Async;

type
  TUserManagementSamples = class
  private
    FUserManager: IIAM4DUserManagerAsync;
  public
    constructor Create(const AClient: IIAM4DClient);

    /// <summary>
    /// Example 1: Create a single user with custom attributes
    /// </summary>
    function CreateUserWithAttributes(const AUser: TIAM4DUser): IAsyncPromise<string>;

    /// <summary>
    /// Example 2: Get user by ID
    /// </summary>
    function GetUserByID(const AUserID: string): IAsyncPromise<TIAM4DUser>;

    /// <summary>
    /// Example 3: Get user by username (with not-found handling)
    /// </summary>
    function GetUserByUsername(const AUsername: string): IAsyncPromise<TIAM4DUser>;

    /// <summary>
    /// Example 4: Update user profile and attributes
    /// </summary>
    function UpdateUserWithAttributes(const AUser: TIAM4dUser): IAsyncVoidPromise;

    /// <summary>
    /// Example 5: Delete a user
    /// </summary>
    function DeleteUser(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Example 6: Create multiple users in batch
    /// </summary>
    function CreateMultipleUsers(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DUsersCreateResult>>;

    /// <summary>
    /// Example 7: Update multiple users with different data
    /// </summary>
    function UpdateMultipleUsers(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Example 8: Delete multiple users in batch
    /// </summary>
    function DeleteMultipleUsers(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Example 9: Set passwords for multiple users
    /// </summary>
    function SetPasswordsForMultipleUsers(const AUserIDPasswords: TArray<TIAM4DPasswordReset>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Example 10: Get client roles
    /// </summary>
    function GetClientRoles: IAsyncPromise<TIAM4DRealmClientArray>;

    /// <summary>
    /// Example 11: Assign roles to multiple users
    /// </summary>
    function AssignRolesToMultipleUsers(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Example 12: Set user password (temporary or permanent)
    /// </summary>
    function SetUserPassword(const AUserID: string; const APassword: string; const ATemporary: Boolean): IAsyncVoidPromise;

    /// <summary>
    /// Example 13: Get all realm roles
    /// </summary>
    function GetAllRealmRoles: IAsyncPromise<TArray<TIAM4DRole>>;

    /// <summary>
    /// Example 14: Get user roles
    /// </summary>
    function GetUserRoles(const AUserID: string): IAsyncPromise<TArray<TIAM4DRole>>;

    /// <summary>
    /// Example 15: Search users with criteria
    /// </summary>
    function SearchUsers(const ACriteria: TIAM4DUserSearchCriteria): IAsyncPromise<TArray<TIAM4DUser>>;

    /// <summary>
    /// Example 16: Check if user is federated
    /// </summary>
    function CheckIfUserIsFederated(const AUserID: string): IAsyncPromise<Boolean>;
  end;

implementation

{ TUserManagementSamples }

constructor TUserManagementSamples.Create(const AClient: IIAM4DClient);
begin
  inherited Create;

  FUserManager := TIAM4DKeycloakUserManagerAsync.Create(AClient);
end;

function TUserManagementSamples.CreateUserWithAttributes(const AUser: TIAM4DUser): IAsyncPromise<string>;
begin
  Result := FUserManager.CreateUserAsync(AUser);
end;

function TUserManagementSamples.GetClientRoles: IAsyncPromise<TIAM4DRealmClientArray>;
begin

  Result := FUserManager.GetClientsAsync();
end;

function TUserManagementSamples.GetUserByID(const AUserID: string): IAsyncPromise<TIAM4DUser>;
begin
  Result := FUserManager.GetUserAsync(AUserID);
end;

function TUserManagementSamples.GetUserByUsername(const AUsername: string): IAsyncPromise<TIAM4DUser>;
begin
  Result := FUserManager.GetUserByUsernameAsync(AUsername);
end;

function TUserManagementSamples.UpdateUserWithAttributes(const AUser: TIAM4dUser): IAsyncVoidPromise;
begin
  Result := FUserManager.UpdateUserAsync(AUser);
end;

function TUserManagementSamples.DeleteUser(const AUserID: string): IAsyncVoidPromise;
begin
  Result := FUserManager.DeleteUserAsync(AUserID);
end;

function TUserManagementSamples.CreateMultipleUsers(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DUsersCreateResult>>;
begin
  Result := FUserManager.CreateUsersAsync(AUsers);
end;

function TUserManagementSamples.UpdateMultipleUsers(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  Result := FUserManager.UpdateUsersAsync(AUsers);
end;

function TUserManagementSamples.DeleteMultipleUsers(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  Result := FUserManager.DeleteUsersAsync(AUserIDs);
end;

function TUserManagementSamples.SetPasswordsForMultipleUsers(const AUserIDPasswords: TArray<TIAM4DPasswordReset>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  Result := FUserManager.SetPasswordsAsync(AUserIDPasswords);
end;

function TUserManagementSamples.AssignRolesToMultipleUsers(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
begin
  Result := FUserManager.AssignClientRolesToUsersAsync(ARoleAssignments);
end;

function TUserManagementSamples.SetUserPassword(const AUserID: string; const APassword: string; const ATemporary: Boolean): IAsyncVoidPromise;
begin
  Result := FUserManager.SetPasswordAsync(AUserID, APassword, ATemporary);
end;

function TUserManagementSamples.GetAllRealmRoles: IAsyncPromise<TArray<TIAM4DRole>>;
begin
  Result := FUserManager.GetRealmRolesAsync;
end;

function TUserManagementSamples.GetUserRoles(const AUserID: string): IAsyncPromise<TArray<TIAM4DRole>>;
begin
  Result := FUserManager.GetUserRolesAsync(AUserID);
end;

function TUserManagementSamples.SearchUsers(const ACriteria: TIAM4DUserSearchCriteria): IAsyncPromise<TArray<TIAM4DUser>>;
begin
  Result := FUserManager.SearchUsersAsync(ACriteria);
end;

function TUserManagementSamples.CheckIfUserIsFederated(const AUserID: string): IAsyncPromise<Boolean>;
begin
  Result := FUserManager.IsUserFederatedAsync(AUserID);
end;

end.

