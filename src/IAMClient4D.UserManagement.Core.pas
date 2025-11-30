{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.UserManagement.Core.pas
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

unit IAMClient4D.UserManagement.Core;

interface

uses
  System.SysUtils,
  Async.Core,
  IAMClient4D.Exceptions,
  IAMClient4D.UserManagement.Constants;

type

  /// <summary>
  /// User required actions enumeration for Keycloak.
  /// </summary>
  TIAM4DRequiredAction = (
    raVerifyEmail,
    raUpdatePassword,
    raConfigureOTP,
    raUpdateProfile,
    raTermsAndConditions);

  /// <summary>
  /// Helper for converting required actions to/from string representation.
  /// </summary>
  TIAM4DRequiredActionHelper = record helper for TIAM4DRequiredAction
    /// <summary>
    /// Converts required action to Keycloak string format.
    /// </summary>
    function ToString: string;
    /// <summary>
    /// Parses required action from Keycloak string format.
    /// </summary>
    class function FromString(const AValue: string): TIAM4DRequiredAction; static;
  end;

  /// <summary>
  /// Single user attribute with name and multi-valued data.
  /// </summary>
  /// <remarks>
  /// Replaces TDictionary to avoid double-free memory issues.
  /// Memory: Fully managed by runtime (no objects to free).
  /// </remarks>
  TIAM4DUserAttribute = record
    /// <summary>
    /// Attribute name (case-insensitive matching).
    /// </summary>
    Name: string;
    /// <summary>
    /// Array of string values for this attribute.
    /// </summary>
    Values: TArray<string>;
  end;

  /// <summary>
  /// Keycloak user representation with profile, attributes, and required actions.
  /// </summary>
  /// <remarks>
  /// Unified structure for create/update/read operations.
  /// Attributes: Multi-valued attributes managed as array of records (Name, Values).
  /// Timestamp: Unix timestamp in milliseconds when user was created.
  /// TemporaryPassword: Used only during creation, ignored in updates.
  /// Memory: Fully managed by runtime (no objects to free).
  /// </remarks>
  TIAM4DUser = record
  private
    FID: string;
    FUsername: string;
    FEmail: string;
    FFirstName: string;
    FLastName: string;
    FEnabled: Boolean;
    FEmailVerified: Boolean;
    FAttributes: TArray<TIAM4DUserAttribute>;
    FCreatedTimestamp: Int64;
    FRequiredActions: TArray<TIAM4DRequiredAction>;
    FTemporaryPassword: string;
    FRequirePasswordChange: Boolean;

    function IndexOfAttribute(const AName: string): Integer;
    function GetAttribute(const AName: string): TArray<string>;
    procedure SetAttribute(const AName: string; const AValues: TArray<string>);
  public
    property ID: string read FID write FID;
    property Username: string read FUsername write FUsername;
    property Email: string read FEmail write FEmail;
    property FirstName: string read FFirstName write FFirstName;
    property LastName: string read FLastName write FLastName;
    property Enabled: Boolean read FEnabled write FEnabled;
    property EmailVerified: Boolean read FEmailVerified write FEmailVerified;

    /// <summary>
    /// Dictionary-style access: User.Attributes['key'] := Values.
    /// If the attribute does not exist, it will be created.
    /// </summary>
    property Attributes[const AName: string]: TArray<string>
    read GetAttribute write SetAttribute;

    /// <summary>
    /// Access to the complete list of attributes.
    /// </summary>
    property AllAttributes: TArray<TIAM4DUserAttribute>
      read FAttributes write FAttributes;

    property CreatedTimestamp: Int64 read FCreatedTimestamp write FCreatedTimestamp;
    property RequiredActions: TArray<TIAM4DRequiredAction>
      read FRequiredActions write FRequiredActions;

    /// <summary>
    /// Temporary password for user creation.
    /// Used only during CreateUserAsync, ignored in UpdateUserAsync.
    /// </summary>
    property TemporaryPassword: string read FTemporaryPassword write FTemporaryPassword;

    /// <summary>
    /// Whether the temporary password requires change on first login.
    /// Used only during CreateUserAsync with TemporaryPassword.
    /// </summary>
    property RequirePasswordChange: Boolean read FRequirePasswordChange write FRequirePasswordChange;

    /// <summary>
    /// Checks if user has a specific required action.
    /// </summary>
    function HasRequiredAction(const AAction: TIAM4DRequiredAction): Boolean;

    /// <summary>
    /// Creates a new user record with specified profile information.
    /// </summary>
    constructor Create(
      const AUsername: string;
      const AEmail: string;
      const AFirstName: string = '';
      const ALastName: string = '';
      const AEnabled: Boolean = True);

    /// <summary>
    /// Adds or replaces an attribute.
    /// </summary>
    procedure AddAttribute(const AName: string; const AValues: array of string);

    /// <summary>
    /// Removes an attribute by name.
    /// Does nothing if attribute doesn't exist.
    /// </summary>
    procedure RemoveAttribute(const AName: string);

    /// <summary>
    /// Tries to get attribute values by name.
    /// Returns True if attribute exists.
    /// </summary>
    function TryGetAttribute(const AName: string; out AValues: TArray<string>): Boolean;

    /// <summary>
    /// Adds a required action if not already present.
    /// Automatically prevents duplicates.
    /// </summary>
    procedure AddRequiredAction(const AAction: TIAM4DRequiredAction);

    /// <summary>
    /// Adds multiple required actions.
    /// Automatically prevents duplicates.
    /// </summary>
    procedure AddRequiredActions(const AActions: array of TIAM4DRequiredAction);

    /// <summary>
    /// Removes a required action if present.
    /// Does nothing if action doesn't exist.
    /// </summary>
    procedure RemoveRequiredAction(const AAction: TIAM4DRequiredAction);
  end;

  /// <summary>
  /// User search criteria with field filters and pagination.
  /// </summary>
  TIAM4DUserSearchCriteria = record
  private
    FUsername: string;
    FEmail: string;
    FFirstName: string;
    FLastName: string;
    FSearch: string;
    FEnabled: Boolean;
    FFirstResult: Integer;
    FMaxResults: Integer;
  public
    property Username: string read FUsername write FUsername;
    property Email: string read FEmail write FEmail;
    property FirstName: string read FFirstName write FFirstName;
    property LastName: string read FLastName write FLastName;
    property Search: string read FSearch write FSearch;
    property Enabled: Boolean read FEnabled write FEnabled;
    property FirstResult: Integer read FFirstResult write FFirstResult;
    property MaxResults: Integer read FMaxResults write FMaxResults;

    /// <summary>
    /// Creates search criteria with pagination (default: 100 results).
    /// </summary>
    class function Create(
      const ASearch: string = '';
      const AFirstResult: Integer = IAM4D_DEFAULT_FIRST_RESULT;
      const AMaxResults: Integer = IAM4D_DEFAULT_PAGE_SIZE
      ): TIAM4DUserSearchCriteria; static;
  end;

  /// <summary>
  /// Keycloak role representation.
  /// </summary>
  /// <remarks>
  /// For client roles, ClientID and ClientName identify the owning client.
  /// For realm roles, ClientID and ClientName remain empty.
  /// This allows the library to automatically route role assignments to the correct endpoint.
  /// </remarks>
  TIAM4DRole = record
  private
    FID: string;
    FName: string;
    FDescription: string;
    FComposite: Boolean;
    FClientID: string;
    FClientName: string;
  public
    property ID: string read FID write FID;
    property Name: string read FName write FName;
    property Description: string read FDescription write FDescription;
    property Composite: Boolean read FComposite write FComposite;

    /// <summary>
    /// Client UUID for client roles (empty for realm roles).
    /// </summary>
    property ClientID: string read FClientID write FClientID;

    /// <summary>
    /// Client name for client roles (empty for realm roles).
    /// </summary>
    property ClientName: string read FClientName write FClientName;
  end;

  /// <summary>
  /// Keycloak group representation with hierarchical path.
  /// </summary>
  TIAM4DGroup = record
  private
    FID: string;
    FName: string;
    FPath: string;
  public
    property ID: string read FID write FID;
    property Name: string read FName write FName;
    property Path: string read FPath write FPath;
  end;

  /// <summary>
  /// Federated identity link for external identity providers.
  /// </summary>
  TIAM4DFederatedIdentity = record
  private
    FIdentityProvider: string;
    FUserID: string;
    FUserName: string;
  public
    property IdentityProvider: string read FIdentityProvider write FIdentityProvider;
    property UserID: string read FUserID write FUserID;
    property UserName: string read FUserName write FUserName;
  end;

  /// <summary>
  /// Result type for TryGetUserByUsername and TryGetUserByEmail operations.
  /// </summary>
  /// <remarks>
  /// Allows checking if a user exists without raising exceptions.
  /// Check Found property before accessing User.
  /// </remarks>
  TIAM4DUserTryResult = record
    /// <summary>
    /// True if the user was found, False otherwise.
    /// </summary>
    Found: Boolean;
    /// <summary>
    /// The user data if Found=True, otherwise contains default/empty values.
    /// </summary>
    User: TIAM4DUser;
  end;

  /// <summary>
  /// Result type for TryGetRoleByName operation.
  /// </summary>
  /// <remarks>
  /// Allows checking if a role exists without raising exceptions.
  /// Check Found property before accessing Role.
  /// </remarks>
  TIAM4DRoleTryResult = record
    /// <summary>
    /// True if the role was found, False otherwise.
    /// </summary>
    Found: Boolean;
    /// <summary>
    /// The role data if Found=True, otherwise contains default/empty values.
    /// </summary>
    Role: TIAM4DRole;
  end;

  /// <summary>
  /// Result type for TryGetGroupByPath operation.
  /// </summary>
  /// <remarks>
  /// Allows checking if a group exists without raising exceptions.
  /// Check Found property before accessing Group.
  /// </remarks>
  TIAM4DGroupTryResult = record
    /// <summary>
    /// True if the group was found, False otherwise.
    /// </summary>
    Found: Boolean;
    /// <summary>
    /// The group data if Found=True, otherwise contains default/empty values.
    /// </summary>
    Group: TIAM4DGroup;
  end;

  /// <summary>
  /// Represents a client application registered in the Keycloak realm with all its roles.
  /// </summary>
  /// <remarks>
  /// Clients are applications and services that can request authentication
  /// of a user or request access tokens. Common examples include realm-management,
  /// account, broker, and custom application clients.
  /// This record includes complete client information with all associated roles.
  /// </remarks>
  TIAM4DRealmClient = record
  private
    FID: string;
    FClientID: string;
    FName: string;
    FDescription: string;
    FEnabled: Boolean;
    FRoles: TArray<TIAM4DRole>;
  public
    /// <summary>
    /// Keycloak internal client identifier (UUID).
    /// </summary>
    property ID: string read FID write FID;

    /// <summary>
    /// Client identifier used for authentication (e.g., "realm-management", "account").
    /// </summary>
    property ClientID: string read FClientID write FClientID;

    /// <summary>
    /// Human-readable client name.
    /// </summary>
    property Name: string read FName write FName;

    /// <summary>
    /// Client description.
    /// </summary>
    property Description: string read FDescription write FDescription;

    /// <summary>
    /// Indicates whether the client is enabled.
    /// </summary>
    property Enabled: Boolean read FEnabled write FEnabled;

    /// <summary>
    /// Array of all roles defined for this client.
    /// </summary>
    /// <remarks>
    /// Contains all roles available for this client application.
    /// For example, the "realm-management" client includes roles like:
    /// realm-admin, manage-users, view-users, etc.
    /// </remarks>
    property Roles: TArray<TIAM4DRole> read FRoles write FRoles;

    /// <summary>
    /// Tries to find a role by its name. Returns True if found.
    /// </summary>
    /// <param name="ARoleName">
    /// The logical name of the role to search for (e.g., "realm-admin", "manage-users").
    /// </param>
    /// <param name="ARole">
    /// When the function returns True, contains the matching role.
    /// </param>
    function TryGetRoleByName(const ARoleName: string; out ARole: TIAM4DRole): Boolean;

    /// <summary>
    /// Checks whether this client exposes a role with the given name.
    /// </summary>
    /// <param name="ARoleName">
    /// The logical name of the role to check.
    /// </param>
    /// <returns>
    /// True if a role with the specified name exists; otherwise False.
    /// </returns>
    function HasRole(const ARoleName: string): Boolean;

    /// <summary>
    /// Tries to find a role by its ID (Keycloak role UUID). Returns True if found.
    /// </summary>
    /// <param name="ARoleID">
    /// The unique identifier (UUID) of the role in Keycloak.
    /// </param>
    /// <param name="ARole">
    /// When the function returns True, contains the matching role.
    /// </param>
    function TryGetRoleByID(const ARoleID: string; out ARole: TIAM4DRole): Boolean;
  end;

  TIAM4DRealmClientArray = TArray<TIAM4DRealmClient>;

  TIAM4DRealmClientArrayHelper = record helper for TIAM4DRealmClientArray
  public
    /// <summary>
    /// Tries to find a role by its name across all clients.
    /// Returns True if a matching role is found.
    /// </summary>
    /// <param name="ARoleName">
    /// The logical role name to search for.
    /// </param>
    /// <param name="ARole">
    /// When the function returns True, contains the first matching role.
    /// </param>
    function TryGetRoleByName(const ARoleName: string; out ARole: TIAM4DRole): Boolean;

    /// <summary>
    /// Tries to find a role by its name across all clients.
    /// Returns True if a matching role is found and also returns the owning client.
    /// </summary>
    /// <param name="ARoleName">
    /// The logical role name to search for.
    /// </param>
    /// <param name="AClient">
    /// When the function returns True, contains the client that owns the role.
    /// </param>
    /// <param name="ARole">
    /// When the function returns True, contains the matching role.
    /// </param>
    function TryGetRoleAndClientByName(const ARoleName: string; out AClient: TIAM4DRealmClient; out ARole: TIAM4DRole): Boolean;

    /// <summary>
    /// Checks whether any client exposes a role with the given name.
    /// </summary>
    /// <param name="ARoleName">
    /// The logical role name to check.
    /// </param>
    /// <returns>
    /// True if a role with the specified name exists in at least one client; otherwise False.
    /// </returns>
    function HasRole(const ARoleName: string): Boolean;
  end;

  /// <summary>
  /// Represents an active user session in Keycloak.
  /// </summary>
  /// <remarks>
  /// Contains session information including client applications, IP address,
  /// and timing data. Used for session management and security monitoring.
  /// </remarks>
  TIAM4DUserSession = record
  private
    FSessionID: string;
    FIPAddress: string;
    FUserAgent: string;
    FStarted: Int64;
    FLastAccess: Int64;
    FClients: TArray<string>;
  public
    /// <summary>
    /// Unique session identifier.
    /// </summary>
    property SessionID: string read FSessionID write FSessionID;

    /// <summary>
    /// IP address from which the session was initiated.
    /// </summary>
    property IPAddress: string read FIPAddress write FIPAddress;

    /// <summary>
    /// User agent string of the client browser/application.
    /// </summary>
    property UserAgent: string read FUserAgent write FUserAgent;

    /// <summary>
    /// Session start timestamp (Unix milliseconds).
    /// </summary>
    property Started: Int64 read FStarted write FStarted;

    /// <summary>
    /// Last access timestamp (Unix milliseconds).
    /// </summary>
    property LastAccess: Int64 read FLastAccess write FLastAccess;

    /// <summary>
    /// Array of client IDs that have accessed this session.
    /// </summary>
    property Clients: TArray<string> read FClients write FClients;
  end;

  /// <summary>
  /// Password reset operation for batch password updates.
  /// </summary>
  /// <remarks>
  /// Used by SetPasswordsAsync to ensure type-safe coupling of user ID,
  /// password, and temporary flag for each password reset operation.
  /// </remarks>
  TIAM4DPasswordReset = record
  private
    FUserID: string;
    FPassword: string;
    FTemporary: Boolean;
  public
    property UserID: string read FUserID write FUserID;
    property Password: string read FPassword write FPassword;
    property Temporary: Boolean read FTemporary write FTemporary;

    /// <summary>
    /// Creates a password reset record with specified parameters.
    /// </summary>
    /// <param name="AUserID">The user identifier</param>
    /// <param name="APassword">The new password</param>
    /// <param name="ATemporary">Whether password must be changed on first login (default: True)</param>
    constructor Create(const AUserID: string; const APassword: string; const ATemporary: Boolean = True);
  end;

  /// <summary>
  /// Role assignment operation for batch role assignments.
  /// </summary>
  /// <remarks>
  /// Used by AssignRolesToUsersAsync to ensure type-safe coupling of user ID
  /// and roles for each role assignment operation.
  /// </remarks>
  TIAM4DRoleAssignment = record
  private
    FUserID: string;
    FRoles: TArray<TIAM4DRole>;
  public
    property UserID: string read FUserID write FUserID;
    property Roles: TArray<TIAM4DRole> read FRoles write FRoles;

    /// <summary>
    /// Creates a role assignment record with specified parameters.
    /// </summary>
    /// <param name="AUserID">The user identifier</param>
    /// <param name="ARoles">The roles to assign to the user</param>
    constructor Create(const AUserID: string; const ARoles: TArray<TIAM4DRole>);
  end;

  /// <summary>
  /// Represents the result of a single operation in a batch request.
  /// </summary>
  /// <remarks>
  /// Used by batch operations (UpdateUsersAsync, DeleteUsersAsync, SetPasswordsAsync, AssignRolesToUsersAsync)
  /// to provide detailed feedback about each individual operation's success or failure.
  /// </remarks>
  TIAM4DOperationResult = record
  private
    FIdentifier: string;
    FSuccess: Boolean;
    FErrorMessage: string;
  public
    /// <summary>
    /// Identifier for the operation (UserID, Username, etc.).
    /// </summary>
    property Identifier: string read FIdentifier write FIdentifier;

    /// <summary>
    /// Indicates whether the operation completed successfully.
    /// </summary>
    property Success: Boolean read FSuccess write FSuccess;

    /// <summary>
    /// Error message if the operation failed. Empty if successful.
    /// </summary>
    property ErrorMessage: string read FErrorMessage write FErrorMessage;

    /// <summary>
    /// Creates an operation result with specified parameters.
    /// </summary>
    /// <param name="AIdentifier">The identifier (UserID, Username, etc.)</param>
    /// <param name="ASuccess">Whether the operation succeeded</param>
    /// <param name="AErrorMessage">Error message if failed (optional)</param>
    constructor Create(const AIdentifier: string; const ASuccess: Boolean; const AErrorMessage: string = '');
  end;

  /// <summary>
  /// Represents the result of users creation operation.
  /// </summary>
  /// <remarks>
  /// The record is used as an item in a batch result set returned by
  /// <c>CreateUsersAsync</c>. For each input user, exactly one
  /// <c>TIAM4DUsersCreateResult</c> instance is produced, preserving the
  /// original order.
  /// </remarks>
  TIAM4DUsersCreateResult = record
  public
    /// <summary>
    /// Username of the user to be created (copied from the input record).
    /// </summary>
    /// <remarks>
    /// This value is provided for correlation and logging purposes and
    /// is never modified by the library.
    /// </remarks>
    Username: string;

    /// <summary>
    /// Generated Keycloak user identifier.
    /// </summary>
    /// <remarks>
    /// When the creation succeeds, this field contains the server-generated
    /// Keycloak user ID. If the creation fails, this value is empty and
    /// <see cref="ErrorMessage"/> contains the error details.
    /// </remarks>
    ID: string;

    /// <summary>
    /// Error message describing the failure reason, if any.
    /// </summary>
    /// <remarks>
    /// When this field is empty, the operation is considered successful.
    /// When not empty, it contains a human-readable description of the
    /// error returned by the underlying HTTP call or by the IAMClient4D
    /// validation logic.
    /// </remarks>
    ErrorMessage: string;

    /// <summary>
    /// Indicates whether the user creation operation has completed successfully.
    /// </summary>
    /// <returns>
    /// <c>True</c> if <see cref="ErrorMessage"/> is empty; otherwise <c>False</c>.
    /// </returns>
    function Success: Boolean;
  end;

  /// <summary>
  /// Represents the result of a single user retrieval operation.
  /// </summary>
  /// <remarks>
  /// The record is used as an item in a batch result set returned by
  /// <c>GetUsersByIDsAsync</c>. For each input user ID, exactly one
  /// <c>TIAM4DUserGetResult</c> instance is produced, preserving the
  /// original order.
  /// </remarks>
  TIAM4DUserGetResult = record
  public
    /// <summary>
    /// User ID requested (copied from the input array).
    /// </summary>
    /// <remarks>
    /// This value is provided for correlation and logging purposes and
    /// is never modified by the library.
    /// </remarks>
    UserID: string;

    /// <summary>
    /// Retrieved user data.
    /// </summary>
    /// <remarks>
    /// When the retrieval succeeds, this field contains the complete user data.
    /// If the retrieval fails, this value will have an empty ID field and
    /// <see cref="ErrorMessage"/> contains the error details.
    /// </remarks>
    User: TIAM4DUser;

    /// <summary>
    /// Error message describing the failure reason, if any.
    /// </summary>
    /// <remarks>
    /// When this field is empty, the operation is considered successful.
    /// When not empty, it contains a human-readable description of the
    /// error (e.g., "User not found", "Access denied", etc.).
    /// </remarks>
    ErrorMessage: string;

    /// <summary>
    /// Indicates whether the user retrieval operation has completed successfully.
    /// </summary>
    /// <returns>
    /// <c>True</c> if <see cref="ErrorMessage"/> is empty; otherwise <c>False</c>.
    /// </returns>
    function Success: Boolean;
  end;

  /// <summary>
  /// User management interface for Keycloak Admin API operations.
  /// </summary>
  /// <remarks>
  /// Operations: CRUD, password management, roles, groups, federated identities, required actions, sessions.
  /// Async: All methods return promises for non-blocking execution.
  /// Authentication: Requires valid admin access token with appropriate permissions.
  /// </remarks>
  IIAM4DUserManager = interface
    ['{102507A7-6A4C-4D3E-B41D-3E8F93A5BF2F}']

    // ========================================================================
    // User CRUD Operations
    // ========================================================================

    /// <summary>
    /// Creates a new user in Keycloak.
    /// </summary>
    /// <param name="AUser">User data including username, email, and optional password</param>
    /// <returns>Promise resolving to the newly created user ID</returns>
    function CreateUserAsync(const AUser: TIAM4DUser): IAsyncPromise<string>;

    /// <summary>
    /// Creates multiple users in a single batch operation.
    /// </summary>
    /// <param name="AUsers">Array of user data to create</param>
    /// <returns>Promise resolving to array of creation results with IDs or errors</returns>
    function CreateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DUsersCreateResult>>;

    /// <summary>
    /// Retrieves a user by their unique ID.
    /// </summary>
    /// <param name="AUserID">The Keycloak user ID</param>
    /// <returns>Promise resolving to user data</returns>
    function GetUserAsync(const AUserID: string): IAsyncPromise<TIAM4DUser>;

    /// <summary>
    /// Retrieves a user by their username.
    /// </summary>
    /// <param name="AUsername">The username to search for</param>
    /// <returns>Promise resolving to user data</returns>
    function GetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUser>;

    /// <summary>
    /// Tries to retrieve a user by username without raising exceptions.
    /// </summary>
    /// <param name="AUsername">The username to search for</param>
    /// <returns>Promise resolving to result with Found flag and User data</returns>
    /// <remarks>
    /// Prefer this method when user absence is a normal flow (e.g., search forms).
    /// Use GetUserByUsernameAsync when user must exist (raises exception if not found).
    /// </remarks>
    function TryGetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUserTryResult>;

    /// <summary>
    /// Retrieves a user by their email address.
    /// </summary>
    /// <param name="AEmail">The email address to search for</param>
    /// <returns>Promise resolving to user data</returns>
    function GetUserByEmailAsync(const AEmail: string): IAsyncPromise<TIAM4DUser>;

    /// <summary>
    /// Tries to retrieve a user by email without raising exceptions.
    /// </summary>
    /// <param name="AEmail">The email address to search for</param>
    /// <returns>Promise resolving to result with Found flag and User data</returns>
    /// <remarks>
    /// Prefer this method when user absence is a normal flow (e.g., search forms).
    /// Use GetUserByEmailAsync when user must exist (raises exception if not found).
    /// </remarks>
    function TryGetUserByEmailAsync(const AEmail: string): IAsyncPromise<TIAM4DUserTryResult>;

    /// <summary>
    /// Retrieves multiple users by their IDs in a single batch operation.
    /// </summary>
    /// <param name="AUserIDs">Array of user IDs to retrieve</param>
    /// <returns>Promise resolving to array of retrieval results (success/failure per user with data)</returns>
    function GetUsersByIDsAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DUserGetResult>>;

    /// <summary>
    /// Updates an existing user's profile data.
    /// </summary>
    /// <param name="AUser">User data with ID and updated fields</param>
    /// <returns>Promise completing when update is done</returns>
    function UpdateUserAsync(const AUser: TIAM4DUser): IAsyncVoidPromise;

    /// <summary>
    /// Updates multiple users in a single batch operation.
    /// </summary>
    /// <param name="AUsers">Array of user data with IDs and updated fields</param>
    /// <returns>Promise resolving to array of operation results (success/failure per user)</returns>
    function UpdateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Deletes a user from Keycloak.
    /// </summary>
    /// <param name="AUserID">The user ID to delete</param>
    /// <returns>Promise completing when deletion is done</returns>
    function DeleteUserAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Deletes multiple users in a single batch operation.
    /// </summary>
    /// <param name="AUserIDs">Array of user IDs to delete</param>
    /// <returns>Promise resolving to array of operation results (success/failure per user)</returns>
    function DeleteUsersAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Searches for users matching the specified criteria.
    /// </summary>
    /// <param name="ACriteria">Search filters including pagination parameters</param>
    /// <returns>Promise resolving to array of matching users</returns>
    function SearchUsersAsync(const ACriteria: TIAM4DUserSearchCriteria): IAsyncPromise<TArray<TIAM4DUser>>;

    /// <summary>
    /// Gets the total count of users in the realm.
    /// </summary>
    /// <returns>Promise resolving to total user count</returns>
    function GetUsersCountAsync: IAsyncPromise<Integer>;

    // ========================================================================
    // Password Management
    // ========================================================================

    /// <summary>
    /// Sets or updates a user's password.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="APassword">The new password</param>
    /// <param name="ATemporary">If True, user must change password on next login (default: False)</param>
    /// <returns>Promise completing when password is set</returns>
    function SetPasswordAsync(const AUserID: string; const APassword: string; const ATemporary: Boolean = False): IAsyncVoidPromise;

    /// <summary>
    /// Sets passwords for multiple users in a single batch operation.
    /// </summary>
    /// <param name="APasswordResets">Array of password reset operations</param>
    /// <returns>Promise resolving to array of operation results (success/failure per user)</returns>
    function SetPasswordsAsync(const APasswordResets: TArray<TIAM4DPasswordReset>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Sends a password reset email to the user.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise completing when email is sent</returns>
    function SendPasswordResetEmailAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Sends an email verification email to the user.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise completing when email is sent</returns>
    function SendVerifyEmailAsync(const AUserID: string): IAsyncVoidPromise;

    // ========================================================================
    // Role Management
    // ========================================================================

    /// <summary>
    /// Retrieves all realm-level roles.
    /// </summary>
    /// <returns>Promise resolving to array of realm roles</returns>
    function GetRealmRolesAsync: IAsyncPromise<TArray<TIAM4DRole>>;

    /// <summary>
    /// Retrieves all roles assigned to a specific user.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise resolving to array of user's roles</returns>
    function GetUserRolesAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DRole>>;

    /// <summary>
    /// Assigns one or more roles to a user.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="ARoles">Array of roles to assign</param>
    /// <returns>Promise completing when roles are assigned</returns>
    function AssignRolesToUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;

    /// <summary>
    /// Assigns roles to multiple users in a single batch operation.
    /// </summary>
    /// <param name="ARoleAssignments">Array of role assignment operations</param>
    /// <returns>Promise resolving to array of operation results (success/failure per user)</returns>
    function AssignRolesToUsersAsync(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Removes one or more roles from a user.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="ARoles">Array of roles to remove</param>
    /// <returns>Promise completing when roles are removed</returns>
    function RemoveRolesFromUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;

    /// <summary>
    /// Assigns a single realm role to a user by role name (convenience method).
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="ARoleName">The realm role name to assign</param>
    /// <returns>Promise completing when role is assigned</returns>
    /// <remarks>
    /// Convenience wrapper around AssignRolesToUserAsync.
    /// Looks up role by name, then assigns it.
    /// Raises exception if role name is not found.
    /// </remarks>
    function AssignRoleByNameAsync(const AUserID: string; const ARoleName: string): IAsyncVoidPromise;

    /// <summary>
    /// Removes a single realm role from a user by role name (convenience method).
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="ARoleName">The realm role name to remove</param>
    /// <returns>Promise completing when role is removed</returns>
    /// <remarks>
    /// Convenience wrapper around RemoveRolesFromUserAsync.
    /// Looks up role by name, then removes it.
    /// Raises exception if role name is not found.
    /// </remarks>
    function RemoveRoleByNameAsync(const AUserID: string; const ARoleName: string): IAsyncVoidPromise;

    /// <summary>
    /// Assigns a single client role to a user by client and role names (convenience method).
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="AClientName">The client name (e.g., "my-app")</param>
    /// <param name="ARoleName">The client role name to assign</param>
    /// <returns>Promise completing when role is assigned</returns>
    /// <remarks>
    /// Convenience wrapper around AssignClientRolesToUserAsync.
    /// Looks up client by name, then looks up role, then assigns it.
    /// Raises exception if client or role name is not found.
    /// </remarks>
    function AssignClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncVoidPromise;

    /// <summary>
    /// Removes a single client role from a user by client and role names (convenience method).
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="AClientName">The client name (e.g., "my-app")</param>
    /// <param name="ARoleName">The client role name to remove</param>
    /// <returns>Promise completing when role is removed</returns>
    /// <remarks>
    /// Convenience wrapper around RemoveClientRolesFromUserByNameAsync.
    /// Looks up client by name, then looks up role, then removes it.
    /// Raises exception if client or role name is not found.
    /// </remarks>
    function RemoveClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncVoidPromise;

    // ========================================================================
    // Group Management
    // ========================================================================

    /// <summary>
    /// Retrieves all groups in the realm.
    /// </summary>
    /// <returns>Promise resolving to array of groups</returns>
    function GetGroupsAsync: IAsyncPromise<TArray<TIAM4DGroup>>;

    /// <summary>
    /// Retrieves all groups a user belongs to.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise resolving to array of user's groups</returns>
    function GetUserGroupsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DGroup>>;

    /// <summary>
    /// Adds a user to a group using the group path.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="AGroupPath">The group path (e.g., "/sales/italy")</param>
    /// <returns>Promise completing when user is added to group</returns>
    /// <remarks>
    /// The group path is resolved to group ID internally via GetGroupByPathAsync.
    /// Raises exception if group path is not found.
    /// </remarks>
    function AddUserToGroupByPathAsync(const AUserID: string; const AGroupPath: string): IAsyncVoidPromise;

    /// <summary>
    /// Removes a user from a group using the group path.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="AGroupPath">The group path (e.g., "/sales/italy")</param>
    /// <returns>Promise completing when user is removed from group</returns>
    /// <remarks>
    /// The group path is resolved to group ID internally via GetGroupByPathAsync.
    /// Raises exception if group path is not found.
    /// </remarks>
    function RemoveUserFromGroupByPathAsync(const AUserID: string; const AGroupPath: string): IAsyncVoidPromise;

    // ========================================================================
    // Session Management
    // ========================================================================

    /// <summary>
    /// Logs out a user by revoking all their active sessions.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise completing when user is logged out</returns>
    function LogoutUserAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Retrieves all active sessions for a user.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise resolving to array of active sessions</returns>
    function GetUserSessionsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DUserSession>>;

    /// <summary>
    /// Gets the count of active sessions for a user.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise resolving to number of active sessions</returns>
    function GetUserSessionCountAsync(const AUserID: string): IAsyncPromise<Integer>;

    /// <summary>
    /// Revokes a specific user session.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="ASessionID">The session ID to revoke</param>
    /// <returns>Promise completing when session is revoked</returns>
    function RevokeUserSessionAsync(const AUserID: string; const ASessionID: string): IAsyncVoidPromise;

    // ========================================================================
    // Federated Identity Management
    // ========================================================================

    /// <summary>
    /// Retrieves all federated identities linked to a user.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise resolving to array of federated identities</returns>
    function GetUserFederatedIdentitiesAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DFederatedIdentity>>;

    /// <summary>
    /// Checks if a user has any federated identities.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise resolving to True if user has federated identities</returns>
    function IsUserFederatedAsync(const AUserID: string): IAsyncPromise<Boolean>;

    // ========================================================================
    // Required Actions Management
    // ========================================================================

    /// <summary>
    /// Retrieves all required actions for a user.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise resolving to array of required actions</returns>
    function GetUserRequiredActionsAsync(const AUserID: string): IAsyncPromise<TArray<TIAM4DRequiredAction>>;

    /// <summary>
    /// Sets required actions for a user (replaces existing actions).
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="AActions">Array of required actions to set</param>
    /// <returns>Promise completing when actions are set</returns>
    function SetUserRequiredActionsAsync(const AUserID: string; const AActions: TArray<TIAM4DRequiredAction>): IAsyncVoidPromise;

    /// <summary>
    /// Removes specific required actions from a user.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="AActions">Array of required actions to remove</param>
    /// <returns>Promise completing when actions are removed</returns>
    function RemoveUserRequiredActionsAsync(const AUserID: string; const AActions: TArray<TIAM4DRequiredAction>): IAsyncVoidPromise;

    // ========================================================================
    // Account Security
    // ========================================================================

    /// <summary>
    /// Checks if a user account is locked (temporarily disabled due to failed login attempts).
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise resolving to True if account is locked</returns>
    function IsUserLockedAsync(const AUserID: string): IAsyncPromise<Boolean>;

    /// <summary>
    /// Unlocks a user account that was locked due to failed login attempts.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise completing when account is unlocked</returns>
    function UnlockUserAsync(const AUserID: string): IAsyncVoidPromise;

    // ========================================================================
    // User State Management
    // ========================================================================

    /// <summary>
    /// Disables a user account (sets enabled=false).
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise completing when account is disabled</returns>
    function DisableUserAsync(const AUserID: string): IAsyncVoidPromise;

    /// <summary>
    /// Enables a user account (sets enabled=true).
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <returns>Promise completing when account is enabled</returns>
    function EnableUserAsync(const AUserID: string): IAsyncVoidPromise;

    // ========================================================================
    // Advanced Role Queries
    // ========================================================================

    /// <summary>
    /// Retrieves a realm role by its name.
    /// </summary>
    /// <param name="ARoleName">The role name to search for</param>
    /// <returns>Promise resolving to the role, raises exception if not found</returns>
    function GetRoleByNameAsync(const ARoleName: string): IAsyncPromise<TIAM4DRole>;

    /// <summary>
    /// Tries to retrieve a role by name without raising exceptions.
    /// </summary>
    /// <param name="ARoleName">The role name to search for</param>
    /// <returns>Promise resolving to result with Found flag and Role data</returns>
    /// <remarks>
    /// Prefer this method when role absence is a normal flow (e.g., role lookup).
    /// Use GetRoleByNameAsync when role must exist (raises exception if not found).
    /// </remarks>
    function TryGetRoleByNameAsync(const ARoleName: string): IAsyncPromise<TIAM4DRoleTryResult>;

    /// <summary>
    /// Checks if a user has a specific role assigned.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="ARoleName">The role name to check</param>
    /// <returns>Promise resolving to True if user has the role</returns>
    function HasRoleAsync(const AUserID: string; const ARoleName: string): IAsyncPromise<Boolean>;

    /// <summary>
    /// Retrieves all users who have a specific role assigned.
    /// </summary>
    /// <param name="ARoleName">The role name</param>
    /// <param name="AFirstResult">Pagination: first result index (default: 0)</param>
    /// <param name="AMaxResults">Pagination: maximum results to return (default: 100)</param>
    /// <returns>Promise resolving to array of users with the role</returns>
    function GetUsersWithRoleAsync(const ARoleName: string; const AFirstResult: Integer = 0; const AMaxResults: Integer = 100): IAsyncPromise<TArray<TIAM4DUser>>;

    // ========================================================================
    // Advanced Group Queries
    // ========================================================================

    /// <summary>
    /// Retrieves a group by its path (e.g., "/sales/italy").
    /// </summary>
    /// <param name="APath">The group path to search for</param>
    /// <returns>Promise resolving to the group, raises exception if not found</returns>
    function GetGroupByPathAsync(const APath: string): IAsyncPromise<TIAM4DGroup>;

    /// <summary>
    /// Tries to retrieve a group by path without raising exceptions.
    /// </summary>
    /// <param name="APath">The group path to search for</param>
    /// <returns>Promise resolving to result with Found flag and Group data</returns>
    /// <remarks>
    /// Prefer this method when group absence is a normal flow (e.g., group lookup).
    /// Use GetGroupByPathAsync when group must exist (raises exception if not found).
    /// </remarks>
    function TryGetGroupByPathAsync(const APath: string): IAsyncPromise<TIAM4DGroupTryResult>;

    /// <summary>
    /// Checks if a user is member of a specific group.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="AGroupPath">The group path to check</param>
    /// <returns>Promise resolving to True if user is member of the group</returns>
    function IsMemberOfGroupAsync(const AUserID: string; const AGroupPath: string): IAsyncPromise<Boolean>;

    /// <summary>
    /// Retrieves all users who are members of a specific group using the group path.
    /// </summary>
    /// <param name="AGroupPath">The group path (e.g., "/sales/italy")</param>
    /// <param name="AFirstResult">Pagination: first result index (default: 0)</param>
    /// <param name="AMaxResults">Pagination: maximum results to return (default: 100)</param>
    /// <returns>Promise resolving to array of users in the group</returns>
    /// <remarks>
    /// The group path is resolved to group ID internally via GetGroupByPathAsync.
    /// Raises exception if group path is not found.
    /// </remarks>
    function GetUsersInGroupByPathAsync(const AGroupPath: string; const AFirstResult: Integer = 0; const AMaxResults: Integer = 100): IAsyncPromise<TArray<TIAM4DUser>>;

    // ========================================================================
    // Client Role Management
    // ========================================================================

    /// <summary>
    /// Retrieves all roles available for a specific client using the client name.
    /// </summary>
    /// <param name="AClientName">The client name (e.g., "my-app")</param>
    /// <returns>Promise resolving to array of client roles</returns>
    /// <remarks>
    /// The client name is resolved to client ID internally via GetClientIDByNameAsync.
    /// Raises exception if client name is not found.
    /// </remarks>
    function GetClientRolesByNameAsync(const AClientName: string): IAsyncPromise<TArray<TIAM4DRole>>;

    /// <summary>
    /// Retrieves all client roles assigned to a specific user using the client name.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="AClientName">The client name (e.g., "my-app")</param>
    /// <returns>Promise resolving to array of user's client roles</returns>
    /// <remarks>
    /// The client name is resolved to client ID internally via GetClientIDByNameAsync.
    /// Raises exception if client name is not found.
    /// </remarks>
    function GetUserClientRolesByNameAsync(const AUserID: string; const AClientName: string): IAsyncPromise<TArray<TIAM4DRole>>;

    /// <summary>
    /// Assigns one or more client roles to a user (automatically extracts client from roles).
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="ARoles">Array of client roles to assign (with ClientID/ClientName populated)</param>
    /// <returns>Promise completing when roles are assigned</returns>
    /// <remarks>
    /// RECOMMENDED METHOD: Use this instead of AssignClientRolesToUserByNameAsync.
    /// Eliminates client name duplication - roles already contain ClientID and ClientName.
    /// Raises exception if any role is missing ClientID or ClientName.
    /// </remarks>
    function AssignClientRolesToUserAsync(const AUserID: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;

    /// <summary>
    /// Assigns client roles to multiple users in a single batch operation.
    /// Automatically routes to correct client based on roles' ClientID/ClientName.
    /// </summary>
    /// <param name="ARoleAssignments">Array of role assignment operations (UserID + Roles with ClientID/ClientName populated)</param>
    /// <returns>Promise resolving to array of operation results (success/failure per user)</returns>
    /// <remarks>
    /// Eliminates client name duplication - roles already contain ClientID and ClientName.
    /// Automatically groups assignments by client if roles from different clients are provided.
    /// Raises exception if any role is missing ClientID or ClientName.
    /// </remarks>
    function AssignClientRolesToUsersAsync(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;

    /// <summary>
    /// Removes one or more client roles from a user using the client name.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="AClientName">The client name (e.g., "my-app")</param>
    /// <param name="ARoles">Array of client roles to remove</param>
    /// <returns>Promise completing when roles are removed</returns>
    /// <remarks>
    /// The client name is resolved to client ID internally via GetClientIDByNameAsync.
    /// Raises exception if client name is not found.
    /// </remarks>
    function RemoveClientRolesFromUserByNameAsync(const AUserID: string; const AClientName: string; const ARoles: TArray<TIAM4DRole>): IAsyncVoidPromise;

    /// <summary>
    /// Checks if a user has a specific client role assigned using the client name.
    /// </summary>
    /// <param name="AUserID">The user ID</param>
    /// <param name="AClientName">The client name (e.g., "my-app")</param>
    /// <param name="ARoleName">The client role name to check</param>
    /// <returns>Promise resolving to True if user has the client role</returns>
    /// <remarks>
    /// The client name is resolved to client ID internally via GetClientIDByNameAsync.
    /// Raises exception if client name is not found.
    /// </remarks>
    function HasClientRoleByNameAsync(const AUserID: string; const AClientName: string; const ARoleName: string): IAsyncPromise<Boolean>;

    // ========================================================================
    // Realm Client Management
    // ========================================================================

    /// <summary>
    /// Retrieves all client applications registered in the realm with their roles.
    /// </summary>
    /// <returns>Promise resolving to array of realm clients with all their roles</returns>
    /// <remarks>
    /// Returns all clients including built-in clients (realm-management, account, broker)
    /// and custom application clients configured in the realm.
    /// Each client includes all its associated roles.
    /// </remarks>
    function GetClientsAsync: IAsyncPromise<TIAM4DRealmClientArray>; overload;

    /// <summary>
    /// Retrieves a specific client application by name with all its roles.
    /// </summary>
    /// <param name="AClientName">The client name (e.g., "realm-management", "account")</param>
    /// <returns>Promise resolving to the client with all its roles</returns>
    /// <remarks>
    /// Returns a single client matching the specified name.
    /// The client includes all its associated roles.
    /// Raises exception if client is not found.
    /// </remarks>
    function GetClientsAsync(const AClientName: string): IAsyncPromise<TIAM4DRealmClient>; overload;
  end;

implementation

{ TIAM4DUser }

uses
  System.DateUtils;

constructor TIAM4DUser.Create(
  const AUsername: string;
  const AEmail: string;
  const AFirstName: string;
  const ALastName: string;
  const AEnabled: Boolean);
begin
  FID := IAM4D_EMPTY_USER_ID;
  FUsername := AUsername;
  FEmail := AEmail;
  FFirstName := AFirstName;
  FLastName := ALastName;
  FEnabled := AEnabled;
  FEmailVerified := False;
  FAttributes := nil;
  FCreatedTimestamp := DateTimeToUnix(Now);
  FRequiredActions := nil;
  FTemporaryPassword := IAM4D_EMPTY_USER_ID;
  FRequirePasswordChange := True;
end;

function TIAM4DUser.HasRequiredAction(const AAction: TIAM4DRequiredAction): Boolean;
var
  LAction: TIAM4DRequiredAction;
begin
  for LAction in FRequiredActions do
    if LAction = AAction then
      Exit(True);
  Result := False;
end;

function TIAM4DUser.IndexOfAttribute(const AName: string): Integer;
var
  LIndex: Integer;
begin
  for LIndex := 0 to Length(FAttributes) - 1 do
    if SameText(FAttributes[LIndex].Name, AName) then
      Exit(LIndex);
  Result := -1;
end;

function TIAM4DUser.GetAttribute(const AName: string): TArray<string>;
var
  LIndex: Integer;
begin
  LIndex := IndexOfAttribute(AName);
  if LIndex >= 0 then
    Result := FAttributes[LIndex].Values
  else
    Result := nil;
end;

procedure TIAM4DUser.SetAttribute(const AName: string; const AValues: TArray<string>);
var
  LIndex: Integer;
begin
  LIndex := IndexOfAttribute(AName);
  if LIndex < 0 then
  begin
    LIndex := Length(FAttributes);
    SetLength(FAttributes, LIndex + 1);
    FAttributes[LIndex].Name := AName;
  end;
  FAttributes[LIndex].Values := AValues;
end;

procedure TIAM4DUser.AddAttribute(const AName: string; const AValues: array of string);
var
  LArray: TArray<string>;
  LIndex: Integer;
begin
  SetLength(LArray, Length(AValues));
  for LIndex := 0 to High(AValues) do
    LArray[LIndex] := AValues[LIndex];
  SetAttribute(AName, LArray);
end;

function TIAM4DUser.TryGetAttribute(
  const AName: string; out AValues: TArray<string>): Boolean;
var
  LIndex: Integer;
begin
  LIndex := IndexOfAttribute(AName);
  Result := LIndex >= 0;
  if Result then
    AValues := FAttributes[LIndex].Values
  else
    AValues := nil;
end;

procedure TIAM4DUser.RemoveAttribute(const AName: string);
var
  LIndex, LIndex2: Integer;
begin
  LIndex := IndexOfAttribute(AName);
  if LIndex < 0 then
    Exit;

  for LIndex2 := LIndex to Length(FAttributes) - 2 do
    FAttributes[LIndex2] := FAttributes[LIndex2 + 1];

  SetLength(FAttributes, Length(FAttributes) - 1);
end;

procedure TIAM4DUser.AddRequiredAction(const AAction: TIAM4DRequiredAction);
var
  LIndex, LLen: Integer;
begin
  for LIndex := 0 to Length(FRequiredActions) - 1 do
    if FRequiredActions[LIndex] = AAction then
      Exit;

  LLen := Length(FRequiredActions);
  SetLength(FRequiredActions, LLen + 1);
  FRequiredActions[LLen] := AAction;
end;

procedure TIAM4DUser.AddRequiredActions(const AActions: array of TIAM4DRequiredAction);
var
  LAction: TIAM4DRequiredAction;
begin
  for LAction in AActions do
    AddRequiredAction(LAction);
end;

procedure TIAM4DUser.RemoveRequiredAction(const AAction: TIAM4DRequiredAction);
var
  LIndex, LIndex2: Integer;
begin
  for LIndex := 0 to Length(FRequiredActions) - 1 do
  begin
    if FRequiredActions[LIndex] = AAction then
    begin
      for LIndex2 := LIndex to Length(FRequiredActions) - 2 do
        FRequiredActions[LIndex2] := FRequiredActions[LIndex2 + 1];

      SetLength(FRequiredActions, Length(FRequiredActions) - 1);
      Exit;
    end;
  end;
end;

{ TIAM4DUserSearchCriteria }

class function TIAM4DUserSearchCriteria.Create(
  const ASearch: string;
  const AFirstResult: Integer;
  const AMaxResults: Integer): TIAM4DUserSearchCriteria;
begin
  Result.FSearch := ASearch;
  Result.FFirstResult := AFirstResult;
  Result.FMaxResults := AMaxResults;
  Result.FUsername := IAM4D_EMPTY_USER_ID;
  Result.FEmail := IAM4D_EMPTY_USER_ID;
  Result.FFirstName := IAM4D_EMPTY_USER_ID;
  Result.FLastName := IAM4D_EMPTY_USER_ID;
  Result.FEnabled := True;
end;

{ TIAM4DRequiredActionHelper }

function TIAM4DRequiredActionHelper.ToString: string;
begin
  case Self of
    raVerifyEmail: Result := 'VERIFY_EMAIL';
    raUpdatePassword: Result := 'UPDATE_PASSWORD';
    raConfigureOTP: Result := 'CONFIGURE_TOTP';
    raUpdateProfile: Result := 'UPDATE_PROFILE';
    raTermsAndConditions: Result := 'TERMS_AND_CONDITIONS';
  else
    Result := '';
  end;
end;

class function TIAM4DRequiredActionHelper.FromString(
  const AValue: string): TIAM4DRequiredAction;
begin
  if SameText(AValue, 'VERIFY_EMAIL') then
    Result := raVerifyEmail
  else if SameText(AValue, 'UPDATE_PASSWORD') then
    Result := raUpdatePassword
  else if SameText(AValue, 'CONFIGURE_TOTP') then
    Result := raConfigureOTP
  else if SameText(AValue, 'UPDATE_PROFILE') then
    Result := raUpdateProfile
  else if SameText(AValue, 'TERMS_AND_CONDITIONS') then
    Result := raTermsAndConditions
  else
    raise EArgumentException.CreateFmt('Unknown required action: %s', [AValue]);
end;

{ TIAM4DPasswordReset }

constructor TIAM4DPasswordReset.Create(
  const AUserID: string;
  const APassword: string;
  const ATemporary: Boolean);
begin
  FUserID := AUserID;
  FPassword := APassword;
  FTemporary := ATemporary;
end;

{ TIAM4DRoleAssignment }

constructor TIAM4DRoleAssignment.Create(
  const AUserID: string;
  const ARoles: TArray<TIAM4DRole>);
begin
  FUserID := AUserID;
  FRoles := ARoles;
end;

{ TIAM4DOperationResult }

constructor TIAM4DOperationResult.Create(
  const AIdentifier: string;
  const ASuccess: Boolean;
  const AErrorMessage: string);
begin
  FIdentifier := AIdentifier;
  FSuccess := ASuccess;
  FErrorMessage := AErrorMessage;
end;

{ TIAM4DUsersCreateResult }

function TIAM4DUsersCreateResult.Success: Boolean;
begin
  Result := ErrorMessage = '';
end;

{ TIAM4DUserGetResult }

function TIAM4DUserGetResult.Success: Boolean;
begin
  Result := ErrorMessage = '';
end;

{ TIAM4DRealmClient }

function TIAM4DRealmClient.HasRole(const ARoleName: string): Boolean;
var
  LDummy: TIAM4DRole;
begin
  Result := TryGetRoleByName(ARoleName, LDummy);
end;

function TIAM4DRealmClient.TryGetRoleByID(const ARoleID: string;
  out ARole: TIAM4DRole): Boolean;
var
  LRole: TIAM4DRole;
begin
  Result := False;

  for LRole in FRoles do
  begin
    if SameText(LRole.ID, ARoleID) then
    begin
      ARole := LRole;
      Result := True;
      Exit;
    end;
  end;
end;

function TIAM4DRealmClient.TryGetRoleByName(const ARoleName: string;
  out ARole: TIAM4DRole): Boolean;
var
  LRole: TIAM4DRole;
begin
  Result := False;

  for LRole in FRoles do
  begin
    if SameText(LRole.Name, ARoleName) then
    begin
      ARole := LRole;
      Result := True;
      Exit;
    end;
  end;
end;

{ TIAM4DRealmClientArrayHelper }

function TIAM4DRealmClientArrayHelper.HasRole(const ARoleName: string): Boolean;
var
  LDummyRole: TIAM4DRole;
begin
  Result := TryGetRoleByName(ARoleName, LDummyRole);
end;

function TIAM4DRealmClientArrayHelper.TryGetRoleAndClientByName(const ARoleName: string; out AClient: TIAM4DRealmClient; out ARole: TIAM4DRole): Boolean;
var
  LClient: TIAM4DRealmClient;
  LRole: TIAM4DRole;
begin
  Result := False;

  for LClient in Self do
    if LClient.TryGetRoleByName(ARoleName, LRole) then
    begin
      AClient := LClient;
      ARole := LRole;
      Result := True;
      Exit;
    end;
end;

function TIAM4DRealmClientArrayHelper.TryGetRoleByName(const ARoleName: string; out ARole: TIAM4DRole): Boolean;
var
  LClient: TIAM4DRealmClient;
  LRole: TIAM4DRole;
begin
  Result := False;

  for LClient in Self do
    if LClient.TryGetRoleByName(ARoleName, LRole) then
    begin
      ARole := LRole;
      Result := True;
      Exit;
    end;
end;

end.