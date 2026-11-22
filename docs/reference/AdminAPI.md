# Keycloak Admin API: user management

Reference of the user manager of IAMClient4D 3.0: users, passwords, required actions, realm and client roles, groups, federated identities and sessions of one realm, through the Keycloak Admin REST API (`{BaseURL}/admin/realms/{realm}`). Identity providers have their own manager on the same base: see [IdentityBrokering.md](IdentityBrokering.md). Logins and tokens are in [Core.md](Core.md), the Keycloak configuration of the admin client in [KeycloakSetup.md](KeycloakSetup.md), the changes from 2.x in [MIGRATION_3.0.md, section 6](../MIGRATION_3.0.md#6-admin-api).

## Contents

- [Units](#units)
- [Admin token](#admin-token)
- [Construction](#construction)
- [Data types](#data-types)
- [Users](#users)
- [Batch operations](#batch-operations)
- [Passwords, emails and required actions](#passwords-emails-and-required-actions)
- [Account state](#account-state)
- [Realm roles](#realm-roles)
- [Clients and client roles](#clients-and-client-roles)
- [Groups](#groups)
- [Federated identities](#federated-identities)
- [Sessions](#sessions)
- [Errors](#errors)
- [Validation](#validation)
- [Helpers](#helpers)
- [Examples](#examples)

## Units

| Unit | Content |
|------|---------|
| `IAMClient4D.UserManagement.Core` | Records (`TIAM4DUser`, `TIAM4DRole`, `TIAM4DGroup`, ...), `IIAM4DUserManager` (sync), `IIAM4DUserManagerAsync` |
| `IAMClient4D.UserManagement.Keycloak` | `TIAM4DKeycloakUserManager` (sync implementation); aliases of the auth providers |
| `IAMClient4D.UserManagement.Keycloak.Async` | `TIAM4DKeycloakUserManagerAsync` (async wrapper) |
| `IAMClient4D.UserManagement.Validation` | `TIAM4DUserManagementValidator` |
| `IAMClient4D.UserManagement.Helpers` | Record helpers (JSON, validation, filters), `TIAM4DRoleLookupCache` |
| `IAMClient4D.UserManagement.Constants` | Limits, page size, batch size |
| `IAMClient4D.Admin.Keycloak.Base` | `TIAM4DKeycloakAdminBase` (constructors, HTTP pool, errors), `IKeycloakAuthProvider`, `TClientBasedAuthProvider`, `TTokenBasedAuthProvider` |
| `IAMClient4D.Exceptions` | Exceptions |

`IIAM4DUserManager` and `IIAM4DUserManagerAsync` are implemented by the library, not extension points: minor versions add methods. To change a behaviour, wrap a `TIAM4DKeycloakUserManager`.

## Admin token

Every request carries the bearer token of the auth provider. Keycloak checks it:

- **Roles**: client roles of `realm-management` that cover the operation (`view-users` / `query-users` to read, `manage-users` to change users, `realm-admin` for everything). A missing role answers 403. See [KeycloakSetup.md](KeycloakSetup.md#admin-rest-api-client).
- **Audience (Keycloak 26.8.2 and later)**: the token must carry the audience of the client scope `kc-admin-api`, a default scope only of `admin-cli` and `security-admin-console`. Add it to the default client scopes of the client that gets the token (*Clients* > client > *Client scopes* > *Add client scope* > `kc-admin-api`, *Default*), otherwise every call answers 401 (`EIAM4DHTTPClientErrorException`).

In the [sample environment](../../Docker/README.md) the public client `iam4d-sample-app` has `kc-admin-api` among its default scopes and the user `demo` (password `demo`) has `realm-admin`: a client of `iam4d-sample-app` logged in as `demo` can call every method. The confidential client `iam4d-sample-service` has no `realm-management` role.

## Construction

Unit `IAMClient4D.Admin.Keycloak.Base` (inherited by `TIAM4DKeycloakUserManager`).

| Constructor | Token |
|-------------|-------|
| `Create(AClient: IIAM4DClient; ABaseURL = ''; ARealm = '')` | `TClientBasedAuthProvider`: `AClient.GetAccessToken` before each operation (refreshed when expired); HTTP clients from `AClient.CreateHTTPClient` (its TLS settings). A missing base URL or realm is taken from `AClient.Issuer` (`{BaseURL}/realms/{realm}`) |
| `Create(AAccessToken, ABaseURL, ARealm)` | `TTokenBasedAuthProvider`: static token, never refreshed; default HTTP configuration |
| `Create(AAccessToken, ABaseURL, ARealm, AHTTPConfig: TIAM4DHTTPClientConfig)` | Static token, timeouts and SSL validation mode of `AHTTPConfig` |
| `Create(AAuthProvider: IKeycloakAuthProvider; ABaseURL, ARealm)` | Your provider: `GetAccessToken` and `CreateHTTPClient` |

`ABaseURL` is the Keycloak URL with its relative path (`http://localhost:18180/auth`), without `/realms`. A nil client or provider, an empty token, base URL or realm, an unconfigured client (empty issuer) or an issuer without `/realms/` raise `EIAM4DInvalidConfigurationException`.

`TIAM4DKeycloakUserManagerAsync` has `Create(ASyncManager: IIAM4DUserManager)` and the client and static-token constructors above (no HTTP configuration nor custom provider: build the sync manager and pass it).

**HTTP clients.** Each operation borrows an HTTP client from a pool of the instance and gives it back (up to 4 idle clients are kept), so connections and TLS sessions are reused: keep one manager for a service or a batch instead of one per call. Concurrent operations of one instance get clients of their own. Redirects are not followed (the bearer would go to the target): a 3xx raises `EIAM4DInvalidConfigurationException`. The `ResponseTimeout` of the HTTP configuration bounds each request as a whole; past it, `EIAM4DNetworkTimeoutException`.

**Sync or async.** `IIAM4DUserManager` blocks: use it on worker threads (DMVC actions, services, console). `IIAM4DUserManagerAsync` runs each method of the sync manager in a task (`TAsyncCore.New`) and returns a promise; callbacks run on the main thread by default (see [AsyncCore.md](AsyncCore.md)). Each operation keeps its own reference to the sync manager: the wrapper can be released (a form closed) while operations run. The async methods copy the arrays they receive.

**URLs.** IDs, names and aliases in the path are percent-encoded one segment at a time (space `%20`; `+`, `/`, `?`, `#`, `%` escaped); an empty segment, `.` or `..` raises `EIAM4DInvalidConfigurationException` before any request (an empty user ID would turn `UnlockUser` into the unlock of the whole realm). Query values are form-encoded (`mario+test@example.com` becomes `email=mario%2Btest%40example.com`).

## Data types

Unit `IAMClient4D.UserManagement.Core`. All are records: no objects to free.

### TIAM4DUser

| Field | Read | Create (`CreateUser`) | Update (`UpdateUser`) |
|-------|------|-----------------------|-----------------------|
| `ID` | yes | sent if not empty (Keycloak assigns it) | required |
| `Username` | yes | sent | not sent when empty (unchanged) |
| `Email`, `FirstName`, `LastName` | yes | sent when not empty | always sent: empty clears the value |
| `Enabled`, `EmailVerified` | yes | always sent | always sent |
| `CreatedTimestamp` | Unix time in ms | sent when greater than 0 | sent when greater than 0 |
| `Attributes[Name]`, `AllAttributes` | yes | sent when any | sent when any (replaces them); none: not sent |
| `RequiredActions` | actions of `TIAM4DRequiredAction` | sent with `OtherRequiredActions` when any | always sent with `OtherRequiredActions` |
| `OtherRequiredActions` | other actions as Keycloak names them (`VERIFY_PROFILE`, `webauthn-register`, custom) | as above | as above: an update never drops them |
| `TemporaryPassword`, `RequirePasswordChange` | no | password credential, `temporary` = `RequirePasswordChange` | ignored |
| `FederationLink` | ID of the user storage provider (LDAP, Kerberos); empty for a local user | never sent | never sent |

`TIAM4DUser.Create(AUsername, AEmail, AFirstName = '', ALastName = '', AEnabled = True)` sets `RequirePasswordChange` to True, `EmailVerified` to False and `CreatedTimestamp` to the current Unix time in milliseconds, the unit of Keycloak. `Default(TIAM4DUser)` has every field empty or False.

Methods: `AddAttribute(Name, Values)` (adds or replaces), `RemoveAttribute`, `TryGetAttribute`, `AddRequiredAction`, `AddRequiredActions` (no duplicates), `RemoveRequiredAction`, `HasRequiredAction`. Attribute names are compared case-insensitively.

`TIAM4DRequiredAction`: `raVerifyEmail` (`VERIFY_EMAIL`), `raUpdatePassword` (`UPDATE_PASSWORD`), `raConfigureOTP` (`CONFIGURE_TOTP`), `raUpdateProfile` (`UPDATE_PROFILE`), `raTermsAndConditions` (`TERMS_AND_CONDITIONS`). The helper has `ToString`, `FromString` (`EArgumentException` for another value) and `TryFromString`.

### Other records

| Type | Fields |
|------|--------|
| `TIAM4DUserSearchCriteria` | `Username`, `Email`, `FirstName`, `LastName`, `Search`, `Enabled` with `FilterByEnabled`, `FirstResult`, `MaxResults`. `Create(ASearch = '', AFirstResult = 0, AMaxResults = 100)`: no enabled filter |
| `TIAM4DRole` | `ID`, `Name`, `Description`, `Composite`, `ContainerID` (internal UUID of the client, empty for a realm role), `ClientID` (`clientId` of the client, empty for a realm role) |
| `TIAM4DGroup` | `ID`, `Name`, `Path` (full path, e.g. `/sales/italy`) |
| `TIAM4DRealmClient` | `ID` (UUID), `ClientID`, `Name`, `Description`, `Enabled`, `Roles`; `TryGetRoleByName` (case-sensitive), `TryGetRoleByID`, `HasRole`. `TIAM4DRealmClientArray` has `TryGetRoleByName`, `TryGetRoleAndClientByName`, `HasRole` |
| `TIAM4DFederatedIdentity` | `IdentityProvider` (alias), `UserID`, `UserName` (the account at that provider) |
| `TIAM4DUserSession` | `SessionID`, `IPAddress`, `UserAgent`, `Started`, `LastAccess` (Unix ms), `Clients` (client IDs of the session) |
| `TIAM4DUserTryResult`, `TIAM4DRoleTryResult`, `TIAM4DGroupTryResult` | `Found` and `User` / `Role` / `Group` (empty when not found) |
| `TIAM4DPasswordReset` | `UserID`, `Password`, `Temporary`; `Create(AUserID, APassword, ATemporary = True)` |
| `TIAM4DRoleAssignment` | `UserID`, `Roles`; `Create(AUserID, ARoles)` |
| `TIAM4DOperationResult` | `Identifier`, `Success`, `ErrorMessage` |
| `TIAM4DUsersCreateResult` | `Username`, `ID` (empty on failure), `ErrorMessage`; `Success` = empty `ErrorMessage` |
| `TIAM4DUserGetResult` | `UserID`, `User`, `ErrorMessage`; `Success` = empty `ErrorMessage` |

## Users

Paths relative to `{BaseURL}/admin/realms/{realm}`. Every method has an `...Async` twin in `IIAM4DUserManagerAsync` (procedures return `IAsyncVoidPromise`, functions `IAsyncPromise<T>`).

| Method | Request | Notes |
|--------|---------|-------|
| `CreateUser(AUser): string` | `POST users` | Returns the new ID (from `Location`). A `TemporaryPassword` must pass `ValidatePassword`. 409 raises `EIAM4DUserAlreadyExistsException` |
| `GetUser(AUserID)` | `GET users/{id}` | 404: `EIAM4DHTTPNotFoundException` |
| `GetUserByUsername(AUsername)`, `TryGetUserByUsername` | `GET users?username=&exact=true` | Not found: `EIAM4DUserNotFoundException` / `Found` False. `ValidateUsernameLookup` first |
| `GetUserByEmail(AEmail)`, `TryGetUserByEmail` | `GET users?email=&exact=true` | As above, `ValidateEmail` first. Two or more users with that email (realm with duplicate emails allowed) raise `EIAM4DInvalidUserDataException` in both |
| `GetUsersByIDs(AUserIDs, ACancellationToken = nil)` | `GET users/{id}` per item | Batch: one `TIAM4DUserGetResult` per ID, in order; see [Batch operations](#batch-operations) |
| `SearchUsers(ACriteria)` | `GET users?...&first=&max=` | Only the criteria that are set; `enabled` only with `FilterByEnabled`. `ValidatePaging` first |
| `GetUsersCount: Integer` | `GET users/count` | A body that is not a number raises `EIAM4DException` |
| `UpdateUser(AUser)` | `PUT users/{id}` | Replaces the profile (table above): read with `GetUser`, change, update. Empty `ID`: `EIAM4DInvalidConfigurationException` |
| `DeleteUser(AUserID)` | `DELETE users/{id}` | |
| `CreateUsers`, `UpdateUsers`, `DeleteUsers` | one request per item | Batches |

## Batch operations

| Sync (`IIAM4DUserManager`) | Async | Item result |
|----------------------------|-------|-------------|
| `CreateUsers(AUsers, ACancellationToken)` | `CreateUsersAsync(AUsers)` | `TIAM4DUsersCreateResult` |
| `GetUsersByIDs(AUserIDs, ACancellationToken)` | `GetUsersByIDsAsync(AUserIDs)` | `TIAM4DUserGetResult` |
| `UpdateUsers(AUsers, ACancellationToken)` | `UpdateUsersAsync(AUsers)` | `TIAM4DOperationResult` (`Identifier` = username) |
| `DeleteUsers(AUserIDs, ACancellationToken)` | `DeleteUsersAsync(AUserIDs)` | `TIAM4DOperationResult` (user ID) |
| `SetPasswords(APasswordResets, ACancellationToken)` | `SetPasswordsAsync(APasswordResets)` | `TIAM4DOperationResult` (user ID) |
| `AssignRolesToUsers(ARoleAssignments, ACancellationToken)` | `AssignRolesToUsersAsync(...)` | `TIAM4DOperationResult` (user ID), realm roles |
| `AssignClientRolesToUsers(ARoleAssignments, ACancellationToken)` | `AssignClientRolesToUsersAsync(...)` | `TIAM4DOperationResult` (user ID), client roles |

- **Size**: 1 to 1000 items (`IAM4D_MIN_BATCH_SIZE`, `IAM4D_MAX_BATCH_SIZE`); otherwise `EIAM4DException` before any request (async: in `OnError`).
- **Order and independence**: items run one after another on one HTTP client; one result per item, in input order. A failed item stores its message (with its position and username or ID) and the next one runs. No atomicity: items already done stay done.
- **Token**: the bearer is set again before each item (`TClientBasedAuthProvider` refreshes it; a static token stays the same).
- **Validation per item**: a `TemporaryPassword` or a password that fails `ValidatePassword`, an update without `ID`, a client role without `ID`/`ContainerID`/`ClientID` are the error of their item, with no request for it. An assignment with no roles succeeds without a request.
- **Conflicts**: `CreateUsers` reports a 409 in the `ErrorMessage` of the item (no `EIAM4DUserAlreadyExistsException`). `GetUsersByIDs` reports a 404 as `User not found: {id}`.
- **Cancellation**: sync methods check `ACancellationToken.IsCancellationRequested` before each item; the async methods pass their own operation, so `Cancel` on the operation returned by `Run` works the same way. The items not yet run get `Success` False and `ErrorMessage` `IAM4D_OPERATION_CANCELLED` (`'Operation cancelled'`); the item in progress completes. The promise still completes with the full result array (`OnSuccess`).

## Passwords, emails and required actions

| Method | Request | Notes |
|--------|---------|-------|
| `SetPassword(AUserID, APassword, ATemporary = False)` | `PUT users/{id}/reset-password` | `ValidateUserID`, `ValidatePassword` first; Keycloak applies the password policy of the realm (400 on failure). `ATemporary`: change at next login |
| `SetPasswords(APasswordResets, ...)` | per item | Batch |
| `SendPasswordResetEmail(AUserID)` | `PUT users/{id}/execute-actions-email` with `["UPDATE_PASSWORD"]` | Needs the SMTP settings of the realm |
| `SendVerifyEmail(AUserID)` | `PUT users/{id}/send-verify-email` | |
| `GetUserRequiredActions(AUserID)` | `GET users/{id}` | Only the actions of `TIAM4DRequiredAction`; the others are in `GetUser(...).OtherRequiredActions` |
| `SetUserRequiredActions(AUserID, AActions)` | `PUT users/{id}` with `requiredActions` | Replaces every action, also those not in `TIAM4DRequiredAction` |
| `RemoveUserRequiredActions(AUserID, AActions)` | `GET` then `PUT users/{id}` | Removes `AActions`; the other actions stay, unknown ones included |

## Account state

| Method | Request | Notes |
|--------|---------|-------|
| `EnableUser(AUserID)`, `DisableUser(AUserID)` | `PUT users/{id}` with `enabled` only | |
| `IsUserLocked(AUserID): Boolean` | `GET attack-detection/brute-force/users/{id}` | Value of `disabled` (temporary lockout of brute force detection). False on 404 (no record); any other error raises |
| `UnlockUser(AUserID)` | `DELETE attack-detection/brute-force/users/{id}` | Clears the brute force record of that user |

## Realm roles

Role names are compared case-sensitively, as Keycloak does: a role read with another case is not found.

| Method | Request | Notes |
|--------|---------|-------|
| `GetRealmRoles` | `GET roles` | |
| `GetRoleByName(ARoleName)`, `TryGetRoleByName` | `GET roles/{name}` | 404: `EIAM4DRoleNotFoundException` / `Found` False |
| `GetUserRoles(AUserID)` | `GET users/{id}/role-mappings/realm` | Direct realm role mappings |
| `HasRole(AUserID, ARoleName)` | as `GetUserRoles` | Exact name among the direct mappings |
| `AssignRolesToUser(AUserID, ARoles)`, `RemoveRolesFromUser` | `POST` / `DELETE users/{id}/role-mappings/realm` | Sends `id`, `name` and `description` of each role: pass roles read from Keycloak |
| `AssignRoleByName(AUserID, ARoleName)`, `RemoveRoleByName` | `GET roles/{name}`, then `POST` / `DELETE` | One request for the role, not the list. Missing role (or another case): `EIAM4DRoleNotFoundException` |
| `GetUsersWithRole(ARoleName, AFirstResult = 0, AMaxResults = 100)` | `GET roles/{name}/users?first=&max=` | `ValidatePaging` first |
| `AssignRolesToUsers(ARoleAssignments, ...)` | per item | Batch |

## Clients and client roles

`AClientID` is the `clientId` of the client (e.g. `api-server`), looked up with `GET clients?clientId=` (first match); a client that does not exist raises `EIAM4DHTTPNotFoundException` (`Client "..." not found`). Roles returned by these methods have `ContainerID` and `ClientID` set.

| Method | Request | Notes |
|--------|---------|-------|
| `GetClients: TIAM4DRealmClientArray` | `GET clients`, then `GET clients/{uuid}/roles` per client | Every client with its roles |
| `GetClientByClientID(AClientID)` | lookup, `GET clients/{uuid}`, `GET clients/{uuid}/roles` | |
| `GetClientRolesByClientID(AClientID)` | lookup, `GET clients/{uuid}/roles` | Roles ready for `AssignClientRolesToUser` |
| `GetUserClientRolesByClientID(AUserID, AClientID)` | lookup, `GET users/{id}/role-mappings/clients/{uuid}` | Direct mappings |
| `HasClientRoleByClientID(AUserID, AClientID, ARoleName)` | as above | Exact name |
| `AssignClientRolesToUser(AUserID, ARoles)` | `POST users/{id}/role-mappings/clients/{ContainerID}`, one per client | Every role is checked before any request: one without `ID`, `ContainerID` or `ClientID` raises `EIAM4DInvalidConfigurationException`. Roles of several clients go each to its own client, in the order of their first role |
| `AssignClientRoleByClientID(AUserID, AClientID, ARoleName)` | lookup, `GET clients/{uuid}/roles/{name}`, `POST` | Missing role: `EIAM4DRoleNotFoundException` |
| `RemoveClientRoleByClientID(AUserID, AClientID, ARoleName)` | lookup, `GET` role, `DELETE` | |
| `RemoveClientRolesFromUserByClientID(AUserID, AClientID, ARoles)` | lookup, `DELETE users/{id}/role-mappings/clients/{uuid}` | |
| `AssignClientRolesToUsers(ARoleAssignments, ...)` | per item | Batch |

Empty user ID, client ID, role name or role array raise `EIAM4DInvalidConfigurationException` before any request.

## Groups

Group paths start with `/` and name each level (`/sales/italy`); they are case-sensitive.

| Method | Request | Notes |
|--------|---------|-------|
| `GetGroups` | `GET groups`, then `GET groups/{id}/children?first=&max=100` for each group with children | The whole tree, flattened (subgroups included). Inline `subGroups` (Keycloak before 23) are read as they are |
| `GetGroupByPath(APath)`, `TryGetGroupByPath` | `GET group-by-path/{segment}/{segment}...` | One request; segments encoded one by one; a leading `/` is added if missing. A group returned with another path (case) is not found: `EIAM4DGroupNotFoundException` / `Found` False. Empty path: `EIAM4DInvalidConfigurationException` |
| `GetUserGroups(AUserID)` | `GET users/{id}/groups` | Direct memberships |
| `IsMemberOfGroup(AUserID, AGroupPath)` | as `GetUserGroups` | Exact full path among the direct memberships |
| `AddUserToGroupByPath(AUserID, AGroupPath)`, `RemoveUserFromGroupByPath` | path lookup, `PUT` / `DELETE users/{id}/groups/{groupId}` | Missing group: `EIAM4DGroupNotFoundException` |
| `GetUsersInGroupByPath(AGroupPath, AFirstResult = 0, AMaxResults = 100)` | path lookup, `GET groups/{id}/members?first=&max=` | `ValidatePaging` before the lookup |

## Federated identities

Links between a user and accounts at the identity providers of the realm (brokering, see [IdentityBrokering.md](IdentityBrokering.md)). Not the user storage link (`TIAM4DUser.FederationLink`).

| Method | Request | Notes |
|--------|---------|-------|
| `GetUserFederatedIdentities(AUserID)` | `GET users/{id}/federated-identity` | |
| `IsUserFederated(AUserID)` | as above | True with at least one link |
| `LinkFederatedIdentity(AUserID, AFederatedIdentity)` | `POST users/{id}/federated-identity/{alias}` | `IdentityProvider`, `UserID` and `UserName` required (else `EIAM4DInvalidConfigurationException`). Needs `manage-users`. Already linked: `EIAM4DHTTPConflictException` |
| `UnlinkFederatedIdentity(AUserID, AIdentityProvider)` | `DELETE users/{id}/federated-identity/{alias}` | Not linked: `EIAM4DHTTPNotFoundException` |

`TIAM4DFederatedIdentity.Create(AIdentityProvider, AUserID, AUserName)` is in the record helper of `IAMClient4D.UserManagement.Helpers`: add that unit.

## Sessions

| Method | Request | Notes |
|--------|---------|-------|
| `GetUserSessions(AUserID)`, `GetUserSessionCount` | `GET users/{id}/sessions` | |
| `RevokeUserSession(AUserID, ASessionID)` | `GET users/{id}/sessions`, then `DELETE sessions/{sessionId}` | Ends one session of that user only: a session ID that is not among the user's sessions raises `EIAM4DHTTPNotFoundException` without the `DELETE` (which would end any session of the realm) |
| `LogoutUser(AUserID)` | `POST users/{id}/logout` | Ends every session of the user |

## Errors

Unit `IAMClient4D.Exceptions`. Failed responses (shared with the identity provider manager):

| Status | Exception | Properties |
|--------|-----------|------------|
| 403 | `EIAM4DInsufficientPermissionsException` | `StatusCode`, `ResponseBody` |
| 404 | `EIAM4DHTTPNotFoundException` | as above |
| 409 | `EIAM4DHTTPConflictException` | as above |
| other 4xx (400, 401, ...) | `EIAM4DHTTPClientErrorException` (ancestor of the three above) | as above |
| 5xx | `EIAM4DHTTPServerErrorException` | `StatusCode`, `ResponseBody`, `RetryAfterSeconds` (delay-seconds form of `Retry-After`, else 0) |
| other (3xx) | `EIAM4DInvalidConfigurationException` | the base URL does not point to the Admin API |

The message names the operation, method, URL (without the query string), status and at most 500 characters of the body; the whole body is in `ResponseBody`.

Specific classes:

| Exception | Ancestor | Raised by |
|-----------|----------|-----------|
| `EIAM4DUserNotFoundException` (`ErrorCode` `ecUserNotFound`, `UserIdentifier`) | `EIAM4DHTTPNotFoundException` | `GetUserByUsername`, `GetUserByEmail` |
| `EIAM4DRoleNotFoundException` (`ecRoleNotFound`) | `EIAM4DHTTPNotFoundException` | `GetRoleByName`, `*RoleByName`, `*ClientRoleByClientID` |
| `EIAM4DGroupNotFoundException` (`ecGroupNotFound`) | `EIAM4DHTTPNotFoundException` | `GetGroupByPath`, `*ByPath` |
| `EIAM4DHTTPNotFoundException` | | `GetUser` and the other requests by ID (404), client lookups by `clientId`, `RevokeUserSession`, `UnlinkFederatedIdentity` |
| `EIAM4DUserAlreadyExistsException` (`ecUserAlreadyExists`, `ConflictingField` `'username'` or `'email'`, `Value`) | `EIAM4DHTTPConflictException` | `CreateUser` |
| `EIAM4DInvalidUserDataException` | `EIAM4DException` | `ValidateUsername`, `ValidateUsernameLookup`, `ValidateEmail`, `ValidatePassword`; duplicate email in `GetUserByEmail` / `TryGetUserByEmail` |
| `EIAM4DInvalidConfigurationException` | `EIAM4DException` | Empty or invalid arguments (IDs, names, paths, paging), roles without client data, constructors |
| `EIAM4DException` | | Batch size, non-numeric `GetUsersCount` |

Every "not found", whether Keycloak answered 404 or the name was missing from a list, is an `EIAM4DHTTPNotFoundException` with `StatusCode` 404: one handler catches them all, `ErrorCode` or the class tells them apart. The async methods deliver the same classes to `OnError`.

## Validation

Unit `IAMClient4D.UserManagement.Validation`: `TIAM4DUserManagementValidator`, class methods, thread-safe (the regular expressions run under a lock). The manager calls them before the request; the application can call them on its own input.

| Method | Rule | Exception |
|--------|------|-----------|
| `ValidateUserID`, `ValidateClientID`, `ValidateContainerID`, `ValidateGroupPath`, `ValidateGroupID`, `ValidateRoleName`, `ValidateSessionID` | not empty | `EIAM4DInvalidConfigurationException` |
| `ValidateRolesArray(ACount)` | at least one role | `EIAM4DInvalidConfigurationException` |
| `ValidatePaging(AFirst, AMax)` | `AFirst` 0 or more, `AMax` 1 or more (Keycloak drops the limit for a negative max) | `EIAM4DInvalidConfigurationException` |
| `ValidateUsername` | 3 to 255 characters; letters, digits, `.`, `_`, `-`, `@`, `+` | `EIAM4DInvalidUserDataException` |
| `ValidateUsernameLookup` | not empty, at most 255 characters (format left to Keycloak) | `EIAM4DInvalidUserDataException` |
| `ValidateEmail` | not empty, at most 320 characters, simplified RFC 5322 pattern | `EIAM4DInvalidUserDataException` |
| `ValidatePassword` | 8 to 4096 characters | `EIAM4DInvalidUserDataException` |

`ValidateUsername` is not called by `CreateUser`: Keycloak applies the username rules of the realm user profile. The limits are constants of `IAMClient4D.UserManagement.Constants` (`IAM4D_MIN_PASSWORD_LENGTH`, `IAM4D_MAX_PASSWORD_LENGTH`, `IAM4D_MIN_USERNAME_LENGTH`, `IAM4D_MAX_USERNAME_LENGTH`, `IAM4D_MAX_EMAIL_LENGTH`), as are `IAM4D_DEFAULT_PAGE_SIZE` (100) and the batch limits.

## Helpers

Unit `IAMClient4D.UserManagement.Helpers` (record helpers: only one helper per type is active, the last unit in `uses` wins).

| Helper | Members |
|--------|---------|
| `TIAM4DUserHelper` | `ToJSON`, `FromJSON`, `IsValid` (username and, if set, email), `HasValidEmail`, `HasValidUsername`, `Clone`, `WithEmail`, `WithFirstName`, `WithLastName`, `WithEnabled`, `WithEmailVerified`, `WithTemporaryPassword`, `WithAttribute`, `WithRequiredAction` (copies), `FullName`, `HasAttribute` |
| `TIAM4DUserAttributeHelper` | `GetValue`, `AddValue`, `ToArray`, `Count`, `IsEmpty`, `Create`, `ToJSON` |
| `TIAM4DRoleHelper` | `IsRealmRole` / `IsClientRole` (empty or set `ContainerID`), `Equals`, `SameAs`, `Clone`, `CreateRealmRole`, `CreateClientRole`, `WithDescription`, `DisplayName` |
| `TIAM4DGroupHelper` | `ToJSON`, `FromJSON`, `ParentPath`, `Level`, `IsRootGroup`, `IsSubGroupOf`, `Equals`, `Clone`, `Create` |
| `TIAM4DUserArrayHelper` (`TArray<TIAM4DUser>`) | `TryFindByID`, `TryFindByUsername`, `TryFindByEmail` (case-insensitive), `FilterByEnabled`, `FilterByAttribute`, `FilterByRequiredAction`, `Count` |
| `TIAM4DRoleArrayHelper` (`TArray<TIAM4DRole>`) | `TryFindByName`, `Contains` (case-sensitive), `FilterByRealmRole`, `FilterByClientRole`, `FilterByClientID`, `FilterByContainerID`, `Count` |
| `TIAM4DFederatedIdentityHelper` | `Create`, `ToJSON`, `FromJSON`, `IsValid` (all three fields), `Clone`, `DisplayString` |
| `TIAM4DUserSessionHelper` | `DurationInSeconds`, `IdleTimeInSeconds`, `StartedDateTime`, `LastAccessDateTime`, `HasAccessedClient`, `ClientCount`, `IsActive(AIdleThresholdSeconds = 1800)`, `Clone`, `DisplayString`, JSON |
| `TIAM4DPasswordResetHelper` | `IsValid`, `HasValidPasswordLength`, `Clone`, `WithTemporary` |
| `TIAM4DOperationResultHelper`, `TIAM4DOperationResultArrayHelper` | `CreateSuccess`, `CreateFailure`, `DisplayString`; `SuccessCount`, `FailureCount`, `AllSucceeded`, `AllFailed`, `GetFailures`, `GetSuccesses`, `SummaryString` |
| `TIAM4DRoleLookupCache` (class) | Dictionary lookups on a role array: `TryGetRoleByName` (case-sensitive), `TryGetRoleByID` (case-insensitive), `HasRole`. Free it |

## Examples

The examples use `LClient`, a client of `iam4d-sample-app` logged in as `demo` (see [Admin token](#admin-token)), and `LUserManager: IIAM4DUserManager`.

Construction:

<!-- snippet ver=3.0 kind=body ctx=client,umgr -->
```delphi
// Base URL and realm from LClient.Issuer; the token is refreshed by LClient
LUserManager := TIAM4DKeycloakUserManager.Create(LClient);

// Static token (e.g. received from another service): never refreshed
LUserManager := TIAM4DKeycloakUserManager.Create(LClient.GetAccessToken,
  'http://localhost:18180/auth', 'iamclient4d');
```

Create a user with a temporary password, a realm role, a group and the verification email (worker thread):

<!-- snippet ver=3.0 kind=body ctx=umgr -->
```delphi
var LUser := TIAM4DUser.Create('mario.rossi', 'mario.rossi@example.com', 'Mario', 'Rossi');
LUser.TemporaryPassword := 'Welcome#2026';   // RequirePasswordChange is True
LUser.AddAttribute('department', ['sales']);
try
  var LUserID := LUserManager.CreateUser(LUser);
  LUserManager.AssignRoleByName(LUserID, 'offline_access');
  LUserManager.AddUserToGroupByPath(LUserID, '/sales/italy');  // an existing group
  LUserManager.SendVerifyEmail(LUserID);
except
  on E: EIAM4DUserAlreadyExistsException do
    Writeln('Already exists: ', E.ConflictingField, ' ', E.Value);
  on E: EIAM4DHTTPNotFoundException do
    Writeln('Missing role or group: ', E.Message);
  on E: EIAM4DInsufficientPermissionsException do
    Writeln('Missing realm-management roles');
end;
```

Read, change, update (empty fields clear the values):

<!-- snippet ver=3.0 kind=body ctx=umgr -->
```delphi
var LUser := LUserManager.GetUserByUsername('student');
LUser.LastName := '';
LUser.AddRequiredAction(raUpdateProfile);
LUserManager.UpdateUser(LUser);
```

Search page by page:

<!-- snippet ver=3.0 kind=body ctx=umgr -->
```delphi
var LCriteria := TIAM4DUserSearchCriteria.Create('example.com', 0, 50);
LCriteria.FilterByEnabled := True;
LCriteria.Enabled := True;
repeat
  var LPage := LUserManager.SearchUsers(LCriteria);
  for var LUser in LPage do
    Writeln(LUser.Username);
  if Length(LPage) < LCriteria.MaxResults then
    Break;
  LCriteria.FirstResult := LCriteria.FirstResult + LCriteria.MaxResults;
until False;
```

Client roles of `api-server`:

<!-- snippet ver=3.0 kind=body ctx=umgr -->
```delphi
var LUser := LUserManager.GetUserByUsername('student');
LUserManager.AssignClientRoleByClientID(LUser.ID, 'api-server', 'calculator-advanced');
if LUserManager.HasClientRoleByClientID(LUser.ID, 'api-server', 'calculator-advanced') then
  LUserManager.RemoveClientRoleByClientID(LUser.ID, 'api-server', 'calculator-advanced');
```

Batch import from a form, with cancellation:

<!-- snippet ver=3.0 kind=body ctx=umgr,ui uses=IAMClient4D.UserManagement.Keycloak.Async -->
```delphi
var LAsync: IIAM4DUserManagerAsync := TIAM4DKeycloakUserManagerAsync.Create(LUserManager);
var LUsers: TArray<TIAM4DUser>;
SetLength(LUsers, 100);
for var I := 0 to High(LUsers) do
begin
  LUsers[I] := TIAM4DUser.Create(Format('user%.3d', [I]), Format('user%.3d@example.com', [I]));
  LUsers[I].TemporaryPassword := 'Welcome#2026';
end;

var LOperation := LAsync.CreateUsersAsync(LUsers)
  .OnSuccess(
    procedure(const AResults: TArray<TIAM4DUsersCreateResult>)
    begin
      for var LResult in AResults do
        if not LResult.Success then
          ShowMessage(LResult.ErrorMessage);  // 'Operation cancelled' for the items not run
    end)
  .OnError(
    procedure(const AException: Exception)
    begin
      ShowMessage(AException.Message);        // e.g. more than 1000 items
    end)
  .Run;
// Later, e.g. from a Cancel button
LOperation.Cancel;
```

Link a local user to an account of an identity provider:

<!-- snippet ver=3.0 kind=body ctx=umgr uses=IAMClient4D.UserManagement.Helpers -->
```delphi
var LUser := LUserManager.GetUserByEmail('mario.rossi@example.com');
LUserManager.LinkFederatedIdentity(LUser.ID,
  TIAM4DFederatedIdentity.Create('entra', '00000000-0000-0000-0000-000000000000', 'mario.rossi@example.com'));
for var LLink in LUserManager.GetUserFederatedIdentities(LUser.ID) do
  Writeln(LLink.IdentityProvider, ': ', LLink.UserName);
```
