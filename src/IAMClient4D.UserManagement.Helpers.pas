{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.UserManagement.Helpers.pas
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

unit IAMClient4D.UserManagement.Helpers;

interface

uses
  System.SysUtils,
  System.JSON,
  System.Generics.Collections,
  System.Generics.Defaults,
  System.RegularExpressions,
  System.DateUtils,
  IAMClient4D.UserManagement.Core,
  IAMClient4D.UserManagement.Constants,
  IAMClient4D.Exceptions;

const
  /// <summary>Default idle threshold for session activity check (30 minutes)</summary>
  IAM4D_DEFAULT_IDLE_THRESHOLD_SECONDS = 1800;

type
  /// <summary>
  /// Helper for TIAM4DUserAttribute record.
  /// Provides utility methods for attribute manipulation and conversion.
  /// </summary>
  TIAM4DUserAttributeHelper = record helper for TIAM4DUserAttribute
  public
    /// <summary>
    /// Gets a value by index. Returns empty string if index is out of bounds.
    /// </summary>
    function GetValue(const AIndex: Integer): string;

    /// <summary>
    /// Adds a value to the attribute values array.
    /// Returns a new TIAM4DUserAttribute with the added value.
    /// </summary>
    function AddValue(const AValue: string): TIAM4DUserAttribute;

    /// <summary>
    /// Returns a copy of the values array.
    /// </summary>
    function ToArray: TArray<string>;

    /// <summary>
    /// Returns the count of values in this attribute.
    /// </summary>
    function Count: Integer;

    /// <summary>
    /// Checks if the attribute has any values.
    /// </summary>
    function IsEmpty: Boolean;

    /// <summary>
    /// Creates a new attribute with name and single value.
    /// </summary>
    class function Create(const AName: string; const AValue: string): TIAM4DUserAttribute; overload; static;

    /// <summary>
    /// Creates a new attribute with name and multiple values.
    /// </summary>
    class function Create(const AName: string; const AValues: array of string): TIAM4DUserAttribute; overload; static;

    /// <summary>
    /// Converts attribute to JSON pair (name: [values]).
    /// </summary>
    function ToJSON: TJSONPair;
  end;

  /// <summary>
  /// Helper for TIAM4DUser record.
  /// Provides JSON conversion, validation, builder pattern, and utility methods.
  /// </summary>
  TIAM4DUserHelper = record helper for TIAM4DUser
  public
    /// <summary>
    /// Converts user record to JSON object for Keycloak API.
    /// </summary>
    /// <remarks>
    /// Caller is responsible for freeing the returned TJSONObject.
    /// TemporaryPassword is excluded (handled separately by CreateUserAsync).
    /// </remarks>
    function ToJSON: TJSONObject;

    /// <summary>
    /// Creates a user record from JSON object returned by Keycloak API.
    /// </summary>
    class function FromJSON(const AJSON: TJSONObject): TIAM4DUser; static;

    /// <summary>
    /// Validates user data according to library constraints.
    /// Returns True if valid, False otherwise.
    /// </summary>
    function IsValid: Boolean; overload;

    /// <summary>
    /// Validates user data and returns error message if invalid.
    /// </summary>
    function IsValid(out AErrorMessage: string): Boolean; overload;

    /// <summary>
    /// Validates email format using regex pattern.
    /// </summary>
    function HasValidEmail: Boolean;

    /// <summary>
    /// Validates username format and length.
    /// </summary>
    function HasValidUsername: Boolean;

    /// <summary>
    /// Creates a deep clone of the user record.
    /// </summary>
    function Clone: TIAM4DUser;

    // Fluent builder methods

    /// <summary>
    /// Returns a new user record with updated email.
    /// </summary>
    function WithEmail(const AEmail: string): TIAM4DUser;

    /// <summary>
    /// Returns a new user record with updated first name.
    /// </summary>
    function WithFirstName(const AFirstName: string): TIAM4DUser;

    /// <summary>
    /// Returns a new user record with updated last name.
    /// </summary>
    function WithLastName(const ALastName: string): TIAM4DUser;

    /// <summary>
    /// Returns a new user record with updated enabled status.
    /// </summary>
    function WithEnabled(const AEnabled: Boolean): TIAM4DUser;

    /// <summary>
    /// Returns a new user record with updated email verified status.
    /// </summary>
    function WithEmailVerified(const AEmailVerified: Boolean): TIAM4DUser;

    /// <summary>
    /// Returns a new user record with a temporary password set.
    /// </summary>
    function WithTemporaryPassword(const APassword: string; const ARequireChange: Boolean = True): TIAM4DUser;

    /// <summary>
    /// Returns a new user record with an added attribute.
    /// </summary>
    function WithAttribute(const AName: string; const AValues: array of string): TIAM4DUser;

    /// <summary>
    /// Returns a new user record with an added required action.
    /// </summary>
    function WithRequiredAction(const AAction: TIAM4DRequiredAction): TIAM4DUser;

    /// <summary>
    /// Returns the full name (FirstName + LastName).
    /// </summary>
    function FullName: string;

    /// <summary>
    /// Checks if user has a specific attribute.
    /// </summary>
    function HasAttribute(const AName: string): Boolean;
  end;

  /// <summary>
  /// Helper for TIAM4DRole record.
  /// Provides JSON conversion, comparison, and builder pattern.
  /// </summary>
  TIAM4DRoleHelper = record helper for TIAM4DRole
  public
    /// <summary>
    /// Converts role record to JSON object for Keycloak API.
    /// </summary>
    /// <remarks>
    /// Caller is responsible for freeing the returned TJSONObject.
    /// </remarks>
    function ToJSON: TJSONObject;

    /// <summary>
    /// Checks if this is a realm-level role (ClientID is empty).
    /// </summary>
    function IsRealmRole: Boolean;

    /// <summary>
    /// Checks if this is a client-level role (ClientID is not empty).
    /// </summary>
    function IsClientRole: Boolean;

    /// <summary>
    /// Compares roles by ID.
    /// </summary>
    function Equals(const AOther: TIAM4DRole): Boolean;

    /// <summary>
    /// Compares roles by name (case-insensitive).
    /// </summary>
    function SameAs(const AOther: TIAM4DRole): Boolean;

    /// <summary>
    /// Creates a deep clone of the role record.
    /// </summary>
    function Clone: TIAM4DRole;

    // Fluent builder methods

    /// <summary>
    /// Creates a new realm role with specified name.
    /// </summary>
    class function CreateRealmRole(const AName: string; const ADescription: string = ''): TIAM4DRole; static;

    /// <summary>
    /// Creates a new client role with specified name and client info.
    /// </summary>
    class function CreateClientRole(const AName: string; const AClientID: string; const AClientName: string; const ADescription: string = ''): TIAM4DRole; static;

    /// <summary>
    /// Returns a new role record with updated description.
    /// </summary>
    function WithDescription(const ADescription: string): TIAM4DRole;

    /// <summary>
    /// Returns a formatted display name (includes client name for client roles).
    /// </summary>
    function DisplayName: string;
  end;

  /// <summary>
  /// Helper for TIAM4DGroup record.
  /// Provides JSON conversion, path management, and builder pattern.
  /// </summary>
  TIAM4DGroupHelper = record helper for TIAM4DGroup
  public
    /// <summary>
    /// Converts group record to JSON object for Keycloak API.
    /// </summary>
    /// <remarks>
    /// Caller is responsible for freeing the returned TJSONObject.
    /// </remarks>
    function ToJSON: TJSONObject;

    /// <summary>
    /// Creates a group record from JSON object returned by Keycloak API.
    /// </summary>
    class function FromJSON(const AJSON: TJSONObject): TIAM4DGroup; static;

    /// <summary>
    /// Gets the parent path (everything before the last slash).
    /// Returns empty string if this is a root group.
    /// </summary>
    function ParentPath: string;

    /// <summary>
    /// Gets the depth level in the hierarchy (count of slashes).
    /// Root level groups return 1.
    /// </summary>
    function Level: Integer;

    /// <summary>
    /// Checks if this is a root-level group.
    /// </summary>
    function IsRootGroup: Boolean;

    /// <summary>
    /// Checks if this group is a subgroup of another group.
    /// </summary>
    function IsSubGroupOf(const AParentPath: string): Boolean;

    /// <summary>
    /// Compares groups by ID.
    /// </summary>
    function Equals(const AOther: TIAM4DGroup): Boolean;

    /// <summary>
    /// Creates a deep clone of the group record.
    /// </summary>
    function Clone: TIAM4DGroup;

    /// <summary>
    /// Creates a new group with specified name and path.
    /// </summary>
    class function Create(const AName: string; const APath: string): TIAM4DGroup; static;
  end;

  /// <summary>
  /// Helper for TArray&lt;TIAM4DUser&gt;.
  /// Provides filtering, searching, and sorting operations.
  /// </summary>
  TIAM4DUserArrayHelper = record helper for TArray<TIAM4DUser>
  public
    /// <summary>
    /// Finds a user by ID. Returns True if found.
    /// </summary>
    function TryFindByID(const AUserID: string; out AUser: TIAM4DUser): Boolean;

    /// <summary>
    /// Finds a user by username. Returns True if found.
    /// </summary>
    function TryFindByUsername(const AUsername: string; out AUser: TIAM4DUser): Boolean;

    /// <summary>
    /// Finds a user by email. Returns True if found.
    /// </summary>
    function TryFindByEmail(const AEmail: string; out AUser: TIAM4DUser): Boolean;

    /// <summary>
    /// Filters users by enabled status.
    /// </summary>
    function FilterByEnabled(const AEnabled: Boolean): TArray<TIAM4DUser>;

    /// <summary>
    /// Filters users who have a specific attribute.
    /// </summary>
    function FilterByAttribute(const AAttributeName: string): TArray<TIAM4DUser>;

    /// <summary>
    /// Filters users who have a specific required action.
    /// </summary>
    function FilterByRequiredAction(const AAction: TIAM4DRequiredAction): TArray<TIAM4DUser>;

    /// <summary>
    /// Returns count of users in the array.
    /// </summary>
    function Count: Integer;
  end;

  /// <summary>
  /// Helper for TArray&lt;TIAM4DRole&gt;.
  /// Provides filtering and searching operations.
  /// </summary>
  TIAM4DRoleArrayHelper = record helper for TArray<TIAM4DRole>
  public
    /// <summary>
    /// Finds a role by name. Returns True if found.
    /// </summary>
    function TryFindByName(const ARoleName: string; out ARole: TIAM4DRole): Boolean;

    /// <summary>
    /// Filters roles by type (realm or client).
    /// </summary>
    function FilterByRealmRole: TArray<TIAM4DRole>;

    /// <summary>
    /// Filters client roles only.
    /// </summary>
    function FilterByClientRole: TArray<TIAM4DRole>;

    /// <summary>
    /// Filters roles by client ID.
    /// </summary>
    function FilterByClientID(const AClientID: string): TArray<TIAM4DRole>;

    /// <summary>
    /// Checks if array contains a role with specified name.
    /// </summary>
    function Contains(const ARoleName: string): Boolean;

    /// <summary>
    /// Returns count of roles in the array.
    /// </summary>
    function Count: Integer;
  end;

  /// <summary>
  /// Helper for TIAM4DFederatedIdentity record.
  /// Provides JSON conversion, validation, and utility methods.
  /// </summary>
  TIAM4DFederatedIdentityHelper = record helper for TIAM4DFederatedIdentity
  public
    /// <summary>
    /// Converts federated identity record to JSON object for Keycloak API.
    /// </summary>
    /// <remarks>
    /// Caller is responsible for freeing the returned TJSONObject.
    /// </remarks>
    function ToJSON: TJSONObject;

    /// <summary>
    /// Creates a federated identity record from JSON object returned by Keycloak API.
    /// </summary>
    class function FromJSON(const AJSON: TJSONObject): TIAM4DFederatedIdentity; static;

    /// <summary>
    /// Validates federated identity data.
    /// Returns True if all required fields are present.
    /// </summary>
    function IsValid: Boolean; overload;

    /// <summary>
    /// Validates federated identity data and returns error message if invalid.
    /// </summary>
    function IsValid(out AErrorMessage: string): Boolean; overload;

    /// <summary>
    /// Creates a new federated identity with specified parameters.
    /// </summary>
    class function Create(const AIdentityProvider: string; const AUserID: string; const AUserName: string): TIAM4DFederatedIdentity; static;

    /// <summary>
    /// Creates a deep clone of the federated identity record.
    /// </summary>
    function Clone: TIAM4DFederatedIdentity;

    /// <summary>
    /// Returns a formatted display string for the federated identity.
    /// Format: "provider: username (userID)"
    /// </summary>
    function DisplayString: string;
  end;

  /// <summary>
  /// Helper for TIAM4DUserSession record.
  /// Provides JSON conversion, time calculations, and utility methods.
  /// </summary>
  TIAM4DUserSessionHelper = record helper for TIAM4DUserSession
  public
    /// <summary>
    /// Converts user session record to JSON object.
    /// </summary>
    /// <remarks>
    /// Caller is responsible for freeing the returned TJSONObject.
    /// </remarks>
    function ToJSON: TJSONObject;

    /// <summary>
    /// Creates a user session record from JSON object returned by Keycloak API.
    /// </summary>
    class function FromJSON(const AJSON: TJSONObject): TIAM4DUserSession; static;

    /// <summary>
    /// Calculates the duration of the session in seconds.
    /// </summary>
    function DurationInSeconds: Int64;

    /// <summary>
    /// Calculates the idle time (time since last access) in seconds.
    /// </summary>
    function IdleTimeInSeconds: Int64;

    /// <summary>
    /// Returns the session start time as TDateTime.
    /// </summary>
    function StartedDateTime: TDateTime;

    /// <summary>
    /// Returns the last access time as TDateTime.
    /// </summary>
    function LastAccessDateTime: TDateTime;

    /// <summary>
    /// Checks if session has accessed a specific client.
    /// </summary>
    function HasAccessedClient(const AClientID: string): Boolean;

    /// <summary>
    /// Returns the count of clients that have accessed this session.
    /// </summary>
    function ClientCount: Integer;

    /// <summary>
    /// Checks if the session is considered active based on idle time.
    /// Default threshold: 30 minutes (IAM4D_DEFAULT_IDLE_THRESHOLD_SECONDS).
    /// </summary>
    function IsActive(const AIdleThresholdSeconds: Int64 = IAM4D_DEFAULT_IDLE_THRESHOLD_SECONDS): Boolean;

    /// <summary>
    /// Creates a deep clone of the user session record.
    /// </summary>
    function Clone: TIAM4DUserSession;

    /// <summary>
    /// Returns a formatted display string for the session.
    /// Format: "IP: ipaddress, Duration: X minutes, Clients: N"
    /// </summary>
    function DisplayString: string;
  end;

  /// <summary>
  /// Helper for TIAM4DPasswordReset record.
  /// Provides validation and utility methods for password reset operations.
  /// </summary>
  TIAM4DPasswordResetHelper = record helper for TIAM4DPasswordReset
  public
    /// <summary>
    /// Validates password reset data.
    /// Checks UserID is not empty and password meets minimum requirements.
    /// </summary>
    function IsValid: Boolean; overload;

    /// <summary>
    /// Validates password reset data and returns error message if invalid.
    /// </summary>
    function IsValid(out AErrorMessage: string): Boolean; overload;

    /// <summary>
    /// Checks if password meets minimum length requirement.
    /// </summary>
    function HasValidPasswordLength: Boolean;

    /// <summary>
    /// Creates a deep clone of the password reset record.
    /// </summary>
    function Clone: TIAM4DPasswordReset;

    /// <summary>
    /// Returns a new password reset record with updated temporary flag.
    /// </summary>
    function WithTemporary(const ATemporary: Boolean): TIAM4DPasswordReset;
  end;

  /// <summary>
  /// Helper for TIAM4DOperationResult record.
  /// Provides utility methods for batch operation results.
  /// </summary>
  TIAM4DOperationResultHelper = record helper for TIAM4DOperationResult
  public
    /// <summary>
    /// Creates a successful operation result.
    /// </summary>
    class function CreateSuccess(const AIdentifier: string): TIAM4DOperationResult; static;

    /// <summary>
    /// Creates a failed operation result with error message.
    /// </summary>
    class function CreateFailure(const AIdentifier: string; const AErrorMessage: string): TIAM4DOperationResult; static;

    /// <summary>
    /// Returns a formatted display string for the result.
    /// </summary>
    function DisplayString: string;
  end;

  /// <summary>
  /// Helper for TArray&lt;TIAM4DOperationResult&gt;.
  /// Provides aggregation and filtering operations for batch results.
  /// </summary>
  TIAM4DOperationResultArrayHelper = record helper for TArray<TIAM4DOperationResult>
  public
    /// <summary>
    /// Returns the count of successful operations.
    /// </summary>
    function SuccessCount: Integer;

    /// <summary>
    /// Returns the count of failed operations.
    /// </summary>
    function FailureCount: Integer;

    /// <summary>
    /// Checks if all operations succeeded.
    /// </summary>
    function AllSucceeded: Boolean;

    /// <summary>
    /// Checks if all operations failed.
    /// </summary>
    function AllFailed: Boolean;

    /// <summary>
    /// Returns array of failed results only.
    /// </summary>
    function GetFailures: TArray<TIAM4DOperationResult>;

    /// <summary>
    /// Returns array of successful results only.
    /// </summary>
    function GetSuccesses: TArray<TIAM4DOperationResult>;

    /// <summary>
    /// Returns a summary string with success/failure counts.
    /// Format: "X succeeded, Y failed out of Z total"
    /// </summary>
    function SummaryString: string;
  end;

  /// <summary>
  /// Optimized role lookup helper using dictionaries for O(1) access.
  /// Use this when performing multiple role lookups on the same role array.
  /// </summary>
  TIAM4DRoleLookupCache = class
  private
    FRolesByName: TDictionary<string, TIAM4DRole>;
    FRolesByID: TDictionary<string, TIAM4DRole>;
  public
    /// <summary>
    /// Creates a lookup cache from an array of roles.
    /// </summary>
    constructor Create(const ARoles: TArray<TIAM4DRole>);
    destructor Destroy; override;

    /// <summary>
    /// Tries to get a role by name. O(1) lookup.
    /// </summary>
    function TryGetRoleByName(const ARoleName: string; out ARole: TIAM4DRole): Boolean;

    /// <summary>
    /// Tries to get a role by ID. O(1) lookup.
    /// </summary>
    function TryGetRoleByID(const ARoleID: string; out ARole: TIAM4DRole): Boolean;

    /// <summary>
    /// Checks if a role exists by name. O(1) lookup.
    /// </summary>
    function HasRole(const ARoleName: string): Boolean;
  end;

  /// <summary>
  /// JSON parsing helper to reduce boilerplate in JSON mapping functions.
  /// Provides safe extraction of values with default fallbacks.
  /// </summary>
  TIAM4DJSONHelper = class
  public
    /// <summary>
    /// Safely extracts a string value from JSON object.
    /// Returns ADefault if key doesn't exist or value is null.
    /// </summary>
    class function GetString(const AJSON: TJSONObject; const AKey: string; const ADefault: string = ''): string;

    /// <summary>
    /// Safely extracts a boolean value from JSON object.
    /// Returns ADefault if key doesn't exist or value is null.
    /// </summary>
    class function GetBool(const AJSON: TJSONObject; const AKey: string; const ADefault: Boolean = False): Boolean;

    /// <summary>
    /// Safely extracts an Int64 value from JSON object.
    /// Returns ADefault if key doesn't exist or value is null.
    /// </summary>
    class function GetInt64(const AJSON: TJSONObject; const AKey: string; const ADefault: Int64 = 0): Int64;

    /// <summary>
    /// Safely extracts a TJSONArray from JSON object.
    /// Returns nil if key doesn't exist or value is not an array.
    /// </summary>
    class function GetArray(const AJSON: TJSONObject; const AKey: string): TJSONArray;

    /// <summary>
    /// Maps a TJSONArray to TArray using a mapper function.
    /// Useful for converting JSON arrays to strongly-typed arrays.
    /// </summary>
    class function MapArray<T>(const AArray: TJSONArray; AMapper: TFunc<TJSONValue, T>): TArray<T>;
  end;

implementation

{ TIAM4DUserAttributeHelper }

function TIAM4DUserAttributeHelper.GetValue(const AIndex: Integer): string;
begin
  if (AIndex >= 0) and (AIndex < Length(Values)) then
    Result := Values[AIndex]
  else
    Result := '';
end;

function TIAM4DUserAttributeHelper.AddValue(const AValue: string): TIAM4DUserAttribute;
var
  LLen: Integer;
begin
  Result := Self;
  LLen := Length(Result.Values);
  SetLength(Result.Values, LLen + 1);
  Result.Values[LLen] := AValue;
end;

function TIAM4DUserAttributeHelper.ToArray: TArray<string>;
begin
  Result := Values;
end;

function TIAM4DUserAttributeHelper.Count: Integer;
begin
  Result := Length(Values);
end;

function TIAM4DUserAttributeHelper.IsEmpty: Boolean;
begin
  Result := Length(Values) = 0;
end;

class function TIAM4DUserAttributeHelper.Create(const AName: string; const AValue: string): TIAM4DUserAttribute;
begin
  Result.Name := AName;
  SetLength(Result.Values, 1);
  Result.Values[0] := AValue;
end;

class function TIAM4DUserAttributeHelper.Create(const AName: string; const AValues: array of string): TIAM4DUserAttribute;
var
  LIndex: Integer;
begin
  Result.Name := AName;
  SetLength(Result.Values, Length(AValues));
  for LIndex := 0 to High(AValues) do
    Result.Values[LIndex] := AValues[LIndex];
end;

function TIAM4DUserAttributeHelper.ToJSON: TJSONPair;
var
  LArray: TJSONArray;
  LValue: string;
begin
  LArray := TJSONArray.Create;
  try
    for LValue in Values do
      LArray.Add(LValue);
    Result := TJSONPair.Create(Name, LArray);
  except
    LArray.Free;
    raise;
  end;
end;

{ TIAM4DUserHelper }

function TIAM4DUserHelper.ToJSON: TJSONObject;
var
  LAttr: TIAM4DUserAttribute;
  LAttrsObj: TJSONObject;
  LActionsArray: TJSONArray;
  LAction: TIAM4DRequiredAction;
begin
  Result := TJSONObject.Create;
  try
    if ID <> IAM4D_EMPTY_USER_ID then
      Result.AddPair('id', ID);

    Result.AddPair('username', Username);
    Result.AddPair('email', Email);

    if FirstName <> '' then
      Result.AddPair('firstName', FirstName);

    if LastName <> '' then
      Result.AddPair('lastName', LastName);

    Result.AddPair('enabled', TJSONBool.Create(Enabled));
    Result.AddPair('emailVerified', TJSONBool.Create(EmailVerified));

    if Length(AllAttributes) > 0 then
    begin
      LAttrsObj := TJSONObject.Create;
      try
        for LAttr in AllAttributes do
          LAttrsObj.AddPair(LAttr.ToJSON);
        Result.AddPair('attributes', LAttrsObj);
      except
        LAttrsObj.Free;
        raise;
      end;
    end;

    if Length(RequiredActions) > 0 then
    begin
      LActionsArray := TJSONArray.Create;
      try
        for LAction in RequiredActions do
          LActionsArray.Add(LAction.ToString);
        Result.AddPair('requiredActions', LActionsArray);
      except
        LActionsArray.Free;
        raise;
      end;
    end;

    if CreatedTimestamp > 0 then
      Result.AddPair('createdTimestamp', TJSONNumber.Create(CreatedTimestamp));
  except
    Result.Free;
    raise;
  end;
end;

class function TIAM4DUserHelper.FromJSON(const AJSON: TJSONObject): TIAM4DUser;
var
  LValue: TJSONValue;
  LAttrsObj: TJSONObject;
  LAttrPair: TJSONPair;
  LAttrArray: TJSONArray;
  LAttrIndex: Integer;
  LAttr: TIAM4DUserAttribute;
  LActionsArray: TJSONArray;
  LActionIndex: Integer;
  LActionStr: string;
  LAttributes: TArray<TIAM4DUserAttribute>;
  LActions: TArray<TIAM4DRequiredAction>;
begin
  Result := Default(TIAM4DUser);

  LValue := AJSON.GetValue('id');
  if Assigned(LValue) and not (LValue is TJSONNull) then
    Result.ID := LValue.Value
  else
    Result.ID := IAM4D_EMPTY_USER_ID;

  LValue := AJSON.GetValue('username');
  if Assigned(LValue) then
    Result.Username := LValue.Value;

  LValue := AJSON.GetValue('email');
  if Assigned(LValue) and not (LValue is TJSONNull) then
    Result.Email := LValue.Value;

  LValue := AJSON.GetValue('firstName');
  if Assigned(LValue) and not (LValue is TJSONNull) then
    Result.FirstName := LValue.Value;

  LValue := AJSON.GetValue('lastName');
  if Assigned(LValue) and not (LValue is TJSONNull) then
    Result.LastName := LValue.Value;

  LValue := AJSON.GetValue('enabled');
  if Assigned(LValue) then
    Result.Enabled := (LValue is TJSONTrue)
  else
    Result.Enabled := True;

  LValue := AJSON.GetValue('emailVerified');
  if Assigned(LValue) then
    Result.EmailVerified := (LValue is TJSONTrue)
  else
    Result.EmailVerified := False;

  LValue := AJSON.GetValue('createdTimestamp');
  if Assigned(LValue) and (LValue is TJSONNumber) then
    Result.CreatedTimestamp := TJSONNumber(LValue).AsInt64;

  LValue := AJSON.GetValue('attributes');
  if Assigned(LValue) and (LValue is TJSONObject) then
  begin
    LAttrsObj := TJSONObject(LValue);
    SetLength(LAttributes, LAttrsObj.Count);

    for LAttrIndex := 0 to LAttrsObj.Count - 1 do
    begin
      LAttrPair := LAttrsObj.Pairs[LAttrIndex];
      LAttr.Name := LAttrPair.JsonString.Value;

      if LAttrPair.JsonValue is TJSONArray then
      begin
        LAttrArray := TJSONArray(LAttrPair.JsonValue);
        SetLength(LAttr.Values, LAttrArray.Count);

        for LActionIndex := 0 to LAttrArray.Count - 1 do
          LAttr.Values[LActionIndex] := LAttrArray.Items[LActionIndex].Value;
      end
      else
      begin
        SetLength(LAttr.Values, 1);
        LAttr.Values[0] := LAttrPair.JsonValue.Value;
      end;

      LAttributes[LAttrIndex] := LAttr;
    end;
    Result.AllAttributes := LAttributes;
  end;

  LValue := AJSON.GetValue('requiredActions');
  if Assigned(LValue) and (LValue is TJSONArray) then
  begin
    LActionsArray := TJSONArray(LValue);
    SetLength(LActions, LActionsArray.Count);

    for LActionIndex := 0 to LActionsArray.Count - 1 do
    begin
      LActionStr := LActionsArray.Items[LActionIndex].Value;
      LActions[LActionIndex] := TIAM4DRequiredAction.FromString(LActionStr);
    end;
    Result.RequiredActions := LActions;
  end;
end;

function TIAM4DUserHelper.IsValid: Boolean;
var
  LDummy: string;
begin
  Result := IsValid(LDummy);
end;

function TIAM4DUserHelper.IsValid(out AErrorMessage: string): Boolean;
begin
  Result := False;
  AErrorMessage := '';

  if Username = '' then
  begin
    AErrorMessage := 'Username is required';
    Exit;
  end;

  if not HasValidUsername then
  begin
    AErrorMessage := Format('Username "%s" is invalid. Must be %d-%d characters and contain only letters, numbers, dots, hyphens, and underscores',
      [Username, IAM4D_MIN_USERNAME_LENGTH, IAM4D_MAX_USERNAME_LENGTH]);
    Exit;
  end;

  if Email <> '' then
  begin
    if not HasValidEmail then
    begin
      AErrorMessage := Format('Email "%s" is invalid', [Email]);
      Exit;
    end;
  end;

  Result := True;
end;

function TIAM4DUserHelper.HasValidEmail: Boolean;
begin
  if Email = '' then
    Exit(True);

  if Length(Email) > IAM4D_MAX_EMAIL_LENGTH then
    Exit(False);

  Result := TRegEx.IsMatch(Email, IAM4D_EMAIL_REGEX_PATTERN, [roCompiled]);
end;

function TIAM4DUserHelper.HasValidUsername: Boolean;
begin
  if (Length(Username) < IAM4D_MIN_USERNAME_LENGTH) or
    (Length(Username) > IAM4D_MAX_USERNAME_LENGTH) then
    Exit(False);

  Result := TRegEx.IsMatch(Username, IAM4D_USERNAME_REGEX_PATTERN, [roCompiled]);
end;

function TIAM4DUserHelper.Clone: TIAM4DUser;
var
  LIndex: Integer;
  LAttributes: TArray<TIAM4DUserAttribute>;
  LActions: TArray<TIAM4DRequiredAction>;
begin
  Result := Self;

  if Length(AllAttributes) > 0 then
  begin
    SetLength(LAttributes, Length(AllAttributes));
    for LIndex := 0 to High(AllAttributes) do
    begin
      LAttributes[LIndex].Name := AllAttributes[LIndex].Name;
      LAttributes[LIndex].Values := Copy(AllAttributes[LIndex].Values);
    end;
    Result.AllAttributes := LAttributes;
  end;

  if Length(RequiredActions) > 0 then
  begin
    LActions := Copy(RequiredActions);
    Result.RequiredActions := LActions;
  end;
end;

function TIAM4DUserHelper.WithEmail(const AEmail: string): TIAM4DUser;
begin
  Result := Self;
  Result.Email := AEmail;
end;

function TIAM4DUserHelper.WithFirstName(const AFirstName: string): TIAM4DUser;
begin
  Result := Self;
  Result.FirstName := AFirstName;
end;

function TIAM4DUserHelper.WithLastName(const ALastName: string): TIAM4DUser;
begin
  Result := Self;
  Result.LastName := ALastName;
end;

function TIAM4DUserHelper.WithEnabled(const AEnabled: Boolean): TIAM4DUser;
begin
  Result := Self;
  Result.Enabled := AEnabled;
end;

function TIAM4DUserHelper.WithEmailVerified(const AEmailVerified: Boolean): TIAM4DUser;
begin
  Result := Self;
  Result.EmailVerified := AEmailVerified;
end;

function TIAM4DUserHelper.WithTemporaryPassword(const APassword: string; const ARequireChange: Boolean): TIAM4DUser;
begin
  Result := Self;
  Result.TemporaryPassword := APassword;
  Result.RequirePasswordChange := ARequireChange;
end;

function TIAM4DUserHelper.WithAttribute(const AName: string; const AValues: array of string): TIAM4DUser;
var
  LIndex: Integer;
  LAttributes: TArray<TIAM4DUserAttribute>;
begin
  Result := Self;

  if Length(AllAttributes) > 0 then
  begin
    SetLength(LAttributes, Length(AllAttributes));
    for LIndex := 0 to High(AllAttributes) do
    begin
      LAttributes[LIndex].Name := AllAttributes[LIndex].Name;
      LAttributes[LIndex].Values := Copy(AllAttributes[LIndex].Values);
    end;
    Result.AllAttributes := LAttributes;
  end;

  Result.AddAttribute(AName, AValues);
end;

function TIAM4DUserHelper.WithRequiredAction(const AAction: TIAM4DRequiredAction): TIAM4DUser;
begin
  Result := Self;

  if Length(RequiredActions) > 0 then
    Result.RequiredActions := Copy(RequiredActions);

  Result.AddRequiredAction(AAction);
end;

function TIAM4DUserHelper.FullName: string;
begin
  Result := Trim(FirstName + ' ' + LastName);
end;

function TIAM4DUserHelper.HasAttribute(const AName: string): Boolean;
var
  LDummy: TArray<string>;
begin
  Result := TryGetAttribute(AName, LDummy);
end;

{ TIAM4DRoleHelper }

function TIAM4DRoleHelper.ToJSON: TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    if ID <> '' then
      Result.AddPair('id', ID);

    Result.AddPair('name', Name);

    if Description <> '' then
      Result.AddPair('description', Description);

    Result.AddPair('composite', TJSONBool.Create(Composite));

    if ClientID <> '' then
      Result.AddPair('clientId', ClientID);

    if ClientName <> '' then
      Result.AddPair('containerId', ClientID);
  except
    Result.Free;
    raise;
  end;
end;

function TIAM4DRoleHelper.IsRealmRole: Boolean;
begin
  Result := ClientID = '';
end;

function TIAM4DRoleHelper.IsClientRole: Boolean;
begin
  Result := ClientID <> '';
end;

function TIAM4DRoleHelper.Equals(const AOther: TIAM4DRole): Boolean;
begin
  Result := SameText(ID, AOther.ID);
end;

function TIAM4DRoleHelper.SameAs(const AOther: TIAM4DRole): Boolean;
begin
  Result := SameText(Name, AOther.Name) and SameText(ClientID, AOther.ClientID);
end;

function TIAM4DRoleHelper.Clone: TIAM4DRole;
begin
  Result := Self;
end;

class function TIAM4DRoleHelper.CreateRealmRole(const AName: string; const ADescription: string): TIAM4DRole;
begin
  Result := Default(TIAM4DRole);
  Result.Name := AName;
  Result.Description := ADescription;
  Result.Composite := False;
  Result.ClientID := '';
  Result.ClientName := '';
end;

class function TIAM4DRoleHelper.CreateClientRole(const AName: string; const AClientID: string; const AClientName: string; const ADescription: string): TIAM4DRole;
begin
  Result := Default(TIAM4DRole);
  Result.Name := AName;
  Result.Description := ADescription;
  Result.Composite := False;
  Result.ClientID := AClientID;
  Result.ClientName := AClientName;
end;

function TIAM4DRoleHelper.WithDescription(const ADescription: string): TIAM4DRole;
begin
  Result := Clone;
  Result.Description := ADescription;
end;

function TIAM4DRoleHelper.DisplayName: string;
begin
  if IsClientRole then
    Result := Format('%s (%s)', [Name, ClientName])
  else
    Result := Name;
end;

{ TIAM4DGroupHelper }

function TIAM4DGroupHelper.ToJSON: TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    if ID <> '' then
      Result.AddPair('id', ID);

    Result.AddPair('name', Name);
    Result.AddPair('path', Path);
  except
    Result.Free;
    raise;
  end;
end;

class function TIAM4DGroupHelper.FromJSON(const AJSON: TJSONObject): TIAM4DGroup;
var
  LValue: TJSONValue;
begin
  Result := Default(TIAM4DGroup);

  LValue := AJSON.GetValue('id');
  if Assigned(LValue) then
    Result.ID := LValue.Value;

  LValue := AJSON.GetValue('name');
  if Assigned(LValue) then
    Result.Name := LValue.Value;

  LValue := AJSON.GetValue('path');
  if Assigned(LValue) then
    Result.Path := LValue.Value;
end;

function TIAM4DGroupHelper.ParentPath: string;
var
  LLastSlash: Integer;
begin
  LLastSlash := Path.LastIndexOf('/');
  if LLastSlash > 0 then
    Result := Path.Substring(0, LLastSlash)
  else
    Result := '';
end;

function TIAM4DGroupHelper.Level: Integer;
var
  LIndex: Integer;
begin
  Result := 0;
  for LIndex := 1 to Length(Path) do
    if Path[LIndex] = '/' then
      Inc(Result);
end;

function TIAM4DGroupHelper.IsRootGroup: Boolean;
begin
  Result := Level = 1;
end;

function TIAM4DGroupHelper.IsSubGroupOf(const AParentPath: string): Boolean;
begin
  Result := Path.StartsWith(AParentPath + '/');
end;

function TIAM4DGroupHelper.Equals(const AOther: TIAM4DGroup): Boolean;
begin
  Result := SameText(ID, AOther.ID);
end;

function TIAM4DGroupHelper.Clone: TIAM4DGroup;
begin
  Result := Self;
end;

class function TIAM4DGroupHelper.Create(const AName: string; const APath: string): TIAM4DGroup;
begin
  Result := Default(TIAM4DGroup);
  Result.Name := AName;
  Result.Path := APath;
end;

{ TIAM4DUserArrayHelper }

function TIAM4DUserArrayHelper.TryFindByID(const AUserID: string; out AUser: TIAM4DUser): Boolean;
var
  LUser: TIAM4DUser;
begin
  Result := False;
  for LUser in Self do
    if SameText(LUser.ID, AUserID) then
    begin
      AUser := LUser;
      Exit(True);
    end;
end;

function TIAM4DUserArrayHelper.TryFindByUsername(const AUsername: string; out AUser: TIAM4DUser): Boolean;
var
  LUser: TIAM4DUser;
begin
  Result := False;
  for LUser in Self do
    if SameText(LUser.Username, AUsername) then
    begin
      AUser := LUser;
      Exit(True);
    end;
end;

function TIAM4DUserArrayHelper.TryFindByEmail(const AEmail: string; out AUser: TIAM4DUser): Boolean;
var
  LUser: TIAM4DUser;
begin
  Result := False;
  for LUser in Self do
    if SameText(LUser.Email, AEmail) then
    begin
      AUser := LUser;
      Exit(True);
    end;
end;

function TIAM4DUserArrayHelper.FilterByEnabled(const AEnabled: Boolean): TArray<TIAM4DUser>;
var
  LList: TList<TIAM4DUser>;
  LUser: TIAM4DUser;
begin
  LList := TList<TIAM4DUser>.Create;
  try
    for LUser in Self do
      if LUser.Enabled = AEnabled then
        LList.Add(LUser);

    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TIAM4DUserArrayHelper.FilterByAttribute(const AAttributeName: string): TArray<TIAM4DUser>;
var
  LList: TList<TIAM4DUser>;
  LUser: TIAM4DUser;
begin
  LList := TList<TIAM4DUser>.Create;
  try
    for LUser in Self do
      if LUser.HasAttribute(AAttributeName) then
        LList.Add(LUser);

    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TIAM4DUserArrayHelper.FilterByRequiredAction(const AAction: TIAM4DRequiredAction): TArray<TIAM4DUser>;
var
  LList: TList<TIAM4DUser>;
  LUser: TIAM4DUser;
begin
  LList := TList<TIAM4DUser>.Create;
  try
    for LUser in Self do
      if LUser.HasRequiredAction(AAction) then
        LList.Add(LUser);

    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TIAM4DUserArrayHelper.Count: Integer;
begin
  Result := Length(Self);
end;

{ TIAM4DRoleArrayHelper }

function TIAM4DRoleArrayHelper.TryFindByName(const ARoleName: string; out ARole: TIAM4DRole): Boolean;
var
  LRole: TIAM4DRole;
begin
  Result := False;
  for LRole in Self do
    if SameText(LRole.Name, ARoleName) then
    begin
      ARole := LRole;
      Exit(True);
    end;
end;

function TIAM4DRoleArrayHelper.FilterByRealmRole: TArray<TIAM4DRole>;
var
  LList: TList<TIAM4DRole>;
  LRole: TIAM4DRole;
begin
  LList := TList<TIAM4DRole>.Create;
  try
    for LRole in Self do
      if LRole.IsRealmRole then
        LList.Add(LRole);

    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TIAM4DRoleArrayHelper.FilterByClientRole: TArray<TIAM4DRole>;
var
  LList: TList<TIAM4DRole>;
  LRole: TIAM4DRole;
begin
  LList := TList<TIAM4DRole>.Create;
  try
    for LRole in Self do
      if LRole.IsClientRole then
        LList.Add(LRole);

    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TIAM4DRoleArrayHelper.FilterByClientID(
  const AClientID: string
  ): TArray<TIAM4DRole>;
var
  LList: TList<TIAM4DRole>;
  LRole: TIAM4DRole;
begin
  LList := TList<TIAM4DRole>.Create;
  try
    for LRole in Self do
      if SameText(LRole.ClientID, AClientID) then
        LList.Add(LRole);

    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TIAM4DRoleArrayHelper.Contains(const ARoleName: string): Boolean;
var
  LDummy: TIAM4DRole;
begin
  Result := TryFindByName(ARoleName, LDummy);
end;

function TIAM4DRoleArrayHelper.Count: Integer;
begin
  Result := Length(Self);
end;

{ TIAM4DFederatedIdentityHelper }

function TIAM4DFederatedIdentityHelper.ToJSON: TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('identityProvider', IdentityProvider);
    Result.AddPair('userId', UserID);
    Result.AddPair('userName', UserName);
  except
    Result.Free;
    raise;
  end;
end;

class function TIAM4DFederatedIdentityHelper.FromJSON(const AJSON: TJSONObject): TIAM4DFederatedIdentity;
var
  LValue: TJSONValue;
begin
  Result := Default(TIAM4DFederatedIdentity);

  LValue := AJSON.GetValue('identityProvider');
  if Assigned(LValue) then
    Result.IdentityProvider := LValue.Value;

  LValue := AJSON.GetValue('userId');
  if Assigned(LValue) then
    Result.UserID := LValue.Value;

  LValue := AJSON.GetValue('userName');
  if Assigned(LValue) then
    Result.UserName := LValue.Value;
end;

function TIAM4DFederatedIdentityHelper.IsValid: Boolean;
var
  LDummy: string;
begin
  Result := IsValid(LDummy);
end;

function TIAM4DFederatedIdentityHelper.IsValid(out AErrorMessage: string): Boolean;
begin
  Result := False;
  AErrorMessage := '';

  if IdentityProvider = '' then
  begin
    AErrorMessage := 'IdentityProvider is required';
    Exit;
  end;

  if UserID = '' then
  begin
    AErrorMessage := 'UserID is required';
    Exit;
  end;

  if UserName = '' then
  begin
    AErrorMessage := 'UserName is required';
    Exit;
  end;

  Result := True;
end;

class function TIAM4DFederatedIdentityHelper.Create(const AIdentityProvider: string; const AUserID: string; const AUserName: string): TIAM4DFederatedIdentity;
begin
  Result := Default(TIAM4DFederatedIdentity);
  Result.IdentityProvider := AIdentityProvider;
  Result.UserID := AUserID;
  Result.UserName := AUserName;
end;

function TIAM4DFederatedIdentityHelper.Clone: TIAM4DFederatedIdentity;
begin
  Result := Self;
end;

function TIAM4DFederatedIdentityHelper.DisplayString: string;
begin
  Result := Format('%s: %s (%s)', [IdentityProvider, UserName, UserID]);
end;

{ TIAM4DUserSessionHelper }

function TIAM4DUserSessionHelper.ToJSON: TJSONObject;
var
  LClientsArray: TJSONArray;
  LClient: string;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('id', SessionID);
    Result.AddPair('ipAddress', IPAddress);

    if UserAgent <> '' then
      Result.AddPair('userAgent', UserAgent);

    Result.AddPair('start', TJSONNumber.Create(Started));
    Result.AddPair('lastAccess', TJSONNumber.Create(LastAccess));

    if Length(Clients) > 0 then
    begin
      LClientsArray := TJSONArray.Create;
      try
        for LClient in Clients do
          LClientsArray.Add(LClient);
        Result.AddPair('clients', LClientsArray);
      except
        LClientsArray.Free;
        raise;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class function TIAM4DUserSessionHelper.FromJSON(const AJSON: TJSONObject): TIAM4DUserSession;
var
  LValue: TJSONValue;
  LClientsArray: TJSONArray;
  LIndex: Integer;
  LClients: TArray<string>;
begin
  Result := Default(TIAM4DUserSession);

  LValue := AJSON.GetValue('id');
  if Assigned(LValue) then
    Result.SessionID := LValue.Value;

  LValue := AJSON.GetValue('ipAddress');
  if Assigned(LValue) then
    Result.IPAddress := LValue.Value;

  LValue := AJSON.GetValue('userAgent');
  if Assigned(LValue) and not (LValue is TJSONNull) then
    Result.UserAgent := LValue.Value;

  LValue := AJSON.GetValue('start');
  if Assigned(LValue) and (LValue is TJSONNumber) then
    Result.Started := TJSONNumber(LValue).AsInt64;

  LValue := AJSON.GetValue('lastAccess');
  if Assigned(LValue) and (LValue is TJSONNumber) then
    Result.LastAccess := TJSONNumber(LValue).AsInt64;

  LValue := AJSON.GetValue('clients');
  if Assigned(LValue) and (LValue is TJSONArray) then
  begin
    LClientsArray := TJSONArray(LValue);
    SetLength(LClients, LClientsArray.Count);
    for LIndex := 0 to LClientsArray.Count - 1 do
      LClients[LIndex] := LClientsArray.Items[LIndex].Value;
    Result.Clients := LClients;
  end;
end;

function TIAM4DUserSessionHelper.DurationInSeconds: Int64;
begin
  Result := (LastAccess - Started) div 1000;
end;

function TIAM4DUserSessionHelper.IdleTimeInSeconds: Int64;
var
  LNow: Int64;
begin
  LNow := DateTimeToUnix(Now, False) * 1000;
  Result := (LNow - LastAccess) div 1000;
end;

function TIAM4DUserSessionHelper.StartedDateTime: TDateTime;
begin
  Result := UnixToDateTime(Started div 1000, False);
end;

function TIAM4DUserSessionHelper.LastAccessDateTime: TDateTime;
begin
  Result := UnixToDateTime(LastAccess div 1000, False);
end;

function TIAM4DUserSessionHelper.HasAccessedClient(const AClientID: string): Boolean;
var
  LClient: string;
begin
  Result := False;
  for LClient in Clients do
    if SameText(LClient, AClientID) then
      Exit(True);
end;

function TIAM4DUserSessionHelper.ClientCount: Integer;
begin
  Result := Length(Clients);
end;

function TIAM4DUserSessionHelper.IsActive(const AIdleThresholdSeconds: Int64): Boolean;
begin
  Result := IdleTimeInSeconds < AIdleThresholdSeconds;
end;

function TIAM4DUserSessionHelper.Clone: TIAM4DUserSession;
begin
  Result := Self;
  if Length(Clients) > 0 then
    Result.Clients := Copy(Clients);
end;

function TIAM4DUserSessionHelper.DisplayString: string;
var
  LDurationMinutes: Int64;
begin
  LDurationMinutes := DurationInSeconds div 60;
  Result := Format('IP: %s, Duration: %d minutes, Clients: %d',
    [IPAddress, LDurationMinutes, ClientCount]);
end;

{ TIAM4DPasswordResetHelper }

function TIAM4DPasswordResetHelper.IsValid: Boolean;
var
  LDummy: string;
begin
  Result := IsValid(LDummy);
end;

function TIAM4DPasswordResetHelper.IsValid(out AErrorMessage: string): Boolean;
begin
  Result := False;
  AErrorMessage := '';

  if UserID = '' then
  begin
    AErrorMessage := 'UserID is required';
    Exit;
  end;

  if Password = '' then
  begin
    AErrorMessage := 'Password is required';
    Exit;
  end;

  if not HasValidPasswordLength then
  begin
    AErrorMessage := Format('Password must be between %d and %d characters',
      [IAM4D_MIN_PASSWORD_LENGTH, IAM4D_MAX_PASSWORD_LENGTH]);
    Exit;
  end;

  Result := True;
end;

function TIAM4DPasswordResetHelper.HasValidPasswordLength: Boolean;
begin
  Result := (Length(Password) >= IAM4D_MIN_PASSWORD_LENGTH) and
    (Length(Password) <= IAM4D_MAX_PASSWORD_LENGTH);
end;

function TIAM4DPasswordResetHelper.Clone: TIAM4DPasswordReset;
begin
  Result := Self;
end;

function TIAM4DPasswordResetHelper.WithTemporary(const ATemporary: Boolean): TIAM4DPasswordReset;
begin
  Result := Clone;
  Result.Temporary := ATemporary;
end;

{ TIAM4DOperationResultHelper }

class function TIAM4DOperationResultHelper.CreateSuccess(const AIdentifier: string): TIAM4DOperationResult;
begin
  Result := TIAM4DOperationResult.Create(AIdentifier, True, '');
end;

class function TIAM4DOperationResultHelper.CreateFailure(const AIdentifier: string; const AErrorMessage: string): TIAM4DOperationResult;
begin
  Result := TIAM4DOperationResult.Create(AIdentifier, False, AErrorMessage);
end;

function TIAM4DOperationResultHelper.DisplayString: string;
begin
  if Success then
    Result := Format('[SUCCESS] %s', [Identifier])
  else
    Result := Format('[FAILURE] %s: %s', [Identifier, ErrorMessage]);
end;

{ TIAM4DOperationResultArrayHelper }

function TIAM4DOperationResultArrayHelper.SuccessCount: Integer;
var
  LResult: TIAM4DOperationResult;
begin
  Result := 0;
  for LResult in Self do
    if LResult.Success then
      Inc(Result);
end;

function TIAM4DOperationResultArrayHelper.FailureCount: Integer;
var
  LResult: TIAM4DOperationResult;
begin
  Result := 0;
  for LResult in Self do
    if not LResult.Success then
      Inc(Result);
end;

function TIAM4DOperationResultArrayHelper.AllSucceeded: Boolean;
begin
  Result := FailureCount = 0;
end;

function TIAM4DOperationResultArrayHelper.AllFailed: Boolean;
begin
  Result := SuccessCount = 0;
end;

function TIAM4DOperationResultArrayHelper.GetFailures: TArray<TIAM4DOperationResult>;
var
  LList: TList<TIAM4DOperationResult>;
  LItem: TIAM4DOperationResult;
begin
  LList := TList<TIAM4DOperationResult>.Create;
  try
    for LItem in Self do
      if not LItem.Success then
        LList.Add(LItem);

    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TIAM4DOperationResultArrayHelper.GetSuccesses: TArray<TIAM4DOperationResult>;
var
  LList: TList<TIAM4DOperationResult>;
  LItem: TIAM4DOperationResult;
begin
  LList := TList<TIAM4DOperationResult>.Create;
  try
    for LItem in Self do
      if LItem.Success then
        LList.Add(LItem);

    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TIAM4DOperationResultArrayHelper.SummaryString: string;
var
  LTotal, LSuccess, LFailure: Integer;
begin
  LTotal := Length(Self);
  LSuccess := SuccessCount;
  LFailure := FailureCount;

  Result := Format('%d succeeded, %d failed out of %d total',
    [LSuccess, LFailure, LTotal]);
end;

{ TIAM4DRoleLookupCache }

constructor TIAM4DRoleLookupCache.Create(const ARoles: TArray<TIAM4DRole>);
var
  LRole: TIAM4DRole;
begin
  inherited Create;

  FRolesByName := TDictionary<string, TIAM4DRole>.Create(
    TIStringComparer.Ordinal);
  FRolesByID := TDictionary<string, TIAM4DRole>.Create(
    TIStringComparer.Ordinal);

  for LRole in ARoles do
  begin
    if not FRolesByName.ContainsKey(LRole.Name) then
      FRolesByName.Add(LRole.Name, LRole);

    if not FRolesByID.ContainsKey(LRole.ID) then
      FRolesByID.Add(LRole.ID, LRole);
  end;
end;

destructor TIAM4DRoleLookupCache.Destroy;
begin
  FRolesByName.Free;
  FRolesByID.Free;
  inherited;
end;

function TIAM4DRoleLookupCache.TryGetRoleByName(const ARoleName: string;
  out ARole: TIAM4DRole): Boolean;
begin
  Result := FRolesByName.TryGetValue(ARoleName, ARole);
end;

function TIAM4DRoleLookupCache.TryGetRoleByID(const ARoleID: string;
  out ARole: TIAM4DRole): Boolean;
begin
  Result := FRolesByID.TryGetValue(ARoleID, ARole);
end;

function TIAM4DRoleLookupCache.HasRole(const ARoleName: string): Boolean;
begin
  Result := FRolesByName.ContainsKey(ARoleName);
end;

{ TIAM4DJSONHelper }

class function TIAM4DJSONHelper.GetString(const AJSON: TJSONObject; const AKey: string; const ADefault: string): string;
var
  LValue: TJSONValue;
begin
  if (AJSON <> nil) and AJSON.TryGetValue<TJSONValue>(AKey, LValue) and (LValue <> nil) and not (LValue is TJSONNull) then
    Result := LValue.Value
  else
    Result := ADefault;
end;

class function TIAM4DJSONHelper.GetBool(const AJSON: TJSONObject; const AKey: string; const ADefault: Boolean): Boolean;
var
  LValue: TJSONValue;
begin
  if (AJSON <> nil) and AJSON.TryGetValue<TJSONValue>(AKey, LValue) and (LValue <> nil) and (LValue is TJSONBool) then
    Result := (LValue as TJSONBool).AsBoolean
  else
    Result := ADefault;
end;

class function TIAM4DJSONHelper.GetInt64(const AJSON: TJSONObject; const AKey: string; const ADefault: Int64): Int64;
var
  LValue: TJSONValue;
begin
  if (AJSON <> nil) and AJSON.TryGetValue<TJSONValue>(AKey, LValue) and (LValue <> nil) and not (LValue is TJSONNull) then
  begin
    if LValue is TJSONNumber then
      Result := (LValue as TJSONNumber).AsInt64
    else
      Result := StrToInt64Def(LValue.Value, ADefault);
  end
  else
    Result := ADefault;
end;

class function TIAM4DJSONHelper.GetArray(const AJSON: TJSONObject; const AKey: string): TJSONArray;
var
  LValue: TJSONValue;
begin
  if (AJSON <> nil) and AJSON.TryGetValue<TJSONValue>(AKey, LValue) and (LValue is TJSONArray) then
    Result := LValue as TJSONArray
  else
    Result := nil;
end;

class function TIAM4DJSONHelper.MapArray<T>(const AArray: TJSONArray; AMapper: TFunc<TJSONValue, T>): TArray<T>;
var
  I: Integer;
begin
  if AArray = nil then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  SetLength(Result, AArray.Count);
  for I := 0 to AArray.Count - 1 do
    Result[I] := AMapper(AArray.Items[I]);
end;

end.