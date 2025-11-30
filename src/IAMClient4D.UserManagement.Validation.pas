{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.UserManagement.Validation.pas
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

unit IAMClient4D.UserManagement.Validation;

interface

uses
  System.SysUtils,
  System.RegularExpressions,
  IAMClient4D.Exceptions,
  IAMClient4D.UserManagement.Constants;

type
  /// <summary>
  /// Static validation helper for user management operations.
  /// </summary>
  /// <remarks>
  /// All methods raise typed exceptions on validation failure.
  /// Use these validators consistently across all user management methods.
  /// </remarks>
  TIAM4DUserManagementValidator = class sealed
  private
    class constructor Create;
    class var FEmailRegex: TRegEx;
    class var FUsernameRegex: TRegEx;
  public
    /// <summary>
    /// Validates that UserID is not empty.
    /// </summary>
    /// <exception cref="EIAM4DInvalidConfigurationException">UserID is empty</exception>
    class procedure ValidateUserID(const AUserID: string); static; inline;

    /// <summary>
    /// Validates that Username is not empty and meets format requirements.
    /// </summary>
    /// <exception cref="EIAM4DInvalidUserDataException">Username is invalid</exception>
    class procedure ValidateUsername(const AUsername: string); static;

    /// <summary>
    /// Validates that Email is not empty and matches RFC 5322 format.
    /// </summary>
    /// <exception cref="EIAM4DInvalidUserDataException">Email is invalid</exception>
    class procedure ValidateEmail(const AEmail: string); static;

    /// <summary>
    /// Validates that Password meets minimum requirements.
    /// </summary>
    /// <exception cref="EIAM4DInvalidUserDataException">Password is invalid</exception>
    class procedure ValidatePassword(const APassword: string); static;

    /// <summary>
    /// Validates that ClientName is not empty.
    /// </summary>
    /// <exception cref="EIAM4DInvalidConfigurationException">ClientName is empty</exception>
    class procedure ValidateClientName(const AClientName: string); static; inline;

    /// <summary>
    /// Validates that ClientID is not empty.
    /// </summary>
    /// <exception cref="EIAM4DInvalidConfigurationException">ClientID is empty</exception>
    class procedure ValidateClientID(const AClientID: string); static; inline;

    /// <summary>
    /// Validates that GroupPath is not empty.
    /// </summary>
    /// <exception cref="EIAM4DInvalidConfigurationException">GroupPath is empty</exception>
    class procedure ValidateGroupPath(const AGroupPath: string); static; inline;

    /// <summary>
    /// Validates that GroupID is not empty.
    /// </summary>
    /// <exception cref="EIAM4DInvalidConfigurationException">GroupID is empty</exception>
    class procedure ValidateGroupID(const AGroupID: string); static; inline;

    /// <summary>
    /// Validates that RoleName is not empty.
    /// </summary>
    /// <exception cref="EIAM4DInvalidConfigurationException">RoleName is empty</exception>
    class procedure ValidateRoleName(const ARoleName: string); static; inline;

    /// <summary>
    /// Validates that SessionID is not empty.
    /// </summary>
    /// <exception cref="EIAM4DInvalidConfigurationException">SessionID is empty</exception>
    class procedure ValidateSessionID(const ASessionID: string); static; inline;

    /// <summary>
    /// Validates that Roles array is not empty.
    /// </summary>
    /// <exception cref="EIAM4DInvalidConfigurationException">Roles array is empty</exception>
    class procedure ValidateRolesArray(const ARolesCount: Integer); static; inline;
  end;

implementation

{ TIAM4DUserManagementValidator }

class constructor TIAM4DUserManagementValidator.Create;
begin
  FEmailRegex := TRegEx.Create(IAM4D_EMAIL_REGEX_PATTERN, [roIgnoreCase, roCompiled]);
  FUsernameRegex := TRegEx.Create(IAM4D_USERNAME_REGEX_PATTERN, [roIgnoreCase, roCompiled]);
end;

class procedure TIAM4DUserManagementValidator.ValidateUserID(const AUserID: string);
begin
  if AUserID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('UserID cannot be empty');
end;

class procedure TIAM4DUserManagementValidator.ValidateUsername(const AUsername: string);
begin
  if AUsername.IsEmpty then
    raise EIAM4DInvalidUserDataException.Create('Username cannot be empty');

  if AUsername.Length < IAM4D_MIN_USERNAME_LENGTH then
    raise EIAM4DInvalidUserDataException.Create(
      Format('Username must be at least %d characters long', [IAM4D_MIN_USERNAME_LENGTH]));

  if AUsername.Length > IAM4D_MAX_USERNAME_LENGTH then
    raise EIAM4DInvalidUserDataException.Create(
      Format('Username cannot exceed %d characters', [IAM4D_MAX_USERNAME_LENGTH]));

  if not FUsernameRegex.IsMatch(AUsername) then
    raise EIAM4DInvalidUserDataException.Create(
      'Username can only contain letters, numbers, dots, underscores and hyphens');
end;

class procedure TIAM4DUserManagementValidator.ValidateEmail(const AEmail: string);
begin
  if AEmail.IsEmpty then
    raise EIAM4DInvalidUserDataException.Create('Email cannot be empty');

  if AEmail.Length > IAM4D_MAX_EMAIL_LENGTH then
    raise EIAM4DInvalidUserDataException.Create(
      Format('Email cannot exceed %d characters', [IAM4D_MAX_EMAIL_LENGTH]));

  if not FEmailRegex.IsMatch(AEmail) then
    raise EIAM4DInvalidUserDataException.Create(
      Format('Email format is invalid: %s', [AEmail]));
end;

class procedure TIAM4DUserManagementValidator.ValidatePassword(const APassword: string);
begin
  if APassword.IsEmpty then
    raise EIAM4DInvalidUserDataException.Create('Password cannot be empty');

  if APassword.Length < IAM4D_MIN_PASSWORD_LENGTH then
    raise EIAM4DInvalidUserDataException.Create(
      Format('Password must be at least %d characters long', [IAM4D_MIN_PASSWORD_LENGTH]));

  if APassword.Length > IAM4D_MAX_PASSWORD_LENGTH then
    raise EIAM4DInvalidUserDataException.Create(
      Format('Password cannot exceed %d characters (potential DoS attack)', [IAM4D_MAX_PASSWORD_LENGTH]));
end;

class procedure TIAM4DUserManagementValidator.ValidateClientName(const AClientName: string);
begin
  if AClientName.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('ClientName cannot be empty');
end;

class procedure TIAM4DUserManagementValidator.ValidateClientID(const AClientID: string);
begin
  if AClientID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('ClientID cannot be empty');
end;

class procedure TIAM4DUserManagementValidator.ValidateGroupPath(const AGroupPath: string);
begin
  if AGroupPath.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('GroupPath cannot be empty');
end;

class procedure TIAM4DUserManagementValidator.ValidateGroupID(const AGroupID: string);
begin
  if AGroupID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('GroupID cannot be empty');
end;

class procedure TIAM4DUserManagementValidator.ValidateRoleName(const ARoleName: string);
begin
  if ARoleName.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('RoleName cannot be empty');
end;

class procedure TIAM4DUserManagementValidator.ValidateSessionID(const ASessionID: string);
begin
  if ASessionID.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('SessionID cannot be empty');
end;

class procedure TIAM4DUserManagementValidator.ValidateRolesArray(const ARolesCount: Integer);
begin
  if ARolesCount = 0 then
    raise EIAM4DInvalidConfigurationException.Create('Roles array cannot be empty');
end;

end.