{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Common.TokenValidator.pas
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

unit IAMClient4D.Common.TokenValidator;

interface

uses
  System.SysUtils,
  System.DateUtils,
  System.TimeSpan,
  IAMClient4D.Core;

const
  /// <summary>
  /// Default buffer time in seconds before token expiry for validation
  /// </summary>
  IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS = 10;

type
  /// <summary>
  /// Validator for OAuth2 token expiry and validity checks.
  /// </summary>
  /// <remarks>
  /// Provides time-based validation for access and refresh tokens.
  /// Buffer mechanism: Considers tokens invalid N seconds before actual expiry (default 10s).
  /// All methods are static and thread-safe.
  /// Expiry = 0 is treated as "never expires" (returns valid).
  /// </remarks>
  TIAM4DTokenValidator = class
  public
    /// <summary>
    /// Checks if access token is present and not expired
    /// </summary>
    class function IsAccessTokenValid(const ATokens: TIAM4DTokens;
      const ABufferSeconds: Integer = IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS): Boolean; static;

    /// <summary>
    /// Checks if refresh token is present and not expired
    /// </summary>
    class function IsRefreshTokenValid(const ATokens: TIAM4DTokens;
      const ABufferSeconds: Integer = IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS): Boolean; static;

    /// <summary>
    /// Checks if expiry time is valid considering buffer
    /// </summary>
    class function IsExpiryTimeValid(const AExpiryTime: TDateTime;
      const ABufferSeconds: Integer = IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS): Boolean; static;

    /// <summary>
    /// Checks if either access or refresh token is valid
    /// </summary>
    class function HasAnyValidToken(const ATokens: TIAM4DTokens;
      const ABufferSeconds: Integer = IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS): Boolean; static;

    /// <summary>
    /// Calculates seconds until expiry (negative if already expired)
    /// </summary>
    class function GetSecondsUntilExpiry(const AExpiryTime: TDateTime): Int64; static;

    /// <summary>
    /// Checks if tokens contain any token data (ignoring expiry)
    /// </summary>
    class function HasTokenData(const ATokens: TIAM4DTokens): Boolean; static;
  end;

implementation

/// <summary>
/// Returns current time in UTC.
/// </summary>
/// <remarks>
/// IMPORTANT: JWT expiry times (exp claim) are Unix timestamps in UTC.
/// All expiry comparisons must use UTC to avoid timezone-dependent behavior.
/// </remarks>
function NowUTC: TDateTime;
begin
  Result := TTimeZone.Local.ToUniversalTime(Now);
end;

{ TIAM4DTokenValidator }

class function TIAM4DTokenValidator.IsAccessTokenValid(
  const ATokens: TIAM4DTokens;
  const ABufferSeconds: Integer): Boolean;
begin
  Result := (not ATokens.AccessToken.Trim.IsEmpty) and
            IsExpiryTimeValid(ATokens.AccessTokenExpiry, ABufferSeconds);
end;

class function TIAM4DTokenValidator.IsRefreshTokenValid(
  const ATokens: TIAM4DTokens;
  const ABufferSeconds: Integer): Boolean;
begin
  Result := (not ATokens.RefreshToken.Trim.IsEmpty) and
            IsExpiryTimeValid(ATokens.RefreshTokenExpiry, ABufferSeconds);
end;

class function TIAM4DTokenValidator.IsExpiryTimeValid(
  const AExpiryTime: TDateTime;
  const ABufferSeconds: Integer): Boolean;
var
  LBufferedExpiry: TDateTime;
  LNowUTC: TDateTime;
begin
  if AExpiryTime = 0 then
    Exit(True);

  LBufferedExpiry := IncSecond(AExpiryTime, -ABufferSeconds);

  // IMPORTANT: JWT expiry times are Unix timestamps (UTC).
  // Use UTC time for comparison to avoid timezone-dependent behavior.
  LNowUTC := NowUTC;
  Result := LBufferedExpiry > LNowUTC;
end;

class function TIAM4DTokenValidator.HasAnyValidToken(
  const ATokens: TIAM4DTokens;
  const ABufferSeconds: Integer): Boolean;
begin
  Result := IsAccessTokenValid(ATokens, ABufferSeconds) or
            IsRefreshTokenValid(ATokens, ABufferSeconds);
end;

class function TIAM4DTokenValidator.GetSecondsUntilExpiry(const AExpiryTime: TDateTime): Int64;
var
  LNowUTC: TDateTime;
begin
  // Expiry = 0 means "never expires"
  if AExpiryTime = 0 then
    Exit(MaxInt);

  // IMPORTANT: Use UTC time for calculation
  LNowUTC := NowUTC;
  Result := SecondsBetween(LNowUTC, AExpiryTime);
  if LNowUTC > AExpiryTime then
    Result := -Result;
end;

class function TIAM4DTokenValidator.HasTokenData(const ATokens: TIAM4DTokens): Boolean;
begin
  Result := (not ATokens.AccessToken.Trim.IsEmpty) or
            (not ATokens.RefreshToken.Trim.IsEmpty);
end;

end.