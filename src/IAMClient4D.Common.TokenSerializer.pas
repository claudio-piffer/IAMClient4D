{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Common.TokenSerializer.pas
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

unit IAMClient4D.Common.TokenSerializer;

interface

uses
  System.SysUtils,
  System.JSON,
  System.DateUtils,
  IAMClient4D.Core,
  IAMClient4D.Common.JSONUtils;

type
  /// <summary>
  /// Serializer for OAuth2 tokens to/from JSON and binary formats.
  /// </summary>
  /// <remarks>
  /// Handles serialization of TIAM4DTokens including expiry timestamps.
  /// Supports JSON (object/string) and binary (UTF-8 encoded) formats.
  /// All methods are static and thread-safe.
  /// Expiry calculation: Uses ISO8601 format for persistence, calculates from ExpiresIn if not present.
  /// Memory: Caller responsible for freeing returned TJSONObject instances.
  /// </remarks>
  TIAM4DTokenSerializer = class
  private
    const
      JSON_KEY_ACCESS_TOKEN_EXPIRY = 'access_token_expiry';
      JSON_KEY_REFRESH_TOKEN_EXPIRY = 'refresh_token_expiry';
  public
    /// <summary>
    /// Deserializes tokens from JSON object
    /// </summary>
    class function FromJSONObject(const AJSONObject: TJSONObject): TIAM4DTokens; static;

    /// <summary>
    /// Serializes tokens to JSON object
    /// </summary>
    class function ToJSONObject(const ATokens: TIAM4DTokens): TJSONObject; static;

    /// <summary>
    /// Serializes tokens to JSON string
    /// </summary>
    class function ToJSONString(const ATokens: TIAM4DTokens): string; static;

    /// <summary>
    /// Deserializes tokens from JSON string
    /// </summary>
    class function FromJSONString(const AJSONString: string): TIAM4DTokens; static;

    /// <summary>
    /// Serializes tokens to UTF-8 encoded byte array
    /// </summary>
    class function ToBytes(const ATokens: TIAM4DTokens): TBytes; static;

    /// <summary>
    /// Deserializes tokens from UTF-8 encoded byte array
    /// </summary>
    class function FromBytes(const ABytes: TBytes): TIAM4DTokens; static;
  end;

implementation

uses
  System.NetEncoding,
  IAMClient4D.Common.Constants;

{ TIAM4DTokenSerializer }

class function TIAM4DTokenSerializer.FromJSONObject(const AJSONObject: TJSONObject): TIAM4DTokens;
var
  LExpiryStr: string;
begin
  if not Assigned(AJSONObject) then
    raise EArgumentNilException.Create('JSON object cannot be nil');

  Result.AccessToken := AJSONObject.GetValue<string>(IAM4D_OAUTH2_TOKEN_ACCESS_TOKEN, '');
  Result.RefreshToken := AJSONObject.GetValue<string>(IAM4D_OAUTH2_TOKEN_REFRESH_TOKEN, '');
  Result.IDToken := AJSONObject.GetValue<string>(IAM4D_OAUTH2_TOKEN_ID_TOKEN, '');
  Result.ExpiresIn := AJSONObject.GetValue<Integer>(IAM4D_OAUTH2_TOKEN_EXPIRES_IN, 0);
  Result.RefreshExpiresIn := AJSONObject.GetValue<Integer>(IAM4D_OAUTH2_TOKEN_REFRESH_EXPIRES_IN, 0);

  // All expiry times are stored and compared in UTC for consistency
  if AJSONObject.TryGetValue<string>(JSON_KEY_ACCESS_TOKEN_EXPIRY, LExpiryStr) and (LExpiryStr <> EmptyStr) then
    Result.AccessTokenExpiry := ISO8601ToDate(LExpiryStr, True)
  else
    Result.AccessTokenExpiry := TTimeZone.Local.ToUniversalTime(Now) + Result.ExpiresIn / IAM4D_SECOND_PER_DAY;

  if AJSONObject.TryGetValue<string>(JSON_KEY_REFRESH_TOKEN_EXPIRY, LExpiryStr) and (LExpiryStr <> EmptyStr) then
    Result.RefreshTokenExpiry := ISO8601ToDate(LExpiryStr, True)
  else
  begin
    if Result.RefreshExpiresIn = 0 then
      Result.RefreshTokenExpiry := IncDay(TTimeZone.Local.ToUniversalTime(Now), 10)
    else
      Result.RefreshTokenExpiry := TTimeZone.Local.ToUniversalTime(Now) + Result.RefreshExpiresIn / IAM4D_SECOND_PER_DAY;
  end;
end;

class function TIAM4DTokenSerializer.ToJSONObject(const ATokens: TIAM4DTokens): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair(IAM4D_OAUTH2_TOKEN_ACCESS_TOKEN, ATokens.AccessToken);
    Result.AddPair(IAM4D_OAUTH2_TOKEN_REFRESH_TOKEN, ATokens.RefreshToken);
    Result.AddPair(IAM4D_OAUTH2_TOKEN_ID_TOKEN, ATokens.IDToken);
    Result.AddPair(IAM4D_OAUTH2_TOKEN_EXPIRES_IN, TJSONNumber.Create(ATokens.ExpiresIn));
    Result.AddPair(IAM4D_OAUTH2_TOKEN_REFRESH_EXPIRES_IN, TJSONNumber.Create(ATokens.RefreshExpiresIn));

    Result.AddPair(JSON_KEY_ACCESS_TOKEN_EXPIRY, DateToISO8601(ATokens.AccessTokenExpiry, True));
    Result.AddPair(JSON_KEY_REFRESH_TOKEN_EXPIRY, DateToISO8601(ATokens.RefreshTokenExpiry, True));
  except
    Result.Free;
    raise;
  end;
end;

class function TIAM4DTokenSerializer.ToJSONString(const ATokens: TIAM4DTokens): string;
var
  LJSONObj: TJSONObject;
begin
  LJSONObj := ToJSONObject(ATokens);
  try
    Result := LJSONObj.ToJSON;
  finally
    LJSONObj.Free;
  end;
end;

class function TIAM4DTokenSerializer.FromJSONString(const AJSONString: string): TIAM4DTokens;
var
  LJSONObj: TJSONObject;
begin
  LJSONObj := TIAM4DJSONUtils.SafeParseJSONObject(AJSONString, 'Token JSON');
  try
    Result := FromJSONObject(LJSONObj);
  finally
    LJSONObj.Free;
  end;
end;

class function TIAM4DTokenSerializer.ToBytes(const ATokens: TIAM4DTokens): TBytes;
var
  LJSONString: string;
begin
  LJSONString := ToJSONString(ATokens);
  Result := TEncoding.UTF8.GetBytes(LJSONString);
end;

class function TIAM4DTokenSerializer.FromBytes(const ABytes: TBytes): TIAM4DTokens;
var
  LJSONString: string;
begin
  LJSONString := TEncoding.UTF8.GetString(ABytes);
  Result := FromJSONString(LJSONString);
end;

end.