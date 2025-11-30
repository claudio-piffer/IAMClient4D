{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Common.OAuth2URLParser.pas
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

unit IAMClient4D.Common.OAuth2URLParser;

interface

uses
  System.SysUtils,
  System.Classes,
  System.NetEncoding,
  System.Net.URLClient,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// Result of OAuth2 callback URL parsing.
  /// </summary>
  /// <remarks>
  /// Contains authorization code, state, and error information from callback.
  /// Use IsSuccess to check if authorization was successful.
  /// Use IsError to check if authorization server returned an error.
  /// </remarks>
  TIAM4DOAuth2CallbackResult = record
    Code: string;

    State: string;

    Error: string;

    ErrorDescription: string;

    /// <summary>
    /// Checks if callback contains valid authorization code
    /// </summary>
    function IsSuccess: Boolean;

    /// <summary>
    /// Checks if callback contains OAuth2 error
    /// </summary>
    function IsError: Boolean;
  end;

  /// <summary>
  /// Utility class for parsing OAuth2 callback URLs and query strings.
  /// </summary>
  /// <remarks>
  /// Handles URL decoding and extraction of OAuth2 parameters (code, state, error).
  /// All methods are static and thread-safe.
  /// Validates presence of required parameters and OAuth2 error conditions.
  /// </remarks>
  TIAM4DOAuth2URLParser = class
  public
    /// <summary>
    /// Parses URL query string into name-value pairs
    /// </summary>
    class function ParseQueryString(const AQueryString: string): TStringList; static;

    /// <summary>
    /// Parses OAuth2 callback URL and extracts all relevant parameters
    /// </summary>
    class function ParseOAuth2Callback(const ACallbackURL: string): TIAM4DOAuth2CallbackResult; static;

    /// <summary>
    /// Extracts and validates code and state from callback URL
    /// </summary>
    class procedure ExtractCodeAndState(const ACallbackURL: string; out ACode, AState: string); static;

    /// <summary>
    /// Checks if query parameters contain OAuth2 error
    /// </summary>
    class function HasOAuth2Error(const AQueryParams: TStringList): Boolean; static;

    /// <summary>
    /// Formats OAuth2 error message from query parameters
    /// </summary>
    class function GetOAuth2ErrorMessage(const AQueryParams: TStringList): string; static;
  end;

implementation

uses
  IAMClient4D.Common.Constants;

{ TIAM4DOAuth2CallbackResult }

function TIAM4DOAuth2CallbackResult.IsSuccess: Boolean;
begin
  Result := (not Code.Trim.IsEmpty) and Error.Trim.IsEmpty;
end;

function TIAM4DOAuth2CallbackResult.IsError: Boolean;
begin
  Result := not Error.Trim.IsEmpty;
end;

{ TIAM4DOAuth2URLParser }

class function TIAM4DOAuth2URLParser.ParseQueryString(const AQueryString: string): TStringList;
var
  LPairs: TArray<string>;
  LPair: string;
  LName, LValue: string;
  LPosEqual: Integer;
begin
  Result := TStringList.Create;
  Result.NameValueSeparator := '=';

  if AQueryString.Trim.IsEmpty then
    Exit;

  LPairs := AQueryString.Split(['&']);
  for LPair in LPairs do
  begin
    LPosEqual := LPair.IndexOf('=');
    if LPosEqual > 0 then
    begin
      LName := TNetEncoding.URL.Decode(LPair.Substring(0, LPosEqual));
      LValue := TNetEncoding.URL.Decode(LPair.Substring(LPosEqual + 1));
      Result.AddPair(LName, LValue);
    end
    else if LPosEqual = 0 then
    begin
      Continue;
    end
    else
    begin
      LName := TNetEncoding.URL.Decode(LPair);
      Result.AddPair(LName, '');
    end;
  end;
end;

class function TIAM4DOAuth2URLParser.ParseOAuth2Callback(const ACallbackURL: string): TIAM4DOAuth2CallbackResult;
var
  LUri: TURI;
  LParams: TStringList;
  LRawQuery: string;
begin
  Result.Code := EmptyStr;
  Result.State := EmptyStr;
  Result.Error := EmptyStr;
  Result.ErrorDescription := EmptyStr;

  try
    LUri := TURI.Create(ACallbackURL);

    LRawQuery := LUri.Query;
    if LRawQuery.StartsWith('?') then
      LRawQuery := LRawQuery.Substring(1);

    LParams := ParseQueryString(LRawQuery);
    try
      Result.Code := LParams.Values[IAM4D_OAUTH2_PARAM_CODE];
      Result.State := LParams.Values[IAM4D_OAUTH2_PARAM_STATE];
      Result.Error := LParams.Values['error'];
      Result.ErrorDescription := LParams.Values['error_description'];
    finally
      LParams.Free;
    end;
  except
    on E: Exception do
      raise EIAM4DOAuth2CallbackException.CreateFmt('Failed to parse OAuth2 callback URL: %s', [E.Message]);
  end;
end;

class procedure TIAM4DOAuth2URLParser.ExtractCodeAndState(
  const ACallbackURL: string; out ACode, AState: string);
var
  LResult: TIAM4DOAuth2CallbackResult;
begin
  ACode := EmptyStr;
  AState := EmptyStr;

  LResult := ParseOAuth2Callback(ACallbackURL);

  if LResult.IsError then
    raise EIAM4DOAuth2CallbackException.CreateFmt('OAuth2 authorization error: %s - %s', [LResult.Error, LResult.ErrorDescription]);

  ACode := LResult.Code;
  AState := LResult.State;

  if AState.Trim.IsEmpty then
    raise EIAM4DOAuth2CallbackException.Create('Missing state parameter in OAuth2 callback');

  if ACode.Trim.IsEmpty then
    raise EIAM4DOAuth2CallbackException.Create('Missing authorization code in OAuth2 callback');
end;

class function TIAM4DOAuth2URLParser.HasOAuth2Error(const AQueryParams: TStringList): Boolean;
begin
  Result := AQueryParams.Values['error'] <> EmptyStr;
end;

class function TIAM4DOAuth2URLParser.GetOAuth2ErrorMessage(const AQueryParams: TStringList): string;
var
  LError, LErrorDesc: string;
begin
  LError := AQueryParams.Values['error'];
  LErrorDesc := AQueryParams.Values['error_description'];

  if LError.IsEmpty then
    Result := 'Unknown OAuth2 error'
  else if LErrorDesc.IsEmpty then
    Result := Format('OAuth2 error: %s', [LError])
  else
    Result := Format('OAuth2 error: %s - %s', [LError, LErrorDesc]);
end;

end.