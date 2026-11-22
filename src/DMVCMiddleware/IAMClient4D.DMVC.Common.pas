{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.DMVC.Common.pas
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

unit IAMClient4D.DMVC.Common;

interface

uses
  System.Generics.Collections,
  System.Generics.Defaults;

const
  CONTEXT_KEY_JWT_CLAIMS = 'JWT_Claims_JSON';
  CONTEXT_KEY_JWT_TOKEN = 'JWT_Token';
  CONTEXT_KEY_STD_JSON = 'JWT_STD_JSON' deprecated 'No longer populated: use Context.JWT';
  CONTEXT_KEY_KC_JSON = 'JWT_KC_JSON' deprecated 'No longer populated: use Context.Keycloak';
  CACHE_KEY = '__IAM4D_JWT_CLAIMS_CACHE__' deprecated 'No longer used';
  KC_CACHE_KEY = '__IAM4D_KC_CLAIMS_CACHE__' deprecated 'No longer used';
  CONTEXT_KEY_AUTH_STATUS = 'JWT_Auth_Status';
  AUTH_STATUS_AUTHENTICATED = 'authenticated';
  /// <summary>No bearer token in the request.</summary>
  AUTH_STATUS_NOT_AUTHENTICATED = 'not_authenticated';
  /// <summary>Bearer token sent and rejected.</summary>
  AUTH_STATUS_INVALID_TOKEN = 'invalid_token';
  /// <summary>Bearer token sent, not validated: identity provider unavailable (503).</summary>
  AUTH_STATUS_UNAVAILABLE = 'unavailable';
  /// <summary>Realm of the WWW-Authenticate challenges (the configured Audience).</summary>
  CONTEXT_KEY_REALM = 'JWT_Realm';
  /// <summary>Seconds for the Retry-After header of a 503.</summary>
  CONTEXT_KEY_RETRY_AFTER = 'JWT_Retry_After';
  /// <summary>Authenticator that processed the request (validated once per request).</summary>
  CONTEXT_KEY_AUTHENTICATED_BY = '__IAM4D_AUTHENTICATED_BY__';

  /// <summary>Default cap of SanitizeLogText.</summary>
  IAM4D_LOG_TEXT_MAX_LENGTH = 512;

type
  /// <summary>
  /// Case-insensitive string comparer.
  /// Preserves original casing of first inserted value in TDictionary.
  /// </summary>
  /// <remarks>
  /// Not used by the library since 3.0: roles, scopes, groups and claims are case-sensitive, as in
  /// Keycloak ("Admin" and "admin" are two roles). Kept for application code.
  /// Use with TDictionary to achieve O(1) case-insensitive deduplication
  /// while preserving the original case of the first occurrence.
  /// Example:
  ///   var Dict := TDictionary&lt;string, Boolean&gt;.Create(CaseInsensitiveComparer);
  ///   Dict.Add('Admin', True);  // First occurrence
  ///   if not Dict.ContainsKey('ADMIN') then  // Returns True (case-insensitive match)
  ///     Dict.Add('ADMIN', True);  // Skipped, 'Admin' preserved
  /// </remarks>
  TCaseInsensitiveStringComparer = class(TInterfacedObject, IEqualityComparer<string>)
  public
    /// <summary>
    /// Compares two strings case-insensitively.
    /// </summary>
    function Equals(const Left, Right: string): Boolean; reintroduce;

    /// <summary>
    /// Returns hash code for case-insensitive comparison.
    /// Uses lowercase version to ensure same hash for different cases.
    /// </summary>
    function GetHashCode(const Value: string): Integer; reintroduce;
  end;

/// <summary>
/// Returns singleton instance of case-insensitive comparer.
/// Reuses same instance to avoid allocations in hot paths.
/// Thread-safe: created at unit initialization, immutable and stateless.
/// </summary>
function CaseInsensitiveComparer: IEqualityComparer<string>;

/// <summary>
/// Text safe for a single log line: control characters (CR, LF, NUL, ESC, C1, U+2028/2029)
/// escaped as \r, \n, \t, \xHH or \uHHHH, result capped at AMaxLength characters.
/// </summary>
/// <remarks>For text the client controls, e.g. the rejection reason of a token (iss, alg, kid).</remarks>
function SanitizeLogText(const AText: string; AMaxLength: Integer = IAM4D_LOG_TEXT_MAX_LENGTH): string;

/// <summary>
/// WWW-Authenticate value of the Bearer scheme (RFC 6750 3): realm, then error, error_description
/// and scope when not empty. Values are reduced to the characters RFC 6750 allows.
/// </summary>
function BearerChallenge(const ARealm, AError, ADescription: string; const AScope: string = ''): string;

implementation

uses
  System.SysUtils,
  System.Hash;

var
  _CaseInsensitiveComparer: IEqualityComparer<string>;

function CaseInsensitiveComparer: IEqualityComparer<string>;
begin
  Result := _CaseInsensitiveComparer;
end;

function SanitizeLogText(const AText: string; AMaxLength: Integer): string;
var
  LBuilder: TStringBuilder;
  LChar: Char;
  LTruncated: Boolean;
  I: Integer;
begin
  LBuilder := TStringBuilder.Create;
  try
    I := 1;
    // Escapes only as much text as the cap keeps
    while (I <= AText.Length) and (LBuilder.Length < AMaxLength) do
    begin
      LChar := AText[I];
      case LChar of
        #13: LBuilder.Append('\r');
        #10: LBuilder.Append('\n');
        #9: LBuilder.Append('\t');
        #0..#8, #11, #12, #14..#31, #127:
          LBuilder.Append('\x').Append(IntToHex(Ord(LChar), 2));
        #$0080..#$009F, #$2028, #$2029:
          LBuilder.Append('\u').Append(IntToHex(Ord(LChar), 4));
      else
        LBuilder.Append(LChar);
      end;
      Inc(I);
    end;

    LTruncated := (I <= AText.Length) or (LBuilder.Length > AMaxLength);
    if LBuilder.Length > AMaxLength then
      LBuilder.Length := AMaxLength;
    // Never end with the first half of a surrogate pair
    if LTruncated and (LBuilder.Length > 0) and
       (LBuilder.Chars[LBuilder.Length - 1] >= #$D800) and (LBuilder.Chars[LBuilder.Length - 1] <= #$DBFF) then
      LBuilder.Length := LBuilder.Length - 1;
    if LTruncated then
      LBuilder.Append(Format('... (%d characters)', [AText.Length]));
    Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

function BearerChallenge(const ARealm, AError, ADescription, AScope: string): string;

  // RFC 6750 3: %x20-21 / %x23-5B / %x5D-7E
  function Quoted(const AValue: string): string;
  var
    LChar: Char;
  begin
    Result := '';
    for LChar in AValue do
      if (LChar >= ' ') and (LChar <= '~') and (LChar <> '"') and (LChar <> '\') then
        Result := Result + LChar
      else if LChar = '"' then
        Result := Result + ''''
      else
        Result := Result + '?';
    Result := '"' + Result + '"';
  end;

var
  LParams: TArray<string>;
begin
  LParams := [];
  if ARealm <> '' then
    LParams := LParams + ['realm=' + Quoted(ARealm)];
  if AError <> '' then
    LParams := LParams + ['error=' + Quoted(AError)];
  if ADescription <> '' then
    LParams := LParams + ['error_description=' + Quoted(ADescription)];
  if AScope <> '' then
    LParams := LParams + ['scope=' + Quoted(AScope)];

  Result := 'Bearer';
  if Length(LParams) > 0 then
    Result := Result + ' ' + string.Join(', ', LParams);
end;

{ TCaseInsensitiveStringComparer }

function TCaseInsensitiveStringComparer.Equals(const Left, Right: string): Boolean;
begin
  Result := CompareText(Left, Right) = 0;
end;

function TCaseInsensitiveStringComparer.GetHashCode(const Value: string): Integer;
begin
  Result := THashBobJenkins.GetHashValue(Value.ToLower);
end;

initialization
  // Before any request thread: no lazy initialization race
  _CaseInsensitiveComparer := TCaseInsensitiveStringComparer.Create;

finalization
  _CaseInsensitiveComparer := nil;

end.