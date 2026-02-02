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
  CONTEXT_KEY_STD_JSON = 'JWT_STD_JSON';
  CONTEXT_KEY_KC_JSON = 'JWT_KC_JSON';
  CACHE_KEY = '__IAM4D_JWT_CLAIMS_CACHE__';
  KC_CACHE_KEY = '__IAM4D_KC_CLAIMS_CACHE__';
  CONTEXT_KEY_AUTH_STATUS = 'JWT_Auth_Status';
  AUTH_STATUS_AUTHENTICATED = 'authenticated';
  AUTH_STATUS_NOT_AUTHENTICATED = 'not_authenticated';

type
  /// <summary>
  /// Case-insensitive string comparer for role/claim deduplication.
  /// Preserves original casing of first inserted value in TDictionary.
  /// </summary>
  /// <remarks>
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
/// Thread-safe: instance is immutable and stateless.
/// </summary>
function CaseInsensitiveComparer: IEqualityComparer<string>;

implementation

uses
  System.SysUtils,
  System.Hash;

var
  _CaseInsensitiveComparer: IEqualityComparer<string>;

function CaseInsensitiveComparer: IEqualityComparer<string>;
begin
  if not Assigned(_CaseInsensitiveComparer) then
    _CaseInsensitiveComparer := TCaseInsensitiveStringComparer.Create;
  Result := _CaseInsensitiveComparer;
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

end.