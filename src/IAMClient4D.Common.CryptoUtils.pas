{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Common.CryptoUtils.pas
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

unit IAMClient4D.Common.CryptoUtils;

interface

uses
  System.SysUtils,
  System.Hash,
  IAMClient4D.Exceptions;

/// <summary>
/// Computes HMAC-SHA256 of data with given key
/// </summary>
function HMAC_SHA256(const Key, Data: TBytes): TBytes;

/// <summary>
/// Converts UInt64 to 8-byte big-endian representation
/// </summary>
function UInt64ToBigEndian8(const V: UInt64): TBytes;

type
  /// <summary>
  /// Cryptographic utility class for secure random generation.
  /// </summary>
  /// <remarks>
  /// Uses CSPRNG (Cryptographically Secure Pseudo-Random Number Generator).
  /// Suitable for generating keys, nonces, and other security-critical random data.
  /// All methods are static and thread-safe.
  /// </remarks>
  TIAM4DCryptoUtils = class
  public
    /// <summary>
    /// Generates cryptographically secure random bytes
    /// </summary>
    class function GenerateSecureRandomBytes(const ACount: Integer): TBytes;
  end;

implementation

uses
  {$IF Defined(IOS)}
  // CSPRNG.pas does not compile for iOS (POSIX and MACOS are both defined, two GetCSPRNGProvider)
  iOSapi.Security;
  {$ELSEIF Defined(MACOS)}
  // Same problem on macOS: the Posix provider reads /dev/urandom
  CSPRNG.Provider.Posix,
  CSPRNG.Interfaces;
  {$ELSE}
  CSPRNG,
  CSPRNG.Interfaces;
  {$ENDIF}

function HMAC_SHA256(const Key, Data: TBytes): TBytes;
begin
  Result := THashSHA2.GetHMACAsBytes(Data, Key, THashSHA2.TSHA2Version.SHA256);
end;

function UInt64ToBigEndian8(const V: UInt64): TBytes;
begin
  SetLength(Result, 8);
  Result[0] := Byte(V shr 56);
  Result[1] := Byte(V shr 48);
  Result[2] := Byte(V shr 40);
  Result[3] := Byte(V shr 32);
  Result[4] := Byte(V shr 24);
  Result[5] := Byte(V shr 16);
  Result[6] := Byte(V shr 8);
  Result[7] := Byte(V);
end;

{ TIAM4DCryptoUtils }

class function TIAM4DCryptoUtils.GenerateSecureRandomBytes(const ACount: Integer): TBytes;
begin
  if ACount <= 0 then
    raise EIAM4DCryptoUtilsException.Create('Count must be a value > 0');

  {$IF Defined(IOS)}
  SetLength(Result, ACount);
  if SecRandomCopyBytes(kSecRandomDefault, ACount, @Result[0]) <> errSecSuccess then
    raise EIAM4DCryptoUtilsException.Create('Unable to generate random bytes using SecRandomCopyBytes');
  {$ELSE}
  {$IF Defined(MACOS)}
  var LCSPRNGProvider: ICSPRNGProvider := TCSPRNGProviderPosix.Create;
  {$ELSE}
  var LCSPRNGProvider: ICSPRNGProvider := GetCSPRNGProvider;
  {$ENDIF}
  SetLength(Result, ACount);
  Result := LCSPRNGProvider.GetBytes(ACount);
  {$ENDIF}
end;

end.
