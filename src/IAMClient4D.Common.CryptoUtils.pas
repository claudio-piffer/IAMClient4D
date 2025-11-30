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
  IAMClient4D.Exceptions;

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

{TCryptoUtils}

uses
  CSPRNG,
  CSPRNG.Interfaces;

class function TIAM4DCryptoUtils.GenerateSecureRandomBytes(const ACount: Integer): TBytes;
begin
  SetLength(Result, ACount);
  if ACount <= 0 then
    raise EIAM4DCryptoUtilsException.Create('Count must be a value > 0');

  var LCSPRNGProvider: ICSPRNGProvider := GetCSPRNGProvider;
  Result := LCSPRNGProvider.GetBytes(ACount);
end;

end.