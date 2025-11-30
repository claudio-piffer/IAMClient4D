{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Common.CryptoHashUtils.pas
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

unit IAMClient4D.Common.CryptoHashUtils;

interface

uses
  System.SysUtils,
  System.Hash;

type
  /// <summary>
  /// Utility class for public key hashing and cryptographic operations.
  /// </summary>
  /// <remarks>
  /// Provides SHA-256 hashing for public keys and general data.
  /// Used for certificate pinning and public key validation.
  /// All methods are static and thread-safe.
  /// Normalizes various public key formats (PEM, certificates) before hashing.
  /// </remarks>
  TIAM4DPublicKeyHashUtils = class
  public
    /// <summary>
    /// Converts byte array to uppercase hexadecimal string
    /// </summary>
    class function BytesToHex(const ABytes: TBytes): string; static;

    /// <summary>
    /// Normalizes public key format by removing PEM headers and whitespace
    /// </summary>
    class function NormalizePublicKeyFormat(const APublicKey: string): string; static;

    /// <summary>
    /// Calculates SHA-256 hash of normalized public key string
    /// </summary>
    class function CalculatePublicKeyHash(const APublicKeyString: string): string; static;

    /// <summary>
    /// Calculates SHA-256 hash of byte array
    /// </summary>
    class function CalculateSHA256Hash(const AData: TBytes): string; static;

    /// <summary>
    /// Calculates SHA-256 hash of UTF-8 encoded text
    /// </summary>
    class function CalculateSHA256HashString(const AText: string): string; static;
  end;

implementation

{ TIAM4DPublicKeyHashUtils }

class function TIAM4DPublicKeyHashUtils.BytesToHex(const ABytes: TBytes): string;
var
  LIndex: Integer;
begin
  SetLength(Result, Length(ABytes) * 2);
  for LIndex := 0 to High(ABytes) do
  begin
    Result[LIndex * 2 + 1] := IntToHex(ABytes[LIndex] shr 4, 1)[1];
    Result[LIndex * 2 + 2] := IntToHex(ABytes[LIndex] and $0F, 1)[1];
  end;
end;

class function TIAM4DPublicKeyHashUtils.NormalizePublicKeyFormat(const APublicKey: string): string;
begin
  Result := APublicKey;

  // Remove PEM headers and footers
  Result := StringReplace(Result, '-----BEGIN PUBLIC KEY-----', '', [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '-----END PUBLIC KEY-----', '', [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '-----BEGIN RSA PUBLIC KEY-----', '', [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '-----END RSA PUBLIC KEY-----', '', [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '-----BEGIN CERTIFICATE-----', '', [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '-----END CERTIFICATE-----', '', [rfReplaceAll, rfIgnoreCase]);

  // Remove all whitespace (spaces, tabs, newlines, carriage returns)
  Result := StringReplace(Result, ' ', '', [rfReplaceAll]);
  Result := StringReplace(Result, #9, '', [rfReplaceAll]);   // Tab
  Result := StringReplace(Result, #10, '', [rfReplaceAll]);  // LF
  Result := StringReplace(Result, #13, '', [rfReplaceAll]);  // CR

  Result := Result.Trim;
end;

class function TIAM4DPublicKeyHashUtils.CalculatePublicKeyHash(const APublicKeyString: string): string;
var
  LNormalizedKey: string;
  LBytes: TBytes;
  LHashBytes: TBytes;
  LHash: THashSHA2;
begin
  if APublicKeyString.Trim.IsEmpty then
    raise EArgumentException.Create('Public key string cannot be empty');

  LNormalizedKey := NormalizePublicKeyFormat(APublicKeyString);

  if LNormalizedKey.IsEmpty then
    raise EArgumentException.Create('Public key string is empty after normalization');

  LBytes := TEncoding.UTF8.GetBytes(LNormalizedKey);

  LHash := THashSHA2.Create;
  LHash.Update(LBytes, Length(LBytes));
  LHashBytes := LHash.HashAsBytes;

  Result := BytesToHex(LHashBytes);
end;

class function TIAM4DPublicKeyHashUtils.CalculateSHA256Hash(const AData: TBytes): string;
var
  LHashBytes: TBytes;
  LHash: THashSHA2;
begin
  if Length(AData) = 0 then
    raise EArgumentException.Create('Data cannot be empty');

  LHash := THashSHA2.Create;
  LHash.Update(AData, Length(AData));
  LHashBytes := LHash.HashAsBytes;

  Result := BytesToHex(LHashBytes);
end;

class function TIAM4DPublicKeyHashUtils.CalculateSHA256HashString(const AText: string): string;
var
  LBytes: TBytes;
begin
  if AText.Trim.IsEmpty then
    raise EArgumentException.Create('Text cannot be empty');

  LBytes := TEncoding.UTF8.GetBytes(AText);
  Result := CalculateSHA256Hash(LBytes);
end;

end.