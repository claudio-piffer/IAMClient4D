{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Storage.Crypto.LockBox3.pas
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

/// <summary>
/// LockBox3-based storage crypto provider using AES-256-CBC + HMAC-SHA256.
/// </summary>
/// <remarks>
/// This provider implements authenticated encryption using the Encrypt-then-MAC
/// (EtM) construction with AES-256-CBC for encryption and HMAC-SHA256 for
/// authentication.
/// </remarks>
unit IAMClient4D.Storage.Crypto.LockBox3;

interface

uses
  System.SysUtils,
  System.Hash,
  IAMClient4D.Storage.Crypto.Interfaces,
  IAMClient4D.Crypto.AES256_CBC_HMAC_LB;

type
  /// <summary>
  /// LockBox3 storage crypto provider using AES-256-CBC + HMAC-SHA256.
  /// </summary>
  /// <remarks>
  /// <para>
  /// <b>Encryption scheme:</b> Encrypt-then-MAC (EtM)
  /// </para>
  /// <para>
  /// <b>Key derivation:</b> Uses HMAC-SHA256 to derive separate encryption (Kenc)
  /// and MAC (Kmac) keys from the 32-byte master key:
  /// - Kenc = HMAC-SHA256(Key32, 'enc')
  /// - Kmac = HMAC-SHA256(Key32, 'mac')
  /// </para>
  /// <para>
  /// <b>Frame format:</b> [IV 16 bytes][Ciphertext][HMAC Tag 32 bytes]
  /// </para>
  /// <para>
  /// <b>HMAC calculation:</b> HMAC-SHA256(Kmac, AAD || CipherWithIV || Length(AAD))
  /// where Length(AAD) is encoded as 8-byte big-endian.
  /// </para>
  /// <para>
  /// <b>Thread-safety:</b> Not thread-safe. Create one instance per storage.
  /// </para>
  /// <para>
  /// <b>Security:</b> Uses constant-time comparison for HMAC verification.
  /// Securely wipes key material on destruction.
  /// </para>
  /// </remarks>
  TIAM4DLockBox3StorageCryptoProvider = class(TInterfacedObject, IIAM4DStorageCryptoProvider)
  private const
    HMAC_TAG_SIZE = 32;  // HMAC-SHA256 output size
    MIN_CIPHERTEXT_SIZE = 16 + HMAC_TAG_SIZE;  // IV (16) + Tag (32)
  private
    FKEnc: TBytes;
    FKMac: TBytes;
    FAES: TLB_AES256CBC;

    function BuildTag(const ACipherWithIV, AAAD: TBytes): TBytes;
    procedure SecureWipe(var AData: TBytes);
  public
    /// <summary>
    /// Creates LockBox3 storage crypto provider with 32-byte master key.
    /// </summary>
    /// <param name="AKey32">32-byte master key for encryption</param>
    /// <exception cref="EArgumentException">If key is not exactly 32 bytes</exception>
    constructor Create(const AKey32: TBytes);

    /// <summary>
    /// Destroys provider and securely wipes all key material.
    /// </summary>
    destructor Destroy; override;

    { IIAM4DStorageCryptoProvider }

    /// <summary>
    /// Encrypts plaintext using AES-256-CBC and appends HMAC-SHA256 tag.
    /// </summary>
    function Encrypt(const APlaintext, AAAD: TBytes): TBytes;

    /// <summary>
    /// Verifies HMAC tag and decrypts ciphertext using AES-256-CBC.
    /// </summary>
    /// <exception cref="EIAM4DStorageDecryptionException">If HMAC verification fails</exception>
    function Decrypt(const ACiphertext, AAAD: TBytes): TBytes;

    /// <summary>
    /// Returns 'LockBox3'.
    /// </summary>
    function GetProviderName: string;

    /// <summary>
    /// Returns 'AES-256-CBC-HMAC-SHA256'.
    /// </summary>
    function GetAlgorithm: string;
  end;

implementation

uses
  IAMClient4D.Common.SecureMemory;

{ TIAM4DLockBox3StorageCryptoProvider }

constructor TIAM4DLockBox3StorageCryptoProvider.Create(const AKey32: TBytes);
begin
  inherited Create;

  if Length(AKey32) <> 32 then
    raise EArgumentException.Create('Key must be exactly 32 bytes');

  DeriveFromRawKey32(AKey32, FKEnc, FKMac);

  FAES := TLB_AES256CBC.Create(FKEnc);
end;

destructor TIAM4DLockBox3StorageCryptoProvider.Destroy;
begin
  SecureWipe(FKEnc);
  SecureWipe(FKMac);

  FreeAndNil(FAES);

  inherited;
end;

procedure TIAM4DLockBox3StorageCryptoProvider.SecureWipe(var AData: TBytes);
begin
  SecureZero(AData);
end;

function TIAM4DLockBox3StorageCryptoProvider.BuildTag(const ACipherWithIV, AAAD: TBytes): TBytes;
var
  LLenAAD: TBytes;
  LMacData: TBytes;
  LOffset: Integer;
begin
  LLenAAD := UInt64ToBigEndian8(Length(AAAD));
  SetLength(LMacData, Length(AAAD) + Length(ACipherWithIV) + 8);
  LOffset := 0;

  if Length(AAAD) > 0 then
  begin
    Move(AAAD[0], LMacData[LOffset], Length(AAAD));
    Inc(LOffset, Length(AAAD));
  end;

  if Length(ACipherWithIV) > 0 then
  begin
    Move(ACipherWithIV[0], LMacData[LOffset], Length(ACipherWithIV));
    Inc(LOffset, Length(ACipherWithIV));
  end;

  Move(LLenAAD[0], LMacData[LOffset], 8);

  Result := HMAC_SHA256(FKMac, LMacData);
end;

function TIAM4DLockBox3StorageCryptoProvider.Encrypt(const APlaintext, AAAD: TBytes): TBytes;
var
  LCipherWithIV: TBytes;
  LTag: TBytes;
begin
  try
    LCipherWithIV := FAES.Encrypt(APlaintext);

    LTag := BuildTag(LCipherWithIV, AAAD);

    SetLength(Result, Length(LCipherWithIV) + HMAC_TAG_SIZE);
    if Length(LCipherWithIV) > 0 then
      Move(LCipherWithIV[0], Result[0], Length(LCipherWithIV));
    Move(LTag[0], Result[Length(LCipherWithIV)], HMAC_TAG_SIZE);
  except
    on E: Exception do
      raise EIAM4DStorageEncryptionException.Create(GetProviderName, E.Message);
  end;
end;

function TIAM4DLockBox3StorageCryptoProvider.Decrypt(const ACiphertext, AAAD: TBytes): TBytes;
var
  LCipherLen: Integer;
  LCipherWithIV: TBytes;
  LTag, LTagCalc: TBytes;
begin
  if Length(ACiphertext) < MIN_CIPHERTEXT_SIZE then
    raise EIAM4DStorageDecryptionException.Create(GetProviderName, 'Ciphertext too short');

  LCipherLen := Length(ACiphertext) - HMAC_TAG_SIZE;
  SetLength(LCipherWithIV, LCipherLen);
  Move(ACiphertext[0], LCipherWithIV[0], LCipherLen);

  SetLength(LTag, HMAC_TAG_SIZE);
  Move(ACiphertext[LCipherLen], LTag[0], HMAC_TAG_SIZE);

  LTagCalc := BuildTag(LCipherWithIV, AAAD);
  if not SecureEquals(LTag, LTagCalc) then
    raise EIAM4DStorageDecryptionException.Create(GetProviderName, 'Authentication failed (HMAC mismatch)');

  try
    Result := FAES.Decrypt(LCipherWithIV);
  except
    on E: Exception do
      raise EIAM4DStorageDecryptionException.Create(GetProviderName, 'Decryption failed: ' + E.Message);
  end;
end;

function TIAM4DLockBox3StorageCryptoProvider.GetProviderName: string;
begin
  Result := 'LockBox3';
end;

function TIAM4DLockBox3StorageCryptoProvider.GetAlgorithm: string;
begin
  Result := 'AES-256-CBC-HMAC-SHA256';
end;

end.