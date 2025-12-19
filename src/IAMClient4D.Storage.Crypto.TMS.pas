{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Storage.Crypto.TMS.pas
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
/// TMS Cryptography Pack storage crypto provider using AES-256-GCM.
/// </summary>
/// <remarks>
/// This unit requires the IAM4D_TMS define to be enabled in IAMClient4D.Config.inc
/// and the TMS Cryptography Pack library to be installed.
/// When IAM4D_TMS is not defined, this unit compiles as an empty stub.
/// </remarks>
unit IAMClient4D.Storage.Crypto.TMS;

{$I IAMClient4D.Config.inc}

interface

{$IFDEF IAM4D_TMS}
uses
  System.SysUtils,
  IAMClient4D.Storage.Crypto.Interfaces;

type
  /// <summary>
  /// TMS Cryptography Pack storage crypto provider using AES-256-GCM.
  /// </summary>
  /// <remarks>
  /// <para>
  /// <b>Encryption scheme:</b> AES-256-GCM (Authenticated Encryption with Associated Data)
  /// </para>
  /// <para>
  /// <b>Key:</b> 256-bit (32 bytes) encryption key used directly (no derivation).
  /// </para>
  /// <para>
  /// <b>Nonce:</b> 96-bit (12 bytes) random nonce generated per encryption.
  /// NIST recommends 96-bit nonces for GCM mode.
  /// </para>
  /// <para>
  /// <b>Tag:</b> 128-bit (16 bytes) authentication tag.
  /// </para>
  /// <para>
  /// <b>Frame format:</b> [Nonce 12 bytes][Ciphertext][Tag 16 bytes]
  /// </para>
  /// <para>
  /// <b>Thread-safety:</b> Not thread-safe. Create one instance per storage.
  /// </para>
  /// <para>
  /// <b>Security:</b> GCM provides authenticated encryption - tag verification is
  /// performed internally by the TMS library. Securely wipes key material on destruction.
  /// </para>
  /// </remarks>
  TIAM4DTMSStorageCryptoProvider = class(TInterfacedObject, IIAM4DStorageCryptoProvider)
  private const
    GCM_NONCE_SIZE = 12;  // 96-bit nonce (NIST recommended)
    GCM_TAG_SIZE = 16;    // 128-bit tag
    GCM_TAG_BITS = 128;   // Tag size in bits for TMS API
    MIN_CIPHERTEXT_SIZE = GCM_NONCE_SIZE + GCM_TAG_SIZE;  // Minimum: nonce + tag
  private
    FKey: TBytes;

    procedure SecureWipe(var AData: TBytes);
  public
    /// <summary>
    /// Creates TMS storage crypto provider with 32-byte encryption key.
    /// </summary>
    /// <param name="AKey32">32-byte encryption key</param>
    /// <exception cref="EArgumentException">If key is not exactly 32 bytes</exception>
    constructor Create(const AKey32: TBytes);

    /// <summary>
    /// Destroys provider and securely wipes key material.
    /// </summary>
    destructor Destroy; override;

    { IIAM4DStorageCryptoProvider }

    /// <summary>
    /// Encrypts plaintext using AES-256-GCM with random nonce.
    /// </summary>
    function Encrypt(const APlaintext, AAAD: TBytes): TBytes;

    /// <summary>
    /// Decrypts and authenticates ciphertext using AES-256-GCM.
    /// </summary>
    /// <exception cref="EIAM4DStorageDecryptionException">If authentication fails</exception>
    function Decrypt(const ACiphertext, AAAD: TBytes): TBytes;

    /// <summary>
    /// Returns 'TMS Cryptography Pack'.
    /// </summary>
    function GetProviderName: string;

    /// <summary>
    /// Returns 'AES-256-GCM'.
    /// </summary>
    function GetAlgorithm: string;
  end;
{$ENDIF}

implementation

{$IFDEF IAM4D_TMS}
uses
  AESModes,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Common.CryptoUtils;

{ TIAM4DTMSStorageCryptoProvider }

constructor TIAM4DTMSStorageCryptoProvider.Create(const AKey32: TBytes);
begin
  inherited Create;

  if Length(AKey32) <> 32 then
    raise EArgumentException.Create('Key must be exactly 32 bytes');

  FKey := Copy(AKey32);
end;

destructor TIAM4DTMSStorageCryptoProvider.Destroy;
begin
  SecureWipe(FKey);
  inherited;
end;

procedure TIAM4DTMSStorageCryptoProvider.SecureWipe(var AData: TBytes);
begin
  SecureZero(AData);
end;

function TIAM4DTMSStorageCryptoProvider.Encrypt(const APlaintext, AAAD: TBytes): TBytes;
var
  LAES: TAESModes;
  LNonce: TBytes;
  LCiphertext: TBytes;
  LTag: TBytes;
  LErr: Integer;
begin
  LAES := TAESModes.Create;
  try
    LNonce := TIAM4DCryptoUtils.GenerateSecureRandomBytes(GCM_NONCE_SIZE);

    SetLength(LCiphertext, 0);
    SetLength(LTag, GCM_TAG_SIZE);

    LErr := LAES.GCM_EncryptBinaryBuffer(
      APlaintext,
      AAAD,
      LCiphertext,
      FKey,
      LNonce,
      LTag,
      GCM_TAG_BITS);

    if LErr <> 0 then
      raise EIAM4DStorageEncryptionException.Create(GetProviderName,
        Format('GCM encryption failed with error code %d', [LErr]));

    SetLength(Result, GCM_NONCE_SIZE + Length(LCiphertext) + GCM_TAG_SIZE);
    Move(LNonce[0], Result[0], GCM_NONCE_SIZE);
    if Length(LCiphertext) > 0 then
      Move(LCiphertext[0], Result[GCM_NONCE_SIZE], Length(LCiphertext));
    Move(LTag[0], Result[GCM_NONCE_SIZE + Length(LCiphertext)], GCM_TAG_SIZE);
  finally
    LAES.Free;
  end;
end;

function TIAM4DTMSStorageCryptoProvider.Decrypt(const ACiphertext, AAAD: TBytes): TBytes;
var
  LAES: TAESModes;
  LNonce: TBytes;
  LCipher: TBytes;
  LTag: TBytes;
  LCipherLen: Integer;
  LErr: Integer;
begin
  if Length(ACiphertext) < MIN_CIPHERTEXT_SIZE then
    raise EIAM4DStorageDecryptionException.Create(GetProviderName, 'Ciphertext too short');

  LCipherLen := Length(ACiphertext) - GCM_NONCE_SIZE - GCM_TAG_SIZE;

  SetLength(LNonce, GCM_NONCE_SIZE);
  Move(ACiphertext[0], LNonce[0], GCM_NONCE_SIZE);

  SetLength(LCipher, LCipherLen);
  if LCipherLen > 0 then
    Move(ACiphertext[GCM_NONCE_SIZE], LCipher[0], LCipherLen);

  SetLength(LTag, GCM_TAG_SIZE);
  Move(ACiphertext[GCM_NONCE_SIZE + LCipherLen], LTag[0], GCM_TAG_SIZE);

  LAES := TAESModes.Create;
  try
    SetLength(Result, 0);

    LErr := LAES.GCM_DecryptBinaryBuffer(
      LCipher,
      AAAD,
      Result,
      FKey,
      LNonce,
      LTag,
      GCM_TAG_BITS);

    if LErr <> 0 then
      raise EIAM4DStorageDecryptionException.Create(GetProviderName,
        'Authentication failed (GCM tag mismatch)');
  finally
    LAES.Free;
  end;
end;

function TIAM4DTMSStorageCryptoProvider.GetProviderName: string;
begin
  Result := 'TMS Cryptography Pack';
end;

function TIAM4DTMSStorageCryptoProvider.GetAlgorithm: string;
begin
  Result := 'AES-256-GCM';
end;

{$ENDIF}

end.