{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Storage.Crypto.TaurusTLS.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2026 Claudio Piffer
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
/// TaurusTLS (OpenSSL) storage crypto provider using AES-256-GCM.
/// </summary>
/// <remarks>
/// Compiles as an empty stub unless IAM4D_TAURUSTLS is defined.
/// </remarks>
unit IAMClient4D.Storage.Crypto.TaurusTLS;

{$I IAMClient4D.Config.inc}

{$IFDEF IAM4D_CRYPTO_TAURUSTLS}
interface

uses
  System.SysUtils,
  IAMClient4D.Storage.Crypto.Interfaces;

type
  /// <summary>
  /// OpenSSL storage crypto provider using AES-256-GCM.
  /// </summary>
  /// <remarks>
  /// <para>
  /// <b>Frame format:</b> [Nonce 12 bytes][Ciphertext][Tag 16 bytes], same as the TMS provider.
  /// </para>
  /// <para>
  /// <b>Nonce:</b> 96-bit, from OpenSSL RAND_bytes, new per encryption.
  /// </para>
  /// <para>
  /// <b>Thread-safety:</b> stateless apart from the key, safe for concurrent use.
  /// </para>
  /// </remarks>
  TIAM4DTaurusTLSStorageCryptoProvider = class(TInterfacedObject, IIAM4DStorageCryptoProvider)
  private const
    GCM_NONCE_SIZE = 12;
    GCM_TAG_SIZE = 16;
    MIN_CIPHERTEXT_SIZE = GCM_NONCE_SIZE + GCM_TAG_SIZE;
  private
    FKey: TBytes;
  public
    /// <summary>
    /// Creates the provider with a 32-byte key, loading OpenSSL if needed.
    /// </summary>
    /// <exception cref="EArgumentException">If key is not exactly 32 bytes</exception>
    /// <exception cref="EIAM4DOpenSSLException">OpenSSL not available or older than 3.0</exception>
    constructor Create(const AKey32: TBytes);

    /// <summary>
    /// Securely wipes the key.
    /// </summary>
    destructor Destroy; override;

    { IIAM4DStorageCryptoProvider }
    function Encrypt(const APlaintext, AAAD: TBytes): TBytes;
    /// <exception cref="EIAM4DStorageDecryptionException">If authentication fails</exception>
    function Decrypt(const ACiphertext, AAAD: TBytes): TBytes;
    function GetProviderName: string;
    function GetAlgorithm: string;
  end;

implementation

uses
  IdCTypes,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_rand,
  TaurusTLSHeaders_err,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Crypto.TaurusTLS.Common;

{ TIAM4DTaurusTLSStorageCryptoProvider }

constructor TIAM4DTaurusTLSStorageCryptoProvider.Create(const AKey32: TBytes);
begin
  inherited Create;

  if Length(AKey32) <> 32 then
    raise EArgumentException.Create('Key must be exactly 32 bytes');

  TIAM4DOpenSSL.EnsureLoaded;
  FKey := Copy(AKey32);
end;

destructor TIAM4DTaurusTLSStorageCryptoProvider.Destroy;
begin
  SecureZero(FKey);
  inherited;
end;

function TIAM4DTaurusTLSStorageCryptoProvider.Encrypt(const APlaintext, AAAD: TBytes): TBytes;

  procedure Check(AResult: TIdC_INT; const AStep: string);
  begin
    if AResult <> 1 then
      raise EIAM4DStorageEncryptionException.Create(GetProviderName,
        Format('%s failed: %s', [AStep, TIAM4DOpenSSL.LastErrorMessage]));
  end;

var
  LCtx: PEVP_CIPHER_CTX;
  LNonce, LCipher, LTag: TBytes;
  LLen, LFinalLen: TIdC_INT;
  LTail: array[0..GCM_TAG_SIZE - 1] of Byte;
begin
  SetLength(LNonce, GCM_NONCE_SIZE);
  Check(RAND_bytes(@LNonce[0], GCM_NONCE_SIZE), 'RAND_bytes');

  SetLength(LCipher, Length(APlaintext));
  SetLength(LTag, GCM_TAG_SIZE);
  LLen := 0;

  LCtx := EVP_CIPHER_CTX_new();
  if LCtx = nil then
    raise EIAM4DStorageEncryptionException.Create(GetProviderName, 'EVP_CIPHER_CTX_new failed');
  try
    Check(EVP_EncryptInit_ex(LCtx, EVP_aes_256_gcm(), nil, nil, nil), 'EVP_EncryptInit_ex');
    Check(EVP_CIPHER_CTX_ctrl(LCtx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, nil), 'Set IV length');
    Check(EVP_EncryptInit_ex(LCtx, nil, nil, @FKey[0], @LNonce[0]), 'EVP_EncryptInit_ex (key)');

    // AAD: nil output buffer
    if Length(AAAD) > 0 then
      Check(EVP_EncryptUpdate(LCtx, PByte(nil)^, LLen, AAAD[0], Length(AAAD)), 'EVP_EncryptUpdate (AAD)');

    LLen := 0;
    if Length(APlaintext) > 0 then
      Check(EVP_EncryptUpdate(LCtx, LCipher[0], LLen, APlaintext[0], Length(APlaintext)), 'EVP_EncryptUpdate');

    // GCM emits no final block
    LFinalLen := 0;
    Check(EVP_EncryptFinal_ex(LCtx, LTail, LFinalLen), 'EVP_EncryptFinal_ex');
    if (LLen <> Length(APlaintext)) or (LFinalLen <> 0) then
      raise EIAM4DStorageEncryptionException.Create(GetProviderName, 'Unexpected GCM output length');

    Check(EVP_CIPHER_CTX_ctrl(LCtx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, @LTag[0]), 'Get tag');

    Result := LNonce + LCipher + LTag;
  finally
    EVP_CIPHER_CTX_free(LCtx);
    ERR_clear_error();
  end;
end;

function TIAM4DTaurusTLSStorageCryptoProvider.Decrypt(const ACiphertext, AAAD: TBytes): TBytes;

  procedure Check(AResult: TIdC_INT; const AStep: string);
  begin
    if AResult <> 1 then
      raise EIAM4DStorageDecryptionException.Create(GetProviderName,
        Format('%s failed: %s', [AStep, TIAM4DOpenSSL.LastErrorMessage]));
  end;

var
  LCtx: PEVP_CIPHER_CTX;
  LNonce, LCipher, LTag: TBytes;
  LCipherLen: Integer;
  LLen, LFinalLen: TIdC_INT;
  LTail: array[0..GCM_TAG_SIZE - 1] of Byte;
  LAuthenticated: Boolean;
begin
  if Length(ACiphertext) < MIN_CIPHERTEXT_SIZE then
    raise EIAM4DStorageDecryptionException.Create(GetProviderName, 'Ciphertext too short');

  LCipherLen := Length(ACiphertext) - MIN_CIPHERTEXT_SIZE;
  LNonce := Copy(ACiphertext, 0, GCM_NONCE_SIZE);
  LCipher := Copy(ACiphertext, GCM_NONCE_SIZE, LCipherLen);
  LTag := Copy(ACiphertext, GCM_NONCE_SIZE + LCipherLen, GCM_TAG_SIZE);

  SetLength(Result, LCipherLen);
  LLen := 0;
  LAuthenticated := False;

  LCtx := EVP_CIPHER_CTX_new();
  if LCtx = nil then
    raise EIAM4DStorageDecryptionException.Create(GetProviderName, 'EVP_CIPHER_CTX_new failed');
  try
    Check(EVP_DecryptInit_ex(LCtx, EVP_aes_256_gcm(), nil, nil, nil), 'EVP_DecryptInit_ex');
    Check(EVP_CIPHER_CTX_ctrl(LCtx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, nil), 'Set IV length');
    Check(EVP_DecryptInit_ex(LCtx, nil, nil, @FKey[0], @LNonce[0]), 'EVP_DecryptInit_ex (key)');

    if Length(AAAD) > 0 then
      Check(EVP_DecryptUpdate(LCtx, PByte(nil)^, LLen, AAAD[0], Length(AAAD)), 'EVP_DecryptUpdate (AAD)');

    LLen := 0;
    if LCipherLen > 0 then
      Check(EVP_DecryptUpdate(LCtx, Result[0], LLen, LCipher[0], LCipherLen), 'EVP_DecryptUpdate');

    Check(EVP_CIPHER_CTX_ctrl(LCtx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, @LTag[0]), 'Set tag');

    // Header types ctx as PEVP_MD_CTX; the C API takes EVP_CIPHER_CTX
    LFinalLen := 0;
    LAuthenticated := (EVP_DecryptFinal_ex(PEVP_MD_CTX(LCtx), LTail, LFinalLen) > 0) and
      (LLen = LCipherLen) and (LFinalLen = 0);

    if not LAuthenticated then
      raise EIAM4DStorageDecryptionException.Create(GetProviderName,
        'Authentication failed (GCM tag mismatch)');
  finally
    EVP_CIPHER_CTX_free(LCtx);
    if not LAuthenticated then
      SecureZero(Result);
    ERR_clear_error();
  end;
end;

function TIAM4DTaurusTLSStorageCryptoProvider.GetProviderName: string;
begin
  Result := 'TaurusTLS (OpenSSL)';
end;

function TIAM4DTaurusTLSStorageCryptoProvider.GetAlgorithm: string;
begin
  Result := 'AES-256-GCM';
end;

{$ELSE}
// Unit is empty when TaurusTLS is not the active provider (mutual exclusivity)
interface
implementation
{$ENDIF}

end.
