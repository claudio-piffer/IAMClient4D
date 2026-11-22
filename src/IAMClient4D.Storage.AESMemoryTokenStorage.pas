{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Storage.AESMemoryTokenStorage.pas
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

unit IAMClient4D.Storage.AESMemoryTokenStorage;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.DateUtils,
  System.SyncObjs,
  IAMClient4D.Storage.Core,
  IAMClient4D.Storage.Crypto.Interfaces,
  IAMClient4D.Core,
  IAMClient4D.Common.JSONUtils;

const
  /// <summary>
  /// Maximum encrypted frame size (10 MB).
  /// </summary>
  MAX_FRAME_SIZE = 10 * 1024 * 1024;

  /// <summary>
  /// Blob format major version.
  /// </summary>
  BLOB_FORMAT_VERSION_MAJOR = 1;
  /// <summary>
  /// Blob format minor version.
  /// </summary>
  BLOB_FORMAT_VERSION_MINOR = 0;

type
  /// <summary>
  /// AES-256 encrypted in-memory token storage with authenticated encryption.
  /// </summary>
  /// <remarks>
  /// Encryption: storage crypto provider compiled in (TIAM4DStorageCryptoProviderFactory):
  /// LockBox3 AES-256-CBC + HMAC-SHA256, TMS or TaurusTLS AES-256-GCM, or a custom provider.
  /// AAD: Additional authenticated data bound to the ciphertext.
  /// Blob format: 2-byte version header (major.minor) + provider output.
  /// Plaintext: 4-byte length prefix + JSON payload.
  /// Security: Secure wiping of sensitive data on clear/destroy (zeros + 0xFF + zeros).
  /// Memory only: Tokens stored encrypted in memory, never written to disk.
  /// Thread-safety: Thread-safe using TLightweightMREW (multiple readers, single writer).
  /// Max size: 10 MB encrypted frame limit to prevent memory exhaustion.
  /// </remarks>
  TIAM4DAESMemoryTokenStorageRawKey32 = class(TInterfacedObject, IIAM4DTokenStorage)
  private
    FEncryptedBlob: TBytes;

    FAAD: TBytes;
    FCrypto: IIAM4DStorageCryptoProvider;

    FHasTokens: Boolean;
    FAccessTokenExpiry: TDateTime;
    FRefreshTokenExpiry: TDateTime;
    FTokenExpiryBufferSeconds: Integer;
    FLock: TLightweightMREW;

    function TokenRecordToBytes(const ATokens: TIAM4DTokens): TBytes;
    function BytesToTokenRecord(const ABytes: TBytes): TIAM4DTokens;
    procedure SecureWipe(var A: TBytes);
    procedure ClearTokensUnlocked;

    function BuildFrame(const Payload: TBytes): TBytes;
    function ParseFrame(const Frame: TBytes): TBytes;
  protected
    /// <summary>
    /// Encrypts and saves tokens to memory.
    /// </summary>
    procedure SaveTokens(const Tokens: TIAM4DTokens);
    /// <summary>
    /// Decrypts and loads tokens from memory.
    /// </summary>
    function LoadTokens: TIAM4DTokens;
    /// <summary>
    /// Securely wipes tokens from memory.
    /// </summary>
    procedure ClearTokens;
    /// <summary>
    /// Returns true if tokens are stored.
    /// </summary>
    function HasTokens: Boolean;
    /// <summary>
    /// Returns true if access token is valid (not expired).
    /// </summary>
    function IsAccessTokenValid: Boolean;
    /// <summary>
    /// Returns true if refresh token is valid (not expired).
    /// </summary>
    function IsRefreshTokenValid: Boolean;
  public
    /// <summary>
    /// Creates AES-encrypted memory storage with 32-byte key and AAD,
    /// using the compiled storage crypto provider.
    /// </summary>
    constructor Create(const AKey32, AAAD: TBytes; const ATokenExpiryBufferSeconds: Integer = IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS); overload;
    /// <summary>
    /// Creates encrypted memory storage with a custom storage crypto provider.
    /// </summary>
    constructor Create(const ACryptoProvider: IIAM4DStorageCryptoProvider; const AAAD: TBytes;
      const ATokenExpiryBufferSeconds: Integer = IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS); overload;
    /// <summary>
    /// Destroys storage and securely wipes all sensitive data.
    /// </summary>
    destructor Destroy; override;
  end;

implementation

uses
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Storage.Crypto.Factory,
  IAMClient4D.Exceptions;

constructor TIAM4DAESMemoryTokenStorageRawKey32.Create(const AKey32, AAAD: TBytes; const ATokenExpiryBufferSeconds: Integer);
begin
  if Length(AKey32) <> 32 then
    raise EIAM4DStorageException.Create('Raw key must be 32 bytes.');

  Create(TIAM4DStorageCryptoProviderFactory.CreateProvider(AKey32), AAAD, ATokenExpiryBufferSeconds);
end;

constructor TIAM4DAESMemoryTokenStorageRawKey32.Create(const ACryptoProvider: IIAM4DStorageCryptoProvider;
  const AAAD: TBytes; const ATokenExpiryBufferSeconds: Integer);
begin
  inherited Create;
  if not Assigned(ACryptoProvider) then
    raise EIAM4DStorageException.Create('Storage crypto provider is required.');

  if ATokenExpiryBufferSeconds < 0 then
    raise EIAM4DStorageException.Create('Token expiry buffer cannot be negative.');

  FCrypto := ACryptoProvider;
  FAAD := Copy(AAAD);

  SetLength(FEncryptedBlob, 0);
  FHasTokens := False;
  FAccessTokenExpiry := 0;
  FRefreshTokenExpiry := 0;
  FTokenExpiryBufferSeconds := ATokenExpiryBufferSeconds;
end;

destructor TIAM4DAESMemoryTokenStorageRawKey32.Destroy;
begin
  FLock.BeginWrite;
  try
    ClearTokensUnlocked;
    SecureWipe(FAAD);
    FCrypto := nil;
  finally
    FLock.EndWrite;
  end;

  inherited;
end;

procedure TIAM4DAESMemoryTokenStorageRawKey32.SecureWipe(var A: TBytes);
var
  LIndex: Integer;
  LP: PByte;
begin
  if Length(A) > 0 then
  begin
    LP := @A[0];
    for LIndex := 0 to Length(A) - 1 do
    begin
      LP^ := 0;
      Inc(LP);
    end;
    FillChar(A[0], Length(A), $FF);
    FillChar(A[0], Length(A), 0);
    SetLength(A, 0);
  end;
end;

procedure TIAM4DAESMemoryTokenStorageRawKey32.ClearTokensUnlocked;
begin
  SecureWipe(FEncryptedBlob);
  FHasTokens := False;
  FAccessTokenExpiry := 0;
  FRefreshTokenExpiry := 0;
end;

function TIAM4DAESMemoryTokenStorageRawKey32.TokenRecordToBytes(const ATokens: TIAM4DTokens): TBytes;
var
  LObj: TJSONObject;
  LS: string;
begin
  LObj := TIAM4DTokens.ToJSONObject(ATokens);
  try
    LS := LObj.ToString;
    Result := TEncoding.UTF8.GetBytes(LS);
  finally
    // The JSON text holds every token in clear: wiped (the bytes are wiped by the caller)
    SecureZeroString(LS);
    LObj.Free;
  end;
end;

function TIAM4DAESMemoryTokenStorageRawKey32.BytesToTokenRecord(const ABytes: TBytes): TIAM4DTokens;
var
  LJSONObj: TJSONObject;
  LS: string;
begin
  if Length(ABytes) = 0 then
    raise EIAM4DStorageException.Create('Cannot deserialize empty bytes.');
  LS := TEncoding.UTF8.GetString(ABytes);
  try
    LJSONObj := TIAM4DJSONUtils.SafeParseJSONObject(LS, 'AES encrypted token storage');
    try
      Result := TIAM4DTokens.FromJSONObject(LJSONObj);
    finally
      LJSONObj.Free;
    end;
  finally
    SecureZeroString(LS);
  end;
end;

function TIAM4DAESMemoryTokenStorageRawKey32.BuildFrame(const Payload: TBytes): TBytes;
var
  LLength: Integer;
begin
  LLength := Length(Payload);
  if (LLength < 0) or (LLength > MAX_FRAME_SIZE) then
    raise EIAM4DStorageException.Create('Payload size exceeds maximum frame size limit.');

  SetLength(Result, 4 + LLength);
  Result[0] := Byte((LLength shr 24) and $FF);
  Result[1] := Byte((LLength shr 16) and $FF);
  Result[2] := Byte((LLength shr 8) and $FF);
  Result[3] := Byte(LLength and $FF);
  if LLength > 0 then
    Move(Payload[0], Result[4], LLength);
end;

function TIAM4DAESMemoryTokenStorageRawKey32.ParseFrame(const Frame: TBytes): TBytes;
var
  LLength, LTotal: Integer;
begin
  LTotal := Length(Frame);
  if LTotal < 4 then
    raise EIAM4DStorageException.Create('Corrupted frame (too short).');

  LLength := (Integer(Frame[0]) shl 24) or (Integer(Frame[1]) shl 16) or
    (Integer(Frame[2]) shl 8) or Integer(Frame[3]);

  if (LLength < 0) or (LLength > MAX_FRAME_SIZE) or (4 + LLength > LTotal) then
    raise EIAM4DStorageException.Create('Corrupted frame (invalid length or size exceeds limit).');

  SetLength(Result, LLength);
  if LLength > 0 then
    Move(Frame[4], Result[0], LLength);
end;

procedure TIAM4DAESMemoryTokenStorageRawKey32.SaveTokens(const Tokens: TIAM4DTokens);
var
  LPlain, LFramed, LCiph, LOutBlob: TBytes;
begin
  FLock.BeginWrite;
  try
    try
      LPlain := TokenRecordToBytes(Tokens);
      LFramed := BuildFrame(LPlain);
      LCiph := FCrypto.Encrypt(LFramed, FAAD);

      LOutBlob := TBytes.Create(BLOB_FORMAT_VERSION_MAJOR, BLOB_FORMAT_VERSION_MINOR) + LCiph;

      SecureWipe(FEncryptedBlob);
      FEncryptedBlob := LOutBlob;

      FAccessTokenExpiry := Tokens.AccessTokenExpiry;
      FRefreshTokenExpiry := Tokens.RefreshTokenExpiry;
      FHasTokens := True;
    except
      on E: Exception do
      begin
        ClearTokensUnlocked;
        raise EIAM4DStorageException.CreateFmt('Failed to save tokens (RawKey32): %s', [E.Message]);
      end;
    end;
  finally
    SecureWipe(LPlain);
    SecureWipe(LFramed);
    FLock.EndWrite;
  end;
end;

function TIAM4DAESMemoryTokenStorageRawKey32.LoadTokens: TIAM4DTokens;
var
  LCiph, LPlainFramed, LPlain: TBytes;
  LVerMajor, LVerMinor: Byte;
begin
  // Write lock required: ClearTokensUnlocked may be called on authentication failure
  FLock.BeginWrite;
  try
    // Default, not FillChar: zeroing a record of strings would leak the ones it held
    Result := Default(TIAM4DTokens);
    if not FHasTokens then
      Exit;

    if Length(FEncryptedBlob) <= 2 then
      raise EIAM4DStorageException.Create('Corrupted blob (too short).');

    LVerMajor := FEncryptedBlob[0];
    LVerMinor := FEncryptedBlob[1];

    if LVerMajor <> BLOB_FORMAT_VERSION_MAJOR then
      raise EIAM4DStorageException.CreateFmt(
        'Unsupported blob format version %d.%d (expected %d.x)',
        [LVerMajor, LVerMinor, BLOB_FORMAT_VERSION_MAJOR]);

    LCiph := Copy(FEncryptedBlob, 2, MaxInt);

    try
      // Provider authenticates ciphertext and AAD before returning plaintext
      LPlainFramed := FCrypto.Decrypt(LCiph, FAAD);
      LPlain := ParseFrame(LPlainFramed);
      Result := BytesToTokenRecord(LPlain);
    except
      on E: Exception do
      begin
        ClearTokensUnlocked;
        raise EIAM4DStorageException.CreateFmt('Failed to load tokens (RawKey32): %s', [E.Message]);
      end;
    end;
  finally
    SecureWipe(LPlainFramed);
    SecureWipe(LPlain);
    FLock.EndWrite;
  end;
end;

procedure TIAM4DAESMemoryTokenStorageRawKey32.ClearTokens;
begin
  FLock.BeginWrite;
  try
    ClearTokensUnlocked;
  finally
    FLock.EndWrite;
  end;
end;

function TIAM4DAESMemoryTokenStorageRawKey32.HasTokens: Boolean;
begin
  FLock.BeginRead;
  try
    Result := FHasTokens;
  finally
    FLock.EndRead;
  end;
end;

function TIAM4DAESMemoryTokenStorageRawKey32.IsAccessTokenValid: Boolean;
var
  LBufferDays: Double;
begin
  FLock.BeginRead;
  try
    LBufferDays := FTokenExpiryBufferSeconds / IAM4D_SECOND_PER_DAY;
    Result := FHasTokens and (TDateTime.NowUTC < (FAccessTokenExpiry - LBufferDays));
  finally
    FLock.EndRead;
  end;
end;

function TIAM4DAESMemoryTokenStorageRawKey32.IsRefreshTokenValid: Boolean;
var
  LBufferDays: Double;
begin
  FLock.BeginRead;
  try
    LBufferDays := FTokenExpiryBufferSeconds / IAM4D_SECOND_PER_DAY;
    Result := FHasTokens and (TDateTime.NowUTC < (FRefreshTokenExpiry - LBufferDays));
  finally
    FLock.EndRead;
  end;
end;

end.
