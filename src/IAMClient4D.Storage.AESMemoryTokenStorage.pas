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

/// <summary>
/// AES-encrypted in-memory token storage with pluggable crypto providers.
/// </summary>
/// <remarks>
/// Supports multiple encryption backends via IIAM4DStorageCryptoProvider:
/// - LockBox3 (default): AES-256-CBC + HMAC-SHA256
/// - TMS: AES-256-GCM (requires IAM4D_TMS define)
/// - Custom: User-provided provider implementation
/// </remarks>
unit IAMClient4D.Storage.AESMemoryTokenStorage;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
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
  /// AES-encrypted in-memory token storage with pluggable crypto providers.
  /// </summary>
  /// <remarks>
  /// <para>
  /// <b>Encryption:</b> Delegated to IIAM4DStorageCryptoProvider implementation.
  /// Default provider uses AES-256-CBC with HMAC-SHA256 (LockBox3).
  /// TMS provider uses AES-256-GCM when available.
  /// </para>
  /// <para>
  /// <b>AAD:</b> Additional authenticated data included in authentication but not encrypted.
  /// </para>
  /// <para>
  /// <b>Frame format:</b> 4-byte length prefix + encrypted JSON payload.
  /// </para>
  /// <para>
  /// <b>Versioning:</b> 2-byte header (major.minor) for future compatibility.
  /// </para>
  /// <para>
  /// <b>Security:</b> Secure wiping of sensitive data on clear/destroy.
  /// </para>
  /// <para>
  /// <b>Memory only:</b> Tokens stored encrypted in memory, never written to disk.
  /// </para>
  /// <para>
  /// <b>Thread-safety:</b> Thread-safe using TLightweightMREW (multiple readers, single writer).
  /// </para>
  /// <para>
  /// <b>Max size:</b> 10 MB encrypted frame limit to prevent memory exhaustion.
  /// </para>
  /// </remarks>
  TIAM4DAESMemoryTokenStorageRawKey32 = class(TInterfacedObject, IIAM4DTokenStorage)
  private
    FEncryptedBlob: TBytes;
    FCryptoProvider: IIAM4DStorageCryptoProvider;
    FAAD: TBytes;

    FHasTokens: Boolean;
    FAccessTokenExpiry: TDateTime;
    FRefreshTokenExpiry: TDateTime;
    FTokenExpiryBufferSeconds: Integer;
    FLock: TLightweightMREW;

    function TokenRecordToBytes(const ATokens: TIAM4DTokens): TBytes;
    function BytesToTokenRecord(const ABytes: TBytes): TIAM4DTokens;
    procedure SecureWipe(var A: TBytes);

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
    /// Creates AES-encrypted memory storage with 32-byte key using default LockBox3 provider.
    /// </summary>
    /// <param name="AKey32">32-byte master encryption key</param>
    /// <param name="AAAD">Additional authenticated data (included in auth, not encrypted)</param>
    /// <param name="ATokenExpiryBufferSeconds">Buffer time before token expiry (default: 30s)</param>
    /// <remarks>
    /// This constructor maintains backward compatibility with existing code.
    /// Uses AES-256-CBC + HMAC-SHA256 (LockBox3) for encryption.
    /// </remarks>
    constructor Create(const AKey32, AAAD: TBytes;
      const ATokenExpiryBufferSeconds: Integer = IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS); overload;

    /// <summary>
    /// Creates AES-encrypted memory storage with custom crypto provider.
    /// </summary>
    /// <param name="ACryptoProvider">Crypto provider instance (LockBox3, TMS, or custom)</param>
    /// <param name="AAAD">Additional authenticated data (included in auth, not encrypted)</param>
    /// <param name="ATokenExpiryBufferSeconds">Buffer time before token expiry (default: 30s)</param>
    /// <remarks>
    /// Use TIAM4DStorageCryptoProviderFactory.CreateProvider to create provider instances:
    /// <code>
    /// // Default LockBox3 (AES-256-CBC + HMAC-SHA256)
    /// LProvider := TIAM4DStorageCryptoProviderFactory.CreateProvider(LKey32, scpLockBox3);
    ///
    /// // TMS (AES-256-GCM) - requires IAM4D_TMS define
    /// LProvider := TIAM4DStorageCryptoProviderFactory.CreateProvider(LKey32, scpTMS);
    /// </code>
    /// </remarks>
    constructor Create(const ACryptoProvider: IIAM4DStorageCryptoProvider;
      const AAAD: TBytes;
      const ATokenExpiryBufferSeconds: Integer = IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS); overload;

    /// <summary>
    /// Destroys storage and securely wipes all sensitive data.
    /// </summary>
    destructor Destroy; override;
  end;

implementation

uses
  System.Hash,
  System.DateUtils,
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Storage.Crypto.Factory,
  IAMClient4D.Exceptions;

constructor TIAM4DAESMemoryTokenStorageRawKey32.Create(const AKey32, AAAD: TBytes;
  const ATokenExpiryBufferSeconds: Integer);
begin
  // Backward compatible constructor: create default LockBox3 provider
  Create(
    TIAM4DStorageCryptoProviderFactory.CreateProvider(AKey32, scpLockBox3),
    AAAD,
    ATokenExpiryBufferSeconds);
end;

constructor TIAM4DAESMemoryTokenStorageRawKey32.Create(
  const ACryptoProvider: IIAM4DStorageCryptoProvider;
  const AAAD: TBytes;
  const ATokenExpiryBufferSeconds: Integer);
begin
  inherited Create;

  if ACryptoProvider = nil then
    raise EIAM4DStorageException.Create('Crypto provider cannot be nil');

  if ATokenExpiryBufferSeconds < 0 then
    raise EIAM4DStorageException.Create('Token expiry buffer cannot be negative.');

  FCryptoProvider := ACryptoProvider;
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
    SecureWipe(FEncryptedBlob);
    SecureWipe(FAAD);
    FCryptoProvider := nil;
  finally
    FLock.EndWrite;
  end;

  inherited;
end;

procedure TIAM4DAESMemoryTokenStorageRawKey32.SecureWipe(var A: TBytes);
begin
  SecureZero(A);
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
  LJSONObj := TIAM4DJSONUtils.SafeParseJSONObject(LS, 'AES encrypted token storage');
  try
    Result := TIAM4DTokens.FromJSONObject(LJSONObj);
  finally
    LJSONObj.Free;
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
  LPlain, LFramed, LEncrypted, LOutBlob: TBytes;
begin
  FLock.BeginWrite;
  try
    try
      LPlain := TokenRecordToBytes(Tokens);
      LFramed := BuildFrame(LPlain);

      LEncrypted := FCryptoProvider.Encrypt(LFramed, FAAD);

      SetLength(LOutBlob, 2 + Length(LEncrypted));
      LOutBlob[0] := BLOB_FORMAT_VERSION_MAJOR;
      LOutBlob[1] := BLOB_FORMAT_VERSION_MINOR;
      if Length(LEncrypted) > 0 then
        Move(LEncrypted[0], LOutBlob[2], Length(LEncrypted));

      SecureWipe(FEncryptedBlob);
      FEncryptedBlob := LOutBlob;

      FAccessTokenExpiry := Tokens.AccessTokenExpiry;
      FRefreshTokenExpiry := Tokens.RefreshTokenExpiry;
      FHasTokens := True;
    except
      on E: Exception do
      begin
        ClearTokens;
        raise EIAM4DStorageException.CreateFmt('Failed to save tokens (%s): %s',
          [FCryptoProvider.GetProviderName, E.Message]);
      end;
    end;
  finally
    FLock.EndWrite;
  end;
end;

function TIAM4DAESMemoryTokenStorageRawKey32.LoadTokens: TIAM4DTokens;
var
  LEncrypted, LPlainFramed, LPlain: TBytes;
  LVerMajor, LVerMinor: Byte;
  LNeedsClear: Boolean;
  LExceptionMsg: string;
begin
  LNeedsClear := False;
  LExceptionMsg := '';

  FLock.BeginRead;
  try
    FillChar(Result, SizeOf(Result), 0);
    if not FHasTokens then
      Exit;

    if Length(FEncryptedBlob) < 2 then
      raise EIAM4DStorageException.Create('Corrupted blob (too short).');

    LVerMajor := FEncryptedBlob[0];
    LVerMinor := FEncryptedBlob[1];

    if LVerMajor <> BLOB_FORMAT_VERSION_MAJOR then
      raise EIAM4DStorageException.CreateFmt(
        'Unsupported blob format version %d.%d (expected %d.x)',
        [LVerMajor, LVerMinor, BLOB_FORMAT_VERSION_MAJOR]);

    SetLength(LEncrypted, Length(FEncryptedBlob) - 2);
    if Length(LEncrypted) > 0 then
      Move(FEncryptedBlob[2], LEncrypted[0], Length(LEncrypted));

    try
      LPlainFramed := FCryptoProvider.Decrypt(LEncrypted, FAAD);
      LPlain := ParseFrame(LPlainFramed);
      Result := BytesToTokenRecord(LPlain);
    except
      on E: EIAM4DStorageDecryptionException do
      begin
        LNeedsClear := True;
        LExceptionMsg := Format('Authentication failed (%s): %s',
          [FCryptoProvider.GetProviderName, E.Message]);
      end;
      on E: EIAM4DStorageCryptoException do
      begin
        LNeedsClear := True;
        LExceptionMsg := Format('Decryption failed (%s): %s',
          [FCryptoProvider.GetProviderName, E.Message]);
      end;
      on E: Exception do
      begin
        LNeedsClear := True;
        LExceptionMsg := Format('Failed to load tokens (%s): %s',
          [FCryptoProvider.GetProviderName, E.Message]);
      end;
    end;
  finally
    FLock.EndRead;
  end;

  if LNeedsClear then
  begin
    ClearTokens;
    raise EIAM4DStorageException.Create(LExceptionMsg);
  end;
end;

procedure TIAM4DAESMemoryTokenStorageRawKey32.ClearTokens;
begin
  FLock.BeginWrite;
  try
    SecureWipe(FEncryptedBlob);
    FHasTokens := False;
    FAccessTokenExpiry := 0;
    FRefreshTokenExpiry := 0;
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
  LNowUTC: TDateTime;
begin
  FLock.BeginRead;
  try
    LBufferDays := FTokenExpiryBufferSeconds / IAM4D_SECOND_PER_DAY;
    LNowUTC := TTimeZone.Local.ToUniversalTime(Now);
    Result := FHasTokens and (LNowUTC < (FAccessTokenExpiry - LBufferDays));
  finally
    FLock.EndRead;
  end;
end;

function TIAM4DAESMemoryTokenStorageRawKey32.IsRefreshTokenValid: Boolean;
var
  LBufferDays: Double;
  LNowUTC: TDateTime;
begin
  FLock.BeginRead;
  try
    LBufferDays := FTokenExpiryBufferSeconds / IAM4D_SECOND_PER_DAY;
    LNowUTC := TTimeZone.Local.ToUniversalTime(Now);
    Result := FHasTokens and (LNowUTC < (FRefreshTokenExpiry - LBufferDays));
  finally
    FLock.EndRead;
  end;
end;

end.