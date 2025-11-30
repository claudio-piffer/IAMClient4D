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
  System.SyncObjs,
  IAMClient4D.Storage.Core,
  IAMClient4D.Core,
  IAMClient4D.Crypto.AES256_CBC_HMAC_LB,
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
  /// AES-256-CBC encrypted in-memory token storage with HMAC authentication.
  /// </summary>
  /// <remarks>
  /// Encryption: AES-256-CBC with HMAC-SHA256 for authenticated encryption.
  /// Key derivation: Splits 32-byte key into encryption and MAC keys via DeriveFromRawKey32.
  /// AAD: Additional authenticated data included in HMAC calculation.
  /// Frame format: 4-byte length prefix + encrypted JSON payload + 32-byte HMAC tag.
  /// Versioning: 2-byte header (major.minor) for future compatibility.
  /// Security: Secure wiping of sensitive data on clear/destroy (zeros + 0xFF + zeros).
  /// HMAC verification: Constant-time comparison to prevent timing attacks.
  /// Memory only: Tokens stored encrypted in memory, never written to disk.
  /// Thread-safety: Thread-safe using TLightweightMREW (multiple readers, single writer).
  /// Max size: 10 MB encrypted frame limit to prevent memory exhaustion.
  /// </remarks>
  TIAM4DAESMemoryTokenStorageRawKey32 = class(TInterfacedObject, IIAM4DTokenStorage)
  private
    FEncryptedBlob: TBytes;

    FKEnc: TBytes;
    FKMak: TBytes;
    FAAD: TBytes;
    FAES: TLB_AES256CBC;

    FHasTokens: Boolean;
    FAccessTokenExpiry: TDateTime;
    FRefreshTokenExpiry: TDateTime;
    FTokenExpiryBufferSeconds: Integer;
    FLock: TLightweightMREW;

    function TokenRecordToBytes(const ATokens: TIAM4DTokens): TBytes;
    function BytesToTokenRecord(const ABytes: TBytes): TIAM4DTokens;
    procedure SecureWipe(var A: TBytes);
    function BuildTag(const CipherWithSeed: TBytes): TBytes;

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
    /// Creates AES-encrypted memory storage with 32-byte key and AAAD.
    /// </summary>
    constructor Create(const AKey32, AAAD: TBytes; const ATokenExpiryBufferSeconds: Integer = IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS);
    /// <summary>
    /// Destroys storage and securely wipes all sensitive data.
    /// </summary>
    destructor Destroy; override;
  end;

implementation

uses
  System.Hash,
  IAMClient4D.Common.Constants,
  IAMClient4D.Exceptions;

function HMAC_SHA256(const Key, Data: TBytes): TBytes;
begin
  Result := System.Hash.THashSHA2.GetHMACAsBytes(Data, Key, System.Hash.THashSHA2.TSHA2Version.SHA256);
end;

function ConstTimeEquals(const A, B: TBytes): Boolean;
var
  LIndex: Integer;
  LDiff: Byte;
begin
  if Length(A) <> Length(B) then
    Exit(False);
  LDiff := 0;
  for LIndex := 0 to High(A) do
    LDiff := LDiff or (A[LIndex] xor B[LIndex]);
  Result := (LDiff = 0);
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

constructor TIAM4DAESMemoryTokenStorageRawKey32.Create(const AKey32, AAAD: TBytes; const ATokenExpiryBufferSeconds: Integer);
var
  LKenc, LKmac: TBytes;
begin
  inherited Create;
  if Length(AKey32) <> 32 then
    raise EIAM4DStorageException.Create('Raw key must be 32 bytes.');

  if ATokenExpiryBufferSeconds < 0 then
    raise EIAM4DStorageException.Create('Token expiry buffer cannot be negative.');

  DeriveFromRawKey32(AKey32, LKenc, LKmac);
  FKEnc := LKenc;
  FKMak := LKmac;
  FAAD := Copy(AAAD);

  FAES := TLB_AES256CBC.Create(FKEnc);

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
    SecureWipe(FKEnc);
    SecureWipe(FKMak);
    SecureWipe(FAAD);
    FreeAndNil(FAES);
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

function TIAM4DAESMemoryTokenStorageRawKey32.BuildTag(const CipherWithSeed: TBytes): TBytes;
var
  LLenAAD, LMacData: TBytes;
  LOffs: Integer;
begin
  LLenAAD := UInt64ToBigEndian8(Length(FAAD));
  SetLength(LMacData, Length(FAAD) + Length(CipherWithSeed) + 8);
  LOffs := 0;
  if Length(FAAD) > 0 then
  begin
    Move(FAAD[0], LMacData[LOffs], Length(FAAD));
    Inc(LOffs, Length(FAAD));
  end;
  if Length(CipherWithSeed) > 0 then
  begin
    Move(CipherWithSeed[0], LMacData[LOffs], Length(CipherWithSeed));
    Inc(LOffs, Length(CipherWithSeed));
  end;
  Move(LLenAAD[0], LMacData[LOffs], 8);
  Result := HMAC_SHA256(FKMak, LMacData);
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
  LPlain, LFramed, LCiph, LTag, LOutBlob: TBytes;
begin
  FLock.BeginWrite;
  try
    try
      LPlain := TokenRecordToBytes(Tokens);
      LFramed := BuildFrame(LPlain);
      LCiph := FAES.Encrypt(LFramed);
      LTag := BuildTag(LCiph);

      SetLength(LOutBlob, 2 + Length(LCiph) + 32);
      LOutBlob[0] := BLOB_FORMAT_VERSION_MAJOR;
      LOutBlob[1] := BLOB_FORMAT_VERSION_MINOR;
      if Length(LCiph) > 0 then
        Move(LCiph[0], LOutBlob[2], Length(LCiph));
      Move(LTag[0], LOutBlob[2 + Length(LCiph)], 32);

      SecureWipe(FEncryptedBlob);
      FEncryptedBlob := LOutBlob;

      FAccessTokenExpiry := Tokens.AccessTokenExpiry;
      FRefreshTokenExpiry := Tokens.RefreshTokenExpiry;
      FHasTokens := True;
    except
      on E: Exception do
      begin
        ClearTokens;
        raise EIAM4DStorageException.CreateFmt('Failed to save tokens (RawKey32): %s', [E.Message]);
      end;
    end;
  finally
    FLock.EndWrite;
  end;
end;

function TIAM4DAESMemoryTokenStorageRawKey32.LoadTokens: TIAM4DTokens;
var
  LCLen: Integer;
  LCiph, LTag, LTagCalc, LPlainFramed, LPlain: TBytes;
  LVerMajor, LVerMinor: Byte;
begin
  FLock.BeginRead;
  try
    FillChar(Result, SizeOf(Result), 0);
    if not FHasTokens then
      Exit;

    if Length(FEncryptedBlob) < 34 then
      raise EIAM4DStorageException.Create('Corrupted blob (too short).');

    LVerMajor := FEncryptedBlob[0];
    LVerMinor := FEncryptedBlob[1];

    if LVerMajor <> BLOB_FORMAT_VERSION_MAJOR then
      raise EIAM4DStorageException.CreateFmt(
        'Unsupported blob format version %d.%d (expected %d.x)',
        [LVerMajor, LVerMinor, BLOB_FORMAT_VERSION_MAJOR]);

    LCLen := Length(FEncryptedBlob) - 34;
    SetLength(LCiph, LCLen);
    if LCLen > 0 then
      Move(FEncryptedBlob[2], LCiph[0], LCLen);
    SetLength(LTag, 32);
    Move(FEncryptedBlob[2 + LCLen], LTag[0], 32);

    LTagCalc := BuildTag(LCiph);
    if not ConstTimeEquals(LTag, LTagCalc) then
    begin
      ClearTokens;
      raise EIAM4DStorageException.Create('Authentication failed (HMAC).');
    end;

    try
      LPlainFramed := FAES.Decrypt(LCiph);
      LPlain := ParseFrame(LPlainFramed);
      Result := BytesToTokenRecord(LPlain);
    except
      on E: Exception do
      begin
        ClearTokens;
        raise EIAM4DStorageException.CreateFmt('Failed to load tokens (RawKey32): %s', [E.Message]);
      end;
    end;
  finally
    FLock.EndRead;
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
begin
  FLock.BeginRead;
  try
    LBufferDays := FTokenExpiryBufferSeconds / IAM4D_SECOND_PER_DAY;
    Result := FHasTokens and (Now < (FAccessTokenExpiry - LBufferDays));
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
    Result := FHasTokens and (Now < (FRefreshTokenExpiry - LBufferDays));
  finally
    FLock.EndRead;
  end;
end;

end.