{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Crypto.AES256_CBC_HMAC_LB.pas
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

unit IAMClient4D.Crypto.AES256_CBC_HMAC_LB;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Hash,
  uTPLb_AES,
  uTPLb_CBC,
  uTPLb_BlockCipher,
  uTPLb_StreamCipher,
  uTPLb_StreamToBlock,
  IAMClient4D.Common.CryptoUtils,
  IAMClient4D.Exceptions;

/// <summary>
/// Derives encryption and MAC keys from 32-byte master key using HMAC-SHA256
/// </summary>
procedure DeriveFromRawKey32(const Key32: TBytes; out Kenc, Kmac: TBytes);

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
  /// AES-256-CBC encryption using LockBox library.
  /// </summary>
  /// <remarks>
  /// Provides AES-256 in CBC mode with random IV generation.
  /// IV seed: 16 random bytes automatically prepended to ciphertext.
  /// Thread-safety: Not thread-safe. Create separate instance per thread.
  /// Memory: Destructor securely clears key material.
  /// Library: Uses TurboPower LockBox for AES implementation.
  /// </remarks>
  TLB_AES256CBC = class
  private
    FAES: IBlockCipher;
    FCBC: IBlockChainingModel;
    FSC: IStreamCipher;
    FSel: IBlockCipherSelector;
    FKey: TSymetricKey;
  public
    /// <summary>
    /// Creates AES-256-CBC cipher with 32-byte encryption key
    /// </summary>
    constructor Create(const Kenc32: TBytes);
    destructor Destroy; override;

    /// <summary>
    /// Encrypts plaintext, returns ciphertext with IV prepended
    /// </summary>
    function Encrypt(const Plain: TBytes): TBytes;

    /// <summary>
    /// Decrypts ciphertext with IV, returns plaintext
    /// </summary>
    function Decrypt(const CipherWithSeed: TBytes): TBytes;
  end;

implementation

type
  TMinimalSelector = class(TInterfacedObject, IBlockCipherSelector, IBlockCipherSelectorEx2)
  private
    FBlock: IBlockCipher;
    FChain: IBlockChainingModel;
    FAdv: TSymetricEncryptionOptionSet;
    procedure SetIVSeed(Mem: TMemoryStream); 
  public
    constructor Create(const B: IBlockCipher; const C: IBlockChainingModel);
    function GetBlockCipher: IBlockCipher;
    function GetChainMode: IBlockChainingModel;
    function GetAdvancedOptions2: TSymetricEncryptionOptionSet;
    function hasOnSetIVHandler(var Proc: TSetMemStreamProc): boolean;
  end;

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

procedure DeriveFromRawKey32(const Key32: TBytes; out Kenc, Kmac: TBytes);
begin
  if Length(Key32) <> 32 then
    raise EAES256RawException.Create('Raw key must be 32 bytes.');
  Kenc := THashSHA2.GetHMACAsBytes(TEncoding.ASCII.GetBytes('enc'), Key32, THashSHA2.TSHA2Version.SHA256);
  Kmac := THashSHA2.GetHMACAsBytes(TEncoding.ASCII.GetBytes('mac'), Key32, THashSHA2.TSHA2Version.SHA256);
end;

constructor TMinimalSelector.Create(const B: IBlockCipher; const C: IBlockChainingModel);
begin
  inherited Create;
  FBlock := B;
  FChain := C;
  FAdv := [];
end;

function TMinimalSelector.GetAdvancedOptions2: TSymetricEncryptionOptionSet;
begin
  Result := FAdv;
end;

function TMinimalSelector.GetBlockCipher: IBlockCipher;
begin
  Result := FBlock;
end;

function TMinimalSelector.GetChainMode: IBlockChainingModel;
begin
  Result := FChain;
end;

procedure TMinimalSelector.SetIVSeed(Mem: TMemoryStream);
var
  LSeed: TBytes;
begin
  LSeed := TIAM4DCryptoUtils.GenerateSecureRandomBytes(16);
  Mem.Position := Mem.Size;
  if Length(LSeed) > 0 then
    Mem.WriteBuffer(LSeed[0], 16);
end;

function TMinimalSelector.hasOnSetIVHandler(var Proc: TSetMemStreamProc): boolean;
begin
  Proc := Self.SetIVSeed;
  Result := True;
end;

constructor TLB_AES256CBC.Create(const Kenc32: TBytes);
var
  LSeed: TBytesStream;
begin
  if Length(Kenc32) <> 32 then
    raise EAES256RawException.Create('Kenc must be 32 bytes.');
  FAES := TAES.Create(256);
  FCBC := TCBC.Create;
  FSC := TStreamToBlock_Adapter.Create;
  FSel := TMinimalSelector.Create(FAES, FCBC);
  FSC := FSC.Parameterize(FSel);

  LSeed := TBytesStream.Create(Kenc32);
  try
    FKey := FAES.GenerateKey(LSeed);
  finally
    LSeed.Free;
  end;
end;

destructor TLB_AES256CBC.Destroy;
begin
  FKey.Free;

  inherited;
end;

function TLB_AES256CBC.Encrypt(const Plain: TBytes): TBytes;
var
  LInBS, LOutBS: TBytesStream;
  LEnc: IStreamEncryptor;
begin
  LInBS := TBytesStream.Create(Plain);
  LOutBS := TBytesStream.Create;
  try
    LEnc := FSC.Start_Encrypt(FKey, LOutBS);
    LEnc.Encrypt(LInBS);
    LEnc.End_Encrypt;
    SetLength(Result, LOutBS.Size);
    if LOutBS.Size > 0 then
    begin
      LOutBS.Position := 0;
      LOutBS.ReadBuffer(Result[0], LOutBS.Size);
    end;
  finally
    LInBS.Free;
    LOutBS.Free;
  end;
end;

function TLB_AES256CBC.Decrypt(const CipherWithSeed: TBytes): TBytes;
var
  LInBS, LOutBS: TBytesStream;
  LDec: IStreamDecryptor;
begin
  LInBS := TBytesStream.Create(CipherWithSeed);
  LOutBS := TBytesStream.Create;
  try
    LDec := FSC.Start_Decrypt(FKey, LOutBS);
    LDec.Decrypt(LInBS);
    LDec.End_Decrypt;
    SetLength(Result, LOutBS.Size);
    if LOutBS.Size > 0 then
    begin
      LOutBS.Position := 0;
      LOutBS.ReadBuffer(Result[0], LOutBS.Size);
    end;
  finally
    LInBS.Free;
    LOutBS.Free;
  end;
end;

end.