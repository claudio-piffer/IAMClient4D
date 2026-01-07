{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.Crypto.LockBox3.pas
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

{$I IAMClient4D.Config.inc}

unit IAMClient4D.Security.Crypto.LockBox3;

{$IFDEF IAM4D_CRYPTO_LOCKBOX3}
interface

uses
  System.SysUtils,
  System.Classes,
  System.Hash,
  IAMClient4D.Security.Crypto.Interfaces,
  IAMClient4D.Common.SecureMemory,
  uTPLb_HugeCardinal,
  uTPLb_MemoryStreamPool;

type
  /// <summary>
  /// Cryptographic provider implementation using TurboPower LockBox3.
  /// </summary>
  /// <remarks>
  /// Supports RSA PKCS#1 v1.5 (RS256, RS384, RS512) and RSA-PSS (PS256, PS384, PS512).
  /// ECDSA is NOT supported by this provider - use TMS provider for ECDSA.
  /// Thread-safety: Create separate instance per thread (not thread-safe).
  /// Memory: Uses memory pool for efficient stream management.
  /// </remarks>
  TIAM4DLockBox3CryptoProvider = class(TInterfacedObject, IIAM4DCryptoProvider)
  private
    FMemoryPool: IMemoryStreamPool;

    function GetHashLength(AHashAlg: TIAM4DHashAlgorithm): Integer;
    function ComputeHash(const AData: TBytes; AHashAlg: TIAM4DHashAlgorithm): TBytes;

    /// <summary>
    /// MGF1 Mask Generation Function (RFC 3447 Appendix B.2.1)
    /// </summary>
    function MGF1(const ASeed: TBytes; AMaskLen: Integer; AHashAlg: TIAM4DHashAlgorithm): TBytes;

    /// <summary>
    /// EMSA-PSS verification (RFC 3447 Section 9.1.2)
    /// </summary>
    function EMSA_PSS_Verify(const AMessage, AEM: TBytes; AEmBits: Integer;
      AHashAlg: TIAM4DHashAlgorithm; ASaltLen: Integer): Boolean;
  public
    constructor Create;
    destructor Destroy; override;

    { IIAM4DCryptoProvider }
    function ECDSAVerify(const AHash, AR, AS_, AX, AY: TBytes;
      ACurve: TIAM4DECCurve): Boolean;
    function RSAVerifyPKCS1(const AExpectedEM, ASignature, AModulus, AExponent: TBytes): Boolean;
    function RSAVerifyPSS(const AMessage, ASignature, AModulus, AExponent: TBytes;
      AHashAlg: TIAM4DHashAlgorithm; ASaltLen: Integer): Boolean;
    function GetSupportedAlgorithms: TArray<string>;
    function SupportsAlgorithm(const AAlg: string): Boolean;
    function GetProviderName: string;
  end;

implementation

uses
  uTPLb_RSA_Primitives;

{ TIAM4DLockBox3CryptoProvider }

constructor TIAM4DLockBox3CryptoProvider.Create;
begin
  inherited Create;
  FMemoryPool := NewPool;
end;

destructor TIAM4DLockBox3CryptoProvider.Destroy;
begin
  FMemoryPool := nil;
  inherited;
end;

function TIAM4DLockBox3CryptoProvider.GetProviderName: string;
begin
  Result := 'LockBox3';
end;

function TIAM4DLockBox3CryptoProvider.GetSupportedAlgorithms: TArray<string>;
begin
  Result := TArray<string>.Create('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512');
end;

function TIAM4DLockBox3CryptoProvider.SupportsAlgorithm(const AAlg: string): Boolean;
begin
  Result := SameText(AAlg, 'RS256') or SameText(AAlg, 'RS384') or SameText(AAlg, 'RS512') or
            SameText(AAlg, 'PS256') or SameText(AAlg, 'PS384') or SameText(AAlg, 'PS512');
end;

function TIAM4DLockBox3CryptoProvider.GetHashLength(AHashAlg: TIAM4DHashAlgorithm): Integer;
begin
  case AHashAlg of
    haSHA256: Result := 32;
    haSHA384: Result := 48;
    haSHA512: Result := 64;
  else
    Result := 32;
  end;
end;

function TIAM4DLockBox3CryptoProvider.ComputeHash(const AData: TBytes;
  AHashAlg: TIAM4DHashAlgorithm): TBytes;
var
  LHashSHA2: THashSHA2;
begin
  case AHashAlg of
    haSHA256:
    begin
      LHashSHA2 := THashSHA2.Create(THashSHA2.TSHA2Version.SHA256);
      LHashSHA2.Update(AData[0], Length(AData));
      Result := LHashSHA2.HashAsBytes;
    end;
    haSHA384:
    begin
      LHashSHA2 := THashSHA2.Create(THashSHA2.TSHA2Version.SHA384);
      LHashSHA2.Update(AData[0], Length(AData));
      Result := LHashSHA2.HashAsBytes;
    end;
    haSHA512:
    begin
      LHashSHA2 := THashSHA2.Create(THashSHA2.TSHA2Version.SHA512);
      LHashSHA2.Update(AData[0], Length(AData));
      Result := LHashSHA2.HashAsBytes;
    end;
  else
    SetLength(Result, 0);
  end;
end;

function TIAM4DLockBox3CryptoProvider.ECDSAVerify(const AHash, AR, AS_, AX, AY: TBytes;
  ACurve: TIAM4DECCurve): Boolean;
begin
  raise EIAM4DCryptoNotSupportedException.Create('ECDSA', GetProviderName);
end;

function TIAM4DLockBox3CryptoProvider.RSAVerifyPKCS1(const AExpectedEM, ASignature,
  AModulus, AExponent: TBytes): Boolean;
var
  LModulusHC, LExponentHC: THugeCardinal;
  LSignatureHC: THugeCardinal;
  LMessageHC: THugeCardinal;
  LModulusStream, LExponentStream, LSignatureStream, LMessageStream: TMemoryStream;
  LActualEM: TBytes;
  LModulusLen: Integer;
begin
  Result := False;
  LModulusHC := nil;
  LExponentHC := nil;
  LSignatureHC := nil;
  LMessageHC := nil;

  try
    LModulusStream := TMemoryStream.Create;
    try
      LModulusStream.Write(AModulus[0], Length(AModulus));
      LModulusStream.Position := 0;
      if not OS2IP(LModulusStream, Length(AModulus), LModulusHC, FMemoryPool, Length(AModulus) * 8 + 32) then
        Exit;
    finally
      LModulusStream.Free;
    end;

    LExponentStream := TMemoryStream.Create;
    try
      LExponentStream.Write(AExponent[0], Length(AExponent));
      LExponentStream.Position := 0;
      if not OS2IP(LExponentStream, Length(AExponent), LExponentHC, FMemoryPool, Length(AExponent) * 8 + 32) then
        Exit;
    finally
      LExponentStream.Free;
    end;

    LModulusLen := (LModulusHC.BitLength + 7) div 8;

    if Length(ASignature) <> LModulusLen then
      Exit;

    LSignatureStream := TMemoryStream.Create;
    try
      LSignatureStream.Write(ASignature[0], Length(ASignature));
      LSignatureStream.Position := 0;
      if not OS2IP(LSignatureStream, Length(ASignature), LSignatureHC, FMemoryPool, LModulusHC.BitLength + 32) then
        Exit;
    finally
      LSignatureStream.Free;
    end;

    if LSignatureHC.Compare(LModulusHC) <> rLessThan then
      Exit;

    LMessageHC := LSignatureHC.Clone;
    if not Assigned(LMessageHC) then
      Exit;

    if LExponentHC.isSmall then
      LMessageHC.SmallExponent_PowerMod(LExponentHC.ExtractSmall, LModulusHC)
    else if not LMessageHC.PowerMod(LExponentHC, LModulusHC, nil) then
      Exit;

    LMessageStream := TMemoryStream.Create;
    try
      if not I2OSP(LMessageHC, LModulusLen, LMessageStream, FMemoryPool) then
        Exit;

      SetLength(LActualEM, LModulusLen);
      LMessageStream.Position := 0;
      LMessageStream.Read(LActualEM[0], LModulusLen);
    finally
      LMessageStream.Free;
    end;

    if Length(AExpectedEM) <> Length(LActualEM) then
      Exit;

    Result := SecureEquals(AExpectedEM, LActualEM);
  finally
    if Assigned(LModulusHC) then
      LModulusHC.Free;
    if Assigned(LExponentHC) then
      LExponentHC.Free;
    if Assigned(LSignatureHC) then
      LSignatureHC.Free;
    if Assigned(LMessageHC) then
      LMessageHC.Free;
  end;
end;

function TIAM4DLockBox3CryptoProvider.MGF1(const ASeed: TBytes; AMaskLen: Integer;
  AHashAlg: TIAM4DHashAlgorithm): TBytes;
var
  LCounter: Cardinal;
  LT: TBytes;
  LCounterBytes: TBytes;
  LInput: TBytes;
  LHash: TBytes;
  LTLen: Integer;
begin
  SetLength(LT, 0);
  LCounter := 0;
  SetLength(LCounterBytes, 4);

  while Length(LT) < AMaskLen do
  begin
    LCounterBytes[0] := Byte((LCounter shr 24) and $FF);
    LCounterBytes[1] := Byte((LCounter shr 16) and $FF);
    LCounterBytes[2] := Byte((LCounter shr 8) and $FF);
    LCounterBytes[3] := Byte(LCounter and $FF);

    SetLength(LInput, Length(ASeed) + 4);
    if Length(ASeed) > 0 then
      Move(ASeed[0], LInput[0], Length(ASeed));
    Move(LCounterBytes[0], LInput[Length(ASeed)], 4);

    LHash := ComputeHash(LInput, AHashAlg);

    LTLen := Length(LT);
    SetLength(LT, LTLen + Length(LHash));
    Move(LHash[0], LT[LTLen], Length(LHash));

    Inc(LCounter);
  end;

  SetLength(Result, AMaskLen);
  Move(LT[0], Result[0], AMaskLen);
end;

function TIAM4DLockBox3CryptoProvider.EMSA_PSS_Verify(const AMessage, AEM: TBytes;
  AEmBits: Integer; AHashAlg: TIAM4DHashAlgorithm; ASaltLen: Integer): Boolean;
var
  LHLen: Integer;
  LSLen: Integer;
  LEmLen: Integer;
  LMHash: TBytes;
  LMaskedDB: TBytes;
  LH: TBytes;
  LDBMask: TBytes;
  LDB: TBytes;
  LSalt: TBytes;
  LMPrime: TBytes;
  LHPrime: TBytes;
  LIndex: Integer;
  LBitMask: Byte;
  LZeroBits: Integer;
begin
  Result := False;

  LHLen := GetHashLength(AHashAlg);
  LSLen := ASaltLen;
  LEmLen := (AEmBits + 7) div 8;

  LMHash := ComputeHash(AMessage, AHashAlg);

  if LEmLen < LHLen + LSLen + 2 then
    Exit;

  if Length(AEM) < 1 then
    Exit;
  if AEM[Length(AEM) - 1] <> $BC then
    Exit;

  SetLength(LMaskedDB, LEmLen - LHLen - 1);
  SetLength(LH, LHLen);

  if Length(AEM) < LEmLen then
    Exit;

  Move(AEM[0], LMaskedDB[0], Length(LMaskedDB));
  Move(AEM[Length(LMaskedDB)], LH[0], LHLen);

  LZeroBits := 8 * LEmLen - AEmBits;
  if LZeroBits > 0 then
  begin
    LBitMask := $FF shl (8 - LZeroBits);
    if (LMaskedDB[0] and LBitMask) <> 0 then
      Exit;
  end;

  LDBMask := MGF1(LH, LEmLen - LHLen - 1, AHashAlg);

  SetLength(LDB, Length(LMaskedDB));
  for LIndex := 0 to Length(LDB) - 1 do
    LDB[LIndex] := LMaskedDB[LIndex] xor LDBMask[LIndex];

  if LZeroBits > 0 then
  begin
    LBitMask := $FF shr LZeroBits;
    LDB[0] := LDB[0] and LBitMask;
  end;

  for LIndex := 0 to LEmLen - LHLen - LSLen - 3 do
  begin
    if LDB[LIndex] <> $00 then
      Exit;
  end;

  if LDB[LEmLen - LHLen - LSLen - 2] <> $01 then
    Exit;

  SetLength(LSalt, LSLen);
  Move(LDB[Length(LDB) - LSLen], LSalt[0], LSLen);

  SetLength(LMPrime, 8 + LHLen + LSLen);
  FillChar(LMPrime[0], 8, 0);
  Move(LMHash[0], LMPrime[8], LHLen);
  Move(LSalt[0], LMPrime[8 + LHLen], LSLen);

  LHPrime := ComputeHash(LMPrime, AHashAlg);

  Result := SecureEquals(LH, LHPrime);
end;

function TIAM4DLockBox3CryptoProvider.RSAVerifyPSS(const AMessage, ASignature,
  AModulus, AExponent: TBytes; AHashAlg: TIAM4DHashAlgorithm; ASaltLen: Integer): Boolean;
var
  LModulusHC, LExponentHC: THugeCardinal;
  LSignatureHC: THugeCardinal;
  LMessageHC: THugeCardinal;
  LModulusStream, LExponentStream, LSignatureStream, LMessageStream: TMemoryStream;
  LEM: TBytes;
  LK: Integer;
  LModBits: Integer;
  LEmLen: Integer;
begin
  Result := False;
  LModulusHC := nil;
  LExponentHC := nil;
  LSignatureHC := nil;
  LMessageHC := nil;

  try
    LModulusStream := TMemoryStream.Create;
    try
      LModulusStream.Write(AModulus[0], Length(AModulus));
      LModulusStream.Position := 0;
      if not OS2IP(LModulusStream, Length(AModulus), LModulusHC, FMemoryPool, Length(AModulus) * 8 + 32) then
        Exit;
    finally
      LModulusStream.Free;
    end;

    LExponentStream := TMemoryStream.Create;
    try
      LExponentStream.Write(AExponent[0], Length(AExponent));
      LExponentStream.Position := 0;
      if not OS2IP(LExponentStream, Length(AExponent), LExponentHC, FMemoryPool, Length(AExponent) * 8 + 32) then
        Exit;
    finally
      LExponentStream.Free;
    end;

    LModBits := LModulusHC.BitLength;
    LK := (LModBits + 7) div 8;
    LEmLen := (LModBits + 6) div 8;

    if Length(ASignature) <> LK then
      Exit;

    LSignatureStream := TMemoryStream.Create;
    try
      LSignatureStream.Write(ASignature[0], Length(ASignature));
      LSignatureStream.Position := 0;
      if not OS2IP(LSignatureStream, LK, LSignatureHC, FMemoryPool, LModBits + 32) then
        Exit;
    finally
      LSignatureStream.Free;
    end;

    if LSignatureHC.Compare(LModulusHC) <> rLessThan then
      Exit;

    LMessageHC := LSignatureHC.Clone;
    if not Assigned(LMessageHC) then
      Exit;

    if LExponentHC.isSmall then
      LMessageHC.SmallExponent_PowerMod(LExponentHC.ExtractSmall, LModulusHC)
    else if not LMessageHC.PowerMod(LExponentHC, LModulusHC, nil) then
      Exit;

    LMessageStream := TMemoryStream.Create;
    try
      if not I2OSP(LMessageHC, LEmLen, LMessageStream, FMemoryPool) then
        Exit;

      SetLength(LEM, LEmLen);
      LMessageStream.Position := 0;
      LMessageStream.Read(LEM[0], LEmLen);
    finally
      LMessageStream.Free;
    end;

    Result := EMSA_PSS_Verify(AMessage, LEM, LModBits - 1, AHashAlg, ASaltLen);
  finally
    if Assigned(LModulusHC) then
      LModulusHC.Free;
    if Assigned(LExponentHC) then
      LExponentHC.Free;
    if Assigned(LSignatureHC) then
      LSignatureHC.Free;
    if Assigned(LMessageHC) then
      LMessageHC.Free;
  end;
end;

{$ELSE}
// Unit is empty when TMS is active (mutual exclusivity)
interface
implementation
{$ENDIF}

end.