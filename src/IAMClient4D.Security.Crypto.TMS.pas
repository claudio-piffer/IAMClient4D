{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.Crypto.TMS.pas
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

unit IAMClient4D.Security.Crypto.TMS;

{$I IAMClient4D.Config.inc}

{$IFDEF IAM4D_CRYPTO_TMS}
interface

uses
  System.SysUtils,
  System.Classes,
  System.Hash,
  IAMClient4D.Security.Crypto.Interfaces,
  IAMClient4D.Common.SecureMemory,
  // TMS Cryptography Pack units
  RSAObj,
  RSACore,
  BaseCore,
  MiscObj,
  CryptoConst,
  ECDSAp256,
  ECDSAp384,
  ECDSAp521;

type
  /// <summary>
  /// Wrapper for TECDSAp256 that implements the abstract GeneratePublicKey method.
  /// Used only for signature verification, not key generation.
  /// </summary>
  TIAM4DECDSAp256 = class(TECDSAp256)
  public
    function GeneratePublicKey(var publicKey: TBytes; privateKey: TBytes): integer; override;
  end;

  /// <summary>
  /// Wrapper for TECDSAp384 that implements the abstract GeneratePublicKey method.
  /// </summary>
  TIAM4DECDSAp384 = class(TECDSAp384)
  public
    function GeneratePublicKey(var publicKey: TBytes; privateKey: TBytes): integer; override;
  end;

  /// <summary>
  /// Wrapper for TECDSAp521 that implements the abstract GeneratePublicKey method.
  /// </summary>
  TIAM4DECDSAp521 = class(TECDSAp521)
  public
    function GeneratePublicKey(var publicKey: TBytes; privateKey: TBytes): integer; override;
  end;

type
  /// <summary>
  /// Cryptographic provider implementation using TMS Cryptography Pack.
  /// </summary>
  /// <remarks>
  /// Supports RSA PKCS#1 v1.5 (RS256, RS384, RS512), RSA-PSS (PS256, PS384, PS512),
  /// and ECDSA (ES256, ES384, ES512).
  /// Thread-safety: Create separate instance per thread (not thread-safe).
  /// Requires TMS Cryptography Pack commercial license.
  /// </remarks>
  TIAM4DTMSCryptoProvider = class(TInterfacedObject, IIAM4DCryptoProvider)
  private
    function GetHashLength(AHashAlg: TIAM4DHashAlgorithm): Integer;
    function ComputeHash(const AData: TBytes; AHashAlg: TIAM4DHashAlgorithm): TBytes;
    /// <summary>
    /// Normalizes RSA modulus to standard key size (removes leading zero padding if present)
    /// </summary>
    function NormalizeModulus(const AModulus: TBytes): TBytes;

    /// <summary>
    /// Reverses byte order (big-endian to little-endian and vice versa)
    /// TMS library uses little-endian internally, RSA uses big-endian externally
    /// </summary>
    function ReverseBytes(const AData: TBytes): TBytes;

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
{$ENDIF}

implementation

{$IFDEF IAM4D_TMS}

{ TIAM4DECDSAp256 }

function TIAM4DECDSAp256.GeneratePublicKey(var publicKey: TBytes; privateKey: TBytes): integer;
begin
  // Not implemented - this wrapper is only used for signature verification
  raise ENotSupportedException.Create('GeneratePublicKey is not supported in this context');
end;

{ TIAM4DECDSAp384 }

function TIAM4DECDSAp384.GeneratePublicKey(var publicKey: TBytes; privateKey: TBytes): integer;
begin
  raise ENotSupportedException.Create('GeneratePublicKey is not supported in this context');
end;

{ TIAM4DECDSAp521 }

function TIAM4DECDSAp521.GeneratePublicKey(var publicKey: TBytes; privateKey: TBytes): integer;
begin
  raise ENotSupportedException.Create('GeneratePublicKey is not supported in this context');
end;

{ TIAM4DTMSCryptoProvider }

constructor TIAM4DTMSCryptoProvider.Create;
begin
  inherited Create;
end;

destructor TIAM4DTMSCryptoProvider.Destroy;
begin
  inherited;
end;

function TIAM4DTMSCryptoProvider.GetProviderName: string;
begin
  Result := 'TMS Cryptography Pack';
end;

function TIAM4DTMSCryptoProvider.GetSupportedAlgorithms: TArray<string>;
begin
  Result := TArray<string>.Create(
    'RS256', 'RS384', 'RS512',  // RSA PKCS#1 v1.5
    'PS256', 'PS384', 'PS512',  // RSA-PSS
    'ES256', 'ES384', 'ES512'   // ECDSA
  );
end;

function TIAM4DTMSCryptoProvider.SupportsAlgorithm(const AAlg: string): Boolean;
begin
  Result := SameText(AAlg, 'RS256') or SameText(AAlg, 'RS384') or SameText(AAlg, 'RS512') or
            SameText(AAlg, 'PS256') or SameText(AAlg, 'PS384') or SameText(AAlg, 'PS512') or
            SameText(AAlg, 'ES256') or SameText(AAlg, 'ES384') or SameText(AAlg, 'ES512');
end;

function TIAM4DTMSCryptoProvider.NormalizeModulus(const AModulus: TBytes): TBytes;
var
  LLen: Integer;
  LTargetLen: Integer;
begin
  LLen := Length(AModulus);

  // RSA modulus should be exactly 128, 256, 384, 512, or 1024 bytes
  // If it has an extra leading zero byte (common in ASN.1 encoding), remove it
  if (LLen = 129) or (LLen = 257) or (LLen = 385) or (LLen = 513) or (LLen = 1025) then
  begin
    if AModulus[0] = 0 then
    begin
      // Remove leading zero
      SetLength(Result, LLen - 1);
      Move(AModulus[1], Result[0], LLen - 1);
      Exit;
    end;
  end;

  // Determine target length and pad with leading zeros if needed
  if LLen <= 128 then
    LTargetLen := 128
  else if LLen <= 256 then
    LTargetLen := 256
  else if LLen <= 384 then
    LTargetLen := 384
  else if LLen <= 512 then
    LTargetLen := 512
  else
    LTargetLen := 1024;

  if LLen < LTargetLen then
  begin
    // Pad with leading zeros
    SetLength(Result, LTargetLen);
    FillChar(Result[0], LTargetLen - LLen, 0);
    Move(AModulus[0], Result[LTargetLen - LLen], LLen);
  end
  else
    Result := AModulus;
end;

function TIAM4DTMSCryptoProvider.ReverseBytes(const AData: TBytes): TBytes;
var
  I, LLen: Integer;
begin
  LLen := Length(AData);
  SetLength(Result, LLen);
  for I := 0 to LLen - 1 do
    Result[I] := AData[LLen - 1 - I];
end;

function TIAM4DTMSCryptoProvider.GetHashLength(AHashAlg: TIAM4DHashAlgorithm): Integer;
begin
  case AHashAlg of
    haSHA256: Result := 32;
    haSHA384: Result := 48;
    haSHA512: Result := 64;
  else
    Result := 32;
  end;
end;

function TIAM4DTMSCryptoProvider.ComputeHash(const AData: TBytes;
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

function TIAM4DTMSCryptoProvider.MGF1(const ASeed: TBytes; AMaskLen: Integer;
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
    // Counter as 4 octets big-endian
    LCounterBytes[0] := Byte((LCounter shr 24) and $FF);
    LCounterBytes[1] := Byte((LCounter shr 16) and $FF);
    LCounterBytes[2] := Byte((LCounter shr 8) and $FF);
    LCounterBytes[3] := Byte(LCounter and $FF);

    // Hash(mgfSeed || C)
    SetLength(LInput, Length(ASeed) + 4);
    if Length(ASeed) > 0 then
      Move(ASeed[0], LInput[0], Length(ASeed));
    Move(LCounterBytes[0], LInput[Length(ASeed)], 4);

    LHash := ComputeHash(LInput, AHashAlg);

    // Append to T
    LTLen := Length(LT);
    SetLength(LT, LTLen + Length(LHash));
    Move(LHash[0], LT[LTLen], Length(LHash));

    Inc(LCounter);
  end;

  // Return leftmost maskLen octets
  SetLength(Result, AMaskLen);
  Move(LT[0], Result[0], AMaskLen);
end;

function TIAM4DTMSCryptoProvider.EMSA_PSS_Verify(const AMessage, AEM: TBytes;
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

function TIAM4DTMSCryptoProvider.RSAVerifyPKCS1(const AExpectedEM, ASignature,
  AModulus, AExponent: TBytes): Boolean;
var
  LBase32: TBase32;
  LModulus32, LExponent32, LSignature32, LResult32: IB32;
  LActualEM: TBytes;
  LNormModulus, LNormSignature: TBytes;
  LModulusLE, LSignatureLE, LExponentLE: TBytes;
  LExpResult: Integer;
  LResultLE: TBytes;
  LMaxSize: Integer;
  I: Integer;
begin
  Result := False;

  LNormModulus := NormalizeModulus(AModulus);
  LNormSignature := NormalizeModulus(ASignature);

  if Length(LNormSignature) <> Length(LNormModulus) then
    Exit;

  // TMS library uses little-endian internally, RSA uses big-endian
  // Reverse byte order for TMS compatibility
  LModulusLE := ReverseBytes(LNormModulus);
  LSignatureLE := ReverseBytes(LNormSignature);
  LExponentLE := ReverseBytes(AExponent);

  // Use TBase32 for raw modular exponentiation: m = s^e mod n
  LBase32 := TBase32.Create;
  try
    try
      LBase32.Zeroize(LModulus32);
      LBase32.BytesToIB32(LModulusLE, LModulus32);

      LBase32.Zeroize(LExponent32);
      LBase32.BytesToIB32(LExponentLE, LExponent32);

      LBase32.Zeroize(LSignature32);
      LBase32.BytesToIB32(LSignatureLE, LSignature32);

      LBase32.Zeroize(LResult32);

      LExpResult := LBase32.ExpMod(LSignature32, LExponent32, LModulus32, LResult32);
      if LExpResult <> 0 then
        Exit;

      LMaxSize := Length(LNormModulus) + 16;
      SetLength(LResultLE, LMaxSize);
      FillChar(LResultLE[0], LMaxSize, 0);

      LBase32.IB32ToBytes(LResult32, LResultLE);

      LActualEM := ReverseBytes(LResultLE);

      if Length(LActualEM) > Length(LNormModulus) then
      begin
        I := 0;
        while (I < Length(LActualEM) - Length(LNormModulus)) and (LActualEM[I] = 0) do
          Inc(I);
        if Length(LActualEM) - I >= Length(LNormModulus) then
        begin
          Move(LActualEM[Length(LActualEM) - Length(LNormModulus)], LActualEM[0], Length(LNormModulus));
          SetLength(LActualEM, Length(LNormModulus));
        end;
      end
      else if Length(LActualEM) < Length(LNormModulus) then
      begin
        var LTemp := LActualEM;
        var LPadLen := Length(LNormModulus) - Length(LActualEM);
        SetLength(LActualEM, Length(LNormModulus));
        FillChar(LActualEM[0], Length(LNormModulus), 0);
        Move(LTemp[0], LActualEM[LPadLen], Length(LTemp));
      end;

      if Length(AExpectedEM) <> Length(LActualEM) then
        Exit;

      Result := SecureEquals(AExpectedEM, LActualEM);
    except
      on E: Exception do
        Exit;
    end;
  finally
    LBase32.Free;
  end;
end;

function TIAM4DTMSCryptoProvider.RSAVerifyPSS(const AMessage, ASignature,
  AModulus, AExponent: TBytes; AHashAlg: TIAM4DHashAlgorithm; ASaltLen: Integer): Boolean;
var
  LBase32: TBase32;
  LModulus32, LExponent32, LSignature32, LResult32: IB32;
  LEM: TBytes;
  LNormModulus, LNormSignature: TBytes;
  LModulusLE, LSignatureLE, LExponentLE: TBytes;
  LModBits: Integer;
  LEmLen: Integer;
  LExpResult: Integer;
  LMaxSize: Integer;
  LResultLE: TBytes;
begin
  Result := False;

  LNormModulus := NormalizeModulus(AModulus);
  LNormSignature := NormalizeModulus(ASignature);

  if Length(LNormSignature) <> Length(LNormModulus) then
    Exit;

  LModBits := Length(LNormModulus) * 8;
  LEmLen := (LModBits + 6) div 8;

  LModulusLE := ReverseBytes(LNormModulus);
  LSignatureLE := ReverseBytes(LNormSignature);
  LExponentLE := ReverseBytes(AExponent);

  LBase32 := TBase32.Create;
  try
    try
      LBase32.Zeroize(LModulus32);
      LBase32.BytesToIB32(LModulusLE, LModulus32);

      LBase32.Zeroize(LExponent32);
      LBase32.BytesToIB32(LExponentLE, LExponent32);

      LBase32.Zeroize(LSignature32);
      LBase32.BytesToIB32(LSignatureLE, LSignature32);

      LBase32.Zeroize(LResult32);

      LExpResult := LBase32.ExpMod(LSignature32, LExponent32, LModulus32, LResult32);
      if LExpResult <> 0 then
        Exit;

      LMaxSize := Length(LNormModulus) + 16;
      SetLength(LResultLE, LMaxSize);
      FillChar(LResultLE[0], LMaxSize, 0);

      LBase32.IB32ToBytes(LResult32, LResultLE);

      LEM := ReverseBytes(LResultLE);

      if Length(LEM) < LEmLen then
      begin
        var LTemp := LEM;
        var LPadLen := LEmLen - Length(LEM);
        SetLength(LEM, LEmLen);
        FillChar(LEM[0], LEmLen, 0);
        Move(LTemp[0], LEM[LPadLen], Length(LTemp));
      end
      else if Length(LEM) > LEmLen then
      begin
        var LOffset := Length(LEM) - LEmLen;
        Move(LEM[LOffset], LEM[0], LEmLen);
        SetLength(LEM, LEmLen);
      end;

      Result := EMSA_PSS_Verify(AMessage, LEM, LModBits - 1, AHashAlg, ASaltLen);
    except
      on E: Exception do
        Exit;
    end;
  finally
    LBase32.Free;
  end;
end;

function TIAM4DTMSCryptoProvider.ECDSAVerify(const AHash, AR, AS_, AX, AY: TBytes;
  ACurve: TIAM4DECCurve): Boolean;
var
  LPublicKey: TBytes;
  LSignature: TBytes;
  LVerifyResult: Integer;
  LCurve256: TIAM4DECDSAp256;
  LCurve384: TIAM4DECDSAp384;
  LCurve521: TIAM4DECDSAp521;
begin
  SetLength(LPublicKey, 1 + Length(AX) + Length(AY));
  LPublicKey[0] := $04;
  Move(AX[0], LPublicKey[1], Length(AX));
  Move(AY[0], LPublicKey[1 + Length(AX)], Length(AY));

  SetLength(LSignature, Length(AR) + Length(AS_));
  Move(AR[0], LSignature[0], Length(AR));
  Move(AS_[0], LSignature[Length(AR)], Length(AS_));

  try
    case ACurve of
      eccP256:
      begin
        LCurve256 := TIAM4DECDSAp256.Create(nil);
        try
          LVerifyResult := LCurve256.Verify(AHash, LPublicKey, LSignature);
          Result := (LVerifyResult = 0);
        finally
          LCurve256.Free;
        end;
      end;

      eccP384:
      begin
        LCurve384 := TIAM4DECDSAp384.Create(nil);
        try
          LVerifyResult := LCurve384.Verify(AHash, LPublicKey, LSignature);
          Result := (LVerifyResult = 0);
        finally
          LCurve384.Free;
        end;
      end;

      eccP521:
      begin
        LCurve521 := TIAM4DECDSAp521.Create(nil);
        try
          LVerifyResult := LCurve521.Verify(AHash, LPublicKey, LSignature);
          Result := (LVerifyResult = 0);
        finally
          LCurve521.Free;
        end;
      end;
    else
      raise EIAM4DCryptoNotSupportedException.Create(
        Format('Curve %d not supported', [Ord(ACurve)]), GetProviderName);
    end;
  finally
    SecureZero(LPublicKey);
    SecureZero(LSignature);
  end;
end;

{$ELSE}
// Unit is empty when LockBox3 is active (mutual exclusivity)
interface
implementation
{$ENDIF}

end.