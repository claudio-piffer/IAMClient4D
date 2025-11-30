{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.JWT.Verifiers.RSA.pas
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

unit IAMClient4D.Security.JWT.Verifiers.RSA;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.NetEncoding,
  System.Hash,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Security.Core,
  uTPLb_HugeCardinal,
  uTPLb_MemoryStreamPool;

type
  /// <summary>
  /// RSA JWT signature verifier using PKCS#1 v1.5 padding.
  /// </summary>
  /// <remarks>
  /// Verifies JWT signatures using RSA public key cryptography.
  /// Algorithms: RS256 (SHA-256), RS384 (SHA-384), RS512 (SHA-512).
  /// Padding: EMSA-PKCS1-v1_5 encoding scheme (RFC 3447).
  /// Library: TurboPower LockBox for RSA operations and huge cardinal arithmetic.
  /// Key format: JWK with 'n' (modulus) and 'e' (exponent) parameters in Base64URL.
  /// Thread-safety: Create separate instance per thread (not thread-safe).
  /// Memory: Uses memory pool for efficient stream management.
  /// Security: Production-ready implementation with proper PKCS#1 v1.5 verification.
  /// </remarks>
  TRSAJWTSignatureVerifier = class(TInterfacedObject, IIAM4DJWTSignatureVerifier)
  private
    FMemoryPool: IMemoryStreamPool;

    function Base64URLDecode(const AInput: string): TBytes;

    function ExtractRSAPublicKey(const APublicKeyJWK: TJSONObject;
      out AModulus, AExponent: THugeCardinal): Boolean;

    function EMSA_PKCS1_v1_5_Encode(const AMessage: TBytes; const AAlg: string;
      AEmLen: Integer): TBytes;

    function ComputeHash(const AMessage: TBytes; const AAlg: string): TBytes;

    function GetDigestInfoPrefix(const AAlg: string): TBytes;
  public
    /// <summary>
    /// Creates RSA verifier with memory pool for stream management.
    /// </summary>
    constructor Create;
    /// <summary>
    /// Destroys verifier and releases memory pool.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Verifies RSA signature using public key JWK and specified algorithm.
    /// </summary>
    function Verify(const ASigningInput: string; const ASignatureBytes: TBytes;
      const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;

    /// <summary>
    /// Returns array of supported RSA algorithms.
    /// </summary>
    function GetSupportedAlgorithms: TArray<string>;
  end;

implementation

uses
  uTPLb_RSA_Primitives,
  IAMClient4D.Exceptions;

{ TRSAJWTSignatureVerifier }

constructor TRSAJWTSignatureVerifier.Create;
begin
  inherited Create;
  FMemoryPool := NewPool;
end;

destructor TRSAJWTSignatureVerifier.Destroy;
begin
  FMemoryPool := nil;
  inherited;
end;

function TRSAJWTSignatureVerifier.Base64URLDecode(const AInput: string): TBytes;
var
  LBase64: string;
  LPadding: Integer;
begin
  LBase64 := AInput.Replace('-', '+').Replace('_', '/');

  LPadding := Length(LBase64) mod 4;
  if LPadding > 0 then
    LBase64 := LBase64 + StringOfChar('=', 4 - LPadding);

  Result := TNetEncoding.Base64.DecodeStringToBytes(LBase64);
end;

function TRSAJWTSignatureVerifier.ExtractRSAPublicKey(
  const APublicKeyJWK: TJSONObject;
  out AModulus, AExponent: THugeCardinal): Boolean;
var
  LN, LE: TJSONValue;
  LNBytes, LEBytes: TBytes;
  LNStream, LEStream: TMemoryStream;
begin
  Result := False;
  AModulus := nil;
  AExponent := nil;

  try
    LN := APublicKeyJWK.GetValue('n');
    if not Assigned(LN) then
      Exit;

    LE := APublicKeyJWK.GetValue('e');
    if not Assigned(LE) then
      Exit;

    LNBytes := Base64URLDecode(LN.Value);
    LEBytes := Base64URLDecode(LE.Value);

    if (Length(LNBytes) = 0) or (Length(LEBytes) = 0) then
      Exit;

    LNStream := TMemoryStream.Create;
    try
      LNStream.Write(LNBytes[0], Length(LNBytes));
      LNStream.Position := 0;

      if not OS2IP(LNStream, Length(LNBytes), AModulus, FMemoryPool, Length(LNBytes) * 8 + 32) then
        Exit;
    finally
      LNStream.Free;
    end;

    LEStream := TMemoryStream.Create;
    try
      LEStream.Write(LEBytes[0], Length(LEBytes));
      LEStream.Position := 0;

      if not OS2IP(LEStream, Length(LEBytes), AExponent, FMemoryPool, Length(LEBytes) * 8 + 32) then
      begin
        AModulus.Free;
        AModulus := nil;
        Exit;
      end;
    finally
      LEStream.Free;
    end;

    Result := True;
  except
    if Assigned(AModulus) then
    begin
      AModulus.Free;
      AModulus := nil;
    end;
    if Assigned(AExponent) then
    begin
      AExponent.Free;
      AExponent := nil;
    end;
    Result := False;
  end;
end;

function TRSAJWTSignatureVerifier.ComputeHash(const AMessage: TBytes; const AAlg: string): TBytes;
var
  LHashSHA2: THashSHA2;
begin
  if SameText(AAlg, 'RS256') then
  begin
    LHashSHA2 := THashSHA2.Create(THashSHA2.TSHA2Version.SHA256);
    LHashSHA2.Update(AMessage[0], Length(AMessage));
    Result := LHashSHA2.HashAsBytes;
  end
  else if SameText(AAlg, 'RS384') then
  begin
    LHashSHA2 := THashSHA2.Create(THashSHA2.TSHA2Version.SHA384);
    LHashSHA2.Update(AMessage[0], Length(AMessage));
    Result := LHashSHA2.HashAsBytes;
  end
  else if SameText(AAlg, 'RS512') then
  begin
    LHashSHA2 := THashSHA2.Create(THashSHA2.TSHA2Version.SHA512);
    LHashSHA2.Update(AMessage[0], Length(AMessage));
    Result := LHashSHA2.HashAsBytes;
  end
  else
    raise EIAM4DSecurityValidationException.CreateFmt('Unsupported RSA algorithm: %s', [AAlg]);
end;

function TRSAJWTSignatureVerifier.GetDigestInfoPrefix(const AAlg: string): TBytes;
begin
  if SameText(AAlg, 'RS256') then
  begin
    SetLength(Result, 19);
    Result[0] := $30;
    Result[1] := $31;
    Result[2] := $30;
    Result[3] := $0D;
    Result[4] := $06;
    Result[5] := $09;
    Result[6] := $60;
    Result[7] := $86;
    Result[8] := $48;
    Result[9] := $01;
    Result[10] := $65;
    Result[11] := $03;
    Result[12] := $04;
    Result[13] := $02;
    Result[14] := $01;
    Result[15] := $05;
    Result[16] := $00;
    Result[17] := $04;
    Result[18] := $20;
  end
  else if SameText(AAlg, 'RS384') then
  begin
    SetLength(Result, 19);
    Result[0] := $30;
    Result[1] := $41;
    Result[2] := $30;
    Result[3] := $0D;
    Result[4] := $06;
    Result[5] := $09;
    Result[6] := $60;
    Result[7] := $86;
    Result[8] := $48;
    Result[9] := $01;
    Result[10] := $65;
    Result[11] := $03;
    Result[12] := $04;
    Result[13] := $02;
    Result[14] := $02;
    Result[15] := $05;
    Result[16] := $00;
    Result[17] := $04;
    Result[18] := $30;
  end
  else if SameText(AAlg, 'RS512') then
  begin
    SetLength(Result, 19);
    Result[0] := $30;
    Result[1] := $51;
    Result[2] := $30;
    Result[3] := $0D;
    Result[4] := $06;
    Result[5] := $09;
    Result[6] := $60;
    Result[7] := $86;
    Result[8] := $48;
    Result[9] := $01;
    Result[10] := $65;
    Result[11] := $03;
    Result[12] := $04;
    Result[13] := $02;
    Result[14] := $03;
    Result[15] := $05;
    Result[16] := $00;
    Result[17] := $04;
    Result[18] := $40;
  end
  else
    raise EIAM4DSecurityValidationException.CreateFmt('Unsupported RSA algorithm: %s', [AAlg]);
end;

function TRSAJWTSignatureVerifier.EMSA_PKCS1_v1_5_Encode(
  const AMessage: TBytes; const AAlg: string; AEmLen: Integer): TBytes;
var
  LHash: TBytes;
  LDigestInfo: TBytes;
  LDigestInfoPrefix: TBytes;
  LPaddingLen: Integer;
  LIndex: Integer;
begin
  LHash := ComputeHash(AMessage, AAlg);

  LDigestInfoPrefix := GetDigestInfoPrefix(AAlg);
  SetLength(LDigestInfo, Length(LDigestInfoPrefix) + Length(LHash));
  Move(LDigestInfoPrefix[0], LDigestInfo[0], Length(LDigestInfoPrefix));
  Move(LHash[0], LDigestInfo[Length(LDigestInfoPrefix)], Length(LHash));

  if Length(LDigestInfo) > AEmLen - 11 then
    raise EIAM4DSecurityValidationException.Create('Intended encoded message length too short');

  LPaddingLen := AEmLen - Length(LDigestInfo) - 3;

  SetLength(Result, AEmLen);
  Result[0] := $00;
  Result[1] := $01;

  for LIndex := 2 to LPaddingLen + 1 do
    Result[LIndex] := $FF;

  Result[LPaddingLen + 2] := $00;

  Move(LDigestInfo[0], Result[LPaddingLen + 3], Length(LDigestInfo));
end;

function TRSAJWTSignatureVerifier.GetSupportedAlgorithms: TArray<string>;
begin
  Result := TArray<string>.Create('RS256', 'RS384', 'RS512');
end;

function TRSAJWTSignatureVerifier.Verify(const ASigningInput: string;
  const ASignatureBytes: TBytes; const APublicKeyJWK: TJSONObject;
  const AAlg: string): Boolean;
var
  LModulus, LExponent: THugeCardinal;
  LSignature: THugeCardinal;
  LMessage: THugeCardinal;
  LSignatureStream: TMemoryStream;
  LMessageStream: TMemoryStream;
  LSigningInputBytes: TBytes;
  LExpectedEM: TBytes;
  LActualEM: TBytes;
  LModulusLen: Integer;
begin
  Result := False;
  LModulus := nil;
  LExponent := nil;
  LSignature := nil;
  LMessage := nil;

  try
    if not (SameText(AAlg, 'RS256') or SameText(AAlg, 'RS384') or SameText(AAlg, 'RS512')) then
      Exit;

    if not ExtractRSAPublicKey(APublicKeyJWK, LModulus, LExponent) then
      Exit;

    LModulusLen := (LModulus.BitLength + 7) div 8;
    if Length(ASignatureBytes) <> LModulusLen then
      Exit;

    LSignatureStream := TMemoryStream.Create;
    try
      LSignatureStream.Write(ASignatureBytes[0], Length(ASignatureBytes));
      LSignatureStream.Position := 0;

      if not OS2IP(LSignatureStream, Length(ASignatureBytes), LSignature, FMemoryPool,
        LModulus.BitLength + 32) then
        Exit;
    finally
      LSignatureStream.Free;
    end;

    if LSignature.Compare(LModulus) <> rLessThan then
      Exit;

    LMessage := LSignature.Clone;
    if not Assigned(LMessage) then
      Exit;

    if LExponent.isSmall then
      LMessage.SmallExponent_PowerMod(LExponent.ExtractSmall, LModulus)
    else if not LMessage.PowerMod(LExponent, LModulus, nil) then
      Exit;

    LMessageStream := TMemoryStream.Create;
    try
      if not I2OSP(LMessage, LModulusLen, LMessageStream, FMemoryPool) then
        Exit;

      SetLength(LActualEM, LModulusLen);
      LMessageStream.Position := 0;
      LMessageStream.Read(LActualEM[0], LModulusLen);
    finally
      LMessageStream.Free;
    end;

    LSigningInputBytes := TEncoding.UTF8.GetBytes(ASigningInput);
    LExpectedEM := EMSA_PKCS1_v1_5_Encode(LSigningInputBytes, AAlg, LModulusLen);

    if Length(LExpectedEM) <> Length(LActualEM) then
      Exit;

    Result := SecureEquals(LExpectedEM, LActualEM);
  finally
    if Assigned(LModulus) then
      LModulus.Free;
    if Assigned(LExponent) then
      LExponent.Free;
    if Assigned(LSignature) then
      LSignature.Free;
    if Assigned(LMessage) then
      LMessage.Free;
  end;
end;

end.