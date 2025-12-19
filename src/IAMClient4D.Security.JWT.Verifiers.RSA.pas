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
  IAMClient4D.Security.Crypto.Interfaces;

type
  /// <summary>
  /// RSA JWT signature verifier using PKCS#1 v1.5 padding.
  /// </summary>
  /// <remarks>
  /// Verifies JWT signatures using RSA public key cryptography.
  /// Algorithms: RS256 (SHA-256), RS384 (SHA-384), RS512 (SHA-512).
  /// Padding: EMSA-PKCS1-v1_5 encoding scheme (RFC 3447).
  /// Crypto provider: Configurable (default: LockBox3).
  /// Key format: JWK with 'n' (modulus) and 'e' (exponent) parameters in Base64URL.
  /// Thread-safety: Create separate instance per thread (not thread-safe).
  /// Security: Production-ready implementation with proper PKCS#1 v1.5 verification.
  /// </remarks>
  TRSAJWTSignatureVerifier = class(TInterfacedObject, IIAM4DJWTSignatureVerifier)
  private
    FCryptoProvider: IIAM4DCryptoProvider;

    function Base64URLDecode(const AInput: string): TBytes;

    function ExtractRSAPublicKeyBytes(const APublicKeyJWK: TJSONObject;
      out AModulus, AExponent: TBytes): Boolean;

    function EMSA_PKCS1_v1_5_Encode(const AMessage: TBytes; const AAlg: string;
      AEmLen: Integer): TBytes;

    function ComputeHash(const AMessage: TBytes; const AAlg: string): TBytes;

    function GetDigestInfoPrefix(const AAlg: string): TBytes;
  public
    /// <summary>
    /// Creates RSA verifier with default LockBox3 crypto provider.
    /// </summary>
    constructor Create; overload;
    /// <summary>
    /// Creates RSA verifier with specified crypto provider.
    /// </summary>
    constructor Create(const ACryptoProvider: IIAM4DCryptoProvider); overload;
    /// <summary>
    /// Destroys verifier.
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
  IAMClient4D.Exceptions,
  IAMClient4D.Security.Crypto.LockBox3;

{ TRSAJWTSignatureVerifier }

constructor TRSAJWTSignatureVerifier.Create;
begin
  Create(TIAM4DLockBox3CryptoProvider.Create);
end;

constructor TRSAJWTSignatureVerifier.Create(const ACryptoProvider: IIAM4DCryptoProvider);
begin
  inherited Create;
  FCryptoProvider := ACryptoProvider;
end;

destructor TRSAJWTSignatureVerifier.Destroy;
begin
  FCryptoProvider := nil;
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

function TRSAJWTSignatureVerifier.ExtractRSAPublicKeyBytes(
  const APublicKeyJWK: TJSONObject;
  out AModulus, AExponent: TBytes): Boolean;
var
  LN, LE: TJSONValue;
begin
  Result := False;
  SetLength(AModulus, 0);
  SetLength(AExponent, 0);

  try
    LN := APublicKeyJWK.GetValue('n');
    if not Assigned(LN) then
      Exit;

    LE := APublicKeyJWK.GetValue('e');
    if not Assigned(LE) then
      Exit;

    AModulus := Base64URLDecode(LN.Value);
    AExponent := Base64URLDecode(LE.Value);

    if (Length(AModulus) = 0) or (Length(AExponent) = 0) then
      Exit;

    Result := True;
  except
    SetLength(AModulus, 0);
    SetLength(AExponent, 0);
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
  LModulus, LExponent: TBytes;
  LSigningInputBytes: TBytes;
  LExpectedEM: TBytes;
  LModulusLen: Integer;
begin
  Result := False;

  try
    if not (SameText(AAlg, 'RS256') or SameText(AAlg, 'RS384') or SameText(AAlg, 'RS512')) then
      Exit;

    if not ExtractRSAPublicKeyBytes(APublicKeyJWK, LModulus, LExponent) then
      Exit;

    LModulusLen := Length(LModulus);
    if Length(ASignatureBytes) <> LModulusLen then
      Exit;

    LSigningInputBytes := TEncoding.UTF8.GetBytes(ASigningInput);
    LExpectedEM := EMSA_PKCS1_v1_5_Encode(LSigningInputBytes, AAlg, LModulusLen);

    Result := FCryptoProvider.RSAVerifyPKCS1(LExpectedEM, ASignatureBytes, LModulus, LExponent);
  finally
    SecureZero(LModulus);
    SecureZero(LExponent);
  end;
end;

end.