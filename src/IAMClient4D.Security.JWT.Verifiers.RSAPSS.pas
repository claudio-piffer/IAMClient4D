{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.JWT.Verifiers.RSAPSS.pas
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

unit IAMClient4D.Security.JWT.Verifiers.RSAPSS;

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
  /// RSA-PSS JWT signature verifier (PS256, PS384, PS512).
  /// </summary>
  /// <remarks>
  /// Implements RSASSA-PSS signature verification per RFC 3447 Section 8.1.2.
  /// Algorithms: PS256 (SHA-256), PS384 (SHA-384), PS512 (SHA-512).
  /// Padding: EMSA-PSS encoding scheme with MGF1 mask generation.
  /// Salt length: Uses hash length as salt length (recommended by RFC).
  /// Crypto provider: Configurable (default: LockBox3).
  /// Key format: JWK with 'n' (modulus) and 'e' (exponent) parameters in Base64URL.
  /// Thread-safety: Create separate instance per thread (not thread-safe).
  /// Security: Production-ready implementation with proper PSS verification.
  /// </remarks>
  TRSAPSSJWTSignatureVerifier = class(TInterfacedObject, IIAM4DJWTSignatureVerifier)
  private
    FCryptoProvider: IIAM4DCryptoProvider;

    function Base64URLDecode(const AInput: string): TBytes;

    function ExtractRSAPublicKeyBytes(const APublicKeyJWK: TJSONObject;
      out AModulus, AExponent: TBytes): Boolean;

    function GetHashLength(const AAlg: string): Integer;

    function GetHashAlgorithm(const AAlg: string): TIAM4DHashAlgorithm;
  public
    /// <summary>
    /// Creates RSA-PSS verifier with default LockBox3 crypto provider.
    /// </summary>
    constructor Create; overload;
    /// <summary>
    /// Creates RSA-PSS verifier with specified crypto provider.
    /// </summary>
    constructor Create(const ACryptoProvider: IIAM4DCryptoProvider); overload;
    /// <summary>
    /// Destroys verifier.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Verifies RSA-PSS signature using public key JWK and specified algorithm.
    /// </summary>
    function Verify(const ASigningInput: string; const ASignatureBytes: TBytes;
      const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;

    /// <summary>
    /// Returns array of supported RSA-PSS algorithms.
    /// </summary>
    function GetSupportedAlgorithms: TArray<string>;
  end;

implementation

uses
  IAMClient4D.Exceptions,
  IAMClient4D.Security.Crypto.LockBox3;

{ TRSAPSSJWTSignatureVerifier }

constructor TRSAPSSJWTSignatureVerifier.Create;
begin
  Create(TIAM4DLockBox3CryptoProvider.Create);
end;

constructor TRSAPSSJWTSignatureVerifier.Create(const ACryptoProvider: IIAM4DCryptoProvider);
begin
  inherited Create;
  FCryptoProvider := ACryptoProvider;
end;

destructor TRSAPSSJWTSignatureVerifier.Destroy;
begin
  FCryptoProvider := nil;
  inherited;
end;

function TRSAPSSJWTSignatureVerifier.Base64URLDecode(const AInput: string): TBytes;
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

function TRSAPSSJWTSignatureVerifier.ExtractRSAPublicKeyBytes(
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

function TRSAPSSJWTSignatureVerifier.GetHashLength(const AAlg: string): Integer;
begin
  if SameText(AAlg, 'PS256') then
    Result := 32
  else if SameText(AAlg, 'PS384') then
    Result := 48
  else if SameText(AAlg, 'PS512') then
    Result := 64
  else
    raise EIAM4DSecurityValidationException.CreateFmt('Unsupported RSA-PSS algorithm: %s', [AAlg]);
end;

function TRSAPSSJWTSignatureVerifier.GetHashAlgorithm(const AAlg: string): TIAM4DHashAlgorithm;
begin
  if SameText(AAlg, 'PS256') then
    Result := haSHA256
  else if SameText(AAlg, 'PS384') then
    Result := haSHA384
  else if SameText(AAlg, 'PS512') then
    Result := haSHA512
  else
    raise EIAM4DSecurityValidationException.CreateFmt('Unsupported RSA-PSS algorithm: %s', [AAlg]);
end;

function TRSAPSSJWTSignatureVerifier.GetSupportedAlgorithms: TArray<string>;
begin
  Result := TArray<string>.Create('PS256', 'PS384', 'PS512');
end;

function TRSAPSSJWTSignatureVerifier.Verify(const ASigningInput: string;
  const ASignatureBytes: TBytes; const APublicKeyJWK: TJSONObject;
  const AAlg: string): Boolean;
var
  LModulus, LExponent: TBytes;
  LSigningInputBytes: TBytes;
  LHashAlg: TIAM4DHashAlgorithm;
  LSaltLen: Integer;
begin
  Result := False;

  try
    if not (SameText(AAlg, 'PS256') or SameText(AAlg, 'PS384') or SameText(AAlg, 'PS512')) then
      Exit;

    if not ExtractRSAPublicKeyBytes(APublicKeyJWK, LModulus, LExponent) then
      Exit;

    LSigningInputBytes := TEncoding.UTF8.GetBytes(ASigningInput);
    LHashAlg := GetHashAlgorithm(AAlg);
    LSaltLen := GetHashLength(AAlg);

    Result := FCryptoProvider.RSAVerifyPSS(LSigningInputBytes, ASignatureBytes,
      LModulus, LExponent, LHashAlg, LSaltLen);
  finally
    SecureZero(LModulus);
    SecureZero(LExponent);
  end;
end;

end.