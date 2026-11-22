{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.JWT.Verifiers.ECDSA.pas
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

unit IAMClient4D.Security.JWT.Verifiers.ECDSA;

interface

uses
  System.SysUtils,
  System.JSON,
  System.NetEncoding,
  System.Hash,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.Crypto.Interfaces;

type
  /// <summary>
  /// ECDSA JWT signature verifier (ES256, ES384, ES512).
  /// </summary>
  /// <remarks>
  /// Implements RFC 7518 Section 3.4.
  /// Curves: ES256 = P-256/SHA-256, ES384 = P-384/SHA-384, ES512 = P-521/SHA-512.
  /// Signature: raw R || S, each the full coordinate size (32, 48, 66 bytes).
  /// Key format: JWK with kty 'EC', 'crv' matching the algorithm, 'x' and 'y' in Base64URL.
  /// Crypto provider: must support ECDSA (TMS or TaurusTLS).
  /// Providers implementing IIAM4DECDSAMessageVerifier receive the signing input, the others its digest.
  /// Algorithm names are case-sensitive.
  /// Thread-safety: stateless, safe for concurrent use when the crypto provider is.
  /// </remarks>
  TECDSAJWTSignatureVerifier = class(TInterfacedObject, IIAM4DJWTSignatureVerifier)
  private
    FCryptoProvider: IIAM4DCryptoProvider;

    function Base64URLDecode(const AInput: string): TBytes;

    function TryGetCurveParams(const AAlg: string; out ACurve: TIAM4DECCurve;
      out ACurveName: string; out ACoordinateSize: Integer): Boolean;

    function ExtractECPublicKeyBytes(const APublicKeyJWK: TJSONObject;
      const ACurveName: string; ACoordinateSize: Integer; out AX, AY: TBytes): Boolean;

    function ComputeHash(const AMessage: TBytes; const AAlg: string): TBytes;
  public
    /// <summary>
    /// Creates ECDSA verifier with the default crypto provider.
    /// </summary>
    constructor Create; overload;
    /// <summary>
    /// Creates ECDSA verifier with specified crypto provider.
    /// </summary>
    constructor Create(const ACryptoProvider: IIAM4DCryptoProvider); overload;
    /// <summary>
    /// Destroys verifier.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Verifies ECDSA signature using public key JWK and specified algorithm.
    /// </summary>
    function Verify(const ASigningInput: string; const ASignatureBytes: TBytes;
      const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;

    /// <summary>
    /// Returns array of supported ECDSA algorithms.
    /// </summary>
    function GetSupportedAlgorithms: TArray<string>;
  end;

implementation

uses
  IAMClient4D.Exceptions,
  IAMClient4D.Security.Crypto.Factory;

{ TECDSAJWTSignatureVerifier }

constructor TECDSAJWTSignatureVerifier.Create;
begin
  Create(TIAM4DCryptoProviderFactory.CreateProvider);
end;

constructor TECDSAJWTSignatureVerifier.Create(const ACryptoProvider: IIAM4DCryptoProvider);
begin
  inherited Create;
  FCryptoProvider := ACryptoProvider;
end;

destructor TECDSAJWTSignatureVerifier.Destroy;
begin
  FCryptoProvider := nil;
  inherited;
end;

function TECDSAJWTSignatureVerifier.Base64URLDecode(const AInput: string): TBytes;
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

function TECDSAJWTSignatureVerifier.TryGetCurveParams(const AAlg: string;
  out ACurve: TIAM4DECCurve; out ACurveName: string; out ACoordinateSize: Integer): Boolean;
begin
  // Case-sensitive (RFC 7515 4.1.1)
  Result := True;
  if AAlg = 'ES256' then
  begin
    ACurve := eccP256;
    ACurveName := 'P-256';
    ACoordinateSize := 32;
  end
  else if AAlg = 'ES384' then
  begin
    ACurve := eccP384;
    ACurveName := 'P-384';
    ACoordinateSize := 48;
  end
  else if AAlg = 'ES512' then
  begin
    ACurve := eccP521;
    ACurveName := 'P-521';
    ACoordinateSize := 66;
  end
  else
    Result := False;
end;

function TECDSAJWTSignatureVerifier.ExtractECPublicKeyBytes(
  const APublicKeyJWK: TJSONObject; const ACurveName: string;
  ACoordinateSize: Integer; out AX, AY: TBytes): Boolean;
var
  LX, LY: TJSONValue;
begin
  Result := False;
  SetLength(AX, 0);
  SetLength(AY, 0);

  try
    // Key must match the algorithm curve (prevents cross-curve key confusion)
    if APublicKeyJWK.GetValue<string>('kty', '') <> 'EC' then
      Exit;
    if APublicKeyJWK.GetValue<string>('crv', '') <> ACurveName then
      Exit;

    LX := APublicKeyJWK.GetValue('x');
    LY := APublicKeyJWK.GetValue('y');
    if not Assigned(LX) or not Assigned(LY) then
      Exit;

    AX := Base64URLDecode(LX.Value);
    AY := Base64URLDecode(LY.Value);

    // RFC 7518 6.2.1.2/6.2.1.3: full coordinate size
    Result := (Length(AX) = ACoordinateSize) and (Length(AY) = ACoordinateSize);
  except
    Result := False;
  end;

  if not Result then
  begin
    SetLength(AX, 0);
    SetLength(AY, 0);
  end;
end;

function TECDSAJWTSignatureVerifier.ComputeHash(const AMessage: TBytes; const AAlg: string): TBytes;
var
  LHashSHA2: THashSHA2;
  LVersion: THashSHA2.TSHA2Version;
begin
  if AAlg = 'ES256' then
    LVersion := THashSHA2.TSHA2Version.SHA256
  else if AAlg = 'ES384' then
    LVersion := THashSHA2.TSHA2Version.SHA384
  else if AAlg = 'ES512' then
    LVersion := THashSHA2.TSHA2Version.SHA512
  else
    raise EIAM4DSecurityValidationException.CreateFmt('Unsupported ECDSA algorithm: %s', [AAlg]);

  LHashSHA2 := THashSHA2.Create(LVersion);

  if Length(AMessage) > 0 then
    LHashSHA2.Update(AMessage, Length(AMessage));

  Result := LHashSHA2.HashAsBytes;
end;

function TECDSAJWTSignatureVerifier.GetSupportedAlgorithms: TArray<string>;
begin
  Result := TArray<string>.Create('ES256', 'ES384', 'ES512');
end;

function TECDSAJWTSignatureVerifier.Verify(const ASigningInput: string;
  const ASignatureBytes: TBytes; const APublicKeyJWK: TJSONObject;
  const AAlg: string): Boolean;
var
  LCurve: TIAM4DECCurve;
  LCurveName: string;
  LCoordinateSize: Integer;
  LX, LY, LR, LS: TBytes;
  LMessage: TBytes;
  LMessageVerifier: IIAM4DECDSAMessageVerifier;
begin
  Result := False;

  if not TryGetCurveParams(AAlg, LCurve, LCurveName, LCoordinateSize) then
    Exit;

  // JWS ECDSA signature is R || S, not DER (RFC 7518 3.4)
  if Length(ASignatureBytes) <> 2 * LCoordinateSize then
    Exit;

  if not ExtractECPublicKeyBytes(APublicKeyJWK, LCurveName, LCoordinateSize, LX, LY) then
    Exit;

  LR := Copy(ASignatureBytes, 0, LCoordinateSize);
  LS := Copy(ASignatureBytes, LCoordinateSize, LCoordinateSize);
  LMessage := TEncoding.UTF8.GetBytes(ASigningInput);

  // Providers that hash internally (TMS) need the message, not the digest
  if Supports(FCryptoProvider, IIAM4DECDSAMessageVerifier, LMessageVerifier) then
    Result := LMessageVerifier.ECDSAVerifyMessage(LMessage, LR, LS, LX, LY, LCurve)
  else
    Result := FCryptoProvider.ECDSAVerify(ComputeHash(LMessage, AAlg), LR, LS, LX, LY, LCurve);
end;

end.
