{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.JWT.Verifiers.Universal.pas
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

unit IAMClient4D.Security.JWT.Verifiers.Universal;

interface

uses
  System.SysUtils,
  System.JSON,
  IAMClient4D.Security.Core;

type
  /// <summary>
  /// Universal JWT signature verifier supporting multiple algorithms.
  /// </summary>
  /// <remarks>
  /// Automatically delegates to appropriate verifier based on algorithm.
  /// Supported algorithms: RS256, RS384, RS512 (RSA with PKCS#1 v1.5).
  /// Future extensions: PS256, PS384, PS512 (RSA-PSS), ES256, ES384, ES512 (ECDSA).
  /// Thread-safety: Thread-safe for concurrent verification operations.
  /// </remarks>
  TUniversalJWTSignatureVerifier = class(TInterfacedObject, IIAM4DJWTSignatureVerifier)
  private
    FRSAVerifier: IIAM4DJWTSignatureVerifier;

    function IsRSAAlgorithm(const AAlg: string): Boolean;
  public
    /// <summary>
    /// Creates universal verifier with support for all standard JWT algorithms.
    /// </summary>
    constructor Create;

    /// <summary>
    /// Destroys verifier and releases internal verifier instances.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Verifies JWT signature using appropriate verifier based on algorithm.
    /// </summary>
    /// <param name="ASigningInput">JWT header.payload (base64url encoded)</param>
    /// <param name="ASignatureBytes">Signature bytes</param>
    /// <param name="APublicKeyJWK">Public key in JWK format</param>
    /// <param name="AAlg">Algorithm (RS256, RS384, RS512, etc.)</param>
    /// <returns>True if signature is valid, False otherwise</returns>
    function Verify(const ASigningInput: string; const ASignatureBytes: TBytes;
      const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;

    /// <summary>
    /// Returns array of all supported algorithms.
    /// </summary>
    function GetSupportedAlgorithms: TArray<string>;
  end;

implementation

uses
  IAMClient4D.Security.JWT.Verifiers.RSA,
  IAMClient4D.Exceptions;

{ TUniversalJWTSignatureVerifier }

constructor TUniversalJWTSignatureVerifier.Create;
begin
  inherited Create;
  FRSAVerifier := TRSAJWTSignatureVerifier.Create;
end;

destructor TUniversalJWTSignatureVerifier.Destroy;
begin
  FRSAVerifier := nil;
  inherited;
end;

function TUniversalJWTSignatureVerifier.GetSupportedAlgorithms: TArray<string>;
begin
  Result := TArray<string>.Create('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512');
end;

function TUniversalJWTSignatureVerifier.IsRSAAlgorithm(const AAlg: string): Boolean;
begin
  Result := SameText(AAlg, 'RS256') or
            SameText(AAlg, 'RS384') or
            SameText(AAlg, 'RS512') or
            SameText(AAlg, 'PS256') or
            SameText(AAlg, 'PS384') or
            SameText(AAlg, 'PS512');
end;

function TUniversalJWTSignatureVerifier.Verify(const ASigningInput: string;
  const ASignatureBytes: TBytes; const APublicKeyJWK: TJSONObject;
  const AAlg: string): Boolean;
begin
  if AAlg.Trim.IsEmpty then
    raise EIAM4DSecurityValidationException.Create('Algorithm cannot be empty');

  if IsRSAAlgorithm(AAlg) then
  begin
    Result := FRSAVerifier.Verify(ASigningInput, ASignatureBytes, APublicKeyJWK, AAlg);
  end
  else
  begin
    raise EIAM4DSecurityValidationException.CreateFmt(
      'Unsupported JWT algorithm: %s. Supported algorithms: RS256, RS384, RS512, PS256, PS384, PS512.',
      [AAlg]);
  end;
end;

end.