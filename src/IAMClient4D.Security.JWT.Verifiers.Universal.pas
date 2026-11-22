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
  IAMClient4D.Security.Core,
  IAMClient4D.Security.Crypto.Interfaces;

type
  /// <summary>
  /// Universal JWT signature verifier supporting multiple algorithms.
  /// </summary>
  /// <remarks>
  /// Automatically delegates to appropriate verifier based on algorithm.
  /// Supported algorithms:
  /// - RS256, RS384, RS512 (RSA with PKCS#1 v1.5)
  /// - PS256, PS384, PS512 (RSA-PSS with SHA-2)
  /// - ES256, ES384, ES512 (ECDSA, requires a provider supporting it, TMS or TaurusTLS)
  /// Algorithm names are case-sensitive (RFC 7515 4.1.1): any other value, "none" and HS*
  /// included, and algorithms not supported by the crypto provider raise EIAM4DSecurityValidationException.
  /// Crypto provider: Configurable for different cryptographic backends.
  /// Thread-safety: safe for concurrent verification when the crypto provider is (all built-in
  /// providers are): TIAM4DJWTValidator shares one instance across threads.
  /// </remarks>
  TUniversalJWTSignatureVerifier = class(TInterfacedObject, IIAM4DJWTSignatureVerifier)
  private
    FCryptoProvider: IIAM4DCryptoProvider;
    FRSAVerifier: IIAM4DJWTSignatureVerifier;
    FRSAPSSVerifier: IIAM4DJWTSignatureVerifier;
    FECDSAVerifier: IIAM4DJWTSignatureVerifier;

    function IsRSAPKCS1Algorithm(const AAlg: string): Boolean;
    function IsRSAPSSAlgorithm(const AAlg: string): Boolean;
    function IsECDSAAlgorithm(const AAlg: string): Boolean;

    procedure InitializeVerifiers;
  public
    /// <summary>
    /// Creates universal verifier with default crypto provider (based on compilation defines).
    /// </summary>
    constructor Create; overload;

    /// <summary>
    /// Creates universal verifier with specified crypto provider.
    /// </summary>
    /// <param name="ACryptoProvider">Crypto provider for signature operations</param>
    constructor Create(const ACryptoProvider: IIAM4DCryptoProvider); overload;

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

    /// <summary>
    /// Returns the crypto provider used by this verifier.
    /// </summary>
    property CryptoProvider: IIAM4DCryptoProvider read FCryptoProvider;
  end;

implementation

uses
  IAMClient4D.Security.JWT.Verifiers.RSA,
  IAMClient4D.Security.JWT.Verifiers.RSAPSS,
  IAMClient4D.Security.JWT.Verifiers.ECDSA,
  IAMClient4D.Security.Crypto.Factory,
  IAMClient4D.Exceptions;

{ TUniversalJWTSignatureVerifier }

constructor TUniversalJWTSignatureVerifier.Create;
begin
  Create(TIAM4DCryptoProviderFactory.CreateProvider);
end;

constructor TUniversalJWTSignatureVerifier.Create(const ACryptoProvider: IIAM4DCryptoProvider);
begin
  inherited Create;
  FCryptoProvider := ACryptoProvider;
  InitializeVerifiers;
end;

procedure TUniversalJWTSignatureVerifier.InitializeVerifiers;
begin
  FRSAVerifier := TRSAJWTSignatureVerifier.Create(FCryptoProvider);
  FRSAPSSVerifier := TRSAPSSJWTSignatureVerifier.Create(FCryptoProvider);
  FECDSAVerifier := TECDSAJWTSignatureVerifier.Create(FCryptoProvider);
end;

destructor TUniversalJWTSignatureVerifier.Destroy;
begin
  FRSAVerifier := nil;
  FRSAPSSVerifier := nil;
  FECDSAVerifier := nil;
  FCryptoProvider := nil;
  inherited;
end;

function TUniversalJWTSignatureVerifier.GetSupportedAlgorithms: TArray<string>;
begin
  Result := FCryptoProvider.GetSupportedAlgorithms;
end;

// Algorithm names are case-sensitive (RFC 7515 4.1.1)

function TUniversalJWTSignatureVerifier.IsRSAPKCS1Algorithm(const AAlg: string): Boolean;
begin
  Result := (AAlg = 'RS256') or
            (AAlg = 'RS384') or
            (AAlg = 'RS512');
end;

function TUniversalJWTSignatureVerifier.IsRSAPSSAlgorithm(const AAlg: string): Boolean;
begin
  Result := (AAlg = 'PS256') or
            (AAlg = 'PS384') or
            (AAlg = 'PS512');
end;

function TUniversalJWTSignatureVerifier.IsECDSAAlgorithm(const AAlg: string): Boolean;
begin
  Result := (AAlg = 'ES256') or
            (AAlg = 'ES384') or
            (AAlg = 'ES512');
end;

function TUniversalJWTSignatureVerifier.Verify(const ASigningInput: string;
  const ASignatureBytes: TBytes; const APublicKeyJWK: TJSONObject;
  const AAlg: string): Boolean;
begin
  if AAlg.Trim.IsEmpty then
    raise EIAM4DSecurityValidationException.Create('Algorithm cannot be empty');

  if not (IsRSAPKCS1Algorithm(AAlg) or IsRSAPSSAlgorithm(AAlg) or IsECDSAAlgorithm(AAlg)) or
     not FCryptoProvider.SupportsAlgorithm(AAlg) then
    raise EIAM4DSecurityValidationException.CreateFmt(
      'Unsupported JWT algorithm: %s. Supported algorithms (%s): %s.',
      [AAlg, FCryptoProvider.GetProviderName, string.Join(', ', FCryptoProvider.GetSupportedAlgorithms)]);

  if IsRSAPKCS1Algorithm(AAlg) then
  begin
    // RS256, RS384, RS512 - RSA with PKCS#1 v1.5 padding
    Result := FRSAVerifier.Verify(ASigningInput, ASignatureBytes, APublicKeyJWK, AAlg);
  end
  else if IsRSAPSSAlgorithm(AAlg) then
  begin
    // PS256, PS384, PS512 - RSA-PSS with SHA-2
    Result := FRSAPSSVerifier.Verify(ASigningInput, ASignatureBytes, APublicKeyJWK, AAlg);
  end
  else
  begin
    // ES256, ES384, ES512 - ECDSA
    Result := FECDSAVerifier.Verify(ASigningInput, ASignatureBytes, APublicKeyJWK, AAlg);
  end;
end;

end.