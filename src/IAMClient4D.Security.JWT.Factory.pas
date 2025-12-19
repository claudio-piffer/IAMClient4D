{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.JWT.Factory.pas
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

unit IAMClient4D.Security.JWT.Factory;

interface

uses
  System.SysUtils,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.Crypto.Interfaces,
  IAMClient4D.Core,
  IAMClient4D.Common.Security;

type
  /// <summary>
  /// Factory for creating IIAM4DJWTValidator instances.
  /// </summary>
  /// <remarks>
  /// Returns interface references for automatic lifetime management via reference counting.
  /// Supports pluggable crypto providers (LockBox3, TMS, custom implementations).
  ///
  /// Usage patterns:
  /// - Simple: CreateValidator(issuer, audience) - uses LockBox3
  /// - With provider type: CreateValidator(issuer, audience, cpLockBox3)
  /// - With custom provider: CreateValidator(issuer, audience, myProvider)
  /// - With JWKS provider: CreateValidator(issuer, audience, jwksProvider)
  ///
  /// Thread-safety: Each call creates a new validator instance.
  /// </remarks>
  TIAM4DJWTValidatorFactory = class
  public
    // =========================================================================
    // Basic methods (use LockBox3 by default)
    // =========================================================================

    /// <summary>
    /// Creates JWT validator with default settings (LockBox3, strict SSL).
    /// </summary>
    /// <param name="AExpectedIssuer">Expected token issuer URL</param>
    /// <param name="AExpectedAudience">Expected token audience</param>
    /// <param name="ASSLValidationMode">SSL validation mode (default: strict)</param>
    /// <returns>Interface to the JWT validator (reference counted)</returns>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict
    ): IIAM4DJWTValidator; overload; static;

    /// <summary>
    /// Creates JWT validator with custom HTTP configuration.
    /// </summary>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const AHTTPConfig: TIAM4DHTTPClientConfig
    ): IIAM4DJWTValidator; overload; static;

    // =========================================================================
    // Methods with crypto provider selection
    // =========================================================================

    /// <summary>
    /// Creates JWT validator with specified crypto provider type.
    /// </summary>
    /// <param name="AExpectedIssuer">Expected token issuer URL</param>
    /// <param name="AExpectedAudience">Expected token audience</param>
    /// <param name="ACryptoProviderType">Crypto provider type (cpLockBox3, cpTMS)</param>
    /// <param name="ASSLValidationMode">SSL validation mode (default: strict)</param>
    /// <returns>Interface to the JWT validator (reference counted)</returns>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const ACryptoProviderType: TIAM4DCryptoProviderType;
      const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict
    ): IIAM4DJWTValidator; overload; static;

    /// <summary>
    /// Creates JWT validator with custom crypto provider instance.
    /// </summary>
    /// <param name="AExpectedIssuer">Expected token issuer URL</param>
    /// <param name="AExpectedAudience">Expected token audience</param>
    /// <param name="ACryptoProvider">Custom crypto provider implementation</param>
    /// <param name="ASSLValidationMode">SSL validation mode (default: strict)</param>
    /// <returns>Interface to the JWT validator (reference counted)</returns>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const ACryptoProvider: IIAM4DCryptoProvider;
      const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict
    ): IIAM4DJWTValidator; overload; static;

    /// <summary>
    /// Creates JWT validator with crypto provider type and HTTP configuration.
    /// </summary>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const ACryptoProviderType: TIAM4DCryptoProviderType;
      const AHTTPConfig: TIAM4DHTTPClientConfig
    ): IIAM4DJWTValidator; overload; static;

    /// <summary>
    /// Creates JWT validator with custom crypto provider and HTTP configuration.
    /// </summary>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const ACryptoProvider: IIAM4DCryptoProvider;
      const AHTTPConfig: TIAM4DHTTPClientConfig
    ): IIAM4DJWTValidator; overload; static;

    // =========================================================================
    // Methods with JWKS provider
    // =========================================================================

    /// <summary>
    /// Creates JWT validator with shared JWKS provider (for caching optimization).
    /// </summary>
    /// <param name="AExpectedIssuer">Expected token issuer URL</param>
    /// <param name="AExpectedAudience">Expected token audience</param>
    /// <param name="AJWKSProvider">Shared JWKS provider instance</param>
    /// <param name="ASSLValidationMode">SSL validation mode (default: strict)</param>
    /// <returns>Interface to the JWT validator (reference counted)</returns>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const AJWKSProvider: IIAM4DJWKSProvider;
      const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict
    ): IIAM4DJWTValidator; overload; static;

    /// <summary>
    /// Creates JWT validator with custom crypto provider and shared JWKS provider.
    /// </summary>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const ACryptoProvider: IIAM4DCryptoProvider;
      const AJWKSProvider: IIAM4DJWKSProvider;
      const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict
    ): IIAM4DJWTValidator; overload; static;

    /// <summary>
    /// Creates JWT validator with crypto provider type and shared JWKS provider.
    /// </summary>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const ACryptoProviderType: TIAM4DCryptoProviderType;
      const AJWKSProvider: IIAM4DJWKSProvider;
      const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict
    ): IIAM4DJWTValidator; overload; static;

    /// <summary>
    /// Creates JWT validator with JWKS provider and HTTP configuration.
    /// </summary>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const AJWKSProvider: IIAM4DJWKSProvider;
      const AHTTPConfig: TIAM4DHTTPClientConfig
    ): IIAM4DJWTValidator; overload; static;

    /// <summary>
    /// Creates fully customized JWT validator with all options.
    /// </summary>
    class function CreateValidator(
      const AExpectedIssuer, AExpectedAudience: string;
      const ACryptoProvider: IIAM4DCryptoProvider;
      const AJWKSProvider: IIAM4DJWKSProvider;
      const AHTTPConfig: TIAM4DHTTPClientConfig
    ): IIAM4DJWTValidator; overload; static;
  end;

implementation

uses
  IAMClient4D.Security.JWT,
  IAMClient4D.Security.JWT.Verifiers.Universal,
  IAMClient4D.Security.Crypto.Factory;

{ TIAM4DJWTValidatorFactory }

// =============================================================================
// Basic methods
// =============================================================================

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const ASSLValidationMode: TIAM4DSSLValidationMode): IIAM4DJWTValidator;
begin
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, ASSLValidationMode);
end;

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const AHTTPConfig: TIAM4DHTTPClientConfig): IIAM4DJWTValidator;
begin
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, AHTTPConfig);
end;

// =============================================================================
// Methods with crypto provider selection
// =============================================================================

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const ACryptoProviderType: TIAM4DCryptoProviderType;
  const ASSLValidationMode: TIAM4DSSLValidationMode): IIAM4DJWTValidator;
var
  LCryptoProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
begin
  LCryptoProvider := TIAM4DCryptoProviderFactory.CreateProvider(ACryptoProviderType);
  LVerifier := TUniversalJWTSignatureVerifier.Create(LCryptoProvider);
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, LVerifier, ASSLValidationMode);
end;

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const ACryptoProvider: IIAM4DCryptoProvider;
  const ASSLValidationMode: TIAM4DSSLValidationMode): IIAM4DJWTValidator;
var
  LVerifier: IIAM4DJWTSignatureVerifier;
begin
  LVerifier := TUniversalJWTSignatureVerifier.Create(ACryptoProvider);
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, LVerifier, ASSLValidationMode);
end;

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const ACryptoProviderType: TIAM4DCryptoProviderType;
  const AHTTPConfig: TIAM4DHTTPClientConfig): IIAM4DJWTValidator;
var
  LCryptoProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
begin
  LCryptoProvider := TIAM4DCryptoProviderFactory.CreateProvider(ACryptoProviderType);
  LVerifier := TUniversalJWTSignatureVerifier.Create(LCryptoProvider);
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, LVerifier, AHTTPConfig);
end;

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const ACryptoProvider: IIAM4DCryptoProvider;
  const AHTTPConfig: TIAM4DHTTPClientConfig): IIAM4DJWTValidator;
var
  LVerifier: IIAM4DJWTSignatureVerifier;
begin
  LVerifier := TUniversalJWTSignatureVerifier.Create(ACryptoProvider);
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, LVerifier, AHTTPConfig);
end;

// =============================================================================
// Methods with JWKS provider
// =============================================================================

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const ASSLValidationMode: TIAM4DSSLValidationMode): IIAM4DJWTValidator;
begin
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, AJWKSProvider, ASSLValidationMode);
end;

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const ACryptoProvider: IIAM4DCryptoProvider;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const ASSLValidationMode: TIAM4DSSLValidationMode): IIAM4DJWTValidator;
var
  LVerifier: IIAM4DJWTSignatureVerifier;
  LHTTPConfig: TIAM4DHTTPClientConfig;
begin
  LVerifier := TUniversalJWTSignatureVerifier.Create(ACryptoProvider);
  LHTTPConfig := TIAM4DHTTPClientConfig.Create(30000, 60000, ASSLValidationMode);
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, LVerifier, AJWKSProvider, LHTTPConfig);
end;

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const ACryptoProviderType: TIAM4DCryptoProviderType;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const ASSLValidationMode: TIAM4DSSLValidationMode): IIAM4DJWTValidator;
var
  LCryptoProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
  LHTTPConfig: TIAM4DHTTPClientConfig;
begin
  LCryptoProvider := TIAM4DCryptoProviderFactory.CreateProvider(ACryptoProviderType);
  LVerifier := TUniversalJWTSignatureVerifier.Create(LCryptoProvider);
  LHTTPConfig := TIAM4DHTTPClientConfig.Create(30000, 60000, ASSLValidationMode);
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, LVerifier, AJWKSProvider, LHTTPConfig);
end;

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const AHTTPConfig: TIAM4DHTTPClientConfig): IIAM4DJWTValidator;
begin
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, AJWKSProvider, AHTTPConfig);
end;

class function TIAM4DJWTValidatorFactory.CreateValidator(
  const AExpectedIssuer, AExpectedAudience: string;
  const ACryptoProvider: IIAM4DCryptoProvider;
  const AJWKSProvider: IIAM4DJWKSProvider;
  const AHTTPConfig: TIAM4DHTTPClientConfig): IIAM4DJWTValidator;
var
  LVerifier: IIAM4DJWTSignatureVerifier;
begin
  LVerifier := TUniversalJWTSignatureVerifier.Create(ACryptoProvider);
  Result := TIAM4DJWTValidator.Create(AExpectedIssuer, AExpectedAudience, LVerifier, AJWKSProvider, AHTTPConfig);
end;

end.