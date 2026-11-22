{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.Core.pas
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

unit IAMClient4D.Security.Core;

interface

uses
  System.SysUtils,
  System.JSON,
  IAMClient4D.Common.Security,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// JWT signature verifier interface.
  /// </summary>
  /// <remarks>
  /// Verifies JWT signatures using public keys from JWK format.
  /// Supports RS256, RS384, RS512, ES256, ES384, ES512 algorithms.
  /// Thread-safety: Implementation should be thread-safe for concurrent verification.
  /// </remarks>
  IIAM4DJWTSignatureVerifier = interface
    ['{83EEFAAD-6ECE-4832-B4BD-A752818E99F4}']
    /// <summary>
    /// Verifies JWT signature using public key JWK and specified algorithm.
    /// </summary>
    function Verify(const ASigningInput: string; const ASignatureBytes: TBytes; const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;

    /// <summary>
    /// Returns array of supported algorithm names (e.g., 'RS256', 'RS384', 'RS512').
    /// </summary>
    function GetSupportedAlgorithms: TArray<string>;
  end;

  /// <summary>
  /// JWKS provider interface for retrieving public keys.
  /// </summary>
  /// <remarks>
  /// Fetches public keys from JWKS endpoints with caching support.
  /// Cache: Configurable TTL to reduce network requests.
  /// Manual keys: Allows static key configuration for testing.
  /// SSL validation: Configurable for JWKS URL fetching.
  /// Thread-safety: Implementation should handle concurrent key requests.
  /// </remarks>
  IIAM4DJWKSProvider = interface
    ['{07E824C4-203C-4F02-9C80-8E55DC93C379}']
    /// <summary>
    /// Retrieves a COPY of the public key JWK for specified issuer and key ID.
    /// </summary>
    /// <remarks>
    /// OWNERSHIP CONTRACT:
    /// - The CALLER owns the returned TJSONObject and MUST free it.
    /// - Implementation MUST always return a new instance (Clone/Copy), never cached references.
    /// - A missing key: TIAM4DJWKSProvider raises EIAM4DJWKSKeyNotFoundException; other
    ///   implementations may return nil, which the validator also treats as a missing key.
    /// </remarks>
    /// <returns>
    /// New TJSONObject instance containing the public key, or nil if not found.
    /// CALLER MUST FREE the returned object when non-nil.
    /// </returns>
    /// <exception cref="EIAM4DSecurityValidationException">
    /// Raised if discovery/fetch fails or key not found (implementation-dependent).
    /// </exception>
    function GetPublicKey(const AIssuer, AKeyId: string): TJSONObject;

    /// <summary>
    /// Sets a manual public key for specified issuer and key ID (for testing/static configuration).
    /// </summary>
    /// <remarks>
    /// OWNERSHIP CONTRACT:
    /// - This method takes a COPY of APublicKeyJWK. Caller retains ownership of the original.
    /// - Caller CAN free APublicKeyJWK after this method returns.
    /// - Implementation MUST clone the input before storing.
    /// </remarks>
    /// <param name="AIssuer">Issuer URL (will be normalized by removing trailing slash)</param>
    /// <param name="AKeyId">Key ID from JWT header</param>
    /// <param name="APublicKeyJWK">Public key in JWK format (will be cloned internally)</param>
    procedure SetManualKey(const AIssuer, AKeyId: string; const APublicKeyJWK: TJSONObject);

    /// <summary>
    /// Clears all cached JWKS entries.
    /// </summary>
    procedure ClearCache;

    /// <summary>
    /// Sets cache time-to-live in seconds.
    /// </summary>
    procedure SetCacheTTL(ASeconds: Integer);

    /// <summary>
    /// Sets SSL validation mode for JWKS URL fetching.
    /// </summary>
    procedure SetSSLValidationMode(AMode: TIAM4DSSLValidationMode);
  end;

  /// <summary>
  /// Optional for a JWKS provider: the key of a kid that also fits the algorithm of the token.
  /// RFC 7517 4.5 lets keys of different types share a kid; the validator uses this interface
  /// when the provider supports it, GetPublicKey otherwise.
  /// </summary>
  IIAM4DJWKSKeySelector = interface
    ['{F063B73E-F353-4FD3-9C92-7236EE211DE7}']
    /// <summary>
    /// Like GetPublicKey, restricted to the keys whose type fits AAlg (RS*/PS*: RSA; ES256,
    /// ES384, ES512: EC on P-256, P-384, P-521). CALLER MUST FREE the returned object.
    /// </summary>
    function GetPublicKeyForAlg(const AIssuer, AKeyId, AAlg: string): TJSONObject;
  end;

  /// <summary>
  /// JWT validator interface for token validation.
  /// </summary>
  /// <remarks>
  /// Validates JWT tokens including signature, expiry, issuer, and audience.
  /// JWKS source: Configurable from URL or file.
  /// Clock skew: Configurable tolerance for time-based validations (TIAM4DJWTValidator default:
  /// 5 seconds; TIAM4DJWTMiddlewareConfig default: 60 seconds).
  /// Claims: Returns parsed claims on successful validation.
  /// Thread-safety: Implementation should support concurrent validations.
  /// Caller owns returned AClaims TJSONObject - must free after use.
  /// </remarks>
  IIAM4DJWTValidator = interface
    ['{1AF364CB-C18B-43EE-8719-AC774A4CF393}']
    /// <summary>
    /// Validates JWT token and returns claims if valid.
    /// </summary>
    function ValidateToken(const AToken: string; out AClaims: TJSONObject): Boolean;

    /// <summary>
    /// Returns clock skew tolerance in seconds.
    /// </summary>
    function GetClockSkewSeconds: Integer;
    /// <summary>
    /// Sets clock skew tolerance in seconds.
    /// </summary>
    procedure SetClockSkewSeconds(const AValue: Integer);
    property ClockSkewSeconds: Integer read GetClockSkewSeconds write SetClockSkewSeconds;

    /// <summary>
    /// Returns expected issuer for token validation.
    /// </summary>
    function GetExpectedIssuer: string;
    property ExpectedIssuer: string read GetExpectedIssuer;

    /// <summary>
    /// Returns expected audience for token validation.
    /// </summary>
    function GetExpectedAudience: string;
    property ExpectedAudience: string read GetExpectedAudience;

    /// <summary>
    /// Returns expected authorized party (azp) for token validation.
    /// </summary>
    function GetExpectedAzp: string;
    property ExpectedAzp: string read GetExpectedAzp;
  end;

  /// <summary>
  /// Optional advanced configuration interface for JWT validators.
  /// </summary>
  /// <remarks>
  /// This interface is intentionally separate from IIAM4DJWTValidator to avoid
  /// breaking third-party validator implementations that only support the base
  /// validation contract.
  /// </remarks>
  IIAM4DJWTValidatorConfigurable = interface
    ['{55D1470D-8BFF-4B94-B76B-615F69048CC7}']
    /// <summary>
    /// Returns whether audience (aud) validation is enabled.
    /// </summary>
    function GetAudienceValidationEnabled: Boolean;

    /// <summary>
    /// Enables/disables audience (aud) validation.
    /// </summary>
    procedure SetAudienceValidationEnabled(const AValue: Boolean);

    /// <summary>
    /// Sets expected Client ID in azp claim (empty string = not validated).
    /// </summary>
    procedure SetExpectedAzp(const AValue: string);

    /// <summary>
    /// Requires azp claim when aud contains multiple audiences (default: True, per OIDC specification).
    /// Ignored when audience validation is disabled.
    /// </summary>
    procedure SetRequireAzpWhenMultipleAud(const AValue: Boolean);

    property AudienceValidationEnabled: Boolean read GetAudienceValidationEnabled write SetAudienceValidationEnabled;
  end;

implementation

end.
