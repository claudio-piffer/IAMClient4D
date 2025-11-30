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
  /// JWKS source type enumeration.
  /// </summary>
  TJWKSSourceType = (
    jsstNone,
    jsstURL,
    jsstFile);

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
    /// - Returns nil if key not found (no exception thrown for missing keys in some implementations).
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
  /// JWT validator interface for token validation.
  /// </summary>
  /// <remarks>
  /// Validates JWT tokens including signature, expiry, issuer, and audience.
  /// JWKS source: Configurable from URL or file.
  /// Clock skew: Configurable tolerance for time-based validations (default: 30 seconds).
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
    /// Configures JWKS retrieval from URL with cache duration.
    /// </summary>
    procedure ConfigureJWKSFromURL(const AJWKS_URL: string; const ACacheDurationMinutes: Integer = 5);

    /// <summary>
    /// Configures JWKS from local file path.
    /// </summary>
    procedure ConfigureJWKSFromFile(const AJWKS_FilePath: string);

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

implementation

end.