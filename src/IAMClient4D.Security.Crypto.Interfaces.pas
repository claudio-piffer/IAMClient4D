{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.Crypto.Interfaces.pas
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

unit IAMClient4D.Security.Crypto.Interfaces;

interface

uses
  System.SysUtils;

type
  /// <summary>
  /// Elliptic curves supported for ECDSA operations.
  /// </summary>
  TIAM4DECCurve = (
    /// <summary>NIST P-256 curve (secp256r1) - used by ES256</summary>
    eccP256,
    /// <summary>NIST P-384 curve (secp384r1) - used by ES384</summary>
    eccP384,
    /// <summary>NIST P-521 curve (secp521r1) - used by ES512</summary>
    eccP521);

  /// <summary>
  /// Hash algorithm for cryptographic operations.
  /// </summary>
  TIAM4DHashAlgorithm = (
    /// <summary>SHA-256 (256 bits / 32 bytes)</summary>
    haSHA256,
    /// <summary>SHA-384 (384 bits / 48 bytes)</summary>
    haSHA384,
    /// <summary>SHA-512 (512 bits / 64 bytes)</summary>
    haSHA512);

  /// <summary>
  /// Available cryptographic provider types.
  /// </summary>
  /// <remarks>
  /// Used by TIAM4DCryptoProviderFactory and TIAM4DJWTValidatorFactory
  /// to select the underlying cryptographic library.
  /// </remarks>
  TIAM4DCryptoProviderType = (
    /// <summary>LockBox3 crypto provider (default, integrated)</summary>
    cpLockBox3,
    /// <summary>TMS Cryptography Pack (future implementation)</summary>
    cpTMS,
    /// <summary>Custom provider - user must provide IIAM4DCryptoProvider instance</summary>
    cpCustom);

  /// <summary>
  /// Cryptographic provider interface for signature verification operations.
  /// </summary>
  /// <remarks>
  /// This interface abstracts the underlying cryptographic library (LockBox3, TMS, etc.)
  /// allowing different implementations without changing the JWT verification logic.
  ///
  /// Each provider should implement all algorithms it can support.
  /// For unsupported operations, raise EIAM4DCryptoNotSupportedException.
  ///
  /// Thread-safety: Create separate instance per thread (not thread-safe).
  /// </remarks>
  IIAM4DCryptoProvider = interface
    ['{B7E8F3A1-4C2D-4E5F-9A8B-1C3D5E7F9A2B}']

    /// <summary>
    /// Verifies an ECDSA signature.
    /// </summary>
    /// <param name="AHash">Hash of the message to verify</param>
    /// <param name="AR">R component of the signature</param>
    /// <param name="AS_">S component of the signature</param>
    /// <param name="AX">X coordinate of the public key</param>
    /// <param name="AY">Y coordinate of the public key</param>
    /// <param name="ACurve">Elliptic curve used</param>
    /// <returns>True if signature is valid, False otherwise</returns>
    /// <exception cref="EIAM4DCryptoNotSupportedException">If ECDSA is not supported by this provider</exception>
    function ECDSAVerify(const AHash, AR, AS_, AX, AY: TBytes;
      ACurve: TIAM4DECCurve): Boolean;

    /// <summary>
    /// Verifies an RSA PKCS#1 v1.5 signature.
    /// </summary>
    /// <param name="AExpectedEM">Expected encoded message (EMSA-PKCS1-v1_5 encoded)</param>
    /// <param name="ASignature">Signature bytes</param>
    /// <param name="AModulus">RSA modulus (n) as big-endian bytes</param>
    /// <param name="AExponent">RSA public exponent (e) as big-endian bytes</param>
    /// <returns>True if signature is valid, False otherwise</returns>
    function RSAVerifyPKCS1(const AExpectedEM, ASignature, AModulus, AExponent: TBytes): Boolean;

    /// <summary>
    /// Verifies an RSA-PSS signature.
    /// </summary>
    /// <param name="AMessage">Original message bytes (will be hashed internally)</param>
    /// <param name="ASignature">Signature bytes</param>
    /// <param name="AModulus">RSA modulus (n) as big-endian bytes</param>
    /// <param name="AExponent">RSA public exponent (e) as big-endian bytes</param>
    /// <param name="AHashAlg">Hash algorithm to use</param>
    /// <param name="ASaltLen">Salt length in bytes (typically same as hash length)</param>
    /// <returns>True if signature is valid, False otherwise</returns>
    function RSAVerifyPSS(const AMessage, ASignature, AModulus, AExponent: TBytes;
      AHashAlg: TIAM4DHashAlgorithm; ASaltLen: Integer): Boolean;

    /// <summary>
    /// Returns array of supported JWT algorithm names.
    /// </summary>
    /// <returns>Array of algorithm strings (e.g., 'RS256', 'PS384', 'ES512')</returns>
    function GetSupportedAlgorithms: TArray<string>;

    /// <summary>
    /// Checks if a specific algorithm is supported by this provider.
    /// </summary>
    /// <param name="AAlg">Algorithm name (e.g., 'RS256', 'ES384')</param>
    /// <returns>True if algorithm is supported, False otherwise</returns>
    function SupportsAlgorithm(const AAlg: string): Boolean;

    /// <summary>
    /// Returns the provider name for identification/logging purposes.
    /// </summary>
    function GetProviderName: string;
  end;

  /// <summary>
  /// Exception raised when a cryptographic operation is not supported by the provider.
  /// </summary>
  EIAM4DCryptoNotSupportedException = class(Exception)
  public
    constructor Create(const AMessage: string); overload;
    constructor Create(const AOperation, AProvider: string); overload;
  end;

implementation

{ EIAM4DCryptoNotSupportedException }

constructor EIAM4DCryptoNotSupportedException.Create(const AMessage: string);
begin
  inherited Create(AMessage);
end;

constructor EIAM4DCryptoNotSupportedException.Create(const AOperation, AProvider: string);
begin
  inherited CreateFmt('Operation "%s" is not supported by crypto provider "%s"', [AOperation, AProvider]);
end;

end.