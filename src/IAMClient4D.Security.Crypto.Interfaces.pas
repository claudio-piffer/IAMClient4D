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
  /// The crypto provider is selected at compile-time (IAM4D_TMS / IAM4D_TAURUSTLS defines).
  /// LockBox3, TMS and TaurusTLS are mutually exclusive - only one is compiled at a time.
  /// Use cpDefault for automatic selection based on compilation defines.
  /// </remarks>
  TIAM4DCryptoProviderType = (
    /// <summary>Default provider based on compilation defines (LockBox3, TMS or TaurusTLS)</summary>
    cpDefault,
    /// <summary>Custom provider - user must provide IIAM4DCryptoProvider instance</summary>
    cpCustom);

  /// <summary>
  /// Cryptographic provider interface for signature verification operations.
  /// </summary>
  /// <remarks>
  /// This interface abstracts the underlying cryptographic library (LockBox3, TMS, TaurusTLS, etc.)
  /// allowing different implementations without changing the JWT verification logic.
  ///
  /// Each provider should implement all algorithms it can support.
  /// For unsupported operations, raise EIAM4DCryptoNotSupportedException.
  ///
  /// RSA keys failing TIAM4DRSAPublicKey.IsValid and signatures not exactly k bytes long are rejected.
  ///
  /// Thread-safety: implementations must be safe for concurrent use: TIAM4DJWTValidator shares
  /// one verifier, and so one provider, across threads. The built-in providers are.
  /// </remarks>
  IIAM4DCryptoProvider = interface
    ['{B7E8F3A1-4C2D-4E5F-9A8B-1C3D5E7F9A2B}']

    /// <summary>
    /// Verifies an ECDSA signature.
    /// </summary>
    /// <param name="AHash">Digest of the message with the curve hash (RFC 7518 3.4): 32, 48, 64 bytes</param>
    /// <param name="AR">R component of the signature, full coordinate size (32, 48, 66 bytes)</param>
    /// <param name="AS_">S component of the signature, full coordinate size</param>
    /// <param name="AX">X coordinate of the public key, full coordinate size</param>
    /// <param name="AY">Y coordinate of the public key, full coordinate size</param>
    /// <param name="ACurve">Elliptic curve used</param>
    /// <returns>True if signature is valid, False otherwise (also for any other size)</returns>
    /// <exception cref="EIAM4DCryptoNotSupportedException">If ECDSA is not supported by this provider</exception>
    function ECDSAVerify(const AHash, AR, AS_, AX, AY: TBytes;
      ACurve: TIAM4DECCurve): Boolean;

    /// <summary>
    /// Verifies an RSA PKCS#1 v1.5 signature.
    /// </summary>
    /// <param name="AExpectedEM">Expected encoded message (EMSA-PKCS1-v1_5 encoded)</param>
    /// <param name="ASignature">Signature bytes, exactly k bytes (modulus size)</param>
    /// <param name="AModulus">RSA modulus (n) as big-endian bytes</param>
    /// <param name="AExponent">RSA public exponent (e) as big-endian bytes</param>
    /// <returns>True if signature is valid, False otherwise</returns>
    function RSAVerifyPKCS1(const AExpectedEM, ASignature, AModulus, AExponent: TBytes): Boolean;

    /// <summary>
    /// Verifies an RSA-PSS signature.
    /// </summary>
    /// <param name="AMessage">Original message bytes (will be hashed internally)</param>
    /// <param name="ASignature">Signature bytes, exactly k bytes (modulus size)</param>
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
  /// Optional ECDSA extension for providers that hash the message themselves.
  /// </summary>
  /// <remarks>
  /// Queried with Supports on the IIAM4DCryptoProvider instance: when implemented,
  /// the ECDSA JWT verifier passes the signing input instead of calling ECDSAVerify with its digest.
  /// Hash by curve: P-256 SHA-256, P-384 SHA-384, P-521 SHA-512 (RFC 7518 3.4).
  /// </remarks>
  IIAM4DECDSAMessageVerifier = interface
    ['{A5054484-AF87-496C-88A9-C3DE718FBEB4}']

    /// <summary>
    /// Verifies an ECDSA signature over a message, hashed by the provider.
    /// </summary>
    /// <param name="AMessage">Message bytes (not hashed)</param>
    /// <param name="AR">R component of the signature, full coordinate size</param>
    /// <param name="AS_">S component of the signature, full coordinate size</param>
    /// <param name="AX">X coordinate of the public key</param>
    /// <param name="AY">Y coordinate of the public key</param>
    /// <param name="ACurve">Elliptic curve used</param>
    /// <returns>True if signature is valid, False otherwise</returns>
    function ECDSAVerifyMessage(const AMessage, AR, AS_, AX, AY: TBytes;
      ACurve: TIAM4DECCurve): Boolean;
  end;

  /// <summary>
  /// RSA public key checks shared by the crypto providers and the RSA verifiers.
  /// </summary>
  /// <remarks>
  /// Values are unsigned big-endian (JWK n and e); leading zero bytes are ignored.
  /// Thread-safety: all members are thread-safe. MinModulusBits is process-wide:
  /// set it at startup, before tokens are validated.
  /// </remarks>
  TIAM4DRSAPublicKey = class sealed
  public const
    /// <summary>Largest modulus, in bits (OpenSSL OPENSSL_RSA_MAX_MODULUS_BITS)</summary>
    MAX_MODULUS_BITS = 16384;
    /// <summary>Default smallest modulus, in bits (RFC 7518 3.3, 4.2: 2048 bits or larger)</summary>
    DEFAULT_MIN_MODULUS_BITS = 2048;
    /// <summary>Lowest value MinModulusBits accepts, in bits</summary>
    LOWEST_MIN_MODULUS_BITS = 1024;
    /// <summary>Moduli larger than this (bits) limit the exponent to MAX_EXPONENT_BITS</summary>
    SMALL_MODULUS_BITS = 3072;
    /// <summary>Largest exponent for moduli above SMALL_MODULUS_BITS, in bits</summary>
    MAX_EXPONENT_BITS = 64;
  private
    class function GetMinModulusBits: Integer; static;
    class procedure SetMinModulusBits(AValue: Integer); static;
  public
    /// <summary>
    /// Value without its leading zero bytes.
    /// </summary>
    class function Stripped(const AValue: TBytes): TBytes; static;

    /// <summary>
    /// Modulus size k in bytes, leading zero bytes ignored: the length of every signature.
    /// </summary>
    class function ModulusSize(const AModulus: TBytes): Integer; static;

    /// <summary>
    /// True if the key can verify signatures: n odd, MinModulusBits to MAX_MODULUS_BITS;
    /// e odd, 3 &lt;= e &lt; n, at most MAX_EXPONENT_BITS when n exceeds SMALL_MODULUS_BITS.
    /// </summary>
    /// <remarks>
    /// The limits OpenSSL applies to RSA public operations, plus the RFC 7518 minimum
    /// and e odd and not 1 (with e = 1 the encoded message itself is a valid signature).
    /// </remarks>
    class function IsValid(const AModulus, AExponent: TBytes): Boolean; static;

    /// <summary>
    /// Smallest modulus accepted, in bits: RS* and PS* keys below it are rejected by every provider.
    /// </summary>
    /// <remarks>
    /// Default DEFAULT_MIN_MODULUS_BITS (2048, RFC 7518 3.3 and 4.2). Lower it only for legacy
    /// identity providers still publishing smaller keys: 1024-bit RSA is no longer considered secure.
    /// </remarks>
    /// <exception cref="EArgumentOutOfRangeException">
    /// Value outside LOWEST_MIN_MODULUS_BITS..MAX_MODULUS_BITS
    /// </exception>
    class property MinModulusBits: Integer read GetMinModulusBits write SetMinModulusBits;
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

var
  // Aligned Integer: reads and writes are atomic
  GMinModulusBits: Integer = TIAM4DRSAPublicKey.DEFAULT_MIN_MODULUS_BITS;

function LeadingZeroBytes(const AValue: TBytes): Integer;
begin
  Result := 0;
  while (Result < Length(AValue)) and (AValue[Result] = 0) do
    Inc(Result);
end;

// Bit length of a value without leading zero bytes
function BitLength(const AValue: TBytes): Integer;
var
  LTop: Byte;
begin
  if Length(AValue) = 0 then
    Exit(0);

  Result := (Length(AValue) - 1) * 8;
  LTop := AValue[0];
  while LTop <> 0 do
  begin
    Inc(Result);
    LTop := LTop shr 1;
  end;
end;

{ TIAM4DRSAPublicKey }

class function TIAM4DRSAPublicKey.Stripped(const AValue: TBytes): TBytes;
begin
  Result := Copy(AValue, LeadingZeroBytes(AValue), MaxInt);
end;

class function TIAM4DRSAPublicKey.ModulusSize(const AModulus: TBytes): Integer;
begin
  Result := Length(AModulus) - LeadingZeroBytes(AModulus);
end;

class function TIAM4DRSAPublicKey.IsValid(const AModulus, AExponent: TBytes): Boolean;
var
  LN, LE: TBytes;
  LModulusBits: Integer;
  I: Integer;
begin
  Result := False;
  LN := Stripped(AModulus);
  LE := Stripped(AExponent);
  if (Length(LN) = 0) or (Length(LE) = 0) then
    Exit;

  if not Odd(LN[High(LN)]) or not Odd(LE[High(LE)]) or ((Length(LE) = 1) and (LE[0] = 1)) then
    Exit;

  LModulusBits := BitLength(LN);
  if (LModulusBits < GetMinModulusBits) or (LModulusBits > MAX_MODULUS_BITS) then
    Exit;
  if (LModulusBits > SMALL_MODULUS_BITS) and (BitLength(LE) > MAX_EXPONENT_BITS) then
    Exit;

  // e < n
  if Length(LE) <> Length(LN) then
    Exit(Length(LE) < Length(LN));
  for I := 0 to High(LN) do
    if LE[I] <> LN[I] then
      Exit(LE[I] < LN[I]);
end;

class function TIAM4DRSAPublicKey.GetMinModulusBits: Integer;
begin
  Result := GMinModulusBits;
end;

class procedure TIAM4DRSAPublicKey.SetMinModulusBits(AValue: Integer);
begin
  if (AValue < LOWEST_MIN_MODULUS_BITS) or (AValue > MAX_MODULUS_BITS) then
    raise EArgumentOutOfRangeException.CreateFmt(
      'MinModulusBits must be between %d and %d bits (got %d)',
      [LOWEST_MIN_MODULUS_BITS, MAX_MODULUS_BITS, AValue]);
  AtomicExchange(GMinModulusBits, AValue);
end;

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