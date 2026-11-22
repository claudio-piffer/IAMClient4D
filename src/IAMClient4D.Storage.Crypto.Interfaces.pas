{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Storage.Crypto.Interfaces.pas
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

/// <summary>
/// Interfaces and types for pluggable storage encryption providers.
/// </summary>
/// <remarks>
/// This unit defines the abstraction layer for token storage encryption,
/// allowing different crypto implementations (LockBox3, TMS, TaurusTLS) to be used
/// interchangeably via the factory pattern.
/// </remarks>
unit IAMClient4D.Storage.Crypto.Interfaces;

interface

uses
  System.SysUtils,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// Available storage crypto provider types.
  /// </summary>
  /// <remarks>
  /// The crypto provider is selected at compile-time (IAM4D_TMS / IAM4D_TAURUSTLS defines).
  /// LockBox3, TMS and TaurusTLS are mutually exclusive - only one is compiled at a time.
  /// <para>
  /// <b>LockBox3:</b> AES-256-CBC + HMAC-SHA256 (default)
  /// </para>
  /// <para>
  /// <b>TMS:</b> AES-256-GCM (requires IAM4D_TMS define)
  /// </para>
  /// <para>
  /// <b>TaurusTLS:</b> AES-256-GCM via OpenSSL (requires IAM4D_TAURUSTLS define)
  /// </para>
  /// </remarks>
  TIAM4DStorageCryptoProviderType = (
    /// <summary>
    /// Default provider based on compilation defines (LockBox3, TMS or TaurusTLS).
    /// </summary>
    scpDefault,

    /// <summary>
    /// Custom provider - user must provide IIAM4DStorageCryptoProvider instance.
    /// Use this when you need a custom encryption implementation.
    /// </summary>
    scpCustom);

  /// <summary>
  /// Storage crypto provider interface for encryption/decryption operations.
  /// </summary>
  /// <remarks>
  /// This interface abstracts symmetric encryption for token storage.
  /// <para>
  /// <b>LockBox3 provider:</b> AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
  /// Frame format: [IV seed 8 bytes][Ciphertext][HMAC Tag 32 bytes]
  /// </para>
  /// <para>
  /// <b>TMS and TaurusTLS providers:</b> AES-256-GCM (Authenticated Encryption with Associated Data)
  /// Frame format: [Nonce 12 bytes][Ciphertext][Tag 16 bytes]
  /// </para>
  /// <para>
  /// <b>Thread-safety:</b> not required: TIAM4DAESMemoryTokenStorageRawKey32 serializes its calls.
  /// Create one instance per storage; share it across threads only if the implementation allows it (TaurusTLS).
  /// </para>
  /// <para>
  /// <b>Memory:</b> Implementations must securely wipe sensitive data on Destroy.
  /// </para>
  /// </remarks>
  IIAM4DStorageCryptoProvider = interface
    ['{87717FEE-6EC6-46CB-A01D-F506BD9603C5}']

    /// <summary>
    /// Encrypts plaintext with optional additional authenticated data.
    /// </summary>
    /// <param name="APlaintext">Data to encrypt</param>
    /// <param name="AAAD">Additional authenticated data (included in authentication but not encrypted)</param>
    /// <returns>Encrypted blob (format is provider-specific, includes IV/nonce and auth tag)</returns>
    /// <exception cref="EIAM4DStorageCryptoException">If encryption fails</exception>
    function Encrypt(const APlaintext, AAAD: TBytes): TBytes;

    /// <summary>
    /// Decrypts ciphertext with optional additional authenticated data.
    /// </summary>
    /// <param name="ACiphertext">Encrypted blob from Encrypt</param>
    /// <param name="AAAD">Additional authenticated data (must match Encrypt call)</param>
    /// <returns>Decrypted plaintext</returns>
    /// <exception cref="EIAM4DStorageCryptoException">If decryption or authentication fails</exception>
    function Decrypt(const ACiphertext, AAAD: TBytes): TBytes;

    /// <summary>
    /// Returns the provider name for identification/logging purposes.
    /// </summary>
    /// <returns>Provider name (e.g., 'LockBox3', 'TMS Cryptography Pack')</returns>
    function GetProviderName: string;

    /// <summary>
    /// Returns the algorithm identifier string.
    /// </summary>
    /// <returns>Algorithm name (e.g., 'AES-256-CBC-HMAC-SHA256', 'AES-256-GCM')</returns>
    function GetAlgorithm: string;
  end;

  /// <summary>
  /// Base exception for storage crypto operations.
  /// </summary>
  /// <remarks>
  /// An EIAM4DException: ErrorCode is ecStorageEncryptionFailed or ecStorageDecryptionFailed for the
  /// two descendants, ecUnknown for the base class.
  /// </remarks>
  EIAM4DStorageCryptoException = class(EIAM4DException)
  private
    FProviderName: string;
  protected
    /// <summary>
    /// Copy constructor used by Clone: copies ProviderName too.
    /// </summary>
    constructor CreateCopy(ASource: EIAM4DException); override;
    /// <summary>ErrorCode of the exceptions of this class</summary>
    class function DefaultErrorCode: TIAM4DErrorCode; virtual;
  public
    /// <summary>
    /// Creates exception with message.
    /// </summary>
    constructor Create(const AMessage: string); overload;

    /// <summary>
    /// Creates exception with provider name and reason.
    /// </summary>
    constructor Create(const AProviderName, AReason: string); overload;

    /// <summary>
    /// Returns an independent copy (same class, message, error code and provider name).
    /// </summary>
    /// <remarks>
    /// Async.Core copies it through the cloner of EIAM4DException: WaitForResult keeps ProviderName.
    /// </remarks>
    function Clone: EIAM4DStorageCryptoException;

    /// <summary>
    /// Name of the crypto provider that raised the exception.
    /// </summary>
    property ProviderName: string read FProviderName;
  end;

  EIAM4DStorageCryptoExceptionClass = class of EIAM4DStorageCryptoException;

  /// <summary>
  /// Exception raised when storage encryption fails.
  /// </summary>
  EIAM4DStorageEncryptionException = class(EIAM4DStorageCryptoException)
  protected
    class function DefaultErrorCode: TIAM4DErrorCode; override;
  end;

  /// <summary>
  /// Exception raised when storage decryption or authentication fails.
  /// </summary>
  /// <remarks>
  /// This exception indicates either:
  /// - The ciphertext was tampered with
  /// - The AAD does not match
  /// - The key is incorrect
  /// - The data is corrupted
  /// </remarks>
  EIAM4DStorageDecryptionException = class(EIAM4DStorageCryptoException)
  protected
    class function DefaultErrorCode: TIAM4DErrorCode; override;
  end;

implementation

{ EIAM4DStorageCryptoException }

constructor EIAM4DStorageCryptoException.Create(const AMessage: string);
begin
  inherited Create(AMessage, DefaultErrorCode);
  FProviderName := '';
end;

constructor EIAM4DStorageCryptoException.Create(const AProviderName, AReason: string);
begin
  inherited Create(Format('[%s] %s', [AProviderName, AReason]), DefaultErrorCode);
  FProviderName := AProviderName;
end;

constructor EIAM4DStorageCryptoException.CreateCopy(ASource: EIAM4DException);
begin
  inherited CreateCopy(ASource);
  if ASource is EIAM4DStorageCryptoException then
    FProviderName := EIAM4DStorageCryptoException(ASource).FProviderName;
end;

class function EIAM4DStorageCryptoException.DefaultErrorCode: TIAM4DErrorCode;
begin
  Result := ecUnknown;
end;

function EIAM4DStorageCryptoException.Clone: EIAM4DStorageCryptoException;
begin
  Result := inherited Clone as EIAM4DStorageCryptoException;
end;

{ EIAM4DStorageEncryptionException }

class function EIAM4DStorageEncryptionException.DefaultErrorCode: TIAM4DErrorCode;
begin
  Result := ecStorageEncryptionFailed;
end;

{ EIAM4DStorageDecryptionException }

class function EIAM4DStorageDecryptionException.DefaultErrorCode: TIAM4DErrorCode;
begin
  Result := ecStorageDecryptionFailed;
end;

end.