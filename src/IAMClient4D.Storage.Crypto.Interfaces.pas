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
/// allowing different crypto implementations (LockBox3, TMS) to be used
/// interchangeably via the factory pattern.
/// </remarks>
unit IAMClient4D.Storage.Crypto.Interfaces;

interface

uses
  System.SysUtils;

type
  /// <summary>
  /// Available storage crypto provider types.
  /// </summary>
  /// <remarks>
  /// The crypto provider is selected at compile-time based on IAM4D_TMS define.
  /// LockBox3 and TMS are mutually exclusive - only one is compiled at a time.
  /// <para>
  /// <b>LockBox3:</b> AES-256-CBC + HMAC-SHA256 (default)
  /// </para>
  /// <para>
  /// <b>TMS:</b> AES-256-GCM (requires IAM4D_TMS define)
  /// </para>
  /// </remarks>
  TIAM4DStorageCryptoProviderType = (
    /// <summary>
    /// Default provider based on compilation defines (LockBox3 or TMS).
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
  /// Frame format: [IV 16 bytes][Ciphertext][HMAC Tag 32 bytes]
  /// </para>
  /// <para>
  /// <b>TMS provider:</b> AES-256-GCM (Authenticated Encryption with Associated Data)
  /// Frame format: [Nonce 12 bytes][Ciphertext][Tag 16 bytes]
  /// </para>
  /// <para>
  /// <b>Thread-safety:</b> Create separate instance per storage (not thread-safe).
  /// </para>
  /// <para>
  /// <b>Memory:</b> Implementations must securely wipe sensitive data on Destroy.
  /// </para>
  /// </remarks>
  IIAM4DStorageCryptoProvider = interface
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']

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
  EIAM4DStorageCryptoException = class(Exception)
  private
    FProviderName: string;
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
    /// Name of the crypto provider that raised the exception.
    /// </summary>
    property ProviderName: string read FProviderName;
  end;

  /// <summary>
  /// Exception raised when storage encryption fails.
  /// </summary>
  EIAM4DStorageEncryptionException = class(EIAM4DStorageCryptoException);

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
  EIAM4DStorageDecryptionException = class(EIAM4DStorageCryptoException);

implementation

{ EIAM4DStorageCryptoException }

constructor EIAM4DStorageCryptoException.Create(const AMessage: string);
begin
  inherited Create(AMessage);
  FProviderName := '';
end;

constructor EIAM4DStorageCryptoException.Create(const AProviderName, AReason: string);
begin
  inherited CreateFmt('[%s] %s', [AProviderName, AReason]);
  FProviderName := AProviderName;
end;

end.