{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Storage.Crypto.Factory.pas
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

{$I IAMClient4D.Config.inc}

/// <summary>
/// Factory for creating storage crypto provider instances.
/// </summary>
/// <remarks>
/// The crypto provider is selected at compile-time based on IAM4D_TMS define.
/// LockBox3 and TMS are mutually exclusive - only one is compiled at a time.
/// </remarks>
unit IAMClient4D.Storage.Crypto.Factory;

interface

uses
  System.SysUtils,
  IAMClient4D.Storage.Crypto.Interfaces;

type
  /// <summary>
  /// Factory for creating storage crypto provider instances.
  /// </summary>
  /// <remarks>
  /// The crypto provider is selected at compile-time based on IAM4D_TMS define.
  /// <para>
  /// <b>LockBox3 (default):</b> AES-256-CBC + HMAC-SHA256
  /// </para>
  /// <para>
  /// <b>TMS:</b> AES-256-GCM (requires IAM4D_TMS define)
  /// </para>
  /// <para>
  /// <b>Thread-safety:</b> Each call creates a new provider instance.
  /// </para>
  /// </remarks>
  TIAM4DStorageCryptoProviderFactory = class
  public
    /// <summary>
    /// Creates a storage crypto provider of the specified type.
    /// </summary>
    /// <param name="AKey32">32-byte encryption key</param>
    /// <param name="AType">Type of provider to create (default: scpDefault)</param>
    /// <returns>Interface to the storage crypto provider (reference counted)</returns>
    /// <exception cref="EArgumentException">If key is not 32 bytes or scpCustom is specified</exception>
    class function CreateProvider(
      const AKey32: TBytes;
      AType: TIAM4DStorageCryptoProviderType = scpDefault
    ): IIAM4DStorageCryptoProvider; static;

    /// <summary>
    /// Returns the algorithm name for the default provider.
    /// </summary>
    /// <returns>'AES-256-CBC-HMAC-SHA256' for LockBox3, 'AES-256-GCM' for TMS</returns>
    class function GetDefaultAlgorithmName: string; static;

    /// <summary>
    /// Returns the name of the default provider for this build configuration.
    /// </summary>
    /// <returns>'LockBox3' or 'TMS Cryptography Pack' depending on defines</returns>
    class function GetDefaultProviderName: string; static;
  end;

implementation

uses
  {$IFDEF IAM4D_CRYPTO_LOCKBOX3}
  IAMClient4D.Storage.Crypto.LockBox3;
  {$ENDIF}
  {$IFDEF IAM4D_CRYPTO_TMS}
  IAMClient4D.Storage.Crypto.TMS;
  {$ENDIF}

{ TIAM4DStorageCryptoProviderFactory }

class function TIAM4DStorageCryptoProviderFactory.CreateProvider(
  const AKey32: TBytes;
  AType: TIAM4DStorageCryptoProviderType): IIAM4DStorageCryptoProvider;
begin
  if Length(AKey32) <> 32 then
    raise EArgumentException.Create('Key must be exactly 32 bytes');

  case AType of
    scpDefault:
      {$IFDEF IAM4D_CRYPTO_TMS}
      Result := TIAM4DTMSStorageCryptoProvider.Create(AKey32);
      {$ELSE}
      Result := TIAM4DLockBox3StorageCryptoProvider.Create(AKey32);
      {$ENDIF}

    scpCustom:
      raise EArgumentException.Create(
        'scpCustom requires a custom IIAM4DStorageCryptoProvider instance. ' +
        'Instantiate your custom provider directly instead of using the factory.');
  else
    // Default fallback
    {$IFDEF IAM4D_CRYPTO_TMS}
    Result := TIAM4DTMSStorageCryptoProvider.Create(AKey32);
    {$ELSE}
    Result := TIAM4DLockBox3StorageCryptoProvider.Create(AKey32);
    {$ENDIF}
  end;
end;

class function TIAM4DStorageCryptoProviderFactory.GetDefaultAlgorithmName: string;
begin
  {$IFDEF IAM4D_CRYPTO_TMS}
  Result := 'AES-256-GCM';
  {$ELSE}
  Result := 'AES-256-CBC-HMAC-SHA256';
  {$ENDIF}
end;

class function TIAM4DStorageCryptoProviderFactory.GetDefaultProviderName: string;
begin
  {$IFDEF IAM4D_CRYPTO_TMS}
  Result := 'TMS Cryptography Pack';
  {$ELSE}
  Result := 'LockBox3';
  {$ENDIF}
end;

end.