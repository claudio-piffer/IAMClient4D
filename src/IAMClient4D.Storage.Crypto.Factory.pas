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
/// This factory allows selecting the underlying cryptographic library
/// (LockBox3 AES-CBC+HMAC or TMS AES-GCM) for token storage encryption.
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
  /// This factory creates providers for token storage encryption.
  /// <para>
  /// <b>LockBox3 (default):</b> AES-256-CBC + HMAC-SHA256 - always available.
  /// </para>
  /// <para>
  /// <b>TMS:</b> AES-256-GCM - requires IAM4D_TMS define and TMS library.
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
    /// <param name="AType">Type of provider to create (default: scpLockBox3)</param>
    /// <returns>Interface to the storage crypto provider (reference counted)</returns>
    /// <exception cref="EArgumentException">If key is not 32 bytes or scpCustom is specified</exception>
    /// <exception cref="ENotSupportedException">If TMS is requested but IAM4D_TMS is not defined</exception>
    class function CreateProvider(
      const AKey32: TBytes;
      AType: TIAM4DStorageCryptoProviderType = scpLockBox3
    ): IIAM4DStorageCryptoProvider; static;

    /// <summary>
    /// Checks if a provider type is available at runtime.
    /// </summary>
    /// <param name="AType">Provider type to check</param>
    /// <returns>True if the provider is available, False otherwise</returns>
    /// <remarks>
    /// LockBox3 is always available. TMS is only available when IAM4D_TMS is defined.
    /// Custom providers are always considered "available" (user must provide instance).
    /// </remarks>
    class function IsProviderAvailable(
      AType: TIAM4DStorageCryptoProviderType
    ): Boolean; static;

    /// <summary>
    /// Returns the algorithm name for the specified provider type.
    /// </summary>
    /// <param name="AType">Provider type</param>
    /// <returns>Algorithm name (e.g., 'AES-256-CBC-HMAC-SHA256', 'AES-256-GCM')</returns>
    class function GetAlgorithmName(
      AType: TIAM4DStorageCryptoProviderType
    ): string; static;
  end;

implementation

uses
  IAMClient4D.Storage.Crypto.LockBox3
  {$IFDEF IAM4D_TMS}
  , IAMClient4D.Storage.Crypto.TMS
  {$ENDIF};

{ TIAM4DStorageCryptoProviderFactory }

class function TIAM4DStorageCryptoProviderFactory.CreateProvider(
  const AKey32: TBytes;
  AType: TIAM4DStorageCryptoProviderType): IIAM4DStorageCryptoProvider;
begin
  if Length(AKey32) <> 32 then
    raise EArgumentException.Create('Key must be exactly 32 bytes');

  case AType of
    scpLockBox3:
      Result := TIAM4DLockBox3StorageCryptoProvider.Create(AKey32);

    scpTMS:
      {$IFDEF IAM4D_TMS}
      Result := TIAM4DTMSStorageCryptoProvider.Create(AKey32);
      {$ELSE}
      raise ENotSupportedException.Create(
        'TMS Cryptography Pack provider is not available. ' +
        'Define IAM4D_TMS in IAMClient4D.Config.inc and ensure TMS library is installed. ' +
        'Use scpLockBox3 (default) or provide a custom IIAM4DStorageCryptoProvider.');
      {$ENDIF}

    scpCustom:
      raise EArgumentException.Create(
        'scpCustom requires a custom IIAM4DStorageCryptoProvider instance. ' +
        'Instantiate your custom provider directly instead of using the factory.');
  else
    // Default fallback to LockBox3
    Result := TIAM4DLockBox3StorageCryptoProvider.Create(AKey32);
  end;
end;

class function TIAM4DStorageCryptoProviderFactory.IsProviderAvailable(
  AType: TIAM4DStorageCryptoProviderType): Boolean;
begin
  case AType of
    scpLockBox3:
      Result := True;

    scpTMS:
      {$IFDEF IAM4D_TMS}
      Result := True;
      {$ELSE}
      Result := False;
      {$ENDIF}

    scpCustom:
      Result := True;
  else
    Result := False;
  end;
end;

class function TIAM4DStorageCryptoProviderFactory.GetAlgorithmName(
  AType: TIAM4DStorageCryptoProviderType): string;
begin
  case AType of
    scpLockBox3:
      Result := 'AES-256-CBC-HMAC-SHA256';

    scpTMS:
      Result := 'AES-256-GCM';

    scpCustom:
      Result := 'Custom';
  else
    Result := 'Unknown';
  end;
end;

end.