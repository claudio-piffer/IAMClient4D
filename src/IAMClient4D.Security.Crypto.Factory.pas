{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.Crypto.Factory.pas
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

unit IAMClient4D.Security.Crypto.Factory;

interface

uses
  System.SysUtils,
  IAMClient4D.Security.Crypto.Interfaces;

type
  /// <summary>
  /// Factory for creating cryptographic provider instances.
  /// </summary>
  /// <remarks>
  /// The crypto provider is selected at compile-time based on IAM4D_TMS define.
  /// LockBox3 and TMS are mutually exclusive - only one is compiled at a time.
  ///
  /// Thread-safety: Each call creates a new provider instance.
  /// </remarks>
  TIAM4DCryptoProviderFactory = class
  public
    /// <summary>
    /// Creates a crypto provider of the specified type.
    /// </summary>
    /// <param name="AType">Type of crypto provider to create (default: cpDefault)</param>
    /// <returns>Interface to the crypto provider (reference counted)</returns>
    /// <exception cref="EArgumentException">
    /// Raised if cpCustom is specified (use direct instantiation instead).
    /// </exception>
    class function CreateProvider(
      AType: TIAM4DCryptoProviderType = cpDefault
    ): IIAM4DCryptoProvider; static;

    /// <summary>
    /// Returns the name of the default provider for this build configuration.
    /// </summary>
    /// <returns>'LockBox3' or 'TMS Cryptography Pack' depending on defines</returns>
    class function GetDefaultProviderName: string; static;
  end;

implementation

uses
  {$IFDEF IAM4D_CRYPTO_LOCKBOX3}
  IAMClient4D.Security.Crypto.LockBox3;
  {$ENDIF}
  {$IFDEF IAM4D_CRYPTO_TMS}
  IAMClient4D.Security.Crypto.TMS;
  {$ENDIF}

{ TIAM4DCryptoProviderFactory }

class function TIAM4DCryptoProviderFactory.CreateProvider(
  AType: TIAM4DCryptoProviderType): IIAM4DCryptoProvider;
begin
  case AType of
    cpDefault:
      {$IFDEF IAM4D_CRYPTO_TMS}
      Result := TIAM4DTMSCryptoProvider.Create;
      {$ELSE}
      Result := TIAM4DLockBox3CryptoProvider.Create;
      {$ENDIF}

    cpCustom:
      raise EArgumentException.Create(
        'cpCustom requires a custom IIAM4DCryptoProvider instance. ' +
        'Use direct instantiation instead.');
  else
    // Default fallback
    {$IFDEF IAM4D_CRYPTO_TMS}
    Result := TIAM4DTMSCryptoProvider.Create;
    {$ELSE}
    Result := TIAM4DLockBox3CryptoProvider.Create;
    {$ENDIF}
  end;
end;

class function TIAM4DCryptoProviderFactory.GetDefaultProviderName: string;
begin
  {$IFDEF IAM4D_CRYPTO_TMS}
  Result := 'TMS Cryptography Pack';
  {$ELSE}
  Result := 'LockBox3';
  {$ENDIF}
end;

end.