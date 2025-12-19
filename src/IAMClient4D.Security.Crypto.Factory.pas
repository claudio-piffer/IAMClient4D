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
  /// This factory allows selecting the underlying cryptographic library
  /// (LockBox3, TMS, etc.) without changing client code.
  /// All methods return interface references for automatic lifetime management.
  ///
  /// Thread-safety: Each call creates a new provider instance.
  /// </remarks>
  TIAM4DCryptoProviderFactory = class
  public
    /// <summary>
    /// Creates a crypto provider of the specified type.
    /// </summary>
    /// <param name="AType">Type of crypto provider to create (default: cpLockBox3)</param>
    /// <returns>Interface to the crypto provider (reference counted)</returns>
    /// <exception cref="EIAM4DCryptoNotSupportedException">
    /// Raised if the requested provider type is not yet implemented.
    /// </exception>
    /// <exception cref="EArgumentException">
    /// Raised if cpCustom is specified (use direct instantiation instead).
    /// </exception>
    class function CreateProvider(
      AType: TIAM4DCryptoProviderType = cpLockBox3
    ): IIAM4DCryptoProvider; static;
  end;

implementation

uses
  IAMClient4D.Security.Crypto.LockBox3
  {$IFDEF IAM4D_TMS}
  , IAMClient4D.Security.Crypto.TMS
  {$ENDIF};

{ TIAM4DCryptoProviderFactory }

class function TIAM4DCryptoProviderFactory.CreateProvider(
  AType: TIAM4DCryptoProviderType): IIAM4DCryptoProvider;
begin
  case AType of
    cpLockBox3:
      Result := TIAM4DLockBox3CryptoProvider.Create;

    cpTMS:
      {$IFDEF IAM4D_TMS}
      Result := TIAM4DTMSCryptoProvider.Create;
      {$ELSE}
      raise EIAM4DCryptoNotSupportedException.Create(
        'TMS Cryptography Pack provider is not available. ' +
        'Define IAM4D_TMS in IAMClient4D.Config.inc and ensure TMS library is installed. ' +
        'Use cpLockBox3 or provide a custom IIAM4DCryptoProvider.');
      {$ENDIF}

    cpCustom:
      raise EArgumentException.Create(
        'cpCustom requires a custom IIAM4DCryptoProvider instance. ' +
        'Use CreateValidator with ACryptoProvider parameter instead.');
  else
    // Default fallback to LockBox3
    Result := TIAM4DLockBox3CryptoProvider.Create;
  end;
end;

end.