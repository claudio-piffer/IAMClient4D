{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Storage.Core.pas
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

unit IAMClient4D.Storage.Core;

interface

uses
  System.SysUtils,
  IAMClient4D.Core,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// Token storage interface for OAuth2 token persistence.
  /// </summary>
  /// <remarks>
  /// Abstraction: Allows different storage implementations (memory, file, database, etc.).
  /// Encryption: Implementations should encrypt sensitive token data.
  /// Validation: Provides token expiry validation without decryption (if possible).
  /// Thread-safety: Implementation-specific - check concrete class documentation.
  /// Lifecycle: Save tokens after successful auth, load for API calls, clear on logout.
  /// </remarks>
  IIAM4DTokenStorage = interface(IInterface)
    ['{45558823-10A9-4D7C-BA15-72CD2207F728}']
    /// <summary>
    /// Saves OAuth2 tokens to storage.
    /// </summary>
    procedure SaveTokens(const Tokens: TIAM4DTokens);

    /// <summary>
    /// Loads OAuth2 tokens from storage.
    /// </summary>
    function LoadTokens: TIAM4DTokens;

    /// <summary>
    /// Clears all stored tokens.
    /// </summary>
    procedure ClearTokens;

    /// <summary>
    /// Returns true if tokens exist in storage.
    /// </summary>
    function HasTokens: Boolean;

    /// <summary>
    /// Returns true if access token is valid (not expired).
    /// </summary>
    function IsAccessTokenValid: Boolean;

    /// <summary>
    /// Returns true if refresh token is valid (not expired).
    /// </summary>
    function IsRefreshTokenValid: Boolean;
  end;

implementation

end.