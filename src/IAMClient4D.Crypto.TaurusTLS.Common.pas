{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Crypto.TaurusTLS.Common.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2026 Claudio Piffer
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
/// OpenSSL runtime shared by the TaurusTLS crypto providers.
/// </summary>
/// <remarks>
/// Compiles as an empty stub unless IAM4D_TAURUSTLS is defined.
/// </remarks>
unit IAMClient4D.Crypto.TaurusTLS.Common;

{$I IAMClient4D.Config.inc}

{$IFDEF IAM4D_CRYPTO_TAURUSTLS}
interface

uses
  System.SysUtils,
  IAMClient4D.Exceptions;

const
  /// <summary>
  /// Minimum supported OpenSSL version (3.0.0).
  /// </summary>
  IAM4D_OPENSSL_MIN_VERSION = $30000000;

type
  /// <summary>
  /// Raised when OpenSSL cannot be loaded or is older than 3.0 (ErrorCode ecCryptoProviderUnavailable).
  /// </summary>
  EIAM4DOpenSSLException = class(EIAM4DException)
  public
    constructor Create(const AMessage: string); reintroduce;
  end;

  /// <summary>
  /// OpenSSL loading, version and error helpers.
  /// </summary>
  /// <remarks>
  /// TaurusTLS loads libcrypto and libssl together: both must be deployed.
  /// Thread-safety: all members are thread-safe.
  /// </remarks>
  TIAM4DOpenSSL = class sealed
  private
    class var FLock: TObject;
    class var FLoaded: Boolean;
    class var FLibraryPath: string;
    class constructor Create;
    class destructor Destroy;
    class function DecodeVersion(AVersion: Cardinal): string; static;
  public
    /// <summary>
    /// Loads OpenSSL on first call and checks the version.
    /// </summary>
    /// <remarks>
    /// Once loaded, calls take no lock.
    /// </remarks>
    /// <exception cref="EIAM4DOpenSSLException">Libraries not found or older than 3.0</exception>
    class procedure EnsureLoaded; static;

    /// <summary>
    /// Version number in OPENSSL_VERSION_NUMBER format.
    /// </summary>
    class function VersionNumber: Cardinal; static;

    /// <summary>
    /// Version as "major.minor.patch".
    /// </summary>
    class function VersionText: string; static;

    /// <summary>
    /// Drains the calling thread's OpenSSL error queue into a message.
    /// </summary>
    class function LastErrorMessage: string; static;

    /// <summary>
    /// Folder of libcrypto/libssl. Empty: OPENSSL_LIBRARY_PATH or OS search path.
    /// </summary>
    /// <remarks>
    /// Effective only if set before OpenSSL is loaded.
    /// </remarks>
    class property LibraryPath: string read FLibraryPath write FLibraryPath;
  end;

implementation

uses
  IdCTypes,
  TaurusTLSLoader,
  TaurusTLSHeaders_crypto,
  TaurusTLSHeaders_err;

{ EIAM4DOpenSSLException }

constructor EIAM4DOpenSSLException.Create(const AMessage: string);
begin
  inherited Create(AMessage, ecCryptoProviderUnavailable);
end;

{ TIAM4DOpenSSL }

class constructor TIAM4DOpenSSL.Create;
begin
  FLock := TObject.Create;
end;

class destructor TIAM4DOpenSSL.Destroy;
begin
  FreeAndNil(FLock);
end;

class function TIAM4DOpenSSL.DecodeVersion(AVersion: Cardinal): string;
begin
  // 3.x+ layout: MNN00PP0L
  Result := Format('%d.%d.%d',
    [AVersion shr 28, (AVersion shr 20) and $FF, (AVersion shr 4) and $FF]);
end;

class procedure TIAM4DOpenSSL.EnsureLoaded;
var
  LLoader: IOpenSSLLoader;
  LVersion: Cardinal;
begin
  // Double-checked: FLoaded is set once, after a barrier, and never cleared
  if FLoaded then
  begin
    // Acquire: later reads see what the loading thread wrote before FLoaded
    MemoryBarrier;
    Exit;
  end;

  TMonitor.Enter(FLock);
  try
    if FLoaded then
      Exit;

    // nil in the static link model: libcrypto is already bound
    LLoader := GetOpenSSLLoader;
    if Assigned(LLoader) then
    begin
      if (FLibraryPath <> '') and not LLoader.IsLoaded then
        LLoader.OpenSSLPath := FLibraryPath;

      try
        if not LLoader.Load then
          raise EIAM4DOpenSSLException.Create(Format(
            'Unable to load OpenSSL libcrypto/libssl (path: "%s")', [LLoader.OpenSSLPath]));
      except
        on E: EIAM4DOpenSSLException do
          raise;
        on E: Exception do
          raise EIAM4DOpenSSLException.Create('Unable to load OpenSSL: ' + E.Message);
      end;
    end;

    LVersion := Cardinal(OpenSSL_version_num());
    if LVersion < IAM4D_OPENSSL_MIN_VERSION then
      raise EIAM4DOpenSSLException.Create(Format(
        'OpenSSL %s is not supported: 3.0 or later required', [DecodeVersion(LVersion)]));

    // Release: the loaded state is visible to the fast path before FLoaded
    MemoryBarrier;
    FLoaded := True;
  finally
    TMonitor.Exit(FLock);
  end;
end;

class function TIAM4DOpenSSL.VersionNumber: Cardinal;
begin
  EnsureLoaded;
  Result := Cardinal(OpenSSL_version_num());
end;

class function TIAM4DOpenSSL.VersionText: string;
begin
  Result := DecodeVersion(VersionNumber);
end;

class function TIAM4DOpenSSL.LastErrorMessage: string;
var
  LCode: TIdC_ULONG;
  LBuffer: array[0..255] of AnsiChar;
begin
  Result := '';
  LCode := ERR_get_error();
  while LCode <> 0 do
  begin
    ERR_error_string_n(LCode, @LBuffer[0], Length(LBuffer));
    if Result <> '' then
      Result := Result + '; ';
    Result := Result + string(AnsiString(PAnsiChar(@LBuffer[0])));
    LCode := ERR_get_error();
  end;

  if Result = '' then
    Result := 'no OpenSSL error details';
end;

{$ELSE}
// Unit is empty when TaurusTLS is not the active provider (mutual exclusivity)
interface
implementation
{$ENDIF}

end.
