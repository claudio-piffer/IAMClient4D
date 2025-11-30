{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Builder.pas
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

unit IAMClient4D.Config.Builder;

interface

uses
  System.SysUtils,
  System.Classes,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.Storage.Core,
  IAMClient4D.Common.Security;

type
  /// <summary>
  /// Token storage encryption type
  /// </summary>
  TIAM4DStorageType = (
    stIAMClient4DAES);

  /// <summary>
  /// Fluent builder for IAM client configuration.
  /// </summary>
  /// <remarks>
  /// Usage: Call ForAuthorizationCode() or ForClientCredentials() first to initialize.
  /// Chain With* methods to configure options, then call Build/BuildAsync/BuildAndWait.
  /// Default storage: AES-256-GCM with auto-generated key.
  /// </remarks>
  IIAM4DClientConfigBuilder = interface
    ['{436CC253-634B-452D-9471-B2EA31105C51}']

    /// <summary>
    /// Gets current configuration
    /// </summary>
    function GetConfig: TIAM4DClientConfig;
    property Config: TIAM4DClientConfig read GetConfig;

    /// <summary>
    /// Configures for Authorization Code flow
    /// </summary>
    function ForAuthorizationCode(const ABaseURL, ARealm, AClientID: string): IIAM4DClientConfigBuilder;
    /// <summary>
    /// Configures for Client Credentials flow
    /// </summary>
    function ForClientCredentials(const ABaseURL, ARealm, AClientID, AClientSecret: string): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Uses AES-256-GCM encrypted storage with auto-generated key
    /// </summary>
    function WithIAMClient4DAESStorage: IIAM4DClientConfigBuilder; overload;
    /// <summary>
    /// Uses AES-256-GCM encrypted storage with provided key
    /// </summary>
    function WithIAMClient4DAESStorage(const AKey32: TBytes; const AAAD: TBytes = nil): IIAM4DClientConfigBuilder; overload;
    /// <summary>
    /// Uses custom token storage implementation
    /// </summary>
    function WithCustomStorage(const AStorage: IIAM4DTokenStorage): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Sets OAuth2 scopes
    /// </summary>
    function WithScopes(const AScopes: TArray<string>): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Uses external callback URL for Authorization Code flow
    /// </summary>
    function WithExternalCallback(const ACallbackURL: string): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Enables strict SSL validation
    /// </summary>
    function WithStrictSSL: IIAM4DClientConfigBuilder;
    /// <summary>
    /// Allows self-signed SSL certificates
    /// </summary>
    function WithAllowSelfSignedSSL: IIAM4DClientConfigBuilder;
    /// <summary>
    /// Sets pinned public key hashes for certificate pinning
    /// </summary>
    function WithPinnedPublicKeys(const APublicKeyHashes: TArray<string>): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Sets connection and response timeouts in milliseconds
    /// </summary>
    function WithTimeouts(const AConnectionTimeoutMs, AResponseTimeoutMs: Integer): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Sets token expiration buffer in seconds (default: 120 seconds)
    /// </summary>
    function WithTokenExpiryBuffer(const ABufferSeconds: Integer): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Builds and configures the client synchronously
    /// </summary>
    function Build: IIAM4DClient;
    /// <summary>
    /// Builds and configures the client asynchronously
    /// </summary>
    function BuildAsync: IAsyncPromise<IIAM4DClient>;
  end;

  /// <summary>
  /// Implementation of IAM client builder.
  /// </summary>
  /// <remarks>
  /// Thread-safety: Not thread-safe. Use one instance per thread.
  /// Memory: Sensitive data (keys, passwords) is zeroed in destructor.
  /// Validation: Build methods validate configuration before creating client.
  /// </remarks>
  TIAM4DClientConfigBuilder = class(TInterfacedObject, IIAM4DClientConfigBuilder)
  private
    FConfig: TIAM4DClientConfig;
    FConfigInitialized: Boolean;

    FStorageType: TIAM4DStorageType;
    FStorageKey32: TBytes;
    FStorageAAD: TBytes;
    FStoragePassword: string;
    FCustomStorage: IIAM4DTokenStorage;

    FCallbackMode: TIAM4DCallbackMode;

    FPinnedPublicKeys: TArray<string>;

    procedure EnsureConfigInitialized;
    function CreateStorage: IIAM4DTokenStorage;
    procedure ValidateBeforeBuild;

    function GetConfig: TIAM4DClientConfig;
  public
    /// <summary>
    /// Creates a new builder instance
    /// </summary>
    class function New: IIAM4DClientConfigBuilder;

    function ForAuthorizationCode(
      const ABaseURL, ARealm, AClientID: string
      ): IIAM4DClientConfigBuilder;

    function ForClientCredentials(
      const ABaseURL, ARealm, AClientID, AClientSecret: string
      ): IIAM4DClientConfigBuilder;

    function WithIAMClient4DAESStorage: IIAM4DClientConfigBuilder; overload;

    function WithIAMClient4DAESStorage(const AKey32: TBytes; const AAAD: TBytes = nil): IIAM4DClientConfigBuilder; overload;

    function WithCustomStorage(const AStorage: IIAM4DTokenStorage): IIAM4DClientConfigBuilder;

    function WithScopes(const AScopes: TArray<string>): IIAM4DClientConfigBuilder;

    function WithExternalCallback(const ACallbackURL: string): IIAM4DClientConfigBuilder;

    function WithStrictSSL: IIAM4DClientConfigBuilder;

    function WithAllowSelfSignedSSL: IIAM4DClientConfigBuilder;

    function WithPinnedPublicKeys(const APublicKeyHashes: TArray<string>): IIAM4DClientConfigBuilder;

    function WithTimeouts(const AConnectionTimeoutMs, AResponseTimeoutMs: Integer): IIAM4DClientConfigBuilder;

    function WithTokenExpiryBuffer(const ABufferSeconds: Integer): IIAM4DClientConfigBuilder;

    function BuildAsync: IAsyncPromise<IIAM4DClient>;

    function Build: IIAM4DClient;

    destructor Destroy; override;
  end;

implementation

uses
  IAMClient4D.Common.CryptoUtils,
  IAMClient4D.Keycloak,
  IAMClient4D.Storage.AESMemoryTokenStorage;

{ TIAM4DClientConfigBuilder }

function TIAM4DClientConfigBuilder.GetConfig: TIAM4DClientConfig;
begin
  Result := FConfig;
end;

class function TIAM4DClientConfigBuilder.New: IIAM4DClientConfigBuilder;
var
  LBuilder: TIAM4DClientConfigBuilder;
begin
  LBuilder := TIAM4DClientConfigBuilder.Create;
  LBuilder.FConfigInitialized := False;
  LBuilder.FStorageType := stIAMClient4DAES;
  LBuilder.FCallbackMode := cbmLocalServer;
  LBuilder.FCustomStorage := nil;
  LBuilder.FStoragePassword := '';
  SetLength(LBuilder.FStorageKey32, 0);
  SetLength(LBuilder.FStorageAAD, 0);
  SetLength(LBuilder.FPinnedPublicKeys, 0);
  Result := LBuilder;
end;

destructor TIAM4DClientConfigBuilder.Destroy;
begin
  if Length(FStorageKey32) > 0 then
  begin
    FillChar(FStorageKey32[0], Length(FStorageKey32), 0);
    SetLength(FStorageKey32, 0);
  end;

  if Length(FStorageAAD) > 0 then
  begin
    FillChar(FStorageAAD[0], Length(FStorageAAD), 0);
    SetLength(FStorageAAD, 0);
  end;

  FStoragePassword := '';
  FCustomStorage := nil;

  inherited;
end;

procedure TIAM4DClientConfigBuilder.EnsureConfigInitialized;
begin
  if not FConfigInitialized then
    raise EArgumentException.Create(
      'Configuration not initialized. Call ForAuthorizationCode() or ForClientCredentials() first.');
end;

function TIAM4DClientConfigBuilder.ForAuthorizationCode(
  const ABaseURL, ARealm, AClientID: string): IIAM4DClientConfigBuilder;
begin
  FConfig := TIAM4DClientConfig.CreateForAuthorizationCode(
    ABaseURL,
    ARealm,
    AClientID);

  FConfigInitialized := True;
  FCallbackMode := cbmLocalServer;
  Result := Self;
end;

function TIAM4DClientConfigBuilder.ForClientCredentials(
  const ABaseURL, ARealm, AClientID, AClientSecret: string): IIAM4DClientConfigBuilder;
begin
  FConfig := TIAM4DClientConfig.CreateForClientCredentials(
    ABaseURL,
    ARealm,
    AClientID,
    AClientSecret);

  FConfigInitialized := True;
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithIAMClient4DAESStorage: IIAM4DClientConfigBuilder;
begin
  FStorageType := stIAMClient4DAES;
  FCustomStorage := nil;
  SetLength(FStorageKey32, 0);
  SetLength(FStorageAAD, 0);
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithIAMClient4DAESStorage(const AKey32: TBytes; const AAAD: TBytes): IIAM4DClientConfigBuilder;
begin
  if Length(AKey32) <> 32 then
    raise EArgumentException.Create('AES storage key must be exactly 32 bytes');

  FStorageType := stIAMClient4DAES;
  FCustomStorage := nil;
  FStorageKey32 := Copy(AKey32);
  if Length(AAAD) > 0 then
    FStorageAAD := Copy(AAAD)
  else
    SetLength(FStorageAAD, 0);
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithCustomStorage(const AStorage: IIAM4DTokenStorage): IIAM4DClientConfigBuilder;
begin
  if not Assigned(AStorage) then
    raise EArgumentNilException.Create('Custom storage cannot be nil');

  FCustomStorage := AStorage;
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithScopes(const AScopes: TArray<string>): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType = gtAuthorizationCode then
  begin
    FConfig := TIAM4DClientConfig.CreateForAuthorizationCode(
      FConfig.BaseURL,
      FConfig.Realm,
      FConfig.ClientID,
      AScopes,
      FConfig.SSLValidationMode,
      FConfig.ConnectionTimeout,
      FConfig.ResponseTimeout,
      FConfig.ExternalCallbackURL);
  end
  else if FConfig.GrantType = gtClientCredentials then
  begin
    FConfig := TIAM4DClientConfig.CreateForClientCredentials(
      FConfig.BaseURL,
      FConfig.Realm,
      FConfig.ClientID,
      FConfig.ClientSecret,
      AScopes,
      FConfig.SSLValidationMode,
      FConfig.ConnectionTimeout,
      FConfig.ResponseTimeout);
  end;

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithExternalCallback(const ACallbackURL: string): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType <> gtAuthorizationCode then
    raise EInvalidOpException.Create('External callback is only for Authorization Code flow');

  if ACallbackURL.Trim.IsEmpty then
    raise EArgumentException.Create('External callback URL cannot be empty');

  FCallbackMode := cbmExternal;

  FConfig := TIAM4DClientConfig.CreateForAuthorizationCode(
    FConfig.BaseURL,
    FConfig.Realm,
    FConfig.ClientID,
    FConfig.Scopes,
    FConfig.SSLValidationMode,
    FConfig.ConnectionTimeout,
    FConfig.ResponseTimeout,
    ACallbackURL);

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithStrictSSL: IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType = gtAuthorizationCode then
  begin
    FConfig := TIAM4DClientConfig.CreateForAuthorizationCode(
      FConfig.BaseURL,
      FConfig.Realm,
      FConfig.ClientID,
      FConfig.Scopes,
      svmStrict,
      FConfig.ConnectionTimeout,
      FConfig.ResponseTimeout,
      FConfig.ExternalCallbackURL);
  end
  else if FConfig.GrantType = gtClientCredentials then
  begin
    FConfig := TIAM4DClientConfig.CreateForClientCredentials(
      FConfig.BaseURL,
      FConfig.Realm,
      FConfig.ClientID,
      FConfig.ClientSecret,
      FConfig.Scopes,
      svmStrict,
      FConfig.ConnectionTimeout,
      FConfig.ResponseTimeout);
  end;

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithAllowSelfSignedSSL: IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType = gtAuthorizationCode then
  begin
    FConfig := TIAM4DClientConfig.CreateForAuthorizationCode(
      FConfig.BaseURL,
      FConfig.Realm,
      FConfig.ClientID,
      FConfig.Scopes,
      svmAllowSelfSigned,
      FConfig.ConnectionTimeout,
      FConfig.ResponseTimeout,
      FConfig.ExternalCallbackURL);
  end
  else if FConfig.GrantType = gtClientCredentials then
  begin
    FConfig := TIAM4DClientConfig.CreateForClientCredentials(
      FConfig.BaseURL,
      FConfig.Realm,
      FConfig.ClientID,
      FConfig.ClientSecret,
      FConfig.Scopes,
      svmAllowSelfSigned,
      FConfig.ConnectionTimeout,
      FConfig.ResponseTimeout);
  end;

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithPinnedPublicKeys(const APublicKeyHashes: TArray<string>): IIAM4DClientConfigBuilder;
begin
  FPinnedPublicKeys := Copy(APublicKeyHashes);
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithTimeouts(const AConnectionTimeoutMs, AResponseTimeoutMs: Integer): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if AConnectionTimeoutMs <= 0 then
    raise EArgumentOutOfRangeException.Create('Connection timeout must be > 0');

  if AResponseTimeoutMs <= 0 then
    raise EArgumentOutOfRangeException.Create('Response timeout must be > 0');

  if FConfig.GrantType = gtAuthorizationCode then
  begin
    FConfig := TIAM4DClientConfig.CreateForAuthorizationCode(
      FConfig.BaseURL,
      FConfig.Realm,
      FConfig.ClientID,
      FConfig.Scopes,
      FConfig.SSLValidationMode,
      AConnectionTimeoutMs,
      AResponseTimeoutMs,
      FConfig.ExternalCallbackURL);
  end
  else if FConfig.GrantType = gtClientCredentials then
  begin
    FConfig := TIAM4DClientConfig.CreateForClientCredentials(
      FConfig.BaseURL,
      FConfig.Realm,
      FConfig.ClientID,
      FConfig.ClientSecret,
      FConfig.Scopes,
      FConfig.SSLValidationMode,
      AConnectionTimeoutMs,
      AResponseTimeoutMs);
  end;

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithTokenExpiryBuffer(const ABufferSeconds: Integer): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if ABufferSeconds < 0 then
    raise EArgumentOutOfRangeException.Create('Token expiry buffer cannot be negative');

  if FConfig.GrantType = gtAuthorizationCode then
  begin
    FConfig := TIAM4DClientConfig.CreateForAuthorizationCode(
      FConfig.BaseURL,
      FConfig.Realm,
      FConfig.ClientID,
      FConfig.Scopes,
      FConfig.SSLValidationMode,
      FConfig.ConnectionTimeout,
      FConfig.ResponseTimeout,
      FConfig.ExternalCallbackURL,
      ABufferSeconds);
  end
  else if FConfig.GrantType = gtClientCredentials then
  begin
    FConfig := TIAM4DClientConfig.CreateForClientCredentials(
      FConfig.BaseURL,
      FConfig.Realm,
      FConfig.ClientID,
      FConfig.ClientSecret,
      FConfig.Scopes,
      FConfig.SSLValidationMode,
      FConfig.ConnectionTimeout,
      FConfig.ResponseTimeout,
      ABufferSeconds);
  end;

  Result := Self;
end;

function TIAM4DClientConfigBuilder.CreateStorage: IIAM4DTokenStorage;
var
  LKey32: TBytes;
  LAAD: TBytes;
begin
  if Assigned(FCustomStorage) then
  begin
    Result := FCustomStorage;
    Exit;
  end;

  case FStorageType of
    stIAMClient4DAES:
      begin
        if Length(FStorageKey32) = 32 then
        begin
          LKey32 := Copy(FStorageKey32);
          if Length(FStorageAAD) > 0 then
            LAAD := Copy(FStorageAAD)
          else
            LAAD := TEncoding.UTF8.GetBytes('IAMClient4D/v1');
        end
        else
        begin
          LKey32 := TIAM4DCryptoUtils.GenerateSecureRandomBytes(32);
          LAAD := TEncoding.UTF8.GetBytes('IAMClient4D/v1');
        end;

        Result := TIAM4DAESMemoryTokenStorageRawKey32.Create(LKey32, LAAD, FConfig.TokenExpiryBufferSeconds);
      end;
  else
    raise EInvalidOpException.CreateFmt('Unknown storage type: %d', [Ord(FStorageType)]);
  end;
end;

procedure TIAM4DClientConfigBuilder.ValidateBeforeBuild;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType = gtUnknown then
    raise EInvalidOpException.Create('Grant type not set. Call ForAuthorizationCode() or ForClientCredentials()');

  if (FConfig.GrantType = gtAuthorizationCode) and
    (FCallbackMode = cbmExternal) and
    (FConfig.ExternalCallbackURL.IsEmpty) then
    raise EInvalidOpException.Create(
      'External callback URL required when using WithExternalCallback(). Call WithExternalCallback(url) first.');
end;

function TIAM4DClientConfigBuilder.Build: IIAM4DClient;
var
  LStorage: IIAM4DTokenStorage;
begin
  ValidateBeforeBuild;

  LStorage := CreateStorage;

  Result := TIAM4DKeycloakClient.Create(FCallbackMode, LStorage);

  Result.ConfigureAsync(FConfig).Run.WaitForCompletion(30000);

  if Length(FPinnedPublicKeys) > 0 then
    Result.AddPinnedPublicKeys(FPinnedPublicKeys);
end;

function TIAM4DClientConfigBuilder.BuildAsync: IAsyncPromise<IIAM4DClient>;
var
  LConfig: TIAM4DClientConfig;
  LStorage: IIAM4DTokenStorage;
  LCallbackMode: TIAM4DCallbackMode;
  LPinnedKeys: TArray<string>;
begin
  ValidateBeforeBuild;

  LConfig := FConfig;
  LCallbackMode := FCallbackMode;
  if Length(FPinnedPublicKeys) > 0 then
    LPinnedKeys := Copy(FPinnedPublicKeys);

  LStorage := CreateStorage;

  Result := TAsyncCore.New<IIAM4DClient>(
    function(const AOperationController: IAsyncOperation): IIAM4DClient
    begin
      Result := TIAM4DKeycloakClient.Create(LCallbackMode, LStorage);

      if Length(LPinnedKeys) > 0 then
        Result.AddPinnedPublicKeys(LPinnedKeys);

      Result.ConfigureAsync(LConfig).Run.WaitForCompletion(30000);
    end);
end;

end.