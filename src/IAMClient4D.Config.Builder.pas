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
  /// Usage: Call ForAuthorizationCode(), ForClientCredentials() or ForPassword() first to initialize.
  /// Chain With* methods to configure options, then call Build or BuildAsync.
  /// Default storage: AES-256 encrypted in memory with auto-generated key (AES-256-CBC + HMAC-SHA256
  /// with LockBox3, the default provider; AES-256-GCM with TMS or TaurusTLS).
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
    /// <remarks>
    /// AClientSecret: empty for a public client (recommended for desktop apps: PKCE protects the code).
    /// </remarks>
    function ForAuthorizationCode(const ABaseURL, ARealm, AClientID: string;
      const AClientSecret: string = ''): IIAM4DClientConfigBuilder;
    /// <summary>
    /// Configures for Client Credentials flow
    /// </summary>
    function ForClientCredentials(const ABaseURL, ARealm, AClientID, AClientSecret: string): IIAM4DClientConfigBuilder;
    /// <summary>
    /// Configures for the Resource Owner Password Credentials flow (AuthenticatePassword)
    /// </summary>
    /// <remarks>
    /// Keycloak: "Direct access grants" must be enabled on the client. AClientSecret: empty for a public client.
    /// </remarks>
    function ForPassword(const ABaseURL, ARealm, AClientID: string;
      const AClientSecret: string = ''): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Uses AES-256 encrypted in-memory storage with auto-generated key, through the compiled storage
    /// crypto provider: AES-256-CBC + HMAC-SHA256 with LockBox3 (default), AES-256-GCM with TMS or TaurusTLS
    /// </summary>
    function WithIAMClient4DAESStorage: IIAM4DClientConfigBuilder; overload;
    /// <summary>
    /// Uses AES-256 encrypted in-memory storage with the provided 32-byte key and optional AAD, through the
    /// compiled storage crypto provider: AES-256-CBC + HMAC-SHA256 with LockBox3 (default), AES-256-GCM with
    /// TMS or TaurusTLS
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
    /// Uses a redirect on a private-use URI scheme (RFC 8252 7.1) for Authorization Code flow in mobile apps
    /// </summary>
    /// <remarks>
    /// e.g. com.example.app:/oauth2callback. The app passes the URL it receives to TIAM4DAppRedirect.HandleURL.
    /// </remarks>
    /// <exception cref="EInvalidOpException">Not an Authorization Code client</exception>
    /// <exception cref="EArgumentException">Invalid redirect URI (see TIAM4DAppRedirectCallbackHandler.IsValidRedirectURI)</exception>
    function WithAppRedirect(const ARedirectURI: string): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Enables strict SSL validation
    /// </summary>
    function WithStrictSSL: IIAM4DClientConfigBuilder;
    /// <summary>
    /// Allows self-signed SSL certificates
    /// </summary>
    function WithAllowSelfSignedSSL: IIAM4DClientConfigBuilder;
    /// <summary>
    /// Sets pinned public key hashes for certificate pinning, checked in both SSL modes on every
    /// request of the client (JWKS included): see TIAM4DSSLCertificateValidator for the hash.
    /// Build raises ENotSupportedException on Linux
    /// </summary>
    function WithPinnedPublicKeys(const APublicKeyHashes: TArray<string>): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Sets connection and response timeouts in milliseconds
    /// </summary>
    /// <remarks>
    /// AResponseTimeoutMs bounds each whole request of the client (discovery, token, user info, logout):
    /// past it EIAM4DNetworkTimeoutException. Build waits for the discovery as long as it takes.
    /// </remarks>
    function WithTimeouts(const AConnectionTimeoutMs, AResponseTimeoutMs: Integer): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Sets token expiration buffer in seconds (default: 120 seconds)
    /// </summary>
    function WithTokenExpiryBuffer(const ABufferSeconds: Integer): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Requests specific authentication context classes from Keycloak.
    /// Use to require passkey or MFA authentication.
    /// Example: WithAcrValues([IAM4D_ACR_PASSKEY]) to require passkey authentication.
    /// </summary>
    function WithAcrValues(const AValues: TArray<string>): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Logs in through the given Keycloak identity provider (kc_idp_hint): Keycloak skips its
    /// login page and redirects to it. Example: WithIdentityProvider('entra').
    /// StartAuthorizationFlowAsync(AIdpHint) overrides it for a single login
    /// (IAM4D_IDP_HINT_NONE: Keycloak login page).
    /// </summary>
    function WithIdentityProvider(const AAlias: string): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Sends prompt in the authorization request. Example: WithPrompt(IAM4D_PROMPT_LOGIN) asks for
    /// the credentials even when the browser has an active Keycloak session.
    /// </summary>
    function WithPrompt(const APrompt: string): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Sends max_age in the authorization request: seconds allowed since the last active
    /// authentication; 0 forces a new one. The id_token then carries auth_time.
    /// </summary>
    function WithMaxAge(const ASeconds: Integer): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Sends kc_action in the authorization request: Keycloak runs that required action after the
    /// login. Example: WithKeycloakAction(IAM4D_KC_ACTION_UPDATE_PASSWORD) shows the change-password
    /// page. The outcome is IIAM4DClient.KeycloakActionStatus.
    /// </summary>
    function WithKeycloakAction(const AAction: string): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Fixed port of the local callback server (default 0: free port chosen by the system).
    /// Needed when the client accepts only exact redirect URIs.
    /// </summary>
    function WithCallbackPort(const APort: Integer): IIAM4DClientConfigBuilder;

    /// <summary>
    /// What the app does when the browser redirects to the local callback server: aaNone (default),
    /// aaFlash (taskbar button flashes) or aaForeground (window to the foreground). Windows only.
    /// </summary>
    function WithAppActivation(const AValue: TIAM4DAppActivation): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Host of the redirect URI of the local callback server: lrhLocalhost (default,
    /// http://localhost:port/...) or lrhLoopbackIP (http://127.0.0.1:port/..., RFC 8252 8.3).
    /// The redirect URI registered in Keycloak must use the same host.
    /// </summary>
    function WithLoopbackRedirectHost(const AValue: TIAM4DLoopbackRedirectHost): IIAM4DClientConfigBuilder;

    /// <summary>
    /// Accepts plain HTTP to a host other than the loopback for BaseURL and the external or app
    /// redirect URL. Without it, Build refuses such a configuration: code, tokens and credentials
    /// would travel in clear text. Test environments only (e.g. Keycloak on the LAN for a phone).
    /// </summary>
    function WithAllowInsecureHTTP(const AValue: Boolean = True): IIAM4DClientConfigBuilder;

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
    FCustomStorage: IIAM4DTokenStorage;

    FCallbackMode: TIAM4DCallbackMode;

    FPinnedPublicKeys: TArray<string>;

    procedure EnsureConfigInitialized;
    /// <summary>
    /// Recreates FConfig with the given values, keeping grant type, client, secret, prompt,
    /// max_age and callback port. ACR values and identity provider apply to Authorization Code only
    /// </summary>
    procedure RebuildConfig(
      const AScopes: TArray<string>;
      const ASSLValidationMode: TIAM4DSSLValidationMode;
      const AConnectionTimeout, AResponseTimeout: Integer;
      const AExternalCallbackURL: string;
      const ATokenExpiryBufferSeconds: Integer;
      const AAcrValues: TArray<string>;
      const AIdpHint: string);
    function CreateStorage: IIAM4DTokenStorage;
    procedure ConfigureClientOrFail(const AClient: IIAM4DClient; const AConfig: TIAM4DClientConfig);
    procedure ValidateBeforeBuild;

    function GetConfig: TIAM4DClientConfig;
  public
    /// <summary>
    /// Creates a new builder instance
    /// </summary>
    class function New: IIAM4DClientConfigBuilder;

    function ForAuthorizationCode(
      const ABaseURL, ARealm, AClientID: string;
      const AClientSecret: string = ''
      ): IIAM4DClientConfigBuilder;

    function ForClientCredentials(
      const ABaseURL, ARealm, AClientID, AClientSecret: string
      ): IIAM4DClientConfigBuilder;

    function ForPassword(
      const ABaseURL, ARealm, AClientID: string;
      const AClientSecret: string = ''
      ): IIAM4DClientConfigBuilder;

    function WithIAMClient4DAESStorage: IIAM4DClientConfigBuilder; overload;

    function WithIAMClient4DAESStorage(const AKey32: TBytes; const AAAD: TBytes = nil): IIAM4DClientConfigBuilder; overload;

    function WithCustomStorage(const AStorage: IIAM4DTokenStorage): IIAM4DClientConfigBuilder;

    function WithScopes(const AScopes: TArray<string>): IIAM4DClientConfigBuilder;

    function WithExternalCallback(const ACallbackURL: string): IIAM4DClientConfigBuilder;

    function WithAppRedirect(const ARedirectURI: string): IIAM4DClientConfigBuilder;

    function WithStrictSSL: IIAM4DClientConfigBuilder;

    function WithAllowSelfSignedSSL: IIAM4DClientConfigBuilder;

    function WithPinnedPublicKeys(const APublicKeyHashes: TArray<string>): IIAM4DClientConfigBuilder;

    function WithTimeouts(const AConnectionTimeoutMs, AResponseTimeoutMs: Integer): IIAM4DClientConfigBuilder;

    function WithTokenExpiryBuffer(const ABufferSeconds: Integer): IIAM4DClientConfigBuilder;

    function WithAcrValues(const AValues: TArray<string>): IIAM4DClientConfigBuilder;

    function WithIdentityProvider(const AAlias: string): IIAM4DClientConfigBuilder;

    function WithPrompt(const APrompt: string): IIAM4DClientConfigBuilder;

    function WithMaxAge(const ASeconds: Integer): IIAM4DClientConfigBuilder;

    function WithKeycloakAction(const AAction: string): IIAM4DClientConfigBuilder;

    function WithCallbackPort(const APort: Integer): IIAM4DClientConfigBuilder;

    function WithAppActivation(const AValue: TIAM4DAppActivation): IIAM4DClientConfigBuilder;

    function WithLoopbackRedirectHost(const AValue: TIAM4DLoopbackRedirectHost): IIAM4DClientConfigBuilder;

    function WithAllowInsecureHTTP(const AValue: Boolean = True): IIAM4DClientConfigBuilder;

    function BuildAsync: IAsyncPromise<IIAM4DClient>;

    function Build: IIAM4DClient;

    destructor Destroy; override;
  end;

implementation

uses
  IAMClient4D.Common.CryptoUtils,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Callback.Handler.AppRedirect,
  IAMClient4D.Keycloak,
  IAMClient4D.Storage.AESMemoryTokenStorage,
  IAMClient4D.Exceptions;

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

  FCustomStorage := nil;

  inherited;
end;

procedure TIAM4DClientConfigBuilder.EnsureConfigInitialized;
begin
  if not FConfigInitialized then
    raise EArgumentException.Create(
      'Configuration not initialized. Call ForAuthorizationCode(), ForClientCredentials() or ForPassword() first.');
end;

function TIAM4DClientConfigBuilder.ForAuthorizationCode(
  const ABaseURL, ARealm, AClientID: string;
  const AClientSecret: string): IIAM4DClientConfigBuilder;
begin
  FConfig := TIAM4DClientConfig.Create(
    ABaseURL,
    ARealm,
    AClientID,
    gtAuthorizationCode,
    nil,
    AClientSecret);

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
  FCallbackMode := cbmLocalServer;
  Result := Self;
end;

function TIAM4DClientConfigBuilder.ForPassword(
  const ABaseURL, ARealm, AClientID: string;
  const AClientSecret: string): IIAM4DClientConfigBuilder;
begin
  FConfig := TIAM4DClientConfig.CreateForPassword(
    ABaseURL,
    ARealm,
    AClientID,
    AClientSecret);

  FConfigInitialized := True;
  FCallbackMode := cbmLocalServer;
  Result := Self;
end;

procedure TIAM4DClientConfigBuilder.RebuildConfig(
  const AScopes: TArray<string>;
  const ASSLValidationMode: TIAM4DSSLValidationMode;
  const AConnectionTimeout, AResponseTimeout: Integer;
  const AExternalCallbackURL: string;
  const ATokenExpiryBufferSeconds: Integer;
  const AAcrValues: TArray<string>;
  const AIdpHint: string);
var
  LAcrValues: TArray<string>;
  LIdpHint: string;
  LPrompt: string;
  LMaxAge: Integer;
  LKeycloakAction: string;
  LCallbackPort: Integer;
  LAppActivation: TIAM4DAppActivation;
  LLoopbackRedirectHost: TIAM4DLoopbackRedirectHost;
  LAllowInsecureHTTP: Boolean;
begin
  // ACR values and identity provider need the authorization endpoint
  if FConfig.GrantType = gtAuthorizationCode then
  begin
    LAcrValues := AAcrValues;
    LIdpHint := AIdpHint;
  end
  else
  begin
    LAcrValues := nil;
    LIdpHint := '';
  end;
  LPrompt := FConfig.Prompt;
  LMaxAge := FConfig.MaxAge;
  LKeycloakAction := FConfig.KeycloakAction;
  LCallbackPort := FConfig.CallbackPort;
  LAppActivation := FConfig.AppActivation;
  LLoopbackRedirectHost := FConfig.LoopbackRedirectHost;
  LAllowInsecureHTTP := FConfig.AllowInsecureHTTP;

  FConfig := TIAM4DClientConfig.Create(
    FConfig.BaseURL,
    FConfig.Realm,
    FConfig.ClientID,
    FConfig.GrantType,
    AScopes,
    FConfig.ClientSecret,
    ASSLValidationMode,
    AConnectionTimeout,
    AResponseTimeout,
    AExternalCallbackURL,
    ATokenExpiryBufferSeconds,
    LAcrValues,
    LIdpHint)
    .WithAuthRequestOptions(LPrompt, LMaxAge)
    .WithKeycloakAction(LKeycloakAction)
    .WithCallbackPort(LCallbackPort)
    .WithAppActivation(LAppActivation)
    .WithLoopbackRedirectHost(LLoopbackRedirectHost)
    .WithAllowInsecureHTTP(LAllowInsecureHTTP);
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

  RebuildConfig(
    AScopes,
    FConfig.SSLValidationMode,
    FConfig.ConnectionTimeout,
    FConfig.ResponseTimeout,
    FConfig.ExternalCallbackURL,
    FConfig.TokenExpiryBufferSeconds,
    FConfig.AcrValues,
    FConfig.IdpHint);

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

  RebuildConfig(
    FConfig.Scopes,
    FConfig.SSLValidationMode,
    FConfig.ConnectionTimeout,
    FConfig.ResponseTimeout,
    ACallbackURL,
    FConfig.TokenExpiryBufferSeconds,
    FConfig.AcrValues,
    FConfig.IdpHint);

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithAppRedirect(const ARedirectURI: string): IIAM4DClientConfigBuilder;
var
  LError: string;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType <> gtAuthorizationCode then
    raise EInvalidOpException.Create('App redirect is only for Authorization Code flow');

  if not TIAM4DAppRedirectCallbackHandler.IsValidRedirectURI(ARedirectURI, LError) then
    raise EArgumentException.Create(LError);

  FCallbackMode := cbmAppRedirect;

  RebuildConfig(
    FConfig.Scopes,
    FConfig.SSLValidationMode,
    FConfig.ConnectionTimeout,
    FConfig.ResponseTimeout,
    ARedirectURI,
    FConfig.TokenExpiryBufferSeconds,
    FConfig.AcrValues,
    FConfig.IdpHint);

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithStrictSSL: IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  RebuildConfig(
    FConfig.Scopes,
    svmStrict,
    FConfig.ConnectionTimeout,
    FConfig.ResponseTimeout,
    FConfig.ExternalCallbackURL,
    FConfig.TokenExpiryBufferSeconds,
    FConfig.AcrValues,
    FConfig.IdpHint);

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithAllowSelfSignedSSL: IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  RebuildConfig(
    FConfig.Scopes,
    svmAllowSelfSigned,
    FConfig.ConnectionTimeout,
    FConfig.ResponseTimeout,
    FConfig.ExternalCallbackURL,
    FConfig.TokenExpiryBufferSeconds,
    FConfig.AcrValues,
    FConfig.IdpHint);

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

  RebuildConfig(
    FConfig.Scopes,
    FConfig.SSLValidationMode,
    AConnectionTimeoutMs,
    AResponseTimeoutMs,
    FConfig.ExternalCallbackURL,
    FConfig.TokenExpiryBufferSeconds,
    FConfig.AcrValues,
    FConfig.IdpHint);

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithTokenExpiryBuffer(const ABufferSeconds: Integer): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if ABufferSeconds < 0 then
    raise EArgumentOutOfRangeException.Create('Token expiry buffer cannot be negative');

  RebuildConfig(
    FConfig.Scopes,
    FConfig.SSLValidationMode,
    FConfig.ConnectionTimeout,
    FConfig.ResponseTimeout,
    FConfig.ExternalCallbackURL,
    ABufferSeconds,
    FConfig.AcrValues,
    FConfig.IdpHint);

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithAcrValues(const AValues: TArray<string>): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType <> gtAuthorizationCode then
    raise EInvalidOpException.Create('ACR values are only applicable for Authorization Code flow');

  RebuildConfig(
    FConfig.Scopes,
    FConfig.SSLValidationMode,
    FConfig.ConnectionTimeout,
    FConfig.ResponseTimeout,
    FConfig.ExternalCallbackURL,
    FConfig.TokenExpiryBufferSeconds,
    AValues,
    FConfig.IdpHint);

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithIdentityProvider(const AAlias: string): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType <> gtAuthorizationCode then
    raise EInvalidOpException.Create('Identity provider hint is only applicable for Authorization Code flow');

  RebuildConfig(
    FConfig.Scopes,
    FConfig.SSLValidationMode,
    FConfig.ConnectionTimeout,
    FConfig.ResponseTimeout,
    FConfig.ExternalCallbackURL,
    FConfig.TokenExpiryBufferSeconds,
    FConfig.AcrValues,
    AAlias.Trim);

  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithPrompt(const APrompt: string): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType <> gtAuthorizationCode then
    raise EInvalidOpException.Create('Prompt is only applicable for Authorization Code flow');

  FConfig := FConfig.WithAuthRequestOptions(APrompt, FConfig.MaxAge);
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithMaxAge(const ASeconds: Integer): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType <> gtAuthorizationCode then
    raise EInvalidOpException.Create('Max age is only applicable for Authorization Code flow');

  if ASeconds < 0 then
    raise EArgumentOutOfRangeException.Create('Max age cannot be negative');

  FConfig := FConfig.WithAuthRequestOptions(FConfig.Prompt, ASeconds);
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithKeycloakAction(const AAction: string): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType <> gtAuthorizationCode then
    raise EInvalidOpException.Create('Keycloak action is only applicable for Authorization Code flow');

  FConfig := FConfig.WithKeycloakAction(AAction);
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithCallbackPort(const APort: Integer): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType <> gtAuthorizationCode then
    raise EInvalidOpException.Create('Callback port is only applicable for Authorization Code flow');

  FConfig := FConfig.WithCallbackPort(APort);
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithAppActivation(const AValue: TIAM4DAppActivation): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType <> gtAuthorizationCode then
    raise EInvalidOpException.Create('App activation is only applicable for Authorization Code flow');

  FConfig := FConfig.WithAppActivation(AValue);
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithLoopbackRedirectHost(
  const AValue: TIAM4DLoopbackRedirectHost): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType <> gtAuthorizationCode then
    raise EInvalidOpException.Create('The loopback redirect host is only applicable for Authorization Code flow');

  FConfig := FConfig.WithLoopbackRedirectHost(AValue);
  Result := Self;
end;

function TIAM4DClientConfigBuilder.WithAllowInsecureHTTP(const AValue: Boolean): IIAM4DClientConfigBuilder;
begin
  EnsureConfigInitialized;
  FConfig := FConfig.WithAllowInsecureHTTP(AValue);
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

        try
          Result := TIAM4DAESMemoryTokenStorageRawKey32.Create(LKey32, LAAD, FConfig.TokenExpiryBufferSeconds);
        finally
          // The storage keeps its own copy of the key
          SecureZero(LKey32);
        end;
      end;
  else
    raise EInvalidOpException.CreateFmt('Unknown storage type: %d', [Ord(FStorageType)]);
  end;
end;

procedure TIAM4DClientConfigBuilder.ConfigureClientOrFail(
  const AClient: IIAM4DClient;
  const AConfig: TIAM4DClientConfig);
begin
  // On the calling thread: BuildAsync is already on a task, a second one only blocked it.
  // The discovery request ends within the timeouts of AConfig
  (AClient as TIAM4DKeycloakClient).Configure(AConfig);
end;

procedure TIAM4DClientConfigBuilder.ValidateBeforeBuild;
begin
  EnsureConfigInitialized;

  if FConfig.GrantType = gtUnknown then
    raise EInvalidOpException.Create('Grant type not set. Call ForAuthorizationCode(), ForClientCredentials() or ForPassword()');

  if (FConfig.GrantType = gtAuthorizationCode) and
    (FCallbackMode = cbmExternal) and
    (FConfig.ExternalCallbackURL.IsEmpty) then
    raise EInvalidOpException.Create(
      'External callback URL required when using WithExternalCallback(). Call WithExternalCallback(url) first.');

  if (FConfig.GrantType = gtAuthorizationCode) and
    (FCallbackMode = cbmAppRedirect) and
    (FConfig.ExternalCallbackURL.IsEmpty) then
    raise EInvalidOpException.Create(
      'Redirect URI required when using WithAppRedirect(). Call WithAppRedirect(uri) first.');
end;

function TIAM4DClientConfigBuilder.Build: IIAM4DClient;
var
  LStorage: IIAM4DTokenStorage;
begin
  ValidateBeforeBuild;

  LStorage := CreateStorage;

  Result := TIAM4DKeycloakClient.Create(FCallbackMode, LStorage);

  if Length(FPinnedPublicKeys) > 0 then
    Result.AddPinnedPublicKeys(FPinnedPublicKeys);

  ConfigureClientOrFail(Result, FConfig);
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

      ConfigureClientOrFail(Result, LConfig);
    end);
end;

end.
