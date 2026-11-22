{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Keycloak.pas
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

unit IAMClient4D.Keycloak;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Generics.Collections,
  System.Threading,
  System.SyncObjs,
  System.Net.URLClient,
  System.Net.HttpClient,
  System.NetEncoding,
  System.DateUtils,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.Storage.Core,
  IAMClient4D.Callback.Handler,
  IAMClient4D.Common.Security,
  IAMClient4D.Common.JSONUtils,
  IAMClient4D.Common.PKCEGenerator,
  IAMClient4D.Security.Core,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// Counts the flow callbacks running on other threads: the client waits for them before being freed.
  /// </summary>
  IIAM4DPendingWork = interface
    ['{80903533-5936-4AF6-AF6E-1B3950DDED16}']
    /// <summary>
    /// Registers a running callback; False once the owner is being freed (the callback must not run).
    /// </summary>
    function TryEnter: Boolean;
    procedure Leave;
    /// <summary>
    /// Refuses new callbacks and waits for the running ones.
    /// </summary>
    procedure CloseAndWait;
  end;

  /// <summary>
  /// Keycloak OAuth2/OIDC client implementation.
  /// </summary>
  /// <remarks>
  /// Implements IIAM4DClient for Keycloak identity provider.
  /// Supports Authorization Code (with PKCE), Client Credentials and Password flows.
  ///
  /// Authorization Code flow:
  /// 1. Call ConfigureAsync() to discover endpoints
  /// 2. Desktop apps: Call StartAuthorizationFlowAsync() - opens browser automatically
  /// 3. Web apps: Call InitializeAuthorizationFlow(), GenerateAuthURL(), then CompleteAuthorizationFlowAsync()
  ///
  /// Client Credentials flow:
  /// 1. Call ConfigureAsync()
  /// 2. Call AuthenticateClientAsync()
  /// 3. Use GetAccessTokenAsync() for API calls
  ///
  /// Thread-safety: Internal synchronization for token refresh and auth completion.
  /// Token storage: Configurable via constructor (defaults to AES-encrypted memory storage).
  /// SSL validation: strict or self-signed mode, public key pinning in both modes.
  /// Token refresh: Automatic refresh on access token expiry.
  /// PKCE: Automatically applied to Authorization Code flow (SHA-256).
  /// id_token: every id_token received from the token endpoint is validated before the tokens are
  /// stored (signature with the keys of the jwks_uri of the discovery document, iss, aud, azp, exp, iat;
  /// nonce and auth_time in the Authorization Code flow; sub, aud and nonce of the login after a refresh).
  /// Callback modes: Local server (desktop) or external (web apps like uniGUI).
  /// </remarks>
  TIAM4DKeycloakClient = class(TInterfacedObject, IIAM4DClient)
  private
    FScopes: TStrings;
    FKeycloakConfig: TIAM4DClientConfig;
    FCallbackMode: TIAM4DCallbackMode;
    FCallbackHandler: IIAM4DCallbackHandler;
    FAuthCompletionSource: IAsyncTaskCompletionSource<string>;
    FAuthCompletionLock: TCriticalSection;
    FPendingWork: IIAM4DPendingWork;
    FRefreshLock: TCriticalSection;
    // Serializes the writes of FTokenStorage (leaf lock: nothing else is taken under it).
    // FTokenGeneration grows at each write: a refresh stores its tokens only when no login,
    // logout or new configuration wrote in the meantime
    FTokenSaveLock: TCriticalSection;
    FTokenGeneration: Int64;
    FSSLValidator: IIAM4DSSLCertificateValidator;
    FSSLHelper: TIAM4DHTTPClientSSLHelper;

    // Pool of HTTP clients (connection reuse): each request borrows one, so the calls of a client
    // run in parallel. A new configuration or a pin change bumps the generation: the clients of the
    // previous one are freed when they come back. Under FHTTPClientLock
    FHTTPClientPool: TStack<THTTPClient>;
    FHTTPClientGeneration: Integer;
    FHTTPClientLock: TCriticalSection;

    FWellKnownEndPoints: TIAM4DWellKnownEndpoints;
    // Pinned public keys: the discovery document is always fetched through this client
    FHasPinnedKeys: Boolean;
    FState: string;
    FNonce: string;
    FPKCEVerifier: string;
    FPKCEChallenge: string;
    // Options of the current login (StartAuthorizationFlowAsync, InitializeAuthorizationFlow, GenerateAuthURL)
    FAuthOptions: TIAM4DAuthRequestOptions;
    // kc_action_status of the last local flow; under FAuthCompletionLock
    FKeycloakActionStatus: string;
    FTokenStorage: IIAM4DTokenStorage;
    // Validator of the id_tokens: issuer, keys and timeouts of the current configuration
    FIDTokenValidator: IIAM4DJWTValidator;

    function GetRealmURL: string;
    procedure InternalWellKnownFetchEndpoints;
    function ExecuteCallHTTP<T>(const AOperation: TFunc<THTTPClient, T>): T;
    function AcquireHTTPClient(out AGeneration: Integer): THTTPClient;
    procedure ReleaseHTTPClient(AClient: THTTPClient; AGeneration: Integer);
    /// <summary>Frees the pooled clients; the borrowed ones are freed when they come back</summary>
    procedure DiscardHTTPClients;
    procedure GeneratePKCE;
    /// <summary>
    /// Refresh token grant; APreviousIDToken is the id_token of the session, the refreshed one must
    /// match it (ValidateRefreshedIDToken). The new tokens are stored only after the validation.
    /// </summary>
    /// <summary>
    /// Refreshes ACurrent. A refresh_token or id_token missing from the response keeps the one of
    /// ACurrent (RFC 6749 6, OpenID Connect Core 12.2). With the signing keys unavailable the new
    /// tokens are saved with the id_token of ACurrent: Keycloak may have rotated the refresh token.
    /// AGeneration is the token generation ACurrent was read at: AStored is False when another
    /// write came first (login, logout, new configuration) and the refreshed tokens were dropped.
    /// </summary>
    function RefreshTokensInternal(const ACurrent: TIAM4DTokens; AGeneration: Int64;
      out AStored: Boolean): TIAM4DTokens;
    /// <summary>Stores the tokens of a login, replacing any others</summary>
    procedure StoreTokens(const ATokens: TIAM4DTokens);
    /// <summary>Stores ATokens only if no write happened since AGeneration</summary>
    function TryStoreTokens(const ATokens: TIAM4DTokens; AGeneration: Int64): Boolean;
    function CurrentTokenGeneration: Int64;
    /// <summary>ClearTokens, only if no write happened since AGeneration (a newer login stays)</summary>
    procedure ClearTokensOf(AGeneration: Int64);
    /// <exception cref="EIAM4DException">Raised when HTTP request fails or response is not 200/201</exception>
    /// <exception cref="EIAM4DNetworkUnreachableException">Raised on network errors</exception>
    function PostToTokenEndpoint(const AParams: TStrings): TJSONObject;
    function ExchangeCodeForTokens(const ACode, ACodeVerifier: string): TIAM4DTokens;
    /// <summary>
    /// Validator of the id_tokens for the current discovery document: issuer of the discovery,
    /// keys of its jwks_uri (fetched with the SSL mode and the timeouts of the client), audience
    /// client_id, clock skew IAM4D_AUTH_TIME_CLOCK_SKEW_SECONDS
    /// </summary>
    procedure CreateIDTokenValidator;
    /// <summary>
    /// HTTP client and id_token validator created again with the current pinned keys
    /// </summary>
    procedure PinnedPublicKeysChanged;
    /// <summary>
    /// Validates an id_token received from the token endpoint (OpenID Connect Core 3.1.3.7):
    /// signature (algorithm allow-list, alg=none refused) with the keys of the jwks_uri, iss equal to
    /// the issuer of the discovery, aud containing client_id, azp required with several audiences and
    /// equal to client_id when present, exp in the future and iat neither in the future nor older than
    /// the request, both within the clock skew. Returns the claims (the caller frees them)
    /// </summary>
    /// <exception cref="EIAM4DSecurityValidationException">ecTokenInvalid: the id_token is not valid;
    /// EIAM4DJWKSUnavailableException (ecDiscoveryFailed): the keys cannot be fetched</exception>
    function VerifyIDToken(const AIDToken: string): TJSONObject;
    /// <summary>
    /// Checks the id_token of the code exchange: VerifyIDToken, then nonce of the flow and, when
    /// max_age was sent, auth_time (OpenID Connect Core 3.1.3.7, points 11 and 13)
    /// </summary>
    procedure ValidateIDToken(const AIDToken: string; const AContext: TIAM4DOAuthContext);
    /// <summary>
    /// Checks the id_token of a grant without nonce (password, client credentials): VerifyIDToken.
    /// An empty one is accepted (nothing to trust)
    /// </summary>
    procedure ValidateDirectIDToken(const AIDToken: string);
    /// <summary>
    /// Checks the id_token of a refresh (OpenID Connect Core 12.2): VerifyIDToken, then sub and aud
    /// equal to the ones of APreviousIDToken and nonce absent or equal. A refresh response without
    /// id_token is accepted
    /// </summary>
    procedure ValidateRefreshedIDToken(const AIDToken, APreviousIDToken: string);
    /// <summary>
    /// POSTs one token to the revocation endpoint; unsupported_token_type is not an error
    /// (a server that cannot revoke access tokens: they expire)
    /// </summary>
    procedure RevokeToken(const AToken, ATokenTypeHint: string);
    function EncodeFormParams(const AParams: TStrings): string;
    procedure AddScopesIfMissing(const AScopes: TArray<string>);
    /// <exception cref="EIAM4DException">Raised when response status is not 200 or 201</exception>
    procedure EnsureResponseHTTP200OrFail(const AResponse: IHTTPResponse; const AContext: string);
    procedure ClearAuthorizationContext;
    procedure ClearTokens;
    function RequestClientCredentialsToken: TIAM4DTokens;
    /// <exception cref="EIAM4DInvalidCredentialsException">Wrong username or password</exception>
    /// <exception cref="EIAM4DAccountNotFullySetUpException">A required action is pending</exception>
    /// <exception cref="EIAM4DAccountDisabledException">Account disabled</exception>
    function RequestPasswordToken(const AUserName, APassword: string): TIAM4DTokens;
    /// <summary>
    /// Posts a form (application/x-www-form-urlencoded) and returns the response, whatever its
    /// status. The form may hold a password, a secret or a refresh token: its encoded copies
    /// and the lines of AParams are wiped after the request (AParams is left empty)
    /// </summary>
    function SendFormRequest(const AURL: string; const AParams: TStrings): IHTTPResponse;
    /// <summary>
    /// Posts a form to the token endpoint (SendFormRequest)
    /// </summary>
    function SendTokenRequest(const AParams: TStrings): IHTTPResponse;
    /// <summary>
    /// True for an OAuth2 invalid_grant answer (400/401), with its error_description
    /// </summary>
    function IsInvalidGrant(const AResponse: IHTTPResponse; out ADescription: string): Boolean;
    /// <summary>
    /// Raises the exception of an invalid_grant answer of the password grant, if it is one
    /// </summary>
    procedure RaisePasswordGrantError(const AResponse: IHTTPResponse);
    /// <summary>
    /// Ends a Keycloak session: POST of its refresh token to the end session endpoint
    /// (back-channel: no browser cookies needed). A refresh token Keycloak refuses (invalid_grant:
    /// revoked, expired, unknown) means there is nothing left to end: no exception
    /// </summary>
    /// <exception cref="EIAM4DException">Any other answer, or the request fails (network)</exception>
    procedure LogoutWithRefreshToken(const ARefreshToken: string);
    /// <summary>
    /// Ends the session of the stored tokens before a new login replaces them (errors ignored)
    /// </summary>
    procedure EndReplacedSession;
    /// <summary>
    /// Scopes back to the configured ones (a login adds openid)
    /// </summary>
    procedure ResetScopes;
    function StartAuthorizationFlowInternal(const AOptions: TIAM4DAuthRequestOptions): IAsyncPromise<string>;
    function EffectiveMaxAge(const AOptions: TIAM4DAuthRequestOptions): Integer;
    function BuildAuthURL(const AOptions: TIAM4DAuthRequestOptions): string;

    procedure CreateCallbackHandler;
    procedure InitializeOAuthContext;
    procedure InitializeOAuthContextInternal;
    function CompleteAuthorizationFlowInternal(const ACode, AState, AIss: string): TIAM4DTokens;
    /// <summary>
    /// Checks the state and exchanges the code; stores nothing
    /// </summary>
    function ExchangeAuthorizationCode(const ACode, AState: string; const AContext: TIAM4DOAuthContext): TIAM4DTokens;
    /// <summary>
    /// Token exchange of StartAuthorizationFlowAsync, run on a worker thread
    /// </summary>
    procedure CompleteLocalAuthorizationFlow(const ASource: IAsyncTaskCompletionSource<string>;
      const ACode, AState, AKeycloakActionStatus: string);
    /// <summary>
    /// Copies the OAuth context of ASource, if ASource is still the current flow
    /// </summary>
    function TryGetFlowContext(const ASource: IAsyncTaskCompletionSource<string>; out AContext: TIAM4DOAuthContext): Boolean;
    /// <summary>
    /// Detaches ASource from the client and stops the callback server, if ASource is still the current flow.
    /// AOnEnd runs under the same lock, before detaching: a cancel cannot slip in between.
    /// Returns False if ASource was already ended (cancelled, replaced or completed).
    /// </summary>
    function EndAuthorizationFlow(const ASource: IAsyncTaskCompletionSource<string>; const AOnEnd: TProc = nil): Boolean;
    function IsValidStateFormat(const AState: string): Boolean;

    procedure ConfigureInternal(const AConfig: TIAM4DClientConfig);
    function GetAccessTokenInternal: string;
    function GetUserInfoInternal: TJSONObject;
    procedure LogoutInternal;
    procedure AuthenticateClientInternal;
    function GenerateAuthURL(const ALoginHint: string = ''; const AIdpHint: string = ''): string; overload;
    function GenerateAuthURL(const AOptions: TIAM4DAuthRequestOptions): string; overload;
  protected
    /// <summary>
    /// Returns the OIDC issuer from discovered endpoints.
    /// </summary>
    function GetIssuer: string;
    /// <summary>
    /// Returns the JWKS URI from discovered endpoints.
    /// </summary>
    function GetJWKSUri: string;
    /// <summary>
    /// Returns true if authenticated (valid refresh token for Authorization Code, valid access token for Client Credentials).
    /// </summary>
    function GetIsAuthenticated: Boolean;
    /// <summary>
    /// Returns the OAuth2 redirect URI for the callback handler.
    /// </summary>
    function GetRedirectURI: string;
    /// <summary>
    /// kc_action_status of the last authorization flow completed through the local callback server.
    /// </summary>
    function GetKeycloakActionStatus: string;
    function GetIDTokenClaims: TIAM4DIDTokenClaims;
    function GetGrantedScopes: TArray<string>;
    function HasGrantedScope(const AScope: string): Boolean;
    /// <summary>
    /// Configures the client and discovers OIDC endpoints via well-known URL.
    /// </summary>
    /// <exception cref="EIAM4DNetworkUnreachableException">Raised on network errors during endpoint discovery</exception>
    /// <exception cref="EIAM4DDiscoveryFailedException">Raised when the discovery document cannot be read (HTTP error, invalid JSON)</exception>
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when the configuration or the discovery document is refused (plain HTTP)</exception>
    function ConfigureAsync(const AConfig: TIAM4DClientConfig): IAsyncVoidPromise;
    /// <summary>
    /// Starts Authorization Code flow for desktop apps (opens browser automatically).
    /// </summary>
    /// <remarks>
    /// AIdpHint: Keycloak identity provider alias (kc_idp_hint); empty uses Config.IdpHint;
    /// IAM4D_IDP_HINT_NONE sends no hint. The browser is opened through TIAM4DPlatformUtils.OpenURL.
    /// </remarks>
    /// <exception cref="EIAM4DOAuth2CallbackException">Raised when the authorization server answers with an error (e.g. access_denied); a cancelled login ends without error</exception>
    /// <exception cref="EIAM4DSecurityValidationException">Raised when state, iss or ID token are not valid</exception>
    function StartAuthorizationFlowAsync(const AIdpHint: string = ''): IAsyncPromise<string>; overload;
    /// <summary>
    /// Starts Authorization Code flow for desktop apps with a login_hint.
    /// </summary>
    function StartAuthorizationFlowAsync(const AIdpHint, ALoginHint: string): IAsyncPromise<string>; overload;
    function StartAuthorizationFlowAsync(const AOptions: TIAM4DAuthRequestOptions): IAsyncPromise<string>; overload;
    /// <summary>
    /// Initializes Authorization Code flow for web apps (call before GenerateAuthURL).
    /// </summary>
    procedure InitializeAuthorizationFlow; overload;
    procedure InitializeAuthorizationFlow(const AOptions: TIAM4DAuthRequestOptions); overload;
    /// <summary>
    /// Completes Authorization Code flow with received code and state (for web apps).
    /// </summary>
    /// <exception cref="EIAM4DStateMismatchException">Raised when the state is unknown or already used</exception>
    /// <exception cref="EIAM4DSecurityValidationException">Raised when iss or the ID token are not valid</exception>
    /// <exception cref="EIAM4DException">Raised when the token endpoint refuses the code</exception>
    function CompleteAuthorizationFlowAsync(const ACode, AState: string; const AIss: string = ''): IAsyncPromise<string>;
    /// <summary>
    /// Authenticates using Client Credentials flow.
    /// </summary>
    /// <exception cref="EIAM4DException">Raised when the token endpoint refuses the client credentials</exception>
    function AuthenticateClientAsync: IAsyncPromise<string>;
    /// <summary>
    /// Authenticates using the Resource Owner Password Credentials flow.
    /// </summary>
    function AuthenticatePasswordAsync(const AUserName, APassword: string): IAsyncPromise<string>;
    /// <summary>
    /// Returns valid access token (auto-refreshes if expired).
    /// </summary>
    /// <exception cref="EIAM4DRefreshTokenExpiredException">Raised when there is no session or the refresh token is refused: a new login is needed</exception>
    function GetAccessTokenAsync: IAsyncPromise<string>;
    /// <summary>
    /// Retrieves OIDC user info from UserInfo endpoint.
    /// </summary>
    /// <exception cref="EIAM4DRefreshTokenExpiredException">Raised when there is no session or the refresh token is refused</exception>
    /// <exception cref="EIAM4DNetworkUnreachableException">Raised on network errors</exception>
    function GetUserInfoAsync: IAsyncPromise<TIAM4DUserInfo>;
    /// <summary>
    /// Logs out and clears stored tokens.
    /// </summary>
    /// <exception cref="EIAM4DNetworkUnreachableException">Raised on network errors during logout</exception>
    function LogoutAsync: IAsyncVoidPromise;
    function RevokeTokensAsync: IAsyncVoidPromise;

    // Synchronous Operations
    /// <summary>
    /// Gets valid access token synchronously (auto-refreshes if expired).
    /// </summary>
    function GetAccessToken: string;
    procedure InvalidateAccessToken(const AAccessToken: string);
    /// <summary>
    /// Authenticates using Client Credentials flow synchronously.
    /// </summary>
    function AuthenticateClient: string;
    /// <summary>
    /// Authenticates using the Resource Owner Password Credentials flow synchronously.
    /// </summary>
    function AuthenticatePassword(const AUserName, APassword: string): string;
    /// <summary>
    /// Completes Authorization Code flow synchronously.
    /// </summary>
    function CompleteAuthorizationFlow(const ACode, AState: string; const AIss: string = ''): string;
    /// <summary>
    /// Retrieves OIDC user info synchronously.
    /// </summary>
    function GetUserInfo: TIAM4DUserInfo;
    /// <summary>
    /// Logs out and clears tokens synchronously.
    /// </summary>
    procedure Logout;
    procedure RevokeTokens;
    function GenerateLogoutURL(const APostLogoutRedirectURI: string = ''; const AState: string = ''): string;

    /// <summary>
    /// Creates configured HTTP client with SSL validation and timeouts.
    /// </summary>
    function CreateHTTPClient: THTTPClient;
    /// <summary>
    /// Cancels pending authorization flow and stops callback handler.
    /// </summary>
    procedure CancelAuthorizationFlow;
  public
    /// <summary>
    /// Creates a Keycloak client with specified callback mode and token storage.
    /// </summary>
    constructor Create(
      const ACallbackMode: TIAM4DCallbackMode = cbmLocalServer;
      const AStorage: IIAM4DTokenStorage = nil);
    /// <summary>
    /// Destroys the client and cancels any pending authorization flows.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Adds SHA-256 public key hashes for certificate pinning: every request of the client
    /// (discovery, token, userinfo, logout, JWKS) must present one of them, in both SSL modes.
    /// Call it before the client is used.
    /// </summary>
    /// <exception cref="ENotSupportedException">On Linux</exception>
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
    /// <summary>
    /// Removes all pinned public key hashes.
    /// </summary>
    procedure ClearPinnedPublicKeys;

    /// <summary>
    /// Returns the SSL certificate validator (events, diagnostics). Pin keys through
    /// AddPinnedPublicKeys of the client: it creates the HTTP clients again.
    /// </summary>
    function GetSSLValidator: IIAM4DSSLCertificateValidator;
    property SSLValidator: IIAM4DSSLCertificateValidator read GetSSLValidator;

    /// <summary>
    /// ConfigureAsync on the calling thread: for a caller already on a background thread
    /// (TIAM4DClientConfigBuilder.Build and BuildAsync), no second task to wait for.
    /// </summary>
    procedure Configure(const AConfig: TIAM4DClientConfig);
  end;

implementation

{TKeycloakClient}

uses
  System.StrUtils,
  System.Math,
  System.NetConsts,
  IAMClient4D.Common.Constants,
  IAMClient4D.Security.JWT,
  IAMClient4D.Security.JWT.JWKS,
  IAMClient4D.Common.CryptoUtils,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Callback.Handler.Local,
  IAMClient4D.Callback.Handler.External,
  IAMClient4D.Callback.Handler.AppRedirect,
  IAMClient4D.Storage.AESMemoryTokenStorage,
  IAMClient4D.Common.PlatformUtils,
  IAMClient4D.Discovery.Cache;

function IDTokenClaims(const AIDToken: string): TJSONObject; forward;

type
  TIAM4DPendingWork = class(TInterfacedObject, IIAM4DPendingWork)
  private
    FLock: TCriticalSection;
    FIdle: TEvent;
    FCount: Integer;
    FClosed: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    function TryEnter: Boolean;
    procedure Leave;
    procedure CloseAndWait;
  end;

{ TIAM4DPendingWork }

constructor TIAM4DPendingWork.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  // Manual reset, signaled: no callback running
  FIdle := TEvent.Create(nil, True, True, '');
end;

destructor TIAM4DPendingWork.Destroy;
begin
  FIdle.Free;
  FLock.Free;
  inherited;
end;

function TIAM4DPendingWork.TryEnter: Boolean;
begin
  FLock.Acquire;
  try
    Result := not FClosed;
    if Result then
    begin
      Inc(FCount);
      FIdle.ResetEvent;
    end;
  finally
    FLock.Release;
  end;
end;

procedure TIAM4DPendingWork.Leave;
begin
  FLock.Acquire;
  try
    Dec(FCount);
    if FCount = 0 then
      FIdle.SetEvent;
  finally
    FLock.Release;
  end;
end;

procedure TIAM4DPendingWork.CloseAndWait;
begin
  FLock.Acquire;
  try
    FClosed := True;
  finally
    FLock.Release;
  end;
  FIdle.WaitFor(INFINITE);
end;

{ TIAM4DKeycloakClient }

procedure TIAM4DKeycloakClient.AddScopesIfMissing(const AScopes: TArray<string>);
begin
  for var LScope: string in AScopes do
    if FScopes.IndexOf(LScope) = -1 then
      FScopes.Add(LScope);
end;

procedure TIAM4DKeycloakClient.AuthenticateClientInternal;
begin
  RequestClientCredentialsToken;
end;

// The *Async methods capture an interface reference, not Self: the client may be released
// while the task runs, the reference keeps it alive until the task has finished

function TIAM4DKeycloakClient.AuthenticateClientAsync: IAsyncPromise<string>;
var
  LSelf: IIAM4DClient;
begin
  LSelf := Self;
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := LSelf.AuthenticateClient;
    end);
end;

function TIAM4DKeycloakClient.AuthenticatePasswordAsync(const AUserName, APassword: string): IAsyncPromise<string>;
var
  LSelf: IIAM4DClient;
begin
  LSelf := Self;
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := LSelf.AuthenticatePassword(AUserName, APassword);
    end);
end;

procedure TIAM4DKeycloakClient.ClearTokens;
begin
  FTokenSaveLock.Acquire;
  try
    FTokenStorage.ClearTokens;
    Inc(FTokenGeneration);
  finally
    FTokenSaveLock.Release;
  end;
  ClearAuthorizationContext;
end;

procedure TIAM4DKeycloakClient.ClearTokensOf(AGeneration: Int64);
var
  LCleared: Boolean;
begin
  FTokenSaveLock.Acquire;
  try
    LCleared := FTokenGeneration = AGeneration;
    if LCleared then
    begin
      FTokenStorage.ClearTokens;
      Inc(FTokenGeneration);
    end;
  finally
    FTokenSaveLock.Release;
  end;
  if LCleared then
    ClearAuthorizationContext;
end;

procedure TIAM4DKeycloakClient.StoreTokens(const ATokens: TIAM4DTokens);
var
  LTokens: TIAM4DTokens;
begin
  // RFC 6749 5.1: no scope in the answer = the requested ones. Kept with the tokens, so a later
  // change of the requested scopes does not change what was granted
  LTokens := ATokens;
  if LTokens.Scope.Trim.IsEmpty then
    LTokens.Scope := string.Join(' ', FScopes.ToStringArray);
  FTokenSaveLock.Acquire;
  try
    FTokenStorage.SaveTokens(LTokens);
    Inc(FTokenGeneration);
  finally
    FTokenSaveLock.Release;
  end;
end;

function TIAM4DKeycloakClient.TryStoreTokens(const ATokens: TIAM4DTokens; AGeneration: Int64): Boolean;
begin
  FTokenSaveLock.Acquire;
  try
    Result := FTokenGeneration = AGeneration;
    if Result then
    begin
      FTokenStorage.SaveTokens(ATokens);
      Inc(FTokenGeneration);
    end;
  finally
    FTokenSaveLock.Release;
  end;
end;

function TIAM4DKeycloakClient.GetIDTokenClaims: TIAM4DIDTokenClaims;
begin
  Result := Default(TIAM4DIDTokenClaims);
  if FTokenStorage.HasTokens then
    Result := TIAM4DIDTokenClaims.FromIDToken(FTokenStorage.LoadTokens.IDToken);
end;

function TIAM4DKeycloakClient.GetGrantedScopes: TArray<string>;
var
  LTokens: TIAM4DTokens;
begin
  Result := nil;
  if not FTokenStorage.HasTokens then
    Exit;
  LTokens := FTokenStorage.LoadTokens;
  if LTokens.AccessToken.IsEmpty then
    Exit;
  // The requested scopes when the server sent none: set by StoreTokens at issue time
  Result := LTokens.Scope.Split([' '], TStringSplitOptions.ExcludeEmpty);
end;

function TIAM4DKeycloakClient.HasGrantedScope(const AScope: string): Boolean;
var
  LScope: string;
begin
  for LScope in GetGrantedScopes do
    if SameStr(LScope, AScope.Trim) then
      Exit(True);
  Result := False;
end;

procedure TIAM4DKeycloakClient.InvalidateAccessToken(const AAccessToken: string);
var
  LTokens: TIAM4DTokens;
begin
  if AAccessToken.IsEmpty then
    Exit;
  // Same session: the generation stays, so a renewal in progress still stores its tokens
  FTokenSaveLock.Acquire;
  try
    if not FTokenStorage.HasTokens then
      Exit;
    LTokens := FTokenStorage.LoadTokens;
    if SecureStringEquals(LTokens.AccessToken, AAccessToken) then
    begin
      LTokens.AccessTokenExpiry := 0;
      FTokenStorage.SaveTokens(LTokens);
    end;
  finally
    FTokenSaveLock.Release;
  end;
end;

function TIAM4DKeycloakClient.CurrentTokenGeneration: Int64;
begin
  FTokenSaveLock.Acquire;
  try
    Result := FTokenGeneration;
  finally
    FTokenSaveLock.Release;
  end;
end;

procedure TIAM4DKeycloakClient.ClearAuthorizationContext;
var
  LContext: TIAM4DOAuthContext;
begin
  SecureZeroString(FState);
  SecureZeroString(FNonce);
  SecureZeroString(FPKCEVerifier);
  SecureZeroString(FPKCEChallenge);

  if Assigned(FCallbackHandler) then
  begin
    LContext.Clear;
    // Under the lock: a token exchange may be copying the context
    FAuthCompletionLock.Acquire;
    try
      FCallbackHandler.SetOAuthContext(LContext);
    finally
      FAuthCompletionLock.Release;
    end;
  end;
end;

procedure TIAM4DKeycloakClient.ConfigureInternal(const AConfig: TIAM4DClientConfig);
begin
  // Before anything changes: a refused configuration keeps the current one
  if not AConfig.AllowInsecureHTTP then
  begin
    if TIAM4DClientConfig.IsInsecureHTTPURL(AConfig.BaseURL) then
      raise EIAM4DInvalidConfigurationException.CreateFmt('BaseURL %s is plain HTTP to a host other than the ' +
        'loopback: code, tokens and credentials would travel in clear text. Use https://, or WithAllowInsecureHTTP ' +
        'for a test environment.', [AConfig.BaseURL]);
    if TIAM4DClientConfig.IsInsecureHTTPURL(AConfig.ExternalCallbackURL) then
      raise EIAM4DInvalidConfigurationException.CreateFmt('Redirect URL %s is plain HTTP to a host other than the ' +
        'loopback: the authorization code would travel in clear text. Use https://, or WithAllowInsecureHTTP ' +
        'for a test environment.', [AConfig.ExternalCallbackURL]);
  end;

  FKeycloakConfig := AConfig;
  // Issuer and keys of the previous configuration no longer apply
  FIDTokenValidator := nil;

  // The pooled clients keep the timeouts of the previous configuration
  DiscardHTTPClients;

  FSSLValidator.SetValidationMode(AConfig.SSLValidationMode);

  ResetScopes;

  ClearTokens;

  if Assigned(FCallbackHandler) and FCallbackHandler.IsListening then
    FCallbackHandler.Stop;

  // A login waiting for the callback of the old handler can no longer complete: cancelled
  FAuthCompletionLock.Acquire;
  try
    if Assigned(FAuthCompletionSource) then
      FAuthCompletionSource.TrySetCancelled;
    FAuthCompletionSource := nil;
  finally
    FAuthCompletionLock.Release;
  end;

  FCallbackHandler := nil;

  if FKeycloakConfig.GrantType = gtAuthorizationCode then
    CreateCallbackHandler;

  Self.InternalWellKnownFetchEndpoints;

  CreateIDTokenValidator;
end;

procedure TIAM4DKeycloakClient.CreateIDTokenValidator;
var
  LHTTPConfig: TIAM4DHTTPClientConfig;
  LJWKSProvider: TIAM4DJWKSProvider;
  LJWKS: IIAM4DJWKSProvider;
  LValidator: TIAM4DJWTValidator;
  LValidatorRef: IIAM4DJWTValidator;
begin
  // The keys are fetched like the other requests of the client: same SSL mode and pinned keys
  // (the validator of the client), same timeouts
  LHTTPConfig := TIAM4DHTTPClientConfig.FromClientConfig(FKeycloakConfig);
  // Without pins: the provider of the process for this SSL mode and timeouts, whose keys the other
  // clients of the realm already fetched (nil when TIAM4DSharedJWKSProviders is disabled)
  LJWKS := nil;
  if not FHasPinnedKeys then
    LJWKS := TIAM4DSharedJWKSProviders.Acquire(LHTTPConfig, GetIssuer, GetJWKSUri);
  if not Assigned(LJWKS) then
  begin
    LJWKSProvider := TIAM4DJWKSProvider.Create(LHTTPConfig, FSSLValidator);
    LJWKS := LJWKSProvider;
    // jwks_uri of the discovery document already fetched: no second discovery request. The
    // provider caches the keys and refreshes them when Keycloak rotates them (unknown kid)
    if not (GetIssuer.Trim.IsEmpty or GetJWKSUri.Trim.IsEmpty) then
      LJWKSProvider.SetJWKSUri(GetIssuer, GetJWKSUri);
  end;

  // Empty issuer in the discovery document: every id_token is refused
  LValidator := TIAM4DJWTValidator.Create(GetIssuer, FKeycloakConfig.ClientID, LJWKS, LHTTPConfig);
  LValidatorRef := LValidator;
  LValidatorRef.ClockSkewSeconds := IAM4D_AUTH_TIME_CLOCK_SKEW_SECONDS;
  // The id_token was issued while the client waited for the token response: iat older than
  // the clock skew plus the response timeout is not plausible
  LValidator.SetIatMaxAge(IAM4D_AUTH_TIME_CLOCK_SKEW_SECONDS + Max(FKeycloakConfig.ResponseTimeout div 1000, 60));
  // Each id_token is validated once: nothing to gain from keeping its claims
  LValidator.SetTokenCacheEnabled(False);
  // Keycloak access tokens (typ Bearer) are not ID tokens
  LValidator.SetExpectedTokenType(IAM4D_KEYCLOAK_TOKEN_TYPE_ID);
  FIDTokenValidator := LValidatorRef;
end;

function TIAM4DKeycloakClient.CreateHTTPClient: THTTPClient;
begin
  Result := TIAM4DHTTPClientFactory.CreateHTTPClient(FKeycloakConfig, FSSLHelper);
end;

function TIAM4DKeycloakClient.ExecuteCallHTTP<T>(const AOperation: TFunc<THTTPClient, T>): T;
var
  LClient: THTTPClient;
  LGeneration: Integer;
begin
  // The lock covers only the pool: the request itself runs without it
  LClient := AcquireHTTPClient(LGeneration);
  try
    Result := AOperation(LClient);
  finally
    ReleaseHTTPClient(LClient, LGeneration);
  end;
end;

const
  // Idle clients kept for reuse; more concurrent requests create extra clients, freed afterwards
  IAM4D_HTTP_CLIENT_POOL_SIZE = 4;

function TIAM4DKeycloakClient.AcquireHTTPClient(out AGeneration: Integer): THTTPClient;
begin
  FHTTPClientLock.Acquire;
  try
    AGeneration := FHTTPClientGeneration;
    if FHTTPClientPool.Count > 0 then
      Result := FHTTPClientPool.Pop
    else
      Result := Self.CreateHTTPClient;
  finally
    FHTTPClientLock.Release;
  end;
end;

procedure TIAM4DKeycloakClient.ReleaseHTTPClient(AClient: THTTPClient; AGeneration: Integer);
begin
  FHTTPClientLock.Acquire;
  try
    if (AGeneration = FHTTPClientGeneration) and (FHTTPClientPool.Count < IAM4D_HTTP_CLIENT_POOL_SIZE) then
    begin
      FHTTPClientPool.Push(AClient);
      AClient := nil;
    end;
  finally
    FHTTPClientLock.Release;
  end;
  AClient.Free;
end;

procedure TIAM4DKeycloakClient.DiscardHTTPClients;
var
  LClients: TArray<THTTPClient>;
  LClient: THTTPClient;
begin
  FHTTPClientLock.Acquire;
  try
    Inc(FHTTPClientGeneration);
    LClients := FHTTPClientPool.ToArray;
    FHTTPClientPool.Clear;
  finally
    FHTTPClientLock.Release;
  end;
  for LClient in LClients do
    LClient.Free;
end;

procedure TIAM4DKeycloakClient.Configure(const AConfig: TIAM4DClientConfig);
begin
  ConfigureInternal(AConfig);
end;

function TIAM4DKeycloakClient.ConfigureAsync(const AConfig: TIAM4DClientConfig): IAsyncVoidPromise;
var
  LSelf: IIAM4DClient;
begin
  LSelf := Self;
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      (LSelf as TIAM4DKeycloakClient).ConfigureInternal(AConfig);
    end);
end;

constructor TIAM4DKeycloakClient.Create(
  const ACallbackMode: TIAM4DCallbackMode;
  const AStorage: IIAM4DTokenStorage);
begin
  inherited Create();

  FCallbackMode := ACallbackMode;

  FScopes := TStringList.Create;
  FSSLValidator := TIAM4DSSLCertificateValidator.Create;
  FSSLHelper := TIAM4DHTTPClientSSLHelper.Create(FSSLValidator);

  FHTTPClientPool := TStack<THTTPClient>.Create;
  FHTTPClientLock := TCriticalSection.Create;

  if AStorage = nil then
  begin
    var LKey32: TBytes := TIAM4DCryptoUtils.GenerateSecureRandomBytes(32);
    var LAAD: TBytes := TEncoding.UTF8.GetBytes('IAMClient4D/v1');
    try
      FTokenStorage := TIAM4DAESMemoryTokenStorageRawKey32.Create(LKey32, LAAD);
    finally
      // The storage keeps its own copy of the key
      SecureZero(LKey32);
    end;
  end
  else
    FTokenStorage := AStorage;

  FRefreshLock := TCriticalSection.Create;
  FTokenSaveLock := TCriticalSection.Create;
  FAuthCompletionLock := TCriticalSection.Create;
  FPendingWork := TIAM4DPendingWork.Create;

  ClearTokens;
end;

destructor TIAM4DKeycloakClient.Destroy;
begin
  // Stop the callback server first: no authorization code can arrive while the client is destroyed
  if Assigned(FCallbackHandler) and FCallbackHandler.IsListening then
    FCallbackHandler.Stop;

  // A pending flow ends as cancelled: OnError is not raised while the owner is being destroyed
  FAuthCompletionLock.Acquire;
  try
    if Assigned(FAuthCompletionSource) then
      FAuthCompletionSource.TrySetCancelled;
    FAuthCompletionSource := nil;
  finally
    FAuthCompletionLock.Release;
  end;

  // A token exchange still running uses this object: wait for it (it discards its tokens)
  if Assigned(FPendingWork) then
    FPendingWork.CloseAndWait;

  FCallbackHandler := nil;

  DiscardHTTPClients;
  FHTTPClientPool.Free;
  FHTTPClientLock.Free;

  FSSLHelper.Free;
  FSSLValidator := nil;
  FRefreshLock.Free;
  FTokenSaveLock.Free;
  FAuthCompletionLock.Free;
  FScopes.Free;

  inherited;
end;

procedure TIAM4DKeycloakClient.CreateCallbackHandler;
begin
  case FCallbackMode of
    cbmLocalServer:
      begin
        FCallbackHandler := TIAM4DLocalCallbackHandler.Create(
          FKeycloakConfig.CallbackPort,
          IAM4D_OAUTH2_CALLBACK_DEFAULT_PATH,
          FKeycloakConfig.AppActivation,
          FKeycloakConfig.LoopbackRedirectHost);
      end;

    cbmExternal:
      begin
        FCallbackHandler := TIAM4DExternalCallbackHandler.Create(
          FKeycloakConfig.ExternalCallbackURL);
      end;

    cbmAppRedirect:
      begin
        FCallbackHandler := TIAM4DAppRedirectCallbackHandler.Create(
          FKeycloakConfig.ExternalCallbackURL);
      end;
  else
    raise EIAM4DException.Create('Unsupported callback mode');
  end;
end;

procedure TIAM4DKeycloakClient.InitializeOAuthContext;
var
  LContext: TIAM4DOAuthContext;
begin
  if not Assigned(FCallbackHandler) then
    raise EIAM4DException.Create('Callback handler not initialized');

  LContext.State := FState;
  LContext.Nonce := FNonce;
  LContext.PKCEVerifier := FPKCEVerifier;
  LContext.PKCEChallenge := FPKCEChallenge;
  LContext.RedirectURI := FCallbackHandler.RedirectURI;
  // auth_time is checked against the max_age sent in this login
  LContext.MaxAge := EffectiveMaxAge(FAuthOptions);
  LContext.AuthRequestTime := DateTimeToUnix(TDateTime.NowUTC);
  // RFC 9207: the redirect must come from this issuer (required when the discovery says it sends iss)
  LContext.Issuer := GetIssuer;
  LContext.IssRequired := FWellKnownEndPoints.AuthorizationResponseIssParameterSupported;

  // Under the lock: a token exchange may be copying the context
  FAuthCompletionLock.Acquire;
  try
    FCallbackHandler.SetOAuthContext(LContext);
  finally
    FAuthCompletionLock.Release;
  end;
end;

procedure TIAM4DKeycloakClient.InitializeOAuthContextInternal;

  // 128 bits of the CSPRNG of the library as 32 hex characters (the format IsValidStateFormat expects)
  function RandomHex128: string;
  var
    LBytes: TBytes;
    LByte: Byte;
  begin
    Result := '';
    LBytes := TIAM4DCryptoUtils.GenerateSecureRandomBytes(16);
    for LByte in LBytes do
      Result := Result + IntToHex(LByte, 2).ToLower;
  end;

begin
  if FScopes.IndexOf(IAM4D_OAUTH2_SCOPE_OPENID) = -1 then
    FScopes.Add(IAM4D_OAUTH2_SCOPE_OPENID);

  FState := RandomHex128;
  FNonce := RandomHex128;

  GeneratePKCE;

  InitializeOAuthContext;
end;

function TIAM4DKeycloakClient.IsValidStateFormat(const AState: string): Boolean;
const
  EXPECTED_LENGTH = 32;
  VALID_CHARS = ['0'..'9', 'a'..'f', 'A'..'F'];
var
  I: Integer;
begin
  Result := False;

  if AState.Length <> EXPECTED_LENGTH then
    Exit;

  for I := 1 to AState.Length do
  begin
    if not CharInSet(AState[I], VALID_CHARS) then
      Exit;
  end;

  Result := True;
end;

function TIAM4DKeycloakClient.ExchangeAuthorizationCode(const ACode, AState: string;
  const AContext: TIAM4DOAuthContext): TIAM4DTokens;
begin
  if AState.Trim.IsEmpty then
    raise EIAM4DStateMismatchException.Create(
      'State parameter is missing or empty - possible CSRF attack attempt.');

  if AContext.State.Trim.IsEmpty then
    raise EIAM4DException.Create(
      'No authorization flow is waiting for this callback: not started, already completed or cancelled.');

  if not IsValidStateFormat(AState) then
    raise EIAM4DStateMismatchException.Create(
      'State parameter has invalid format - possible tampering detected.');

  if not SecureStringEquals(AState, AContext.State) then
    raise EIAM4DStateMismatchException.Create(
      'State mismatch in OAuth2 callback. Possible CSRF attack or session mix-up.');

  Result := ExchangeCodeForTokens(ACode, AContext.PKCEVerifier);

  ValidateIDToken(Result.IDToken, AContext);
end;

function TIAM4DKeycloakClient.CompleteAuthorizationFlowInternal(const ACode, AState, AIss: string): TIAM4DTokens;
var
  LContext: TIAM4DOAuthContext;
begin
  if FKeycloakConfig.GrantType <> gtAuthorizationCode then
    raise EIAM4DException.Create('CompleteAuthorizationFlow is only for Authorization Code grant type.');

  if not Assigned(FCallbackHandler) then
    raise EIAM4DException.Create('Callback handler not initialized: call StartAuthorizationFlowAsync or '
      + 'InitializeAuthorizationFlow first.');

  if FCallbackMode = cbmExternal then
    LContext := (FCallbackHandler as TIAM4DExternalCallbackHandler).TakeContext(AState)
  else
    LContext := FCallbackHandler.GetOAuthContext;
  // The application passes iss when it has it: a missing one is not refused here (the redirect
  // URL is parsed by the application, which may not forward it)
  if AIss <> '' then
    LContext.CheckResponseIssuer(AIss);
  Result := ExchangeAuthorizationCode(ACode, AState, LContext);

  StoreTokens(Result);

  if FCallbackMode = cbmExternal then
    (FCallbackHandler as TIAM4DExternalCallbackHandler).ClearContext;
end;

function TIAM4DKeycloakClient.TryGetFlowContext(const ASource: IAsyncTaskCompletionSource<string>;
  out AContext: TIAM4DOAuthContext): Boolean;
begin
  FAuthCompletionLock.Acquire;
  try
    Result := (FAuthCompletionSource = ASource) and Assigned(FCallbackHandler);
    if Result then
      AContext := FCallbackHandler.GetOAuthContext;
  finally
    FAuthCompletionLock.Release;
  end;
end;

procedure TIAM4DKeycloakClient.CompleteLocalAuthorizationFlow(const ASource: IAsyncTaskCompletionSource<string>;
  const ACode, AState, AKeycloakActionStatus: string);
var
  LContext: TIAM4DOAuthContext;
  LTokens: TIAM4DTokens;
  LError: Exception;
begin
  try
    // A copy: a new flow or a cancel may rewrite the context during the exchange
    if not TryGetFlowContext(ASource, LContext) then
      Exit;

    LTokens := ExchangeAuthorizationCode(ACode, AState, LContext);

    // Only a flow still current stores its tokens: after a cancel they are discarded
    if EndAuthorizationFlow(ASource,
      procedure
      begin
        StoreTokens(LTokens);
        FKeycloakActionStatus := AKeycloakActionStatus;
      end) then
      ASource.TrySetResult(LTokens.AccessToken);
  except
    on E: Exception do
    begin
      LError := Exception(AcquireExceptionObject);
      // A flow already ended keeps its outcome (e.g. cancelled)
      if EndAuthorizationFlow(ASource) then
        ASource.TrySetException(LError)
      else
        LError.Free;
    end;
  end;
end;

function TIAM4DKeycloakClient.EncodeFormParams(const AParams: TStrings): string;
var
  LSB: TStringBuilder;
  LIndex: Integer;
begin
  // Use TStringBuilder for O(n) performance instead of O(n²) string concatenation
  LSB := TStringBuilder.Create;
  try
    for LIndex := 0 to AParams.Count - 1 do
    begin
      if LIndex > 0 then
        LSB.Append('&');
      LSB.Append(TNetEncoding.URL.Encode(AParams.Names[LIndex]))
         .Append('=')
         .Append(TNetEncoding.URL.Encode(AParams.ValueFromIndex[LIndex]));
    end;
    Result := LSB.ToString;
  finally
    // The builder's buffer holds the form too (password, secret, refresh token)
    for LIndex := 0 to LSB.Length - 1 do
      LSB.Chars[LIndex] := #0;
    LSB.Free;
  end;
end;

procedure TIAM4DKeycloakClient.EnsureResponseHTTP200OrFail(const AResponse: IHTTPResponse; const AContext: string);
const
  // Keycloak's error JSON fits; a proxy's HTML error page is cut
  MAX_BODY_IN_MESSAGE = 512;
var
  LBody: string;
begin
  if not (AResponse.StatusCode in [200, 201]) then
  begin
    // Redirects are not followed (TIAM4DHTTPClientFactory): say where the server pointed to
    if (AResponse.StatusCode >= 300) and (AResponse.StatusCode <= 399) then
      raise EIAM4DException.CreateFmt('%s failed: %d - redirect to "%s" not followed (check BaseURL and the proxy '
        + 'in front of Keycloak)', [AContext, AResponse.StatusCode, AResponse.HeaderValue['Location']]);
    LBody := AResponse.ContentAsString.Trim;
    if LBody.IsEmpty then
      LBody := AResponse.StatusText
    else if LBody.Length > MAX_BODY_IN_MESSAGE then
      LBody := LBody.Substring(0, MAX_BODY_IN_MESSAGE) + '...';
    raise EIAM4DException.CreateFmt('%s failed: %d - %s', [AContext, AResponse.StatusCode, LBody]);
  end;
end;

function TIAM4DKeycloakClient.ExchangeCodeForTokens(const ACode, ACodeVerifier: string): TIAM4DTokens;
var
  LParams: TStringList;
  LJSONObj: TJSONObject;
begin
  LParams := TStringList.Create;
  try
    LParams.AddPair(IAM4D_OAUTH2_PARAM_GRANT_TYPE, IAM4D_OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_REDIRECT_URI, GetRedirectURI);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CODE, ACode);
    if FKeycloakConfig.GrantType = gtAuthorizationCode then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CODE_VERIFIER, ACodeVerifier);
    if not (FKeycloakConfig.ClientSecret.Trim.IsEmpty) then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_SECRET, FKeycloakConfig.ClientSecret);

    LJSONObj := PostToTokenEndpoint(LParams);
    try
      Result := TIAM4DTokens.FromJSONObject(LJSONObj);
    finally
      LJSONObj.Free;
    end;
  finally
    LParams.Free;
  end;
end;

procedure TIAM4DKeycloakClient.InternalWellKnownFetchEndpoints;
var
  LResponse: IHTTPResponse;
  LJSONObj: TJSONObject;
  LCacheKey: string;
begin
  // A client with pinned keys checks the certificate of its own discovery request
  if not FHasPinnedKeys then
  begin
    LCacheKey := TIAM4DDiscoveryCache.KeyOf(GetRealmURL, FKeycloakConfig.SSLValidationMode);
    if TIAM4DDiscoveryCache.TryGet(LCacheKey, FWellKnownEndPoints) then
      Exit;
  end;

  LResponse := ExecuteCallHTTP<IHTTPResponse>(
    function(AClient: THTTPClient): IHTTPResponse
    begin
      Result := TIAM4DHTTPClientFactory.Execute(AClient, sHTTPMethodGet,
        GetRealmURL + '/.well-known/openid-configuration');
    end);

  // An answer that is not a discovery document; network errors keep their own exceptions
  try
    EnsureResponseHTTP200OrFail(LResponse, 'HTTP request');
    LJSONObj := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'discovery document');
  except
    on E: EIAM4DException do
      raise EIAM4DDiscoveryFailedException.Create(GetRealmURL + '/.well-known/openid-configuration', E.Message);
  end;
  try
    FWellKnownEndPoints := TIAM4DWellKnownEndpoints.FromJSONObject(LJSONObj);
  finally
    LJSONObj.Free;
  end;

  // HTTPS realm: an endpoint of the discovery document in plain HTTP would send code, tokens or
  // credentials in clear text
  if GetRealmURL.ToLower.StartsWith('https://') then
    for var LEndpoint in [FWellKnownEndPoints.AuthorizationEndpoint, FWellKnownEndPoints.TokenEndpoint,
      FWellKnownEndPoints.UserInfoEndpoint, FWellKnownEndPoints.EndSessionEndpoint,
      FWellKnownEndPoints.RevocationEndpoint, FWellKnownEndPoints.JWKSUri] do
      if not (LEndpoint.Trim.IsEmpty or LEndpoint.Trim.ToLower.StartsWith('https://')) then
        raise EIAM4DInvalidConfigurationException.Create(Format(
          'Discovery document of %s has a plain HTTP endpoint: %s', [GetRealmURL, LEndpoint]));

  if not FHasPinnedKeys then
    TIAM4DDiscoveryCache.Put(LCacheKey, FWellKnownEndPoints);
end;

function TIAM4DKeycloakClient.EffectiveMaxAge(const AOptions: TIAM4DAuthRequestOptions): Integer;
begin
  if AOptions.MaxAge = IAM4D_MAX_AGE_CONFIGURED then
    Result := FKeycloakConfig.MaxAge
  else
    Result := AOptions.MaxAge;
end;

function TIAM4DKeycloakClient.GenerateAuthURL(const ALoginHint: string; const AIdpHint: string): string;
var
  LOptions: TIAM4DAuthRequestOptions;
begin
  // The options of InitializeAuthorizationFlow(AOptions), with these hints when given
  LOptions := FAuthOptions;
  if not ALoginHint.Trim.IsEmpty then
    LOptions := LOptions.WithLoginHint(ALoginHint);
  if not AIdpHint.Trim.IsEmpty then
    LOptions := LOptions.WithIdpHint(AIdpHint);
  Result := BuildAuthURL(LOptions);
end;

function TIAM4DKeycloakClient.GenerateAuthURL(const AOptions: TIAM4DAuthRequestOptions): string;
var
  LContext: TIAM4DOAuthContext;
begin
  Result := BuildAuthURL(AOptions);

  if EffectiveMaxAge(AOptions) = EffectiveMaxAge(FAuthOptions) then
  begin
    FAuthOptions := AOptions;
    Exit;
  end;
  FAuthOptions := AOptions;
  // Only the external mode opens the URL built here: a login of the local server or of the app
  // redirect keeps the max_age of the URL it opened (a weaker one here would relax its check)
  if (not Assigned(FCallbackHandler)) or (FCallbackMode <> cbmExternal) then
    Exit;

  // Another max_age: the context of this flow must check auth_time against it.
  // Only while it still holds the state of the URL: a consumed context is not brought back
  FAuthCompletionLock.Acquire;
  try
    LContext := FCallbackHandler.OAuthContext;
    if LContext.IsValid and (LContext.State = FState) then
    begin
      LContext.MaxAge := EffectiveMaxAge(AOptions);
      FCallbackHandler.SetOAuthContext(LContext);
    end;
  finally
    FAuthCompletionLock.Release;
  end;
end;

function TIAM4DKeycloakClient.BuildAuthURL(const AOptions: TIAM4DAuthRequestOptions): string;
var
  LParams: TStringList;
  LIdpHint: string;
  LPrompt: string;
  LMaxAge: Integer;
  LIndex: Integer;
begin
  if FKeycloakConfig.GrantType <> gtAuthorizationCode then
    raise EIAM4DException.Create('GenerateAuthURL is only for the Authorization Code grant type.');

  if FState.IsEmpty or FNonce.IsEmpty or FPKCEVerifier.IsEmpty or FPKCEChallenge.IsEmpty then
    raise EIAM4DException.Create(
      'OAuth2 parameters (state, nonce, PKCE) not initialized. ' +
      'Call StartAuthorizationFlowAsync before GenerateAuthURL.');

  LParams := TStringList.Create;
  try
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_REDIRECT_URI, GetRedirectURI);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_RESPONSE_TYPE, IAM4D_OAUTH2_RESPONSE_TYPE_CODE);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_SCOPE, string.Join(' ', FScopes.ToStringArray));
    LParams.AddPair(IAM4D_OAUTH2_PARAM_STATE, FState);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_NONCE, FNonce);
    if not AOptions.LoginHint.IsEmpty then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_LOGIN_HINT, AOptions.LoginHint);
    // The options of the login replace the configured values, they do not add to them
    if Length(AOptions.AcrValues) > 0 then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_ACR_VALUES, string.Join(' ', AOptions.AcrValues))
    else if Length(FKeycloakConfig.AcrValues) > 0 then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_ACR_VALUES, string.Join(' ', FKeycloakConfig.AcrValues));
    // The argument wins over the configured provider; IAM4D_IDP_HINT_NONE drops both
    LIdpHint := AOptions.IdpHint;
    if LIdpHint.IsEmpty then
      LIdpHint := FKeycloakConfig.IdpHint;
    if LIdpHint = IAM4D_IDP_HINT_NONE then
      LIdpHint := '';
    if not LIdpHint.IsEmpty then
      LParams.AddPair(IAM4D_KEYCLOAK_PARAM_IDP_HINT, LIdpHint);
    LPrompt := AOptions.Prompt;
    if LPrompt.IsEmpty then
      LPrompt := FKeycloakConfig.Prompt;
    if not LPrompt.IsEmpty then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_PROMPT, LPrompt);
    LMaxAge := EffectiveMaxAge(AOptions);
    if LMaxAge <> IAM4D_MAX_AGE_NONE then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_MAX_AGE, IntToStr(LMaxAge));
    if Length(AOptions.UILocales) > 0 then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_UI_LOCALES, string.Join(' ', AOptions.UILocales));
    if not FKeycloakConfig.KeycloakAction.IsEmpty then
      LParams.AddPair(IAM4D_KEYCLOAK_PARAM_KC_ACTION, FKeycloakConfig.KeycloakAction);
    for LIndex := 0 to High(AOptions.ParameterNames) do
      LParams.AddPair(AOptions.ParameterNames[LIndex], AOptions.ParameterValues[LIndex]);
    if FKeycloakConfig.GrantType = gtAuthorizationCode then
    begin
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CODE_CHALLENGE, FPKCEChallenge);
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CODE_CHALLENGE_METHOD, IAM4D_OAUTH2_CODE_CHALLENGE_METHOD_S256);
    end;

    Result := FWellKnownEndPoints.AuthorizationEndpoint + '?' + EncodeFormParams(LParams);
  finally
    LParams.Free;
  end;
end;

function TIAM4DKeycloakClient.EndAuthorizationFlow(const ASource: IAsyncTaskCompletionSource<string>;
  const AOnEnd: TProc): Boolean;
var
  LHandler: IIAM4DCallbackHandler;
begin
  FAuthCompletionLock.Acquire;
  try
    // A flow already replaced or cancelled no longer owns the callback server
    Result := FAuthCompletionSource = ASource;
    if not Result then
      Exit;
    // Raising here leaves the flow current: the caller ends it with the error
    if Assigned(AOnEnd) then
      AOnEnd();
    FAuthCompletionSource := nil;
    LHandler := FCallbackHandler;
  finally
    FAuthCompletionLock.Release;
  end;

  if Assigned(LHandler) and LHandler.IsListening then
    LHandler.Stop;
end;

function TIAM4DKeycloakClient.StartAuthorizationFlowAsync(const AIdpHint: string): IAsyncPromise<string>;
begin
  Result := StartAuthorizationFlowInternal(TIAM4DAuthRequestOptions.Create.WithIdpHint(AIdpHint));
end;

function TIAM4DKeycloakClient.StartAuthorizationFlowAsync(const AIdpHint, ALoginHint: string): IAsyncPromise<string>;
begin
  Result := StartAuthorizationFlowInternal(
    TIAM4DAuthRequestOptions.Create.WithIdpHint(AIdpHint).WithLoginHint(ALoginHint));
end;

function TIAM4DKeycloakClient.StartAuthorizationFlowAsync(const AOptions: TIAM4DAuthRequestOptions): IAsyncPromise<string>;
begin
  Result := StartAuthorizationFlowInternal(AOptions);
end;

function TIAM4DKeycloakClient.StartAuthorizationFlowInternal(const AOptions: TIAM4DAuthRequestOptions): IAsyncPromise<string>;
var
  LSource: IAsyncTaskCompletionSource<string>;
  LAuthURL: string;
  LAuthScheme: string;
  LRedirectHandler: TIAM4DRedirectCallbackHandlerBase;
  LPendingWork: IIAM4DPendingWork;
begin
  if FKeycloakConfig.GrantType <> gtAuthorizationCode then
    raise EIAM4DException.Create('StartAuthorizationFlowAsync is only for Authorization Code grant type.');

  if not (FCallbackMode in [cbmLocalServer, cbmAppRedirect]) then
    raise EIAM4DException.Create(
      'StartAuthorizationFlowAsync can only be used with CallbackMode = cbmLocalServer or cbmAppRedirect. ' +
      'For external callbacks (web apps), use InitializeAuthorizationFlow() + GenerateAuthURL() + CompleteAuthorizationFlowAsync().');

  // The closures below complete this source, not the field: a later flow cannot be completed by them.
  // dmInline: its cancellation handler must not depend on the main thread.
  LSource := TAsyncTaskCompletionSource<string>.Create(TAsyncCallbackDispatchMode.dmInline);

  FAuthCompletionLock.Acquire;
  try
    // A previous flow still waiting would never complete: cancel it before its context is replaced
    if Assigned(FAuthCompletionSource) then
      FAuthCompletionSource.TrySetCancelled;
    FAuthCompletionSource := LSource;
    FKeycloakActionStatus := '';
  finally
    FAuthCompletionLock.Release;
  end;

  // The handler keeps these closures: they must not reference it, or neither would ever be freed
  LRedirectHandler := FCallbackHandler as TIAM4DRedirectCallbackHandlerBase;
  // The closures run on other threads and may outlive the client: they use Self only inside TryEnter/Leave
  LPendingWork := FPendingWork;

  LRedirectHandler.SetOnCodeReceived(
    procedure(ACode, AState, AKeycloakActionStatus: string)
    begin
      if not LPendingWork.TryEnter then
        Exit;
      try
        TTask.Run(
          procedure
          begin
            try
              CompleteLocalAuthorizationFlow(LSource, ACode, AState, AKeycloakActionStatus);
            finally
              LPendingWork.Leave;
            end;
          end);
      except
        LPendingWork.Leave;
        raise;
      end;
    end);

  LRedirectHandler.SetOnError(
    procedure(AException: Exception)
    var
      LCopy: Exception;
    begin
      if not LPendingWork.TryEnter then
        Exit;
      try
        if not EndAuthorizationFlow(LSource) then
          Exit;

        // AException is freed by the handler: the source gets its own copy
        if AException is EIAM4DException then
          LCopy := EIAM4DException(AException).Clone
        else
          LCopy := EIAM4DCallbackHandlerException.Create(AException.Message);
        LSource.TrySetException(LCopy);
      finally
        LPendingWork.Leave;
      end;
    end);

  try
    // Before the context: its max_age comes from the options
    FAuthOptions := AOptions;
    InitializeOAuthContextInternal;
    FCallbackHandler.Start;

    LAuthURL := BuildAuthURL(AOptions);
    if (not TIAM4DPlatformUtils.TryGetURIScheme(LAuthURL, LAuthScheme)) or
       (not (SameText(LAuthScheme, 'http') or SameText(LAuthScheme, 'https'))) then
      raise EIAM4DException.CreateFmt('Authorization URL must use HTTP(S): %s', [LAuthURL]);

    if not TIAM4DPlatformUtils.OpenURL(LAuthURL) then
      raise EIAM4DException.CreateFmt('Failed to open browser for authorization URL: %s', [LAuthURL]);
  except
    on E: Exception do
    begin
      EndAuthorizationFlow(LSource);
      ClearAuthorizationContext;
      raise;
    end;
  end;

  // The user may never come back from the browser: Cancel on the returned operation ends the flow
  LSource.Operation.OnCancelled(
    procedure
    begin
      if not LPendingWork.TryEnter then
        Exit;
      try
        // Too late once the tokens are stored: the flow completes normally
        if EndAuthorizationFlow(LSource) then
          LSource.TrySetCancelled;
      finally
        LPendingWork.Leave;
      end;
    end);

  // No thread waits for the browser, and cancelling raises no exception
  Result := TAsyncCore.FromOperation<string>(LSource.Operation);
end;

procedure TIAM4DKeycloakClient.InitializeAuthorizationFlow;
begin
  if FKeycloakConfig.GrantType <> gtAuthorizationCode then
    raise EIAM4DException.Create('InitializeAuthorizationFlow is only for Authorization Code grant type.');

  if FCallbackMode <> cbmExternal then
    raise EIAM4DException.Create(
      'InitializeAuthorizationFlow can only be used with CallbackMode = cbmExternal. ' +
      'For local server mode (desktop apps), use StartAuthorizationFlowAsync() instead.');

  FAuthOptions := TIAM4DAuthRequestOptions.Create;
  InitializeOAuthContextInternal;
end;

procedure TIAM4DKeycloakClient.InitializeAuthorizationFlow(const AOptions: TIAM4DAuthRequestOptions);
begin
  InitializeAuthorizationFlow;
  // Again, with the max_age of the options (same state, nonce and PKCE)
  FAuthOptions := AOptions;
  InitializeOAuthContext;
end;

function TIAM4DKeycloakClient.CompleteAuthorizationFlowAsync(const ACode, AState, AIss: string): IAsyncPromise<string>;
var
  LSelf: IIAM4DClient;
begin
  LSelf := Self;
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := LSelf.CompleteAuthorizationFlow(ACode, AState, AIss);
    end);
end;

function TIAM4DKeycloakClient.GenerateLogoutURL(const APostLogoutRedirectURI, AState: string): string;
var
  LParams: TStringList;
  LTokens: TIAM4DTokens;
  LScheme: string;
begin
  if FWellKnownEndPoints.EndSessionEndpoint.Trim.IsEmpty then
    raise EIAM4DException.Create('The discovery document has no end session endpoint');
  if not APostLogoutRedirectURI.Trim.IsEmpty then
  begin
    if (not TIAM4DPlatformUtils.TryGetURIScheme(APostLogoutRedirectURI, LScheme)) or
       (not (SameText(LScheme, 'http') or SameText(LScheme, 'https'))) then
      raise EIAM4DInvalidConfigurationException.CreateFmt(
        'post_logout_redirect_uri must use HTTP(S): %s', [APostLogoutRedirectURI]);
    if (not FKeycloakConfig.AllowInsecureHTTP) and TIAM4DClientConfig.IsInsecureHTTPURL(APostLogoutRedirectURI) then
      raise EIAM4DInvalidConfigurationException.CreateFmt(
        'post_logout_redirect_uri in plain HTTP to a host other than the loopback: %s ' +
        '(WithAllowInsecureHTTP: tests only)', [APostLogoutRedirectURI]);
  end;

  // Without tokens: no id_token_hint (Keycloak then asks the user to confirm)
  LTokens := Default(TIAM4DTokens);
  if FTokenStorage.HasTokens then
    LTokens := FTokenStorage.LoadTokens;

  LParams := TStringList.Create;
  try
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    if not LTokens.IDToken.Trim.IsEmpty then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_ID_TOKEN_HINT, LTokens.IDToken);

    if not (APostLogoutRedirectURI.Trim.IsEmpty) then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_POST_LOGOUT_REDIRECT_URI, APostLogoutRedirectURI);
    if not AState.Trim.IsEmpty then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_STATE, AState);
    Result := FWellKnownEndPoints.EndSessionEndpoint + '?' + EncodeFormParams(LParams);
  finally
    LParams.Free;
  end;
end;

procedure TIAM4DKeycloakClient.GeneratePKCE;
begin
  TIAM4DPKCEGenerator.Generate(FPKCEVerifier, FPKCEChallenge);
end;

function TIAM4DKeycloakClient.GetAccessTokenInternal: string;
var
  LRefreshedTokens: TIAM4DTokens;
  LGeneration: Int64;
  LStored: Boolean;
begin
  // Another thread may clear the tokens between the check and the load (Logout, refused refresh):
  // an empty token takes the locked path
  if FTokenStorage.IsAccessTokenValid then
  begin
    Result := FTokenStorage.LoadTokens.AccessToken;
    if not Result.IsEmpty then
      Exit;
  end;

  FRefreshLock.Acquire;
  try
    // Logins save without this lock: the generation tells whether one did during the refresh
    LGeneration := CurrentTokenGeneration;
    if FTokenStorage.IsAccessTokenValid then
    begin
      Result := FTokenStorage.LoadTokens.AccessToken;
      if not Result.IsEmpty then
        Exit;
    end;

    case FKeycloakConfig.GrantType of
      gtAuthorizationCode, gtPassword:
        begin
          if FTokenStorage.IsRefreshTokenValid then
          begin
            var LCurrentTokens := FTokenStorage.LoadTokens;
            try
              LRefreshedTokens := RefreshTokensInternal(LCurrentTokens, LGeneration, LStored);
              Result := LRefreshedTokens.AccessToken;
              if not LStored then
              begin
                // Another login came first: its access token, never the one of the old session
                Result := '';
                if FTokenStorage.IsAccessTokenValid then
                  Result := FTokenStorage.LoadTokens.AccessToken;
                if Result.IsEmpty then
                  raise EIAM4DException.Create('The session changed while its tokens were being refreshed: '
                    + 'call GetAccessToken again');
              end;
            except
              // Keycloak refused the refresh token: the session is over. After a network error,
              // a timeout or a server error the tokens stay and the next call refreshes them.
              // A login saved meanwhile is not the refused session: it stays (ClearTokensOf)
              on E: EIAM4DRefreshTokenExpiredException do
              begin
                ClearTokensOf(LGeneration);
                raise;
              end;
              // Signing keys not reachable while checking the id_token: like a network error,
              // the tokens stay (RefreshTokensInternal keeps the new ones without that id_token)
              on E: EIAM4DJWKSUnavailableException do
                raise;
              // The refreshed id_token is not valid: the session can no longer be trusted
              on E: EIAM4DSecurityValidationException do
              begin
                ClearTokensOf(LGeneration);
                raise;
              end;
            end;
          end
          else
            raise EIAM4DRefreshTokenExpiredException.Create;
        end;

      gtClientCredentials:
        begin
          try
            var LNewTokens := Self.RequestClientCredentialsToken;
            Result := LNewTokens.AccessToken;
          except
            on E: EIAM4DException do
            begin
              // Kept as is: e.g. EIAM4DNetworkTimeoutException
              ClearTokensOf(LGeneration);
              raise;
            end;
            on E: Exception do
            begin
              ClearTokensOf(LGeneration);
              raise EIAM4DException.Create('Failed to re-authenticate client for a new access token: ' + E.Message);
            end;
          end;
        end;
    else
      raise EIAM4DException.Create('Unsupported grant type in GetAccessTokenInternal');
    end;
  finally
    FRefreshLock.Release;
  end;
end;

function TIAM4DKeycloakClient.GetAccessTokenAsync: IAsyncPromise<string>;
var
  LSelf: IIAM4DClient;
begin
  LSelf := Self;
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := LSelf.GetAccessToken;
    end);
end;

function TIAM4DKeycloakClient.GetUserInfoAsync: IAsyncPromise<TIAM4DUserInfo>;
var
  LSelf: IIAM4DClient;
begin
  LSelf := Self;
  Result := TAsyncCore.New<TIAM4DUserInfo>(
    function(const AOperation: IAsyncOperation): TIAM4DUserInfo
    begin
      Result := LSelf.GetUserInfo;
    end);
end;

function TIAM4DKeycloakClient.GetIsAuthenticated: Boolean;
begin
  if not FTokenStorage.HasTokens then
  begin
    Result := False;
    Exit;
  end;

  case FKeycloakConfig.GrantType of
    gtAuthorizationCode, gtPassword:
      Result := FTokenStorage.IsRefreshTokenValid;
    gtClientCredentials:
      Result := FTokenStorage.IsAccessTokenValid;
  else
    Result := False;
  end;
end;

function TIAM4DKeycloakClient.GetIssuer: string;
begin
  Result := FWellKnownEndPoints.Issuer;
end;

function TIAM4DKeycloakClient.GetJWKSUri: string;
begin
  Result := FWellKnownEndPoints.JWKSUri;
end;

function TIAM4DKeycloakClient.GetRealmURL: string;
begin
  Result := FKeycloakConfig.BaseURL.TrimRight(['/']) + '/realms/' + FKeycloakConfig.Realm;
end;

function TIAM4DKeycloakClient.GetKeycloakActionStatus: string;
begin
  FAuthCompletionLock.Acquire;
  try
    Result := FKeycloakActionStatus;
  finally
    FAuthCompletionLock.Release;
  end;
end;

function TIAM4DKeycloakClient.GetRedirectURI: string;
begin
  if FKeycloakConfig.GrantType <> gtAuthorizationCode then
  begin
    Result := '';
    Exit;
  end;

  if not Assigned(FCallbackHandler) then
  begin
    Result := '';
    Exit;
  end;

  Result := FCallbackHandler.RedirectURI;
end;

function TIAM4DKeycloakClient.GetUserInfoInternal: TJSONObject;
var
  LResponse: IHTTPResponse;
  LAccessToken, LIDToken: string;
  LIDClaims: TJSONObject;
begin
  if FKeycloakConfig.GrantType = gtClientCredentials then
    raise EIAM4DException.Create('GetUserInfoInternal is not applicable for the Client Credentials grant type.');

  LAccessToken := GetAccessTokenInternal;

  LResponse := ExecuteCallHTTP<IHTTPResponse>(
    function(AClient: THTTPClient): IHTTPResponse
    var
      LHeaders: TNetHeaders;
    begin
      SetLength(LHeaders, 1);
      LHeaders[0].Name := IAM4D_HTTP_HEADER_AUTHORIZATION;
      LHeaders[0].Value := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LAccessToken;
      Result := TIAM4DHTTPClientFactory.Execute(AClient, sHTTPMethodGet, FWellKnownEndPoints.UserInfoEndpoint,
        nil, LHeaders);
    end);

  EnsureResponseHTTP200OrFail(LResponse, 'User info');

  Result := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'UserInfo response');
  try
    // OpenID Connect Core 5.3.2: the sub of the UserInfo response is the one of the ID Token
    LIDToken := FTokenStorage.LoadTokens.IDToken;
    if not LIDToken.Trim.IsEmpty then
    begin
      LIDClaims := IDTokenClaims(LIDToken);
      try
        if Result.GetValue<string>('sub', '') <> LIDClaims.GetValue<string>('sub', '') then
          raise EIAM4DSecurityValidationException.Create(
            'UserInfo response rejected: its subject (sub) is not the one of the ID Token.', ecTokenInvalid);
      finally
        LIDClaims.Free;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

procedure TIAM4DKeycloakClient.LogoutInternal;
var
  LTokens: TIAM4DTokens;
  LResponse: IHTTPResponse;
begin
  // Under the refresh lock: a refresh in progress ends first, and none saves tokens after the logout
  FRefreshLock.Acquire;
  try
  try
    if FTokenStorage.HasTokens and (FKeycloakConfig.GrantType in [gtAuthorizationCode, gtPassword]) then
    begin
      LTokens := FTokenStorage.LoadTokens;
      // With a refresh token: back-channel logout. A server-side GET of the end session URL
      // carries no browser cookie, so Keycloak may not find the session it should end.
      // A refresh token already expired here would be refused: that session is over anyway
      if not LTokens.RefreshToken.Trim.IsEmpty then
      begin
        if FTokenStorage.IsRefreshTokenValid then
          LogoutWithRefreshToken(LTokens.RefreshToken);
      end
      else if FKeycloakConfig.GrantType = gtAuthorizationCode then
      begin
        LResponse := ExecuteCallHTTP<IHTTPResponse>(
          function(AClient: THTTPClient): IHTTPResponse
          begin
            Result := TIAM4DHTTPClientFactory.Execute(AClient, sHTTPMethodGet, GenerateLogoutURL());
          end);
        EnsureResponseHTTP200OrFail(LResponse, 'Logout');
      end;
    end;
  finally
    // The tokens go even when Keycloak cannot be reached: this client has no session any more
    ClearTokens;
    ResetScopes;
    if Assigned(FCallbackHandler) and FCallbackHandler.IsListening then
      FCallbackHandler.Stop;
  end;
  finally
    FRefreshLock.Release;
  end;
end;

function TIAM4DKeycloakClient.LogoutAsync: IAsyncVoidPromise;
var
  LSelf: IIAM4DClient;
begin
  LSelf := Self;
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      LSelf.Logout;
    end);
end;

function TIAM4DKeycloakClient.RevokeTokensAsync: IAsyncVoidPromise;
var
  LSelf: IIAM4DClient;
begin
  LSelf := Self;
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      LSelf.RevokeTokens;
    end);
end;

procedure TIAM4DKeycloakClient.RevokeToken(const AToken, ATokenTypeHint: string);
var
  LParams: TStringList;
  LResponse: IHTTPResponse;
  LJSON: TJSONValue;
  LError: string;
begin
  LParams := TStringList.Create;
  try
    LParams.AddPair(IAM4D_OAUTH2_PARAM_TOKEN, AToken);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_TOKEN_TYPE_HINT, ATokenTypeHint);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    if not FKeycloakConfig.ClientSecret.Trim.IsEmpty then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_SECRET, FKeycloakConfig.ClientSecret);
    LResponse := SendFormRequest(FWellKnownEndPoints.RevocationEndpoint, LParams);
  finally
    LParams.Free;
  end;

  // RFC 7009 2.2: 200 also for a token already invalid or unknown
  if LResponse.StatusCode = 200 then
    Exit;
  LError := '';
  LJSON := TJSONObject.ParseJSONValue(LResponse.ContentAsString);
  try
    if LJSON is TJSONObject then
      LError := TJSONObject(LJSON).GetValue<string>(IAM4D_OAUTH2_ERROR, '');
  finally
    LJSON.Free;
  end;
  if (LResponse.StatusCode = 400) and (LError = IAM4D_OAUTH2_ERROR_UNSUPPORTED_TOKEN_TYPE) then
    Exit;
  raise EIAM4DException.CreateFmt('Revocation of the %s failed: %d - %s', [ATokenTypeHint,
    LResponse.StatusCode,
    IfThen(LResponse.ContentAsString.Trim.IsEmpty, LResponse.StatusText, LResponse.ContentAsString)]);
end;

procedure TIAM4DKeycloakClient.RevokeTokens;
var
  LTokens: TIAM4DTokens;
  LFirstError: TObject;

  procedure TryRevoke(const AToken, ATokenTypeHint: string);
  begin
    if AToken.Trim.IsEmpty then
      Exit;
    try
      RevokeToken(AToken, ATokenTypeHint);
    except
      // The first error is raised at the end; a later one is dropped
      if not Assigned(LFirstError) then
        LFirstError := AcquireExceptionObject;
    end;
  end;

begin
  // Under the refresh lock, as Logout: no refresh stores tokens after the revocation
  FRefreshLock.Acquire;
  try
    // Nothing can be revoked: the tokens stay, so Logout can still end the session
    if FTokenStorage.HasTokens and FWellKnownEndPoints.RevocationEndpoint.Trim.IsEmpty then
      raise EIAM4DException.Create('The discovery document has no revocation endpoint');
    try
      if FTokenStorage.HasTokens then
      begin
        LTokens := FTokenStorage.LoadTokens;
        LFirstError := nil;
        // The refresh token first: it ends the session that would issue new access tokens. The
        // access token is revoked also when that fails
        TryRevoke(LTokens.RefreshToken, IAM4D_OAUTH2_TOKEN_TYPE_HINT_REFRESH_TOKEN);
        TryRevoke(LTokens.AccessToken, IAM4D_OAUTH2_TOKEN_TYPE_HINT_ACCESS_TOKEN);
        if Assigned(LFirstError) then
          raise LFirstError;
      end;
    finally
      ClearTokens;
      ResetScopes;
      if Assigned(FCallbackHandler) and FCallbackHandler.IsListening then
        FCallbackHandler.Stop;
    end;
  finally
    FRefreshLock.Release;
  end;
end;

// ============================================================================
// Synchronous Operations
// ============================================================================

function TIAM4DKeycloakClient.GetAccessToken: string;
begin
  Result := GetAccessTokenInternal;
end;

function TIAM4DKeycloakClient.AuthenticateClient: string;
begin
  AuthenticateClientInternal;
  Result := FTokenStorage.LoadTokens.AccessToken;
end;

function TIAM4DKeycloakClient.AuthenticatePassword(const AUserName, APassword: string): string;
begin
  Result := RequestPasswordToken(AUserName, APassword).AccessToken;
end;

function TIAM4DKeycloakClient.CompleteAuthorizationFlow(const ACode, AState, AIss: string): string;
begin
  Result := CompleteAuthorizationFlowInternal(ACode, AState, AIss).AccessToken;
end;

function TIAM4DKeycloakClient.GetUserInfo: TIAM4DUserInfo;
var
  LJSONObj: TJSONObject;
begin
  LJSONObj := GetUserInfoInternal;
  try
    Result := TIAM4DUserInfo.FromJSONObject(LJSONObj);
  finally
    LJSONObj.Free;
  end;
end;

procedure TIAM4DKeycloakClient.Logout;
begin
  LogoutInternal;
end;

function TIAM4DKeycloakClient.SendFormRequest(const AURL: string; const AParams: TStrings): IHTTPResponse;
var
  LContent: TBytesStream;
  LEncoded: string;
  LBytes: TBytes;
begin
  LContent := nil;
  try
    LEncoded := EncodeFormParams(AParams);
    LBytes := TEncoding.UTF8.GetBytes(LEncoded);
    SecureZeroString(LEncoded);
    // The stream shares LBytes: wiping LBytes wipes the request body
    LContent := TBytesStream.Create(LBytes);
    Result := ExecuteCallHTTP<IHTTPResponse>(
      function(AClient: THTTPClient): IHTTPResponse
      begin
        Result := TIAM4DHTTPClientFactory.Execute(AClient, sHTTPMethodPost, AURL,
          LContent, [TNetHeader.Create(sContentType, IAM4D_CONTENT_TYPE_FORM_URLENCODED)]);
      end);
  finally
    // The form may hold a password, a secret or a refresh token
    SecureZero(LBytes);
    LContent.Free;
    SecureZeroStrings(AParams);
  end;
end;

function TIAM4DKeycloakClient.SendTokenRequest(const AParams: TStrings): IHTTPResponse;
begin
  Result := SendFormRequest(FWellKnownEndPoints.TokenEndpoint, AParams);
end;

function TIAM4DKeycloakClient.IsInvalidGrant(const AResponse: IHTTPResponse; out ADescription: string): Boolean;
var
  LJSONObj: TJSONObject;
  LError: string;
begin
  Result := False;
  ADescription := '';
  // Keycloak answers 400 (401 for an unauthorized client) with an OAuth2 error object
  if (AResponse.StatusCode <> 400) and (AResponse.StatusCode <> 401) then
    Exit;
  if not TIAM4DJSONUtils.TryParseJSONObject(AResponse.ContentAsString, LJSONObj) then
    Exit;
  try
    LError := LJSONObj.GetValue<string>(IAM4D_OAUTH2_ERROR, '');
    ADescription := LJSONObj.GetValue<string>(IAM4D_OAUTH2_ERROR_DESCRIPTION, '');
  finally
    LJSONObj.Free;
  end;
  Result := SameText(LError, IAM4D_OAUTH2_ERROR_INVALID_GRANT);
end;

function TIAM4DKeycloakClient.PostToTokenEndpoint(
  const
  AParams:
  TStrings): TJSONObject;
var
  LResponse: IHTTPResponse;
begin
  LResponse := SendTokenRequest(AParams);

  EnsureResponseHTTP200OrFail(LResponse, 'Token endpoint');

  Result := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'Token response');
end;

procedure TIAM4DKeycloakClient.RaisePasswordGrantError(const AResponse: IHTTPResponse);
var
  LDescription: string;
begin
  if not IsInvalidGrant(AResponse, LDescription) then
    Exit;

  // Keycloak 26 answers a user locked by the brute force detection with "Invalid user
  // credentials", also for the right password: a temporary lock is not told apart
  if SameText(LDescription, IAM4D_KEYCLOAK_ERROR_INVALID_USER_CREDENTIALS) then
    raise EIAM4DInvalidCredentialsException.Create;
  if SameText(LDescription, IAM4D_KEYCLOAK_ERROR_ACCOUNT_NOT_FULLY_SET_UP) then
    raise EIAM4DAccountNotFullySetUpException.Create;
  if SameText(LDescription, IAM4D_KEYCLOAK_ERROR_ACCOUNT_DISABLED) or
    SameText(LDescription, IAM4D_KEYCLOAK_ERROR_ACCOUNT_TEMPORARILY_DISABLED) then
    raise EIAM4DAccountDisabledException.Create(LDescription);
end;

function TIAM4DKeycloakClient.RequestPasswordToken(const AUserName, APassword: string): TIAM4DTokens;
var
  LParams: TStringList;
  LResponse: IHTTPResponse;
  LJSONObj: TJSONObject;
begin
  if FKeycloakConfig.GrantType <> gtPassword then
    raise EIAM4DException.Create('AuthenticatePassword is only for the Password grant type.');
  if AUserName.Trim.IsEmpty then
    raise EIAM4DInvalidCredentialsException.Create;

  // id_token: needed by Logout; offline scopes are the caller's choice
  if FScopes.IndexOf(IAM4D_OAUTH2_SCOPE_OPENID) = -1 then
    FScopes.Add(IAM4D_OAUTH2_SCOPE_OPENID);

  LParams := TStringList.Create;
  try
    LParams.AddPair(IAM4D_OAUTH2_PARAM_GRANT_TYPE, IAM4D_OAUTH2_GRANT_TYPE_PASSWORD);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    if not FKeycloakConfig.ClientSecret.Trim.IsEmpty then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_SECRET, FKeycloakConfig.ClientSecret);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_USERNAME, AUserName);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_PASSWORD, APassword);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_SCOPE, string.Join(' ', FScopes.ToStringArray));

    LResponse := SendTokenRequest(LParams);
  finally
    LParams.Free;
  end;

  RaisePasswordGrantError(LResponse);
  EnsureResponseHTTP200OrFail(LResponse, 'Token endpoint');

  LJSONObj := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'Token response');
  try
    Result := TIAM4DTokens.FromJSONObject(LJSONObj);
  finally
    LJSONObj.Free;
  end;

  // Before anything changes: a refused id_token keeps the previous session
  ValidateDirectIDToken(Result.IDToken);

  // A new login replaces the tokens of the previous one: without its refresh token that
  // session could not be ended any more, so it ends now
  EndReplacedSession;
  StoreTokens(Result);
end;

procedure TIAM4DKeycloakClient.EndReplacedSession;
var
  LTokens: TIAM4DTokens;
begin
  if not FTokenStorage.HasTokens or not FTokenStorage.IsRefreshTokenValid then
    Exit;
  LTokens := FTokenStorage.LoadTokens;
  try
    LogoutWithRefreshToken(LTokens.RefreshToken);
  except
    // The new login counts: the old session ends at its idle timeout
  end;
end;

procedure TIAM4DKeycloakClient.ResetScopes;
begin
  FScopes.Clear;
  if Length(FKeycloakConfig.Scopes) > 0 then
    AddScopesIfMissing(FKeycloakConfig.Scopes);
end;

procedure TIAM4DKeycloakClient.LogoutWithRefreshToken(const ARefreshToken: string);
var
  LParams: TStringList;
  LResponse: IHTTPResponse;
  LDescription: string;
begin
  // No session to end
  if ARefreshToken.Trim.IsEmpty or FWellKnownEndPoints.EndSessionEndpoint.IsEmpty then
    Exit;

  LParams := TStringList.Create;
  try
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    if not FKeycloakConfig.ClientSecret.Trim.IsEmpty then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_SECRET, FKeycloakConfig.ClientSecret);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_REFRESH_TOKEN, ARefreshToken);
    LResponse := SendFormRequest(FWellKnownEndPoints.EndSessionEndpoint, LParams);
  finally
    LParams.Free;
  end;

  // Keycloak answers 204 No Content, also for a session already closed on the server
  if LResponse.StatusCode in [200, 204] then
    Exit;
  // Refresh token refused (revoked, expired, unknown): no session left to end
  if IsInvalidGrant(LResponse, LDescription) then
    Exit;
  raise EIAM4DException.CreateFmt('Logout failed: %d - %s', [
    LResponse.StatusCode,
    IfThen(LResponse.ContentAsString.Trim.IsEmpty, LResponse.StatusText, LResponse.ContentAsString)]);
end;

function TIAM4DKeycloakClient.RefreshTokensInternal(const ACurrent: TIAM4DTokens; AGeneration: Int64;
  out AStored: Boolean): TIAM4DTokens;
var
  LParams: TStringList;
  LResponse: IHTTPResponse;
  LJSONObj: TJSONObject;
  LDescription: string;
begin
  LParams := TStringList.Create;
  try
    LParams.AddPair(IAM4D_OAUTH2_PARAM_GRANT_TYPE, IAM4D_OAUTH2_GRANT_TYPE_REFRESH_TOKEN);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_REFRESH_TOKEN, ACurrent.RefreshToken);
    if not (FKeycloakConfig.ClientSecret.Trim.IsEmpty) then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_SECRET, FKeycloakConfig.ClientSecret);
    LResponse := SendTokenRequest(LParams);
  finally
    LParams.Free;
  end;

  // Refused by Keycloak ("Session not active", "Token is not active", ...): a new login is needed
  if IsInvalidGrant(LResponse, LDescription) then
    raise EIAM4DRefreshTokenExpiredException.Create.WithContext(IAM4D_OAUTH2_ERROR_DESCRIPTION, LDescription);
  EnsureResponseHTTP200OrFail(LResponse, 'Token endpoint');

  LJSONObj := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'Token response');
  try
    Result := TIAM4DTokens.FromJSONObject(LJSONObj);
  finally
    LJSONObj.Free;
  end;

  if Result.RefreshToken.Trim.IsEmpty then
  begin
    Result.RefreshToken := ACurrent.RefreshToken;
    Result.RefreshExpiresIn := ACurrent.RefreshExpiresIn;
    Result.RefreshTokenExpiry := ACurrent.RefreshTokenExpiry;
  end;

  try
    ValidateRefreshedIDToken(Result.IDToken, ACurrent.IDToken);
  except
    // Tokens already issued: the access and refresh tokens come from the token endpoint over the
    // validated connection, the unverified id_token is dropped
    on EIAM4DJWKSUnavailableException do
      Result.IDToken := '';
  end;
  if Result.IDToken.Trim.IsEmpty then
    Result.IDToken := ACurrent.IDToken;
  // RFC 6749 5.1: scope omitted when unchanged
  if Result.Scope.Trim.IsEmpty then
    Result.Scope := ACurrent.Scope;
  // A login or a new configuration during the request wins: these tokens belong to the old session
  AStored := TryStoreTokens(Result, AGeneration);
end;

function TIAM4DKeycloakClient.RequestClientCredentialsToken: TIAM4DTokens;
var
  LParams: TStringList;
  LJSONObj: TJSONObject;
begin
  if FKeycloakConfig.GrantType <> gtClientCredentials then
    raise EIAM4DException.Create('This method is only for the Client Credentials grant type.');
  if FKeycloakConfig.ClientSecret.Trim.IsEmpty then
    raise EIAM4DException.Create('Client Secret is required for Client Credentials grant type.');

  LParams := TStringList.Create;
  try
    LParams.AddPair(IAM4D_OAUTH2_PARAM_GRANT_TYPE, IAM4D_OAUTH2_GRANT_TYPE_CLIENT_CREDENTIALS);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_SECRET, FKeycloakConfig.ClientSecret);
    if not FScopes.Text.Trim.IsEmpty then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_SCOPE, string.Join(' ', FScopes.ToStringArray));

    LJSONObj := PostToTokenEndpoint(LParams);
    try
      Result := TIAM4DTokens.FromJSONObject(LJSONObj);
    finally
      LJSONObj.Free;
    end;
  finally
    LParams.Free;
  end;

  // Keycloak issues no id_token for this grant unless asked for (scope openid): one is validated too
  ValidateDirectIDToken(Result.IDToken);
  StoreTokens(Result);
end;

const
  CLAIM_SUB = 'sub';
  CLAIM_AUD = 'aud';
  CLAIM_AZP = 'azp';

function IDTokenFailure(const AReason: string;
  AErrorCode: TIAM4DErrorCode = ecTokenInvalid): EIAM4DSecurityValidationException;
begin
  // The reason only: never the token
  Result := EIAM4DSecurityValidationException.Create('ID Token validation failed: ' + AReason, AErrorCode);
end;

/// <summary>Audiences of a claim set, sorted (aud is a string or an array of strings)</summary>
function IDTokenAudiences(const AClaims: TJSONObject): TArray<string>;
var
  LValue, LItem: TJSONValue;
begin
  Result := nil;
  LValue := AClaims.Values[CLAIM_AUD];
  if LValue is TJSONString then
    Result := [TJSONString(LValue).Value]
  else if LValue is TJSONArray then
    for LItem in TJSONArray(LValue) do
      if LItem is TJSONString then
        Result := Result + [TJSONString(LItem).Value];
  TArray.Sort<string>(Result);
end;

/// <summary>Claims of an id_token already validated, without checking it again</summary>
function IDTokenClaims(const AIDToken: string): TJSONObject;
var
  LParts: TArray<string>;
begin
  LParts := AIDToken.Split(['.']);
  if Length(LParts) <> 3 then
    raise IDTokenFailure('the ID Token of the session has an invalid format.');
  Result := TIAM4DJSONUtils.SafeParseJSONObject(
    TEncoding.UTF8.GetString(TNetEncoding.Base64URL.DecodeStringToBytes(LParts[1])), 'ID Token payload');
end;

function TIAM4DKeycloakClient.VerifyIDToken(const AIDToken: string): TJSONObject;
var
  LAzp: TJSONValue;
  LValid: Boolean;
begin
  if not Assigned(FIDTokenValidator) then
    raise EIAM4DException.Create('Client not configured: the ID Token cannot be validated.');

  Result := nil;
  try
    LValid := FIDTokenValidator.ValidateToken(AIDToken, Result);
  except
    // Keys not reachable: a problem of the identity provider, not of the token
    on E: EIAM4DJWKSUnavailableException do
    begin
      FreeAndNil(Result);
      raise;
    end;
    on E: EIAM4DSecurityValidationException do
    begin
      FreeAndNil(Result);
      // The code of the validator (ecJWTExpired, ecJWTAudienceMismatch...), ecTokenInvalid otherwise
      if E.ErrorCode = ecUnknown then
        raise IDTokenFailure(E.Message)
      else
        raise IDTokenFailure(E.Message, E.ErrorCode);
    end;
  end;
  if not LValid then
  begin
    FreeAndNil(Result);
    raise IDTokenFailure('claims not valid.');
  end;

  // OpenID Connect Core 3.1.3.7, points 4-5: the validator requires azp with several audiences;
  // when present, it must be this client
  LAzp := Result.Values[CLAIM_AZP];
  if Assigned(LAzp) and not ((LAzp is TJSONString) and
    SecureStringEquals(TJSONString(LAzp).Value, FKeycloakConfig.ClientID)) then
  begin
    FreeAndNil(Result);
    raise IDTokenFailure(Format('authorized party (azp) is not the client "%s".', [FKeycloakConfig.ClientID]));
  end;
end;

procedure TIAM4DKeycloakClient.ValidateDirectIDToken(const AIDToken: string);
begin
  if AIDToken.Trim.IsEmpty then
    Exit;
  VerifyIDToken(AIDToken).Free;
end;

procedure TIAM4DKeycloakClient.ValidateRefreshedIDToken(const AIDToken, APreviousIDToken: string);
var
  LClaims, LPrevious: TJSONObject;
  LNonce, LPreviousNonce: TJSONValue;
begin
  // OpenID Connect Core 12.2: the refresh response might not contain an id_token
  if AIDToken.Trim.IsEmpty then
    Exit;

  LClaims := VerifyIDToken(AIDToken);
  try
    // No id_token at the login: nothing to compare with
    if APreviousIDToken.Trim.IsEmpty then
      Exit;

    // iss: both validated against the issuer of the discovery document
    LPrevious := IDTokenClaims(APreviousIDToken);
    try
      if LClaims.GetValue<string>(CLAIM_SUB, '') <> LPrevious.GetValue<string>(CLAIM_SUB, '') then
        raise IDTokenFailure('the subject (sub) of the refreshed ID Token is not the one of the login.');

      if string.Join(#0, IDTokenAudiences(LClaims)) <> string.Join(#0, IDTokenAudiences(LPrevious)) then
        raise IDTokenFailure('the audience (aud) of the refreshed ID Token is not the one of the login.');

      // A nonce, if present, is the one of the login
      LNonce := LClaims.Values[IAM4D_OAUTH2_PARAM_NONCE];
      if Assigned(LNonce) then
      begin
        LPreviousNonce := LPrevious.Values[IAM4D_OAUTH2_PARAM_NONCE];
        if not (Assigned(LPreviousNonce) and (LNonce is TJSONString) and (LPreviousNonce is TJSONString) and
          SecureStringEquals(TJSONString(LNonce).Value, TJSONString(LPreviousNonce).Value)) then
          raise IDTokenFailure('the nonce of the refreshed ID Token is not the one of the login.');
      end;
    finally
      LPrevious.Free;
    end;
  finally
    LClaims.Free;
  end;
end;

procedure TIAM4DKeycloakClient.ValidateIDToken(const AIDToken: string; const AContext: TIAM4DOAuthContext);
const
  CLAIM_AUTH_TIME = 'auth_time';
var
  LJSONValue: TJSONObject;
  LNonceValue: string;
  LAuthTime, LOldest: Int64;
  LError: EIAM4DSecurityValidationException;
begin
  if AIDToken.Trim.IsEmpty then
    raise EIAM4DSecurityValidationException.Create('ID Token is empty, cannot validate nonce.', ecTokenInvalid);

  // Signature, iss, aud, azp, exp and iat first: the claims below are trusted only afterwards
  LJSONValue := VerifyIDToken(AIDToken);
  try
    LNonceValue := (LJSONValue as TJSONObject).GetValue<string>(IAM4D_OAUTH2_PARAM_NONCE, '');
    if LNonceValue.Trim.IsEmpty then
      raise EIAM4DSecurityValidationException.Create('Missing nonce in ID Token payload.', ecNonceValidationFailed);

    // Use constant-time comparison for consistency with other security checks
    if not SecureStringEquals(LNonceValue, AContext.Nonce) then
      raise EIAM4DSecurityValidationException.Create(
        'Nonce mismatch in ID Token. Possible replay attack or session mix-up.', ecNonceValidationFailed);

    // max_age travels through the browser: removed from the URL, Keycloak would reuse an older
    // SSO session without asking for the credentials. Only auth_time proves the authentication
    // happened within max_age of the request (counted from the start of the flow, so a slow
    // login or a required action after it is not refused)
    if AContext.MaxAge <> IAM4D_MAX_AGE_NONE then
    begin
      if not TryGetNumericDateClaim(LJSONValue as TJSONObject, CLAIM_AUTH_TIME, LAuthTime) then
        LAuthTime := 0;
      LOldest := AContext.AuthRequestTime - AContext.MaxAge - IAM4D_AUTH_TIME_CLOCK_SKEW_SECONDS;
      LError := nil;
      if LAuthTime <= 0 then
        LError := EIAM4DSecurityValidationException.Create(
          'Missing auth_time in ID Token: max_age was requested, the time of the authentication cannot be verified.',
          ecTokenInvalid)
      else if LAuthTime < LOldest then
        LError := EIAM4DSecurityValidationException.Create(Format(
          'Authentication too old: auth_time %d is more than max_age (%d s) before the login request.',
          [LAuthTime, AContext.MaxAge]), ecTokenInvalid);
      if Assigned(LError) then
      begin
        LError.Context.AddOrSetValue('max_age', IntToStr(AContext.MaxAge));
        if LAuthTime > 0 then
          LError.Context.AddOrSetValue(CLAIM_AUTH_TIME, IntToStr(LAuthTime));
        raise LError;
      end;
    end;
  finally
    LJSONValue.Free;
  end;
end;

function TIAM4DKeycloakClient.GetSSLValidator: IIAM4DSSLCertificateValidator;
begin
  Result := FSSLValidator;
end;

procedure TIAM4DKeycloakClient.AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
begin
  FSSLValidator.AddPinnedPublicKeys(APublicKeyHashes);
  FHasPinnedKeys := FSSLValidator.HasPinnedPublicKeys;
  PinnedPublicKeysChanged;
end;

procedure TIAM4DKeycloakClient.ClearPinnedPublicKeys;
begin
  FSSLValidator.ClearPinnedPublicKeys;
  FHasPinnedKeys := False;
  PinnedPublicKeysChanged;
end;

procedure TIAM4DKeycloakClient.PinnedPublicKeysChanged;
begin
  // A strict client calls the validator only with pins: the HTTP clients are created again
  DiscardHTTPClients;
  if Assigned(FIDTokenValidator) then
    CreateIDTokenValidator;
end;

procedure TIAM4DKeycloakClient.CancelAuthorizationFlow;
begin
  if Assigned(FCallbackHandler) and FCallbackHandler.IsListening then
    FCallbackHandler.Stop;

  // Cancelled, not faulted: the promise runs OnFinally but not OnError
  FAuthCompletionLock.Acquire;
  try
    if Assigned(FAuthCompletionSource) then
      FAuthCompletionSource.TrySetCancelled;
    FAuthCompletionSource := nil;
  finally
    FAuthCompletionLock.Release;
  end;

  ClearAuthorizationContext;
end;

end.
