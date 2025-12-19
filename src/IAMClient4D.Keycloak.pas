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
  System.Hash,
  System.DateUtils,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.Storage.Core,
  IAMClient4D.Server.Callback.Core,
  IAMClient4D.Callback.Handler,
  IAMClient4D.Common.Security,
  IAMClient4D.Common.JSONUtils,
  IAMClient4D.Common.PKCEGenerator,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// Keycloak OAuth2/OIDC client implementation.
  /// </summary>
  /// <remarks>
  /// Implements IIAM4DClient for Keycloak identity provider.
  /// Supports Authorization Code (with PKCE) and Client Credentials flows.
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
  /// SSL validation: Configurable modes (strict/self-signed/disabled) with certificate pinning support.
  /// Token refresh: Automatic refresh on access token expiry.
  /// PKCE: Automatically applied to Authorization Code flow (SHA-256).
  /// Callback modes: Local server (desktop) or external (web apps like uniGUI).
  /// </remarks>
  TIAM4DKeycloakClient = class(TInterfacedObject, IIAM4DClient)
  private
    FScopes: TStrings;
    FKeycloakConfig: TIAM4DClientConfig;
    FCallbackMode: TIAM4DCallbackMode;
    FCallbackHandler: IIAM4DCallbackHandler;
    FAuthCompletionSource: TAsyncTaskCompletionSource<string>;
    FAuthCompletionLock: TCriticalSection;
    FRefreshLock: TCriticalSection;
    FSSLValidator: IIAM4DSSLCertificateValidator;
    FSSLHelper: TIAM4DHTTPClientSSLHelper;

    // HTTP client pooling for connection reuse
    FHTTPClient: THTTPClient;
    FHTTPClientLock: TCriticalSection;

    FWellKnownEndPoints: TIAM4DWellKnownEndpoints;
    FState: string;
    FNonce: string;
    FPKCEVerifier: string;
    FPKCEChallenge: string;
    FTokenStorage: IIAM4DTokenStorage;

    function GetRealmURL: string;
    procedure InternalWellKnownFetchEndpoints;
    function ExecuteCallHTTP<T>(const AOperation: TFunc<THTTPClient, T>): T;
    procedure GeneratePKCE;
    function RefreshTokensInternal(const ARefreshToken: string): TIAM4DTokens;
    /// <exception cref="EIAM4DException">Raised when HTTP request fails or response is not 200/201</exception>
    /// <exception cref="EIAM4DNetworkException">Raised on network errors</exception>
    function PostToTokenEndpoint(const AParams: TStrings): TJSONObject;
    function ExchangeCodeForTokens(const ACode: string): TIAM4DTokens;
    procedure ValidateIDTokenNonce(const AIDToken: string);
    function GenerateLogoutURL(const APostLogoutRedirectURI: string = ''): string;
    function EncodeFormParams(const AParams: TStrings): string;
    procedure AddScopesIfMissing(const AScopes: TArray<string>);
    /// <exception cref="EIAM4DException">Raised when response status is not 200 or 201</exception>
    procedure EnsureResponseHTTP200OrFail(const AResponse: IHTTPResponse; const AContext: string);
    procedure ClearTokens;
    function RequestClientCredentialsToken: TIAM4DTokens;

    procedure CreateCallbackHandler;
    procedure InitializeOAuthContext;
    procedure InitializeOAuthContextInternal;
    function CompleteAuthorizationFlowInternal(const ACode, AState: string): TIAM4DTokens;
    function IsValidStateFormat(const AState: string): Boolean;
    function ConstantTimeEquals(const A, B: string): Boolean;

    procedure ConfigureInternal(const AConfig: TIAM4DClientConfig);
    function GetAccessTokenInternal: string;
    function GetUserInfoInternal: TJSONObject;
    procedure LogoutInternal;
    procedure AuthenticateClientInternal;
    function GenerateAuthURL(const ALoginHint: string = ''): string;
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
    /// Configures the client and discovers OIDC endpoints via well-known URL.
    /// </summary>
    /// <exception cref="EIAM4DNetworkException">Raised on network errors during endpoint discovery</exception>
    /// <exception cref="EIAM4DConfigurationException">Raised when well-known response is invalid</exception>
    function ConfigureAsync(const AConfig: TIAM4DClientConfig): IAsyncVoidPromise;
    /// <summary>
    /// Starts Authorization Code flow for desktop apps (opens browser automatically).
    /// </summary>
    /// <exception cref="EIAM4DAuthenticationException">Raised when authorization fails or is cancelled</exception>
    function StartAuthorizationFlowAsync: IAsyncPromise<string>;
    /// <summary>
    /// Initializes Authorization Code flow for web apps (call before GenerateAuthURL).
    /// </summary>
    procedure InitializeAuthorizationFlow;
    /// <summary>
    /// Completes Authorization Code flow with received code and state (for web apps).
    /// </summary>
    /// <exception cref="EIAM4DAuthenticationException">Raised on invalid state or token exchange failure</exception>
    function CompleteAuthorizationFlowAsync(const ACode, AState: string): IAsyncPromise<string>;
    /// <summary>
    /// Authenticates using Client Credentials flow.
    /// </summary>
    /// <exception cref="EIAM4DAuthenticationException">Raised when client credentials are invalid</exception>
    function AuthenticateClientAsync: IAsyncPromise<string>;
    /// <summary>
    /// Returns valid access token (auto-refreshes if expired).
    /// </summary>
    /// <exception cref="EIAM4DAuthenticationException">Raised when not authenticated or refresh fails</exception>
    function GetAccessTokenAsync: IAsyncPromise<string>;
    /// <summary>
    /// Retrieves OIDC user info from UserInfo endpoint.
    /// </summary>
    /// <exception cref="EIAM4DAuthenticationException">Raised when not authenticated</exception>
    /// <exception cref="EIAM4DNetworkException">Raised on network errors</exception>
    function GetUserInfoAsync: IAsyncPromise<TIAM4DUserInfo>;
    /// <summary>
    /// Logs out and clears stored tokens.
    /// </summary>
    /// <exception cref="EIAM4DNetworkException">Raised on network errors during logout</exception>
    function LogoutAsync: IAsyncVoidPromise;

    // Synchronous Operations
    /// <summary>
    /// Gets valid access token synchronously (auto-refreshes if expired).
    /// </summary>
    function GetAccessToken: string;
    /// <summary>
    /// Authenticates using Client Credentials flow synchronously.
    /// </summary>
    function AuthenticateClient: string;
    /// <summary>
    /// Completes Authorization Code flow synchronously.
    /// </summary>
    function CompleteAuthorizationFlow(const ACode, AState: string): string;
    /// <summary>
    /// Retrieves OIDC user info synchronously.
    /// </summary>
    function GetUserInfo: TIAM4DUserInfo;
    /// <summary>
    /// Logs out and clears tokens synchronously.
    /// </summary>
    procedure Logout;

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
    /// Adds SHA-256 public key hashes for certificate pinning.
    /// </summary>
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
    /// <summary>
    /// Removes all pinned public key hashes.
    /// </summary>
    procedure ClearPinnedPublicKeys;

    /// <summary>
    /// Returns the SSL certificate validator for certificate pinning configuration.
    /// </summary>
    function GetSSLValidator: IIAM4DSSLCertificateValidator;
    property SSLValidator: IIAM4DSSLCertificateValidator read GetSSLValidator;
  end;

implementation

{TKeycloakClient}

uses
  System.StrUtils,
  System.NetConsts,
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.CryptoUtils,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Callback.Handler.Local,
  IAMClient4D.Callback.Handler.External,
  IAMClient4D.Storage.AESMemoryTokenStorage,
  IAMClient4D.Common.PlatformUtils,
  IdCustomHTTPServer;

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

function TIAM4DKeycloakClient.AuthenticateClientAsync: IAsyncPromise<string>;
begin
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := Self.AuthenticateClient;
    end);
end;

procedure TIAM4DKeycloakClient.ClearTokens;
begin
  FTokenStorage.ClearTokens;
  SecureZeroString(FState);
  SecureZeroString(FNonce);
  SecureZeroString(FPKCEVerifier);
  SecureZeroString(FPKCEChallenge);
end;

procedure TIAM4DKeycloakClient.ConfigureInternal(const AConfig: TIAM4DClientConfig);
begin
  FKeycloakConfig := AConfig;

  FSSLValidator.SetValidationMode(AConfig.SSLValidationMode);

  FScopes.Clear;
  if Length(AConfig.Scopes) > 0 then
    AddScopesIfMissing(AConfig.Scopes);

  ClearTokens;

  if Assigned(FCallbackHandler) and FCallbackHandler.IsListening then
    FCallbackHandler.Stop;

  FCallbackHandler := nil;

  if FKeycloakConfig.GrantType = gtAuthorizationCode then
    CreateCallbackHandler;

  Self.InternalWellKnownFetchEndpoints;
end;

function TIAM4DKeycloakClient.CreateHTTPClient: THTTPClient;
begin
  Result := TIAM4DHTTPClientFactory.CreateHTTPClient(FKeycloakConfig, FSSLHelper);
end;

function TIAM4DKeycloakClient.ExecuteCallHTTP<T>(const AOperation: TFunc<THTTPClient, T>): T;
begin
  FHTTPClientLock.Acquire;
  try
    if not Assigned(FHTTPClient) then
      FHTTPClient := Self.CreateHTTPClient;

    Result := AOperation(FHTTPClient);
  finally
    FHTTPClientLock.Release;
  end;
end;

function TIAM4DKeycloakClient.ConfigureAsync(const AConfig: TIAM4DClientConfig): IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      Self.ConfigureInternal(AConfig);
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

  FHTTPClient := nil;
  FHTTPClientLock := TCriticalSection.Create;

  if AStorage = nil then
  begin
    var LKey32: TBytes := TIAM4DCryptoUtils.GenerateSecureRandomBytes(32);
    var LAAD: TBytes := TEncoding.UTF8.GetBytes('IAMClient4D/v1');
    FTokenStorage := TIAM4DAESMemoryTokenStorageRawKey32.Create(LKey32, LAAD);
  end
  else
    FTokenStorage := AStorage;

  FRefreshLock := TCriticalSection.Create;
  FAuthCompletionLock := TCriticalSection.Create;

  ClearTokens;
end;

destructor TIAM4DKeycloakClient.Destroy;
begin
  FAuthCompletionLock.Acquire;
  try
    if Assigned(FAuthCompletionSource) then
    begin
      FAuthCompletionSource.TrySetException(
        EIAM4DException.Create('Client shutdown - authorization cancelled'));

      FAuthCompletionSource.Free;
    end;
  finally
    FAuthCompletionLock.Release;
  end;

  if Assigned(FCallbackHandler) and FCallbackHandler.IsListening then
    FCallbackHandler.Stop;
  FCallbackHandler := nil;

  FHTTPClientLock.Acquire;
  try
    FreeAndNil(FHTTPClient);
  finally
    FHTTPClientLock.Release;
  end;
  FHTTPClientLock.Free;

  FSSLHelper.Free;
  FSSLValidator := nil;
  FRefreshLock.Free;
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
          0,
          IAM4D_OAUTH2_CALLBACK_DEFAULT_PATH);
      end;

    cbmExternal:
      begin
        FCallbackHandler := TIAM4DExternalCallbackHandler.Create(
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

  FCallbackHandler.SetOAuthContext(LContext);
end;

procedure TIAM4DKeycloakClient.InitializeOAuthContextInternal;
var
  LState, LNonce: TGUID;
begin
  if FScopes.IndexOf(IAM4D_OAUTH2_SCOPE_OPENID) = -1 then
    FScopes.Add(IAM4D_OAUTH2_SCOPE_OPENID);

  CreateGUID(LState);
  FState := GUIDToString(LState).Replace('{', '').Replace('}', '').Replace('-', '');

  CreateGUID(LNonce);
  FNonce := GUIDToString(LNonce).Replace('{', '').Replace('}', '').Replace('-', '');

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

function TIAM4DKeycloakClient.ConstantTimeEquals(const A, B: string): Boolean;
var
  I: Integer;
  LDiff: Integer;
  LMinLength: Integer;
begin
  LDiff := Length(A) xor Length(B);

  LMinLength := Length(A);
  if Length(B) < LMinLength then
    LMinLength := Length(B);

  for I := 1 to LMinLength do
    LDiff := LDiff or (Ord(A[I]) xor Ord(B[I]));

  Result := (LDiff = 0);
end;

function TIAM4DKeycloakClient.CompleteAuthorizationFlowInternal(const ACode, AState: string): TIAM4DTokens;
var
  LContext: TIAM4DOAuthContext;
begin
  if FKeycloakConfig.GrantType <> gtAuthorizationCode then
    raise EIAM4DException.Create('CompleteAuthorizationFlow is only for Authorization Code grant type.');

  if not Assigned(FCallbackHandler) then
    raise EIAM4DException.Create('Callback handler not initialized. Call StartAuthorizationFlowAsync first.');

  LContext := FCallbackHandler.GetOAuthContext;

  if AState.Trim.IsEmpty then
    raise EIAM4DStateMismatchException.Create(
      'State parameter is missing or empty - possible CSRF attack attempt.');

  if LContext.State.Trim.IsEmpty then
    raise EIAM4DException.Create(
      'Internal error: OAuth context state is empty. This should never happen.');

  if not IsValidStateFormat(AState) then
    raise EIAM4DStateMismatchException.Create(
      'State parameter has invalid format - possible tampering detected.');

  if not ConstantTimeEquals(AState, LContext.State) then
    raise EIAM4DStateMismatchException.Create(LContext.State, AState);

  FPKCEVerifier := LContext.PKCEVerifier;
  FNonce := LContext.Nonce;

  Result := ExchangeCodeForTokens(ACode);

  ValidateIDTokenNonce(Result.IDToken);

  FTokenStorage.SaveTokens(Result);

  if FCallbackMode = cbmExternal then
    (FCallbackHandler as TIAM4DExternalCallbackHandler).ClearContext;
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
    LSB.Free;
  end;
end;

procedure TIAM4DKeycloakClient.EnsureResponseHTTP200OrFail(const AResponse: IHTTPResponse; const AContext: string);
begin
  if not (AResponse.StatusCode in [200, 201]) then
    raise EIAM4DException.CreateFmt('%s failed: %d - %s', [
        AContext,
        AResponse.StatusCode,
        IfThen(AResponse.ContentAsString.Trim.IsEmpty, AResponse.StatusText, AResponse.ContentAsString)]);
end;

function TIAM4DKeycloakClient.ExchangeCodeForTokens(const ACode: string): TIAM4DTokens;
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
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CODE_VERIFIER, FPKCEVerifier);
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
begin
  LResponse := ExecuteCallHTTP<IHTTPResponse>(
    function(AClient: THTTPClient): IHTTPResponse
    begin
      Result := AClient.Get(GetRealmURL + '/.well-known/openid-configuration');
    end);

  EnsureResponseHTTP200OrFail(LResponse, 'well-known fetch endpoint');

  LJSONObj := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'discovery document');
  try
    FWellKnownEndPoints := TIAM4DWellKnownEndpoints.FromJSONObject(LJSONObj);
  finally
    LJSONObj.Free;
  end;
end;

function TIAM4DKeycloakClient.GenerateAuthURL(const ALoginHint: string): string;
var
  LParams: TStringList;
begin
  if FKeycloakConfig.GrantType <> gtAuthorizationCode then
    raise EIAM4DException.Create('GenerateAuthURL is not applicable for the Client Credentials grant type.');

  if FState.IsEmpty or FNonce.IsEmpty or FPKCEVerifier.IsEmpty or FPKCEChallenge.IsEmpty then
    raise EIAM4DException.Create(
      'OAuth2 parameters (state, nonce, PKCE) not initialized. ' +
      'Call StartAuthorizationFlowAsync before GenerateAuthURL.');

  LParams := TStringList.Create;
  try
    LParams.Delimiter := '&';
    LParams.QuoteChar := #0;
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_REDIRECT_URI, GetRedirectURI);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_RESPONSE_TYPE, IAM4D_OAUTH2_RESPONSE_TYPE_CODE);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_SCOPE, string.Join(' ', FScopes.ToStringArray));
    LParams.AddPair(IAM4D_OAUTH2_PARAM_STATE, FState);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_NONCE, FNonce);
    if not (ALoginHint.Trim.IsEmpty) then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_LOGIN_HINT, ALoginHint);
    if Length(FKeycloakConfig.AcrValues) > 0 then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_ACR_VALUES, string.Join(' ', FKeycloakConfig.AcrValues));
    if FKeycloakConfig.GrantType = gtAuthorizationCode then
    begin
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CODE_CHALLENGE, FPKCEChallenge);
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CODE_CHALLENGE_METHOD, IAM4D_OAUTH2_CODE_CHALLENGE_METHOD_S256);
    end;

    Result := FWellKnownEndPoints.AuthorizationEndpoint + '?' + LParams.DelimitedText;
  finally
    LParams.Free;
  end;
end;

function TIAM4DKeycloakClient.StartAuthorizationFlowAsync: IAsyncPromise<string>;
var
  LOperation: IAsyncOperation<string>;
  LAuthURL: string;
  LLocalHandler: TIAM4DLocalCallbackHandler;
begin
  if FKeycloakConfig.GrantType <> gtAuthorizationCode then
    raise EIAM4DException.Create('StartAuthorizationFlowAsync is only for Authorization Code grant type.');

  if FCallbackMode <> cbmLocalServer then
    raise EIAM4DException.Create(
      'StartAuthorizationFlowAsync can only be used with CallbackMode = cbmLocalServer. ' +
      'For external callbacks (web apps), use InitializeAuthorizationFlow() + GenerateAuthURL() + CompleteAuthorizationFlowAsync().');

  if Assigned(FAuthCompletionSource) then
    FreeAndNil(FAuthCompletionSource);

  InitializeOAuthContextInternal;

  FAuthCompletionSource := TAsyncTaskCompletionSource<string>.Create(TAsyncCallbackDispatchMode.dmQueue);
  LOperation := FAuthCompletionSource.Operation;

  LLocalHandler := FCallbackHandler as TIAM4DLocalCallbackHandler;

  LLocalHandler.SetOnCodeReceived(
    procedure(ACode, AState: string)
    var
      LTokens: TIAM4DTokens;
      LException: Exception;
    begin
      TTask.Run(
        procedure
        begin
          try
            LTokens := CompleteAuthorizationFlowInternal(ACode, AState);

            FCallbackHandler.Stop;

            FAuthCompletionLock.Acquire;
            try
              if Assigned(FAuthCompletionSource) then
                FAuthCompletionSource.SetResult(LTokens.AccessToken);
            finally
              FAuthCompletionLock.Release;
            end;
          except
            on E: Exception do
            begin
              FCallbackHandler.Stop;

              FAuthCompletionLock.Acquire;
              try
                if Assigned(FAuthCompletionSource) then
                begin
                  LException := Exception(AcquireExceptionObject);
                  FAuthCompletionSource.SetException(LException);
                end;
              finally
                FAuthCompletionLock.Release;
              end;
            end;
          end;
        end);
    end);

  LLocalHandler.SetOnError(
    procedure(AException: Exception)
    var
      LException: Exception;
    begin
      FCallbackHandler.Stop;

      FAuthCompletionLock.Acquire;
      try
        if Assigned(FAuthCompletionSource) then
        begin
          LException := AException;
          FAuthCompletionSource.SetException(LException);
        end;
      finally
        FAuthCompletionLock.Release;
      end;
    end);

  FCallbackHandler.Start;

  LAuthURL := GenerateAuthURL();
  if not TIAM4DPlatformUtils.OpenURL(LAuthURL) then
    raise EIAM4DException.CreateFmt('Failed to open browser for authorization URL: %s', [LAuthURL]);

  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := LOperation.WaitForResult();
    end);
end;

procedure TIAM4DKeycloakClient.InitializeAuthorizationFlow;
begin
  if FKeycloakConfig.GrantType <> gtAuthorizationCode then
    raise EIAM4DException.Create('InitializeAuthorizationFlow is only for Authorization Code grant type.');

  if FCallbackMode <> cbmExternal then
    raise EIAM4DException.Create(
      'InitializeAuthorizationFlow can only be used with CallbackMode = cbmExternal. ' +
      'For local server mode (desktop apps), use StartAuthorizationFlowAsync() instead.');

  InitializeOAuthContextInternal;
end;

function TIAM4DKeycloakClient.CompleteAuthorizationFlowAsync(const ACode, AState: string): IAsyncPromise<string>;
begin
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := Self.CompleteAuthorizationFlow(ACode, AState);
    end);
end;

function TIAM4DKeycloakClient.GenerateLogoutURL(const APostLogoutRedirectURI: string): string;
var
  LParams: TStringList;
  LTokens: TIAM4DTokens;
begin
  LTokens := FTokenStorage.LoadTokens;

  LParams := TStringList.Create;
  try
    LParams.Delimiter := '&';
    LParams.QuoteChar := #0;
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    if not LTokens.IDToken.Trim.IsEmpty then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_ID_TOKEN_HINT, LTokens.IDToken);

    if not (APostLogoutRedirectURI.Trim.IsEmpty) then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_POST_LOGOUT_REDIRECT_URI, APostLogoutRedirectURI);
    Result := FWellKnownEndPoints.EndSessionEndpoint + '?' + LParams.DelimitedText;
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
begin
  if FTokenStorage.IsAccessTokenValid then
  begin
    Result := FTokenStorage.LoadTokens.AccessToken;
    Exit;
  end;

  FRefreshLock.Acquire;
  try
    if FTokenStorage.IsAccessTokenValid then
    begin
      Result := FTokenStorage.LoadTokens.AccessToken;
      Exit;
    end;

    case FKeycloakConfig.GrantType of
      gtAuthorizationCode:
        begin
          if FTokenStorage.IsRefreshTokenValid then
          begin
            var LCurrentTokens := FTokenStorage.LoadTokens;
            try
              LRefreshedTokens := RefreshTokensInternal(LCurrentTokens.RefreshToken);
              Result := LRefreshedTokens.AccessToken;
            except
              ClearTokens;
              raise;
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
            ClearTokens;
            raise EIAM4DException.Create('Failed to re-authenticate client for a new access token.');
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
begin
  Result := TAsyncCore.New<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := Self.GetAccessToken;
    end);
end;

function TIAM4DKeycloakClient.GetUserInfoAsync: IAsyncPromise<TIAM4DUserInfo>;
begin
  Result := TAsyncCore.New<TIAM4DUserInfo>(
    function(const AOperation: IAsyncOperation): TIAM4DUserInfo
    begin
      Result := Self.GetUserInfo;
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
    gtAuthorizationCode:
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
  LAccessToken: string;
begin
  if FKeycloakConfig.GrantType = gtClientCredentials then
    raise EIAM4DException.Create('GetUserInfoInternal is not applicable for the Client Credentials grant type.');

  LAccessToken := GetAccessTokenInternal;

  LResponse := ExecuteCallHTTP<IHTTPResponse>(
    function(AClient: THTTPClient): IHTTPResponse
    begin
      AClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := Format('%s %s', [IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER, LAccessToken]);
      Result := AClient.Get(FWellKnownEndPoints.UserInfoEndpoint);
    end);

  EnsureResponseHTTP200OrFail(LResponse, 'User info');

  Result := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'UserInfo response');
end;

procedure TIAM4DKeycloakClient.LogoutInternal;
var
  LResponse: IHTTPResponse;
begin
  try
    case FKeycloakConfig.GrantType of
      gtAuthorizationCode:
        begin
          LResponse := ExecuteCallHTTP<IHTTPResponse>(
            function(AClient: THTTPClient): IHTTPResponse
            begin
              Result := AClient.Get(GenerateLogoutURL());
            end);
          EnsureResponseHTTP200OrFail(LResponse, 'Logout');
        end;
      gtClientCredentials:
        begin
        end;
    end;

    ClearTokens;
    FScopes.Clear;
  finally
    if Assigned(FCallbackHandler) and FCallbackHandler.IsListening then
      FCallbackHandler.Stop;
  end;
end;

function TIAM4DKeycloakClient.LogoutAsync: IAsyncVoidPromise;
begin
  Result := TAsyncCore.New(
    procedure(const AOperation: IAsyncOperation)
    begin
      Self.Logout;
    end);
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

function TIAM4DKeycloakClient.CompleteAuthorizationFlow(const ACode, AState: string): string;
begin
  Result := CompleteAuthorizationFlowInternal(ACode, AState).AccessToken;
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

function TIAM4DKeycloakClient.PostToTokenEndpoint(
  const
  AParams:
  TStrings): TJSONObject;
var
  LContent: TStringStream;
  LResponse: IHTTPResponse;
  LEncoded: string;
begin
  LEncoded := EncodeFormParams(AParams);

  LContent := TStringStream.Create(LEncoded, TEncoding.UTF8);
  try
    LResponse := ExecuteCallHTTP<IHTTPResponse>(
      function(AClient: THTTPClient): IHTTPResponse
      begin
        AClient.ContentType := IAM4D_CONTENT_TYPE_FORM_URLENCODED;
        Result := AClient.Post(FWellKnownEndPoints.TokenEndpoint, LContent);
      end);

    EnsureResponseHTTP200OrFail(LResponse, 'Token endpoint');

    Result := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'Token response');
  finally
    LContent.Free;
  end;
end;

function TIAM4DKeycloakClient.RefreshTokensInternal(const ARefreshToken: string): TIAM4DTokens;
var
  LParams: TStringList;
  LJSONObj: TJSONObject;
begin
  LParams := TStringList.Create;
  try
    LParams.AddPair(IAM4D_OAUTH2_PARAM_GRANT_TYPE, IAM4D_OAUTH2_GRANT_TYPE_REFRESH_TOKEN);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_ID, FKeycloakConfig.ClientID);
    LParams.AddPair(IAM4D_OAUTH2_PARAM_REFRESH_TOKEN, ARefreshToken);
    if not (FKeycloakConfig.ClientSecret.Trim.IsEmpty) then
      LParams.AddPair(IAM4D_OAUTH2_PARAM_CLIENT_SECRET, FKeycloakConfig.ClientSecret);

    LJSONObj := PostToTokenEndpoint(LParams);
    try
      Result := TIAM4DTokens.FromJSONObject(LJSONObj);
      FTokenStorage.SaveTokens(Result);
    finally
      LJSONObj.Free;
    end;
  finally
    LParams.Free;
  end;
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
      FTokenStorage.SaveTokens(Result);
    finally
      LJSONObj.Free;
    end;
  finally
    LParams.Free;
  end;
end;

procedure TIAM4DKeycloakClient.ValidateIDTokenNonce(const AIDToken: string);
var
  LParts: TArray<string>;
  LPayloadJSON: string;
  LJSONValue: TJSONValue;
  LNonceValue: string;
begin
  if AIDToken.Trim.IsEmpty then
    raise EIAM4DException.Create('ID Token is empty, cannot validate nonce.');

  LParts := AIDToken.Split(['.']);
  if Length(LParts) <> 3 then
    raise EIAM4DException.Create('Invalid ID Token format.');

  LPayloadJSON := TNetEncoding.Base64URL.Decode(LParts[1]);
  LJSONValue := TIAM4DJSONUtils.SafeParseJSONObject(LPayloadJSON, 'ID Token payload');
  try
    LNonceValue := (LJSONValue as TJSONObject).GetValue<string>(IAM4D_OAUTH2_PARAM_NONCE, '');
    if LNonceValue.Trim.IsEmpty then
      raise EIAM4DException.Create('Missing nonce in ID Token payload.');

    // Use constant-time comparison for consistency with other security checks
    if not SecureStringEquals(LNonceValue, FNonce) then
      raise EIAM4DException.CreateFmt('Nonce mismatch in ID Token. Expected: %s, Found: %s', [FNonce, LNonceValue]);
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
end;

procedure TIAM4DKeycloakClient.ClearPinnedPublicKeys;
begin
  FSSLValidator.ClearPinnedPublicKeys;
end;

procedure TIAM4DKeycloakClient.CancelAuthorizationFlow;
begin
  FAuthCompletionLock.Acquire;
  try
    if Assigned(FAuthCompletionSource) then
    begin
      FAuthCompletionSource.TrySetException(
        EIAM4DException.Create('Authorization flow cancelled by user'));
    end;
  finally
    FAuthCompletionLock.Release;
  end;

  if Assigned(FCallbackHandler) and FCallbackHandler.IsListening then
    FCallbackHandler.Stop;
end;

end.