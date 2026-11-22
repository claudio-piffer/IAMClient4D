{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Callback.Handler.pas
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

unit IAMClient4D.Callback.Handler;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Threading,
  IAMClient4D.Core,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// OAuth2 authorization context for PKCE flow.
  /// </summary>
  /// <remarks>
  /// Contains security parameters for Authorization Code flow with PKCE.
  /// All fields must be set for context to be valid (IsValid = True).
  /// Thread-safety: Not thread-safe. Use external synchronization if needed.
  /// </remarks>
  TIAM4DOAuthContext = record
  private
    FState: string;
    FNonce: string;
    FPKCEVerifier: string;
    FPKCEChallenge: string;
    FRedirectURI: string;
    FMaxAge: Integer;
    FAuthRequestTime: Int64;
    FIssuer: string;
    FIssRequired: Boolean;
  public
    property State: string read FState write FState;
    property Nonce: string read FNonce write FNonce;
    property PKCEVerifier: string read FPKCEVerifier write FPKCEVerifier;
    property PKCEChallenge: string read FPKCEChallenge write FPKCEChallenge;
    property RedirectURI: string read FRedirectURI write FRedirectURI;
    /// <summary>max_age of the authorization request (IAM4D_MAX_AGE_NONE: not sent)</summary>
    property MaxAge: Integer read FMaxAge write FMaxAge;
    /// <summary>Start of the flow (Unix time, UTC): reference of the auth_time check</summary>
    property AuthRequestTime: Int64 read FAuthRequestTime write FAuthRequestTime;
    /// <summary>Issuer the iss of the authorization response must equal (RFC 9207)</summary>
    property Issuer: string read FIssuer write FIssuer;
    /// <summary>The issuer always sends iss (discovery): a response without it is refused</summary>
    property IssRequired: Boolean read FIssRequired write FIssRequired;

    /// <summary>
    /// RFC 9207 2.4: raises EIAM4DCallbackHandlerException when AIss is present and not Issuer,
    /// or absent while IssRequired. Exact comparison, as the RFC asks.
    /// </summary>
    procedure CheckResponseIssuer(const AIss: string);

    /// <summary>
    /// Clears all context fields
    /// </summary>
    procedure Clear;
    /// <summary>
    /// Checks if all required fields are set
    /// </summary>
    function IsValid: Boolean;
  end;

  /// <summary>
  /// Interface for OAuth2 callback handlers.
  /// </summary>
  /// <remarks>
  /// Implementers handle OAuth2 callbacks for authorization flow completion.
  /// Supported modes: local server (cbmLocalServer), external (cbmExternal) and app redirect (cbmAppRedirect).
  /// Must set OAuthContext before calling Start.
  /// </remarks>
  IIAM4DCallbackHandler = interface
    ['{F3518C74-0DC2-4EF1-B85D-5A79E1D6E8C9}']

    /// <summary>
    /// Starts callback handler
    /// </summary>
    procedure Start;

    /// <summary>
    /// Stops callback handler
    /// </summary>
    procedure Stop;

    /// <summary>
    /// Checks if handler is listening for callbacks
    /// </summary>
    function IsListening: Boolean;

    /// <summary>
    /// Gets OAuth2 redirect URI
    /// </summary>
    function GetRedirectURI: string;

    /// <summary>
    /// Gets callback mode (local/external)
    /// </summary>
    function GetCallbackMode: TIAM4DCallbackMode;

    /// <summary>
    /// Sets OAuth2 context with PKCE parameters
    /// </summary>
    procedure SetOAuthContext(const AContext: TIAM4DOAuthContext);

    /// <summary>
    /// Gets current OAuth2 context
    /// </summary>
    function GetOAuthContext: TIAM4DOAuthContext;

    /// <summary>
    /// Sets callback for successful authorization
    /// </summary>
    procedure SetOnAuthorizationComplete(const ACallback: TProc<TIAM4DTokens>);

    /// <summary>
    /// Sets callback for authorization errors
    /// </summary>
    procedure SetOnAuthorizationError(const ACallback: TProc<Exception>);

    property RedirectURI: string read GetRedirectURI;
    property CallbackMode: TIAM4DCallbackMode read GetCallbackMode;
    property OAuthContext: TIAM4DOAuthContext read GetOAuthContext write SetOAuthContext;
  end;

  /// <summary>
  /// Base class for OAuth2 callback handler implementations.
  /// </summary>
  /// <remarks>
  /// Template Method pattern: Subclasses implement DoStart, DoStop, DoIsListening, DoGetRedirectURI.
  /// Provides OAuth context management and callback notifications.
  /// Thread-safety: the OAuth context and the notification callbacks are guarded by a lock (the
  /// callback arrives on a server or task thread); Start, Stop and the subclass state are not.
  /// Callback exceptions: Exceptions in OnAuthorizationComplete/OnAuthorizationError are silently caught.
  /// </remarks>
  TIAM4DCallbackHandlerBase = class abstract(TInterfacedObject, IIAM4DCallbackHandler)
  private
    FCallbackMode: TIAM4DCallbackMode;
    // Guards FOAuthContext and the two callbacks: a record of strings or a closure read while
    // another thread replaces it is torn
    FStateLock: TObject;
    FOAuthContext: TIAM4DOAuthContext;
    FOnAuthorizationComplete: TProc<TIAM4DTokens>;
    FOnAuthorizationError: TProc<Exception>;
  protected
    /// <summary>
    /// Starts handler (must be implemented by subclass)
    /// </summary>
    procedure DoStart; virtual; abstract;

    /// <summary>
    /// Stops handler (must be implemented by subclass)
    /// </summary>
    procedure DoStop; virtual; abstract;

    /// <summary>
    /// Checks listening state (must be implemented by subclass)
    /// </summary>
    function DoIsListening: Boolean; virtual; abstract;

    /// <summary>
    /// Gets redirect URI (must be implemented by subclass)
    /// </summary>
    function DoGetRedirectURI: string; virtual; abstract;

    /// <summary>
    /// Notifies successful authorization
    /// </summary>
    procedure NotifyAuthorizationComplete(const ATokens: TIAM4DTokens);

    /// <summary>
    /// Notifies authorization error
    /// </summary>
    procedure NotifyAuthorizationError(const AException: Exception);

    property CallbackModeInternal: TIAM4DCallbackMode read FCallbackMode;
  public
    /// <summary>
    /// Creates handler with specified callback mode
    /// </summary>
    constructor Create(const ACallbackMode: TIAM4DCallbackMode); virtual;
    destructor Destroy; override;

    // IIAM4DCallbackHandler implementation
    procedure Start;
    procedure Stop;
    function IsListening: Boolean;
    function GetRedirectURI: string;
    function GetCallbackMode: TIAM4DCallbackMode;
    procedure SetOAuthContext(const AContext: TIAM4DOAuthContext);
    function GetOAuthContext: TIAM4DOAuthContext;
    procedure SetOnAuthorizationComplete(const ACallback: TProc<TIAM4DTokens>);
    procedure SetOnAuthorizationError(const ACallback: TProc<Exception>);
  end;

  /// <summary>
  /// Base class of the handlers that receive the redirect of the browser (local server, app redirect).
  /// </summary>
  /// <remarks>
  /// The subclass gets the redirect URL from its transport and calls CheckCallbackCanEndFlow, then
  /// DispatchCallback. A callback without the state of the flow (code or error), or one that cannot be
  /// parsed, is ignored: the login keeps waiting. With the state of the flow an error response ends the
  /// login with EIAM4DOAuth2CallbackException (error and error_description in its Context).
  /// </remarks>
  TIAM4DRedirectCallbackHandlerBase = class abstract(TIAM4DCallbackHandlerBase)
  private
    FOnCodeReceived: TProc<string, string, string>;
    FOnError: TProc<Exception>;
    class procedure ValidateStateParameter(const AReceivedState: string; const AContext: TIAM4DOAuthContext); static;
    /// <summary>True when the state of the callback is the one of AContext</summary>
    class function IsCallbackOfFlow(const AURL: string; const AContext: TIAM4DOAuthContext): Boolean; static;
    /// <summary>Code, state and kc_action_status of the callback, checked against AContext</summary>
    class procedure ExtractCodeAndStateFromURL(const AURL: string; const AContext: TIAM4DOAuthContext;
      out ACode, AState, AKeycloakActionStatus: string); static;
  protected
    /// <summary>
    /// Raises EIAM4DCallbackHandlerException for a callback that must not end the login:
    /// malformed, or without the state of this flow (code or error response).
    /// </summary>
    procedure CheckCallbackCanEndFlow(const AURL: string);

    /// <summary>
    /// Processes a callback accepted by CheckCallbackCanEndFlow in a task: OnCodeReceived with the code,
    /// otherwise the handler is stopped and OnError and the authorization error are notified.
    /// </summary>
    procedure DispatchCallback(const AURL: string);
  public
    /// <summary>
    /// Sets callback invoked when authorization code is received
    /// </summary>
    /// <remarks>
    /// Arguments: code, state and kc_action_status of Keycloak ('' if absent).
    /// </remarks>
    procedure SetOnCodeReceived(const ACallback: TProc<string, string, string>);

    /// <summary>
    /// Sets callback invoked on callback processing errors
    /// </summary>
    procedure SetOnError(const ACallback: TProc<Exception>);
  end;

implementation

uses
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Common.OAuth2URLParser;

{ TIAM4DOAuthContext }

procedure TIAM4DOAuthContext.Clear;
begin
  FState := '';
  FNonce := '';
  FPKCEVerifier := '';
  FPKCEChallenge := '';
  FRedirectURI := '';
  FMaxAge := IAM4D_MAX_AGE_NONE;
  FAuthRequestTime := 0;
  FIssuer := '';
  FIssRequired := False;
end;

procedure TIAM4DOAuthContext.CheckResponseIssuer(const AIss: string);
begin
  if AIss = '' then
  begin
    if FIssRequired then
      raise EIAM4DCallbackHandlerException.Create(
        'Missing iss parameter in OAuth2 callback: the identity provider always sends it (RFC 9207).');
    Exit;
  end;
  if not SecureStringEquals(AIss, FIssuer) then
    raise EIAM4DCallbackHandlerException.CreateFmt(
      'iss parameter "%s" of the OAuth2 callback is not the issuer of this client (RFC 9207): possible mix-up attack.',
      [AIss]);
end;

function TIAM4DOAuthContext.IsValid: Boolean;
begin
  Result := (FState <> '') and
    (FNonce <> '') and
    (FPKCEVerifier <> '') and
    (FPKCEChallenge <> '') and
    (FRedirectURI <> '');
end;

{ TIAM4DCallbackHandlerBase }

constructor TIAM4DCallbackHandlerBase.Create(const ACallbackMode: TIAM4DCallbackMode);
begin
  inherited Create;
  FStateLock := TObject.Create;
  FCallbackMode := ACallbackMode;
  FOAuthContext.Clear;
end;

destructor TIAM4DCallbackHandlerBase.Destroy;
begin
  FStateLock.Free;
  inherited;
end;

procedure TIAM4DCallbackHandlerBase.Start;
begin
  if not GetOAuthContext.IsValid then
    raise EIAM4DCallbackHandlerException.Create('OAuth context not set. Call SetOAuthContext before Start.');

  DoStart;
end;

procedure TIAM4DCallbackHandlerBase.Stop;
begin
  DoStop;
end;

function TIAM4DCallbackHandlerBase.IsListening: Boolean;
begin
  Result := DoIsListening;
end;

function TIAM4DCallbackHandlerBase.GetRedirectURI: string;
begin
  Result := DoGetRedirectURI;
end;

function TIAM4DCallbackHandlerBase.GetCallbackMode: TIAM4DCallbackMode;
begin
  Result := FCallbackMode;
end;

procedure TIAM4DCallbackHandlerBase.SetOAuthContext(const AContext: TIAM4DOAuthContext);
begin
  TMonitor.Enter(FStateLock);
  try
    FOAuthContext := AContext;
  finally
    TMonitor.Exit(FStateLock);
  end;
end;

function TIAM4DCallbackHandlerBase.GetOAuthContext: TIAM4DOAuthContext;
begin
  TMonitor.Enter(FStateLock);
  try
    Result := FOAuthContext;
  finally
    TMonitor.Exit(FStateLock);
  end;
end;

procedure TIAM4DCallbackHandlerBase.SetOnAuthorizationComplete(const ACallback: TProc<TIAM4DTokens>);
begin
  TMonitor.Enter(FStateLock);
  try
    FOnAuthorizationComplete := ACallback;
  finally
    TMonitor.Exit(FStateLock);
  end;
end;

procedure TIAM4DCallbackHandlerBase.SetOnAuthorizationError(const ACallback: TProc<Exception>);
begin
  TMonitor.Enter(FStateLock);
  try
    FOnAuthorizationError := ACallback;
  finally
    TMonitor.Exit(FStateLock);
  end;
end;

procedure TIAM4DCallbackHandlerBase.NotifyAuthorizationComplete(const ATokens: TIAM4DTokens);
var
  LCallback: TProc<TIAM4DTokens>;
begin
  // Called outside the lock: the callback may set a new context
  TMonitor.Enter(FStateLock);
  try
    LCallback := FOnAuthorizationComplete;
  finally
    TMonitor.Exit(FStateLock);
  end;
  if Assigned(LCallback) then
  begin
    try
      LCallback(ATokens);
    except
      // Callback exceptions are intentionally caught to prevent
      // authorization flow disruption. The OAuth flow must complete
      // regardless of callback handler errors.
    end;
  end;
end;

procedure TIAM4DCallbackHandlerBase.NotifyAuthorizationError(const AException: Exception);
var
  LCallback: TProc<Exception>;
begin
  TMonitor.Enter(FStateLock);
  try
    LCallback := FOnAuthorizationError;
  finally
    TMonitor.Exit(FStateLock);
  end;
  if Assigned(LCallback) then
  begin
    try
      LCallback(AException);
    except
      // Callback exceptions are intentionally caught to prevent
      // authorization flow disruption. The OAuth flow must complete
      // regardless of callback handler errors.
    end;
  end;
end;

{ TIAM4DRedirectCallbackHandlerBase }

procedure TIAM4DRedirectCallbackHandlerBase.DispatchCallback(const AURL: string);
var
  LCode, LState, LKeycloakActionStatus: string;
  LKeepAlive: IIAM4DCallbackHandler;
  LContext: TIAM4DOAuthContext;
  LOnCodeReceived: TProc<string, string, string>;
  LOnError: TProc<Exception>;
begin
  // The flow this callback belongs to, taken together: a new flow started before the task runs
  // replaces context and callbacks, and must not be ended by a callback of the previous one
  TMonitor.Enter(FStateLock);
  try
    LContext := FOAuthContext;
    LOnCodeReceived := FOnCodeReceived;
    LOnError := FOnError;
  finally
    TMonitor.Exit(FStateLock);
  end;
  if not IsCallbackOfFlow(AURL, LContext) then
    Exit;

  // The owner may release the handler while the task runs (the transport is stopped first)
  LKeepAlive := Self;
  TTask.Run(
    procedure
    begin
      try
        try
          ExtractCodeAndStateFromURL(AURL, LContext, LCode, LState, LKeycloakActionStatus);

          if Assigned(LOnCodeReceived) then
            LOnCodeReceived(LCode, LState, LKeycloakActionStatus);
        except
          on E: Exception do
          begin
            DoStop;

            try
              if Assigned(LOnError) then
                LOnError(E);
            except
              // Callback exceptions are intentionally caught to prevent
              // authorization flow disruption. The OAuth flow must complete
              // regardless of callback handler errors.
            end;

            NotifyAuthorizationError(E);
          end;
        end;
      finally
        // May be the last reference: the handler is freed here
        LKeepAlive := nil;
      end;
    end);
end;

procedure TIAM4DRedirectCallbackHandlerBase.CheckCallbackCanEndFlow(const AURL: string);
var
  LResult: TIAM4DOAuth2CallbackResult;
begin
  try
    LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback(AURL);
  except
    on Exception do
      raise EIAM4DCallbackHandlerException.Create('Malformed OAuth2 callback: ignored');
  end;
  // Only the state of this flow ends the login, with a code or an error (RFC 6749 10.12, 4.1.2.1)
  ValidateStateParameter(LResult.State, GetOAuthContext);
end;

class function TIAM4DRedirectCallbackHandlerBase.IsCallbackOfFlow(const AURL: string;
  const AContext: TIAM4DOAuthContext): Boolean;
var
  LResult: TIAM4DOAuth2CallbackResult;
begin
  try
    LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback(AURL);
    ValidateStateParameter(LResult.State, AContext);
    Result := True;
  except
    // CheckCallbackCanEndFlow accepted it for the flow of then: another flow started since
    Result := False;
  end;
end;

class procedure TIAM4DRedirectCallbackHandlerBase.ExtractCodeAndStateFromURL(const AURL: string;
  const AContext: TIAM4DOAuthContext; out ACode, AState, AKeycloakActionStatus: string);
var
  LResult: TIAM4DOAuth2CallbackResult;
begin
  try
    LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback(AURL);
  except
    on E: Exception do
      raise EIAM4DCallbackHandlerException.CreateFmt(
        'Failed to extract authorization code and state from callback URL: %s',
        [E.Message]);
  end;

  // RFC 9207 2.4: iss checked before anything else of the response, error responses included
  AContext.CheckResponseIssuer(LResult.Iss);

  // Error response of the authorization server (state already checked): the login fails with
  // EIAM4DOAuth2CallbackException, error and error_description in its Context
  if LResult.IsError then
    raise TIAM4DOAuth2URLParser.CreateErrorException(LResult);

  ACode := LResult.Code;
  AState := LResult.State;
  AKeycloakActionStatus := LResult.KeycloakActionStatus;

  if AState.Trim.IsEmpty then
    raise EIAM4DCallbackHandlerException.Create('Missing state parameter in OAuth2 callback');

  if ACode.Trim.IsEmpty then
    raise EIAM4DCallbackHandlerException.Create('Missing authorization code in OAuth2 callback');

  ValidateStateParameter(AState, AContext);
end;

class procedure TIAM4DRedirectCallbackHandlerBase.ValidateStateParameter(const AReceivedState: string;
  const AContext: TIAM4DOAuthContext);
const
  MAX_STATE_LENGTH = 256;
begin
  if AReceivedState.Trim.IsEmpty then
    raise EIAM4DCallbackHandlerException.Create('Missing state parameter in OAuth2 callback');

  if Length(AReceivedState) > MAX_STATE_LENGTH then
    raise EIAM4DCallbackHandlerException.CreateFmt(
      'State parameter exceeds maximum length (%d chars). Possible attack attempt.',
      [MAX_STATE_LENGTH]);

  if not SecureStringEquals(AReceivedState, AContext.State) then
    raise EIAM4DCallbackHandlerException.Create(
      'State mismatch in OAuth2 callback. Possible CSRF attack or session mix-up.');
end;

procedure TIAM4DRedirectCallbackHandlerBase.SetOnCodeReceived(const ACallback: TProc<string, string, string>);
begin
  // Under the lock, as the other callbacks: DispatchCallback takes them with the context
  TMonitor.Enter(FStateLock);
  try
    FOnCodeReceived := ACallback;
  finally
    TMonitor.Exit(FStateLock);
  end;
end;

procedure TIAM4DRedirectCallbackHandlerBase.SetOnError(const ACallback: TProc<Exception>);
begin
  TMonitor.Enter(FStateLock);
  try
    FOnError := ACallback;
  finally
    TMonitor.Exit(FStateLock);
  end;
end;

end.