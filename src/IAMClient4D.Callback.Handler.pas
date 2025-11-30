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
  public
    property State: string read FState write FState;
    property Nonce: string read FNonce write FNonce;
    property PKCEVerifier: string read FPKCEVerifier write FPKCEVerifier;
    property PKCEChallenge: string read FPKCEChallenge write FPKCEChallenge;
    property RedirectURI: string read FRedirectURI write FRedirectURI;

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
  /// Supported modes: local server (cbmLocalServer) and external (cbmExternal).
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
  /// Thread-safety: Base implementation is not thread-safe. Subclasses must add synchronization if needed.
  /// Callback exceptions: Exceptions in OnAuthorizationComplete/OnAuthorizationError are silently caught.
  /// </remarks>
  TIAM4DCallbackHandlerBase = class abstract(TInterfacedObject, IIAM4DCallbackHandler)
  private
    FCallbackMode: TIAM4DCallbackMode;
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

implementation

{ TIAM4DOAuthContext }

procedure TIAM4DOAuthContext.Clear;
begin
  FState := '';
  FNonce := '';
  FPKCEVerifier := '';
  FPKCEChallenge := '';
  FRedirectURI := '';
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
  FCallbackMode := ACallbackMode;
  FOAuthContext.Clear;
end;

procedure TIAM4DCallbackHandlerBase.Start;
begin
  if not FOAuthContext.IsValid then
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
  FOAuthContext := AContext;
end;

function TIAM4DCallbackHandlerBase.GetOAuthContext: TIAM4DOAuthContext;
begin
  Result := FOAuthContext;
end;

procedure TIAM4DCallbackHandlerBase.SetOnAuthorizationComplete(const ACallback: TProc<TIAM4DTokens>);
begin
  FOnAuthorizationComplete := ACallback;
end;

procedure TIAM4DCallbackHandlerBase.SetOnAuthorizationError(const ACallback: TProc<Exception>);
begin
  FOnAuthorizationError := ACallback;
end;

procedure TIAM4DCallbackHandlerBase.NotifyAuthorizationComplete(const ATokens: TIAM4DTokens);
begin
  if Assigned(FOnAuthorizationComplete) then
  begin
    try
      FOnAuthorizationComplete(ATokens);
    except
      // ignore
    end;
  end;
end;

procedure TIAM4DCallbackHandlerBase.NotifyAuthorizationError(const AException: Exception);
begin
  if Assigned(FOnAuthorizationError) then
  begin
    try
      FOnAuthorizationError(AException);
    except
      // ignore
    end;
  end;
end;

end.