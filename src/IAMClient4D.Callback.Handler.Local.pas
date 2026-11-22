{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Callback.Handler.Local.pas
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

unit IAMClient4D.Callback.Handler.Local;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Net.URLClient,
  System.NetEncoding,
  IAMClient4D.Core,
  IAMClient4D.Callback.Handler,
  IAMClient4D.Server.Callback.Core;

type
  /// <summary>
  /// OAuth2 callback handler using local HTTP server.
  /// </summary>
  /// <remarks>
  /// Starts a local HTTP server on specified port to receive OAuth2 callbacks.
  /// Suitable for desktop applications and local development.
  ///
  /// Typical flow:
  /// 1. Creates local HTTP server on localhost:port
  /// 2. Start() begins listening for callbacks
  /// 3. User authenticates in browser
  /// 4. Keycloak redirects to http://localhost:port/callback
  /// 5. Server receives code and state, validates state parameter
  /// 6. Calls OnCodeReceived callback with code, state and kc_action_status ('' if absent)
  ///
  /// Error response (error, error_description): with the state of the flow OnError receives an
  /// EIAM4DOAuth2CallbackException (both values in its Context).
  /// A callback without the state of the flow (code or error), or one that cannot be parsed, is
  /// ignored: the browser gets an error page and the login keeps waiting.
  ///
  /// Thread-safety: Callbacks are executed asynchronously via TTask.
  /// Port requirements: Port must be available and not blocked by firewall.
  /// Security: Uses state parameter validation to prevent CSRF attacks.
  /// Cleanup: Automatically stops server in destructor.
  /// </remarks>
  TIAM4DLocalCallbackHandler = class(TIAM4DRedirectCallbackHandlerBase)
  private
    FCallbackServer: IIAM4DHttpCallbackServer;
    FPort: Word;
    FCallbackPath: string;
    FAppActivation: TIAM4DAppActivation;
    FLoopbackRedirectHost: TIAM4DLoopbackRedirectHost;
    // State of the last callback dispatched: the same redirect again does not exchange the code twice
    FTakenState: string;

    procedure HandleServerCallback(AResponseType: TIAM4DCallbackResponseType; AData: string);
  protected
    procedure DoStart; override;
    procedure DoStop; override;
    function DoIsListening: Boolean; override;
    function DoGetRedirectURI: string; override;
  public
    /// <summary>
    /// Creates local callback handler with specified port and path
    /// </summary>
    /// <remarks>
    /// AAppActivation: what the app does when a valid callback arrives (see TIAM4DAppActivation).
    /// ALoopbackRedirectHost: host of the redirect URI (see TIAM4DLoopbackRedirectHost).
    /// </remarks>
    constructor Create(
      const APort: Word;
      const ACallbackPath: string = '/callback';
      const AAppActivation: TIAM4DAppActivation = aaNone;
      const ALoopbackRedirectHost: TIAM4DLoopbackRedirectHost = lrhLocalhost); reintroduce;
    destructor Destroy; override;
  end;

implementation

uses
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.OAuth2URLParser,
  IAMClient4D.Common.PlatformUtils,
  IAMClient4D.Server.Callback.IndyHttpServer,
  IAMClient4D.Exceptions;

{ TIAM4DLocalCallbackHandler }

constructor TIAM4DLocalCallbackHandler.Create(
  const APort: Word;
  const ACallbackPath: string;
  const AAppActivation: TIAM4DAppActivation;
  const ALoopbackRedirectHost: TIAM4DLoopbackRedirectHost);
begin
  inherited Create(cbmLocalServer);

  FPort := APort;
  FAppActivation := AAppActivation;
  FLoopbackRedirectHost := ALoopbackRedirectHost;
  FCallbackPath := ACallbackPath;

  if not FCallbackPath.StartsWith('/') then
    FCallbackPath := '/' + FCallbackPath;

  FCallbackServer := TIAM4DIndyHttpCallbackServer.Create(FPort, FCallbackPath);
end;

destructor TIAM4DLocalCallbackHandler.Destroy;
begin
  DoStop;
  FCallbackServer := nil;
  inherited;
end;

procedure TIAM4DLocalCallbackHandler.DoStart;
begin
  if not Assigned(FCallbackServer) then
    raise EIAM4DCallbackHandlerException.Create('Callback server not initialized.');

  if FCallbackServer.IsRunning then
    Exit;

  FCallbackServer.SetCallbackHandler(HandleServerCallback);

  try
    FCallbackServer.Start;
  except
    on E: Exception do
      raise EIAM4DCallbackHandlerException.CreateFmt(
        'Failed to start local callback server on port %d: %s',
        [FPort, E.Message]);
  end;
end;

procedure TIAM4DLocalCallbackHandler.DoStop;
begin
  if Assigned(FCallbackServer) and FCallbackServer.IsRunning then
  begin
    try
      FCallbackServer.Stop;
    except
      // ignore
    end;
  end;
end;

function TIAM4DLocalCallbackHandler.DoIsListening: Boolean;
begin
  Result := Assigned(FCallbackServer) and FCallbackServer.IsRunning;
end;

function TIAM4DLocalCallbackHandler.DoGetRedirectURI: string;
begin
  if FLoopbackRedirectHost = lrhLoopbackIP then
    Result := Format('http://127.0.0.1:%d%s', [FCallbackServer.GetListeningPort, FCallbackPath])
  else
    Result := Format('http://localhost:%d%s', [FCallbackServer.GetListeningPort, FCallbackPath]);
end;

procedure TIAM4DLocalCallbackHandler.HandleServerCallback(
  AResponseType: TIAM4DCallbackResponseType;
  AData: string);
var
  LState: string;
begin
  if AResponseType <> crtCheckResponseIAM then
    Exit;

  // Anybody can call the loopback URL: raising here leaves the login waiting, the server shows an error page
  CheckCallbackCanEndFlow(AData);

  // One-shot per flow (reload, double request of the browser): a second exchange of the same code would
  // be refused, and Keycloak revokes the tokens already issued for a code used twice (RFC 6749 4.1.2)
  LState := TIAM4DOAuth2URLParser.ParseOAuth2Callback(AData).State;
  TMonitor.Enter(Self);
  try
    if FTakenState = LState then
      raise EIAM4DCallbackHandlerException.Create('OAuth2 callback already received: ignored');
    FTakenState := LState;
  finally
    TMonitor.Exit(Self);
  end;

  // Only a callback of this flow: a stranger calling the loopback URL does not take the focus
  TIAM4DPlatformUtils.ActivateApplication(FAppActivation);

  DispatchCallback(AData);
end;

end.