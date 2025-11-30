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
  System.Threading,
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
  /// 6. Calls OnCodeReceived callback with code and state
  ///
  /// Thread-safety: Callbacks are executed asynchronously via TTask.
  /// Port requirements: Port must be available and not blocked by firewall.
  /// Security: Uses state parameter validation to prevent CSRF attacks.
  /// Cleanup: Automatically stops server in destructor.
  /// </remarks>
  TIAM4DLocalCallbackHandler = class(TIAM4DCallbackHandlerBase)
  private
    FCallbackServer: IIAM4DHttpCallbackServer;
    FPort: Word;
    FCallbackPath: string;
    FOnCodeReceived: TProc<string, string>;
    FOnError: TProc<Exception>;

    procedure HandleServerCallback(AResponseType: TIAM4DCallbackResponseType; AData: string);
    procedure ValidateStateParameter(const AReceivedState: string);
    procedure ExtractCodeAndStateFromURL(const AURL: string; out ACode, AState: string);
  protected
    procedure DoStart; override;
    procedure DoStop; override;
    function DoIsListening: Boolean; override;
    function DoGetRedirectURI: string; override;
  public
    /// <summary>
    /// Creates local callback handler with specified port and path
    /// </summary>
    constructor Create(
      const APort: Word;
      const ACallbackPath: string = '/callback'); reintroduce;
    destructor Destroy; override;

    /// <summary>
    /// Sets callback invoked when authorization code is received
    /// </summary>
    procedure SetOnCodeReceived(const ACallback: TProc<string, string>);

    /// <summary>
    /// Sets callback invoked on callback processing errors
    /// </summary>
    procedure SetOnError(const ACallback: TProc<Exception>);
  end;

implementation

uses
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.OAuth2URLParser,
  IAMClient4D.Server.Callback.IndyHttpServer,
  IAMClient4D.Exceptions;

{ TIAM4DLocalCallbackHandler }

constructor TIAM4DLocalCallbackHandler.Create(
  const APort: Word;
  const ACallbackPath: string);
begin
  inherited Create(cbmLocalServer);

  // Port 0 is allowed (let OS assign ephemeral port)
  // if APort = 0 then
  //   raise EIAM4DCallbackHandlerException.Create('Port must be greater than 0');

  FPort := APort;
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
  Result := Format('http://localhost:%d%s', [FCallbackServer.GetListeningPort, FCallbackPath]);
end;

procedure TIAM4DLocalCallbackHandler.HandleServerCallback(
  AResponseType: TIAM4DCallbackResponseType;
  AData: string);
var
  LCode, LState: string;
  LException: Exception;
begin
  if AResponseType <> crtCheckResponseIAM then
    Exit;

  TTask.Run(
    procedure
    begin
      try
        ExtractCodeAndStateFromURL(AData, LCode, LState);

        if Assigned(FOnCodeReceived) then
          FOnCodeReceived(LCode, LState);
      except
        on E: Exception do
        begin
          DoStop;

          LException := Exception(AcquireExceptionObject);

          if Assigned(FOnError) then
            FOnError(LException)
          else
            LException.Free;

          NotifyAuthorizationError(E);
        end;
      end;
    end);
end;

procedure TIAM4DLocalCallbackHandler.ExtractCodeAndStateFromURL(const AURL: string; out ACode, AState: string);
begin
  try
    TIAM4DOAuth2URLParser.ExtractCodeAndState(AURL, ACode, AState);

    ValidateStateParameter(AState);
  except
    on E: EIAM4DOAuth2CallbackException do
      raise EIAM4DCallbackHandlerException.Create(E.Message);
    on E: Exception do
      raise EIAM4DCallbackHandlerException.CreateFmt(
        'Failed to extract authorization code and state from callback URL: %s',
        [E.Message]);
  end;
end;

procedure TIAM4DLocalCallbackHandler.ValidateStateParameter(const AReceivedState: string);
var
  LContext: TIAM4DOAuthContext;
begin
  LContext := GetOAuthContext;

  if AReceivedState.Trim.IsEmpty then
    raise EIAM4DCallbackHandlerException.Create('Missing state parameter in OAuth2 callback');

  if AReceivedState <> LContext.State then
    raise EIAM4DCallbackHandlerException.CreateFmt(
      'State mismatch in OAuth2 callback. Expected: %s, Received: %s',
      [LContext.State, AReceivedState]);
end;

procedure TIAM4DLocalCallbackHandler.SetOnCodeReceived(const ACallback: TProc<string, string>);
begin
  FOnCodeReceived := ACallback;
end;

procedure TIAM4DLocalCallbackHandler.SetOnError(const ACallback: TProc<Exception>);
begin
  FOnError := ACallback;
end;

end.