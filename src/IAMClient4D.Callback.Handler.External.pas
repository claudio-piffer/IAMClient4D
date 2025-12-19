{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Callback.Handler.External.pas
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

unit IAMClient4D.Callback.Handler.External;

interface

uses
  System.SysUtils,
  System.SyncObjs,
  IAMClient4D.Core,
  IAMClient4D.Callback.Handler;

type
  /// <summary>
  /// OAuth2 callback handler for external web servers (uniGUI, ISAPI, etc).
  /// </summary>
  /// <remarks>
  /// Does NOT start a local server - callbacks are handled by the external web server.
  /// Application must manually call CompleteAuthorizationFlow when receiving the callback.
  ///
  /// Typical flow (uniGUI):
  /// 1. Call StartAuthorizationFlowAsync(False) to generate authorization URL
  /// 2. Redirect browser to authorization URL
  /// 3. Keycloak authenticates user and redirects to external callback URL
  /// 4. External server receives HTTP request at configured endpoint
  /// 5. External server extracts code and state from query string
  /// 6. External server calls CompleteAuthorizationFlow(code, state)
  /// 7. Library validates state, exchanges code+PKCE for tokens, saves tokens
  ///
  /// Thread-safety: All public methods are thread-safe.
  /// Security: URL must be registered in Keycloak as "Valid Redirect URI".
  /// </remarks>
  TIAM4DExternalCallbackHandler = class(TIAM4DCallbackHandlerBase)
  private
    FExternalCallbackURL: string;
    FLock: TCriticalSection;
  protected
    procedure DoStart; override;
    procedure DoStop; override;
    function DoIsListening: Boolean; override;
    function DoGetRedirectURI: string; override;
  public
    /// <summary>
    /// Creates external callback handler with specified redirect URL
    /// </summary>
    constructor Create(const AExternalCallbackURL: string); reintroduce;
    destructor Destroy; override;

    /// <summary>
    /// Validates state parameter from OAuth2 callback
    /// </summary>
    procedure ValidateState(const AReceivedState: string);

    /// <summary>
    /// Gets PKCE verifier for code exchange
    /// </summary>
    function GetPKCEVerifier: string;

    /// <summary>
    /// Gets nonce for ID token validation
    /// </summary>
    function GetNonce: string;

    /// <summary>
    /// Checks if OAuth2 context is valid
    /// </summary>
    function IsContextValid: Boolean;

    /// <summary>
    /// Clears OAuth2 context after flow completion
    /// </summary>
    procedure ClearContext;

    property ExternalCallbackURL: string read FExternalCallbackURL;
  end;

implementation

{ TIAM4DExternalCallbackHandler }

uses
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Exceptions;

constructor TIAM4DExternalCallbackHandler.Create(const AExternalCallbackURL: string);
begin
  inherited Create(cbmExternal);

  if AExternalCallbackURL.Trim.IsEmpty then
    raise EIAM4DCallbackHandlerException.Create('External callback URL cannot be empty');

  if not (AExternalCallbackURL.ToLower.StartsWith('http://') or
    AExternalCallbackURL.ToLower.StartsWith('https://')) then
    raise EIAM4DCallbackHandlerException.Create(
      'External callback URL must start with http:// or https://');

  FExternalCallbackURL := AExternalCallbackURL;
  FLock := TCriticalSection.Create;
end;

destructor TIAM4DExternalCallbackHandler.Destroy;
begin
  FreeAndNil(FLock);

  inherited;
end;

procedure TIAM4DExternalCallbackHandler.DoStart;
begin
  //don't remove
end;

procedure TIAM4DExternalCallbackHandler.DoStop;
begin
  //don't remove
end;

function TIAM4DExternalCallbackHandler.DoIsListening: Boolean;
begin
  Result := IsContextValid;
end;

function TIAM4DExternalCallbackHandler.DoGetRedirectURI: string;
begin
  Result := FExternalCallbackURL;
end;

procedure TIAM4DExternalCallbackHandler.ValidateState(const AReceivedState: string);
const
  MAX_STATE_LENGTH = 256;
var
  LContext: TIAM4DOAuthContext;
begin
  FLock.Acquire;
  try
    LContext := GetOAuthContext;

    if AReceivedState.Trim.IsEmpty then
      raise EIAM4DCallbackHandlerException.Create(
        'Missing state parameter in OAuth2 callback');

    if Length(AReceivedState) > MAX_STATE_LENGTH then
      raise EIAM4DCallbackHandlerException.CreateFmt(
        'State parameter exceeds maximum length (%d chars). Possible attack attempt.',
        [MAX_STATE_LENGTH]);

    if not LContext.IsValid then
      raise EIAM4DCallbackHandlerException.Create(
        'OAuth context is not valid. Authorization flow may have expired or not been started.');

    if not SecureStringEquals(AReceivedState, LContext.State) then
      raise EIAM4DCallbackHandlerException.CreateFmt(
        'State mismatch in OAuth2 callback. Expected: %s, Received: %s. ' +
        'This could indicate a CSRF attack or session mix-up.',
        [LContext.State, AReceivedState]);
  finally
    FLock.Release;
  end;
end;

function TIAM4DExternalCallbackHandler.GetPKCEVerifier: string;
var
  LContext: TIAM4DOAuthContext;
begin
  FLock.Acquire;
  try
    LContext := GetOAuthContext;

    if not LContext.IsValid then
      raise EIAM4DCallbackHandlerException.Create(
        'OAuth context is not valid. Cannot retrieve PKCE verifier.');

    Result := LContext.PKCEVerifier;
  finally
    FLock.Release;
  end;
end;

function TIAM4DExternalCallbackHandler.GetNonce: string;
var
  LContext: TIAM4DOAuthContext;
begin
  FLock.Acquire;
  try
    LContext := GetOAuthContext;

    if not LContext.IsValid then
      raise EIAM4DCallbackHandlerException.Create(
        'OAuth context is not valid. Cannot retrieve nonce.');

    Result := LContext.Nonce;
  finally
    FLock.Release;
  end;
end;

function TIAM4DExternalCallbackHandler.IsContextValid: Boolean;
var
  LContext: TIAM4DOAuthContext;
begin
  FLock.Acquire;
  try
    LContext := GetOAuthContext;
    Result := LContext.IsValid;
  finally
    FLock.Release;
  end;
end;

procedure TIAM4DExternalCallbackHandler.ClearContext;
var
  LContext: TIAM4DOAuthContext;
begin
  FLock.Acquire;
  try
    LContext := GetOAuthContext;
    LContext.Clear;
    SetOAuthContext(LContext);
  finally
    FLock.Release;
  end;
end;

end.