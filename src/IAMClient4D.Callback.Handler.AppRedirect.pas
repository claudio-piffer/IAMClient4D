{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Callback.Handler.AppRedirect.pas
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

unit IAMClient4D.Callback.Handler.AppRedirect;

interface

uses
  System.SysUtils,
  IAMClient4D.Core,
  IAMClient4D.Callback.Handler;

type
  /// <summary>
  /// OAuth2 callback handler for apps that receive the redirect on a private-use URI scheme.
  /// </summary>
  /// <remarks>
  /// For mobile apps (RFC 8252 7.1): the authorization server redirects the browser to
  /// com.example.app:/oauth2callback?code=...&amp;state=..., the operating system hands the URL to the
  /// app and the app passes it to TIAM4DAppRedirect.HandleURL. No server is started.
  ///
  /// The login waits (StartAuthorizationFlowAsync) from Start until HandleURL takes a callback with the
  /// state of the flow, or Stop. A callback without it (other URI, forged state, malformed) is ignored.
  /// Nothing is persisted: if the app process is killed while the browser is open, the login is lost.
  ///
  /// Security: the state parameter and PKCE protect the flow. Another app may claim the same scheme:
  /// without the code verifier it cannot exchange the code (RFC 8252 8.1).
  /// </remarks>
  TIAM4DAppRedirectCallbackHandler = class(TIAM4DRedirectCallbackHandlerBase)
  private
    FRedirectURI: string;
    /// <summary>
    /// True if AURL is a callback to this handler: its redirect URI, malformed or not, and the state of the flow
    /// </summary>
    function Accepts(const AURL: string): Boolean;
  protected
    procedure DoStart; override;
    procedure DoStop; override;
    function DoIsListening: Boolean; override;
    function DoGetRedirectURI: string; override;
  public
    /// <summary>
    /// Creates the handler for the redirect URI, validated with IsValidRedirectURI
    /// </summary>
    /// <exception cref="EIAM4DCallbackHandlerException">Invalid redirect URI</exception>
    constructor Create(const ARedirectURI: string); reintroduce;

    /// <summary>
    /// Checks a redirect URI against RFC 8252 7.1: lowercase scheme, reverse domain name (at least one
    /// dot), followed by :/ (or ://), no query, no fragment. http and https are refused.
    /// </summary>
    class function IsValidRedirectURI(const AURI: string; out AError: string): Boolean; static;
  end;

  /// <summary>
  /// Entry point of the operating system for the redirects on a private-use URI scheme.
  /// </summary>
  /// <remarks>
  /// Thread-safe. Call HandleURL from the code that receives the URL (the FMX unit
  /// IAMClient4D.FMX.AppRedirect does it for Android and iOS).
  /// </remarks>
  TIAM4DAppRedirect = class
  public
    /// <summary>
    /// Passes a URL received by the app to the login that waits for it.
    /// </summary>
    /// <returns>
    /// True if the URL is the redirect of the login in progress: it is processed in the background,
    /// once. False if it is not (other URI, state not of the flow, malformed, no login waiting): nothing
    /// happens, the login keeps waiting.
    /// </returns>
    class function HandleURL(const AURL: string): Boolean; static;

    /// <summary>
    /// True if a login waits for the redirect
    /// </summary>
    class function IsWaiting: Boolean; static;
  end;

implementation

uses
  System.SyncObjs,
  System.Generics.Collections,
  IAMClient4D.Exceptions;

var
  // Handlers between Start and Stop (or the redirect). Strong references: a waiting handler is stopped
  // by its owner, which removes it, so none is freed while HandleURL uses it
  GRegistryLock: TCriticalSection;
  GWaiting: TList<IIAM4DCallbackHandler>;

function IndexOfWaiting(const AHandler: TObject): Integer;
var
  I: Integer;
begin
  for I := 0 to GWaiting.Count - 1 do
    if (GWaiting[I] as TObject) = AHandler then
      Exit(I);
  Result := -1;
end;

{ TIAM4DAppRedirectCallbackHandler }

constructor TIAM4DAppRedirectCallbackHandler.Create(const ARedirectURI: string);
var
  LError: string;
begin
  inherited Create(cbmAppRedirect);

  if not IsValidRedirectURI(ARedirectURI, LError) then
    raise EIAM4DCallbackHandlerException.Create(LError);

  FRedirectURI := ARedirectURI;
end;

class function TIAM4DAppRedirectCallbackHandler.IsValidRedirectURI(const AURI: string;
  out AError: string): Boolean;
var
  LColon, I: Integer;
  LScheme: string;
  LLabel: string;
begin
  Result := False;
  AError := '';

  if AURI.Trim.IsEmpty then
  begin
    AError := 'App redirect URI cannot be empty';
    Exit;
  end;

  if (AURI.IndexOf('?') >= 0) or (AURI.IndexOf('#') >= 0) then
  begin
    AError := 'App redirect URI cannot contain a query or a fragment';
    Exit;
  end;

  LColon := AURI.IndexOf(':');
  if LColon < 1 then
  begin
    AError := 'App redirect URI must be of the form scheme:/path (e.g. com.example.app:/oauth2callback)';
    Exit;
  end;

  LScheme := AURI.Substring(0, LColon);
  if SameText(LScheme, 'http') or SameText(LScheme, 'https') then
  begin
    AError := 'App redirect URI must use a private-use scheme (RFC 8252 7.1), not http(s): ' +
      'use WithExternalCallback() for a web server or the default loopback redirect for a desktop app';
    Exit;
  end;

  if LScheme <> LScheme.ToLower then
  begin
    AError := 'The scheme of the app redirect URI must be lowercase';
    Exit;
  end;

  if not CharInSet(LScheme.Chars[0], ['a'..'z']) then
  begin
    AError := 'The scheme of the app redirect URI must start with a letter';
    Exit;
  end;
  for I := 1 to LScheme.Length - 1 do
    if not CharInSet(LScheme.Chars[I], ['a'..'z', '0'..'9', '+', '-', '.']) then
    begin
      AError := 'The scheme of the app redirect URI has an invalid character: ' + LScheme.Chars[I];
      Exit;
    end;

  if LScheme.IndexOf('.') < 0 then
  begin
    AError := 'The scheme of the app redirect URI must be a reverse domain name of the app ' +
      '(RFC 8252 7.1), with at least one dot, e.g. com.example.app';
    Exit;
  end;
  for LLabel in LScheme.Split(['.']) do
    if LLabel.IsEmpty then
    begin
      AError := 'The scheme of the app redirect URI has an empty label (leading, trailing or double dot)';
      Exit;
    end;

  if not AURI.Substring(LColon + 1).StartsWith('/') then
  begin
    AError := 'App redirect URI must have the form scheme:/path (or scheme://path)';
    Exit;
  end;

  Result := True;
end;

function TIAM4DAppRedirectCallbackHandler.Accepts(const AURL: string): Boolean;
var
  LColon, LEnd: Integer;
  LBase: string;
begin
  Result := False;

  // The URL without query and fragment is the redirect URI (the scheme is case-insensitive)
  LColon := AURL.IndexOf(':');
  if LColon < 1 then
    Exit;
  LEnd := AURL.IndexOfAny(['?', '#'], LColon);
  if LEnd < 0 then
    LBase := AURL
  else
    LBase := AURL.Substring(0, LEnd);
  if (LColon <> FRedirectURI.IndexOf(':')) or
    (not SameText(LBase.Substring(0, LColon), FRedirectURI.Substring(0, LColon))) or
    (LBase.Substring(LColon) <> FRedirectURI.Substring(LColon)) then
    Exit;

  try
    CheckCallbackCanEndFlow(AURL);
    Result := True;
  except
    on Exception do
      Result := False;
  end;
end;

procedure TIAM4DAppRedirectCallbackHandler.DoStart;
begin
  GRegistryLock.Enter;
  try
    if IndexOfWaiting(Self) < 0 then
      GWaiting.Add(Self as IIAM4DCallbackHandler);
  finally
    GRegistryLock.Leave;
  end;
end;

procedure TIAM4DAppRedirectCallbackHandler.DoStop;
var
  LIndex: Integer;
begin
  GRegistryLock.Enter;
  try
    LIndex := IndexOfWaiting(Self);
    if LIndex >= 0 then
      GWaiting.Delete(LIndex);
  finally
    GRegistryLock.Leave;
  end;
end;

function TIAM4DAppRedirectCallbackHandler.DoIsListening: Boolean;
begin
  GRegistryLock.Enter;
  try
    Result := IndexOfWaiting(Self) >= 0;
  finally
    GRegistryLock.Leave;
  end;
end;

function TIAM4DAppRedirectCallbackHandler.DoGetRedirectURI: string;
begin
  Result := FRedirectURI;
end;

{ TIAM4DAppRedirect }

class function TIAM4DAppRedirect.HandleURL(const AURL: string): Boolean;
var
  LClaimed: IIAM4DCallbackHandler;
  I: Integer;
begin
  LClaimed := nil;

  // The handler leaves the registry here: a redirect is taken once, and the reference keeps it alive
  GRegistryLock.Enter;
  try
    for I := 0 to GWaiting.Count - 1 do
      if (GWaiting[I] as TIAM4DAppRedirectCallbackHandler).Accepts(AURL) then
      begin
        LClaimed := GWaiting[I];
        GWaiting.Delete(I);
        Break;
      end;
  finally
    GRegistryLock.Leave;
  end;

  Result := Assigned(LClaimed);
  if Result then
    (LClaimed as TIAM4DAppRedirectCallbackHandler).DispatchCallback(AURL);
end;

class function TIAM4DAppRedirect.IsWaiting: Boolean;
begin
  GRegistryLock.Enter;
  try
    Result := GWaiting.Count > 0;
  finally
    GRegistryLock.Leave;
  end;
end;

initialization
  GRegistryLock := TCriticalSection.Create;
  GWaiting := TList<IIAM4DCallbackHandler>.Create;

finalization
  FreeAndNil(GWaiting);
  FreeAndNil(GRegistryLock);

end.
