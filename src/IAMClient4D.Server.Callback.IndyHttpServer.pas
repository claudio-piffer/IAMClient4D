{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Server.Callback.IndyHttpServer.pas
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

unit IAMClient4D.Server.Callback.IndyHttpServer;

interface

uses
  System.SysUtils,
  System.Classes,
  IdCustomHTTPServer,
  IdHTTPServer,
  IdContext,
  IdGlobal,
  IAMClient4D.Server.Callback.Core;

type
  /// <summary>
  /// Indy-based HTTP callback server for OAuth2 redirects.
  /// </summary>
  /// <remarks>
  /// Implementation: Uses TIdHTTPServer from Indy components.
  /// Threading: Indy handles requests on separate threads automatically.
  /// Lifecycle: Call Start before auth flow, Stop when done. Stop returns once the connection
  /// threads are gone (at most 5 s): a connection accepted while stopping cannot hang it (see
  /// TIAM4DCallbackServerScheduler in the implementation).
  /// Port binding: Validates port > 0 and automatically adds leading '/' to redirect path.
  /// HTML responses: Generates styled HTML pages for success/error/listening states.
  /// Error handling: OAuth2 error responses (error/error_description) go to the callback handler,
  /// which ends the login with them or rejects them (error page, login still waiting).
  /// Every value of the request shown in a page is HTML-escaped.
  /// Favicon: Returns 204 No Content for /favicon.ico requests.
  /// </remarks>
  TIAM4DIndyHttpCallbackServer = class(TInterfacedObject, IIAM4DHttpCallbackServer)
  private
    FServer: TIdHTTPServer;
    // Serializes Stop: the thread of the callback request and the caller may stop at once
    FStopLock: TObject;
    FCallback: TProc< TIAM4DCallbackResponseType, string >;
    FPort: Word;
    FRedirectPath: string;
    FPageTexts: TIAM4DCallbackPageTexts;
    // Requests being answered: Stop lets them send their page
    FActiveRequests: Integer;

    procedure DoCommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure HandleCommandGet(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure DoStopLocked;
  protected
    /// <summary>
    /// Starts HTTP server on configured port.
    /// </summary>
    procedure Start;
    /// <summary>
    /// Stops HTTP server and clears callback handler.
    /// </summary>
    procedure Stop;
    /// <summary>
    /// Returns true if server is active.
    /// </summary>
    function IsRunning: Boolean;
    /// <summary>
    /// Sets callback handler for OAuth2 redirects.
    /// </summary>
    procedure SetCallbackHandler(const Handler: TProc< TIAM4DCallbackResponseType, string >);
    /// <summary>
    /// Returns HTML base page template with title, heading, and body.
    /// </summary>
    function GetHtmlBasePage(const ATitle, AHeading, ABody: string; const AHeadingStyle: string = ''): string;
    /// <summary>
    /// Returns HTML success page.
    /// </summary>
    function GetHtmlAuthSuccessPage: string;
    /// <summary>
    /// Returns HTML error page with error message.
    /// </summary>
    function GetHtmlAuthErrorPage(const AErrorMessage: string): string;
    /// <summary>
    /// Returns HTML page for missing callback handler.
    /// </summary>
    function GetHtmlCallbackHandlerNotSet: string;
    /// <summary>
    /// Returns HTML page for non-IAM callback requests.
    /// </summary>
    function GetHtmlNotIAMCallbackPage: string;
    /// <summary>
    /// Returns HTML page shown when server is listening.
    /// </summary>
    function GetHtmlAppListeningPage: string;
    /// <summary>
    /// Returns HTML 404 not found page.
    /// </summary>
    function GetHtmlNotFoundPage: string;
    /// <summary>
    /// Returns page text configuration.
    /// </summary>
    function GetPageTexts: TIAM4DCallbackPageTexts;
  public
    /// <summary>
    /// Creates Indy HTTP callback server on specified port and redirect path.
    /// </summary>
    constructor Create(const APort: Word; const ARedirectPath: string);
    /// <summary>
    /// Destroys server and stops if running.
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    /// Returns the actual port the server is listening on.
    /// </summary>
    function GetListeningPort: Word;
  end;

implementation

{TIndyHttpCallbackServer}

uses
  System.SyncObjs,
  IdYarn,
  IdThread,
  IdScheduler,
  IdSchedulerOfThread,
  IdSchedulerOfThreadDefault,
  IAMClient4D.Common.Constants,
  IAMClient4D.Exceptions;

const
  // Upper bound for the running requests to send their page before Active := False
  REQUESTS_STOP_TIMEOUT_MS = 2000;
  // Upper bound for the connection threads to end after Active := False
  THREADS_STOP_TIMEOUT_MS = 5000;
  // Poll interval of TerminateAllYarns (Indy's own is 500 ms)
  YARNS_POLL_MS = 5;

threadvar
  // True on a connection thread answering a request: Stop must not wait for itself
  GServingCallbackRequest: Boolean;

type
  /// <summary>
  /// Connection threads alive: shared by the scheduler and its threads, which may outlive it.
  /// </summary>
  IIAM4DThreadCount = interface
    ['{3F1B8E52-7C4A-4D1E-9A63-2B5C0D8E4F17}']
    procedure Increment;
    procedure Decrement;
    function Value: Integer;
  end;

  TIAM4DThreadCount = class(TInterfacedObject, IIAM4DThreadCount)
  private
    FValue: Integer;
  public
    procedure Increment;
    procedure Decrement;
    function Value: Integer;
  end;

  /// <summary>
  /// Connection thread of the callback server: counted until it is freed.
  /// </summary>
  TIAM4DCallbackServerThread = class(TIdThreadWithTask)
  private
    FCount: IIAM4DThreadCount;
  public
    destructor Destroy; override;
  end;

  /// <summary>
  /// Thread scheduler of the callback server: works around two Indy races of Active := False.
  /// </summary>
  /// <remarks>
  /// 1. A connection accepted while the server stops gets a thread that Indy may terminate before
  /// it runs: TIdThread.Execute then exits without releasing its yarn, and
  /// TIdScheduler.TerminateAllYarns waits for it forever. The yarn of a finished thread is released here.
  /// 2. TerminateAllYarns returns while connection threads are still freeing their contexts, which
  /// leave the context list of the server: freeing the server at that moment is a use after free.
  /// Stop waits for them with WaitForThreads.
  /// 3. TIdScheduler.TerminateAllYarns sleeps 500 ms whenever a connection is still open (e.g. a
  /// browser preconnect): it is polled here every YARNS_POLL_MS instead.
  /// </remarks>
  TIAM4DCallbackServerScheduler = class(TIdSchedulerOfThreadDefault)
  private
    FThreadCount: IIAM4DThreadCount;
  protected
    procedure InitComponent; override;
  public
    function NewThread: TIdThreadWithTask; override;
    procedure TerminateYarn(AYarn: TIdYarn); override;
    procedure TerminateAllYarns; override;
    /// <summary>
    /// Waits until every connection thread is freed; False on timeout.
    /// </summary>
    function WaitForThreads(ATimeoutMs: Cardinal): Boolean;
  end;

{ TIAM4DThreadCount }

procedure TIAM4DThreadCount.Increment;
begin
  TInterlocked.Increment(FValue);
end;

procedure TIAM4DThreadCount.Decrement;
begin
  TInterlocked.Decrement(FValue);
end;

function TIAM4DThreadCount.Value: Integer;
begin
  Result := TInterlocked.CompareExchange(FValue, 0, 0);
end;

{ TIAM4DCallbackServerThread }

destructor TIAM4DCallbackServerThread.Destroy;
var
  LCount: IIAM4DThreadCount;
begin
  LCount := FCount;
  FCount := nil;
  // Frees the context, which leaves the context list of the server
  inherited Destroy;
  if Assigned(LCount) then
    LCount.Decrement;
end;

{ TIAM4DCallbackServerScheduler }

procedure TIAM4DCallbackServerScheduler.InitComponent;
begin
  inherited InitComponent;
  FThreadClass := TIAM4DCallbackServerThread;
  FThreadCount := TIAM4DThreadCount.Create;
end;

function TIAM4DCallbackServerScheduler.NewThread: TIdThreadWithTask;
begin
  Result := inherited NewThread;
  // Created suspended: nothing runs before the counter is attached
  FThreadCount.Increment;
  (Result as TIAM4DCallbackServerThread).FCount := FThreadCount;
end;

procedure TIAM4DCallbackServerScheduler.TerminateYarn(AYarn: TIdYarn);
var
  LThread: TIdThreadWithTask;
  LYarn: TIdYarn;
begin
  LThread := TIdYarnOfThread(AYarn).Thread;
  if (LThread <> nil) and LThread.Finished then
  begin
    // Nobody else would release it: freeing the yarn removes it from ActiveYarns and frees the thread
    LYarn := AYarn;
    IdDisposeAndNil(LYarn);
  end
  else
    inherited TerminateYarn(AYarn);
end;

procedure TIAM4DCallbackServerScheduler.TerminateAllYarns;
var
  I: Integer;
  LList: TIdYarnList;
begin
  // Same loop as TIdScheduler.TerminateAllYarns, with a short poll
  while True do
  begin
    // Unlocked between the checks: ending threads remove their yarn
    LList := ActiveYarns.LockList;
    try
      if LList.Count = 0 then
        Break;
      for I := LList.Count - 1 downto 0 do
        TerminateYarn(LList.Items[I]);
    finally
      ActiveYarns.UnlockList;
    end;
    Sleep(YARNS_POLL_MS);
  end;
end;

function TIAM4DCallbackServerScheduler.WaitForThreads(ATimeoutMs: Cardinal): Boolean;
var
  LStart: UInt64;
begin
  LStart := TThread.GetTickCount64;
  while FThreadCount.Value > 0 do
  begin
    if TThread.GetTickCount64 - LStart >= ATimeoutMs then
      Exit(False);
    Sleep(2);
  end;
  Result := True;
end;

/// <summary>
/// Escapes HTML special characters to prevent XSS attacks.
/// </summary>
/// <remarks>
/// Converts: &amp; &lt; &gt; &quot; &#39;
/// SECURITY: Must be applied to all user-controlled input before HTML insertion.
/// </remarks>
function HTMLEscape(const AText: string): string;
var
  I: Integer;
  LChar: Char;
  LBuilder: TStringBuilder;
begin
  LBuilder := TStringBuilder.Create(Length(AText) * 2);
  try
    for I := 1 to Length(AText) do
    begin
      LChar := AText[I];
      case LChar of
        '&': LBuilder.Append('&amp;');
        '<': LBuilder.Append('&lt;');
        '>': LBuilder.Append('&gt;');
        '"': LBuilder.Append('&quot;');
        '''': LBuilder.Append('&#39;');
      else
        LBuilder.Append(LChar);
      end;
    end;
    Result := LBuilder.ToString;
  finally
    LBuilder.Free;
  end;
end;

constructor TIAM4DIndyHttpCallbackServer.Create(const APort: Word; const ARedirectPath: string);
begin
  inherited Create;

  if ARedirectPath.Trim.IsEmpty then
    raise EIAM4DServerCallbackException.Create('RedirectPath cannot be empty');

  FPort := APort;
  FRedirectPath := ARedirectPath;

  if not FRedirectPath.StartsWith('/') then
    FRedirectPath := '/' + FRedirectPath;

  FStopLock := TObject.Create;
  FServer := TIdHTTPServer.Create(nil);
  // Owned by FServer; kept across Start/Stop
  FServer.Scheduler := TIAM4DCallbackServerScheduler.Create(FServer);

  with FServer.Bindings.Add do
  begin
    IP := '127.0.0.1';
    Port := FPort;
  end;
  FServer.OnCommandGet := DoCommandGet;
  FPageTexts := TIAM4DCallbackPageTexts.CreateDefault;
end;

destructor TIAM4DIndyHttpCallbackServer.Destroy;
begin
  Stop;
  FServer.Free;
  FStopLock.Free;

  inherited;
end;

procedure TIAM4DIndyHttpCallbackServer.DoCommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
begin
  TInterlocked.Increment(FActiveRequests);
  GServingCallbackRequest := True;
  try
    HandleCommandGet(ARequestInfo, AResponseInfo);
    // After ContentType, which may reset it; the pages declare UTF-8
    AResponseInfo.CharSet := 'utf-8';
    // Sent now, not after this event: a login ending meanwhile stops the server and would cut the page
    AResponseInfo.WriteContent;
  finally
    GServingCallbackRequest := False;
    TInterlocked.Decrement(FActiveRequests);
  end;
end;

procedure TIAM4DIndyHttpCallbackServer.HandleCommandGet(ARequestInfo: TIdHTTPRequestInfo;
  AResponseInfo: TIdHTTPResponseInfo);
var
  LIsIAMCallback: Boolean;
  LReceivedCode: string;
  LReceivedState: string;
  LHost: string;
  LCallback: TProc< TIAM4DCallbackResponseType, string >;
begin
  LCallback := FCallback;

  // Pages with code and state: not cached, not sent as Referer
  AResponseInfo.CacheControl := 'no-store';
  AResponseInfo.CustomHeaders.Values['Referrer-Policy'] := 'no-referrer';
  AResponseInfo.CustomHeaders.Values['X-Content-Type-Options'] := 'nosniff';

  // The server listens on 127.0.0.1: another Host is a page of another site (DNS rebinding)
  LHost := ARequestInfo.Host.ToLower;
  if LHost.StartsWith('[') then
    LHost := LHost.Substring(0, LHost.IndexOf(']') + 1)
  else if LHost.Contains(':') then
    LHost := LHost.Substring(0, LHost.IndexOf(':'));
  if not ((LHost = 'localhost') or (LHost = '127.0.0.1') or (LHost = '[::1]')) then
  begin
    AResponseInfo.ResponseNo := 400;
    AResponseInfo.ContentType := 'text/plain';
    AResponseInfo.ContentText := 'Bad Request';
    Exit;
  end;

  if ARequestInfo.Document = '/favicon.ico' then
  begin
    AResponseInfo.ResponseNo := 204;
    AResponseInfo.ContentText := '';
    AResponseInfo.FreeContentStream := True;
  end
  else
  begin
    // Plain HTTP loopback server: the Host has been checked above
    var LFullURL: string := 'http://' + ARequestInfo.Host;

    LFullURL := LFullURL + ARequestInfo.Document;

    if ARequestInfo.QueryParams <> '' then
      LFullURL := LFullURL + '?' + ARequestInfo.QueryParams;

    LIsIAMCallback := False;
    if ARequestInfo.Document = FRedirectPath then
      LIsIAMCallback := True;

    if LIsIAMCallback then
    begin
      LReceivedCode := ARequestInfo.Params.Values[IAM4D_OAUTH2_PARAM_CODE];
      LReceivedState := ARequestInfo.Params.Values[IAM4D_OAUTH2_PARAM_STATE];

      if (LReceivedCode <> '') and (LReceivedState <> '') then
      begin
        if Assigned(LCallback) then
        begin
          try
            LCallback(crtCheckResponseIAM, LFullURL);

            AResponseInfo.ContentType := 'text/html';
            AResponseInfo.ContentText := GetHtmlAuthSuccessPage;
            AResponseInfo.ResponseNo := 200;
          except
            on E: Exception do
            begin
              if Assigned(LCallback) then
                LCallback(crtOther, E.Message);
              AResponseInfo.ResponseNo := 400;
              AResponseInfo.ContentText := GetHtmlAuthErrorPage(HTMLEscape(E.Message));
              AResponseInfo.ContentType := 'text/html';
            end;
          end;
        end
        else
        begin
          AResponseInfo.ResponseNo := 500;
          AResponseInfo.ContentText := GetHtmlCallbackHandlerNotSet;
          AResponseInfo.ContentType := 'text/html';
          raise EIAM4DServerCallbackException.Create(FPageTexts.CallbackHandlerNotSet)
        end;
      end
      else if ARequestInfo.Params.Values['error'] <> '' then
      begin
        var LErrorCode: string := ARequestInfo.Params.Values['error'];
        var LErrorDesc: string := ARequestInfo.Params.Values['error_description'];
        var LErrorHtml: string := GetHtmlAuthErrorPage(
          Format('%s<br><br>%s', [HTMLEscape(LErrorCode), HTMLEscape(LErrorDesc)]));
        // Error response of the authorization server: the handler ends the login with it, or
        // raises when it cannot be trusted (no state of the flow) and the login keeps waiting
        if Assigned(LCallback) then
        begin
          try
            LCallback(crtCheckResponseIAM, LFullURL);
          except
            on E: Exception do
            begin
              LCallback(crtOther, E.Message);
              LErrorHtml := GetHtmlAuthErrorPage(HTMLEscape(E.Message));
            end;
          end;
        end;
        AResponseInfo.ResponseNo := 400;
        AResponseInfo.ContentType := 'text/html';
        AResponseInfo.ContentText := LErrorHtml;
      end
      else
      begin
        if Assigned(LCallback) then
          LCallback(crtOther, FPageTexts.NotIamCallbackBody);
        AResponseInfo.ResponseNo := 200;
        AResponseInfo.ContentText := GetHtmlNotIAMCallbackPage;
        AResponseInfo.ContentType := 'text/html';
      end;
    end
    else if ARequestInfo.Document = '/' then
    begin
      if Assigned(LCallback) then
        LCallback(crtOther, FPageTexts.AppListeningBody);
      AResponseInfo.ResponseNo := 200;
      AResponseInfo.ContentText := GetHtmlAppListeningPage;
      AResponseInfo.ContentType := 'text/html';
    end
    else
    begin
      if Assigned(LCallback) then
        LCallback(crtOther, FPageTexts.NotFoundBody);
      AResponseInfo.ResponseNo := 404;
      AResponseInfo.ContentText := GetHtmlNotFoundPage;
      AResponseInfo.ContentType := 'text/html';
    end;
  end;
end;

function TIAM4DIndyHttpCallbackServer.GetHtmlAppListeningPage: string;
begin
  Result := '<html><body><h1>' + FPageTexts.AppListeningHeading + '</h1>' +
    '<p>' + FPageTexts.AppListeningBody + '</p></body></html>';
end;

function TIAM4DIndyHttpCallbackServer.GetHtmlAuthErrorPage(const AErrorMessage: string): string;
begin
  Result := GetHtmlBasePage(
    FPageTexts.PageTitleAuthError,
    FPageTexts.AuthErrorHeading,
    FPageTexts.AuthErrorBodyPrefix + AErrorMessage,
    'color: #D32F2F;');
end;

function TIAM4DIndyHttpCallbackServer.GetHtmlAuthSuccessPage: string;
begin
  Result := GetHtmlBasePage(
    FPageTexts.PageTitleIamCallback,
    FPageTexts.AuthSuccessHeading,
    FPageTexts.AuthSuccessBody);
end;

function TIAM4DIndyHttpCallbackServer.GetHtmlBasePage(const ATitle, AHeading, ABody, AHeadingStyle: string): string;
var
  LHeadingStyleAttr: string;
begin
  if AHeadingStyle <> '' then
    LHeadingStyleAttr := ' style="' + AHeadingStyle + '"'
  else
    LHeadingStyleAttr := '';

  Result :=
    '<!DOCTYPE html>' +
    '<html lang="en">' +
    '<head>' +
    '  <meta charset="UTF-8">' +
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    '  <title>' + ATitle + '</title>' +
    '  <style>' +
    '    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }' +
    '    h1 { color: #4CAF50; }' +
    '    p { font-size: 18px; color: #555; }' +
    '  </style>' +
    '</head>' +
    '<body>' +
    '  <h1' + LHeadingStyleAttr + '>' + AHeading + '</h1>' +
    '  <p>' + ABody + '</p>' +
    '</body>' +
    '</html>';
end;

function TIAM4DIndyHttpCallbackServer.GetHtmlCallbackHandlerNotSet: string;
begin
  Result := GetHtmlBasePage(
    FPageTexts.PageTitleError,
    FPageTexts.PageTitleError,
    FPageTexts.CallbackHandlerNotSet,
    'color: #D32F2F;');
end;

function TIAM4DIndyHttpCallbackServer.GetHtmlNotFoundPage: string;
begin
  Result := GetHtmlBasePage(
    FPageTexts.PageTitleNotFound,
    FPageTexts.PageTitleNotFound,
    FPageTexts.NotFoundBody,
    'color: #D32F2F;');
end;

function TIAM4DIndyHttpCallbackServer.GetHtmlNotIAMCallbackPage: string;
begin
  Result := GetHtmlBasePage(
    FPageTexts.PageTitleAuthEndpoint,
    FPageTexts.NotIamCallbackHeading,
    FPageTexts.NotIamCallbackBody,
    'color: #D32F2F;');
end;

function TIAM4DIndyHttpCallbackServer.GetPageTexts: TIAM4DCallbackPageTexts;
begin
  Result := FPageTexts;
end;

function TIAM4DIndyHttpCallbackServer.IsRunning: Boolean;
begin
  Result := FServer.Active;
end;

procedure TIAM4DIndyHttpCallbackServer.SetCallbackHandler(const Handler: TProc< TIAM4DCallbackResponseType, string >);
begin
  FCallback := Handler;
end;

procedure TIAM4DIndyHttpCallbackServer.Start;
begin
  if not FServer.Active then
    FServer.Active := True;
end;

procedure TIAM4DIndyHttpCallbackServer.Stop;
begin
  // On a connection thread another thread already stopping is enough: waiting for it would
  // deadlock, it waits for this thread to end
  if GServingCallbackRequest then
  begin
    if not TMonitor.TryEnter(FStopLock) then
      Exit;
  end
  else
    TMonitor.Enter(FStopLock);
  try
    DoStopLocked;
  finally
    TMonitor.Exit(FStopLock);
  end;
end;

procedure TIAM4DIndyHttpCallbackServer.DoStopLocked;
var
  LStart: UInt64;
begin
  if FServer.Active then
  begin
    // The request that ended the login (or a concurrent one) is still sending its page
    if not GServingCallbackRequest then
    begin
      LStart := TThread.GetTickCount64;
      while (TInterlocked.CompareExchange(FActiveRequests, 0, 0) > 0) and
            (TThread.GetTickCount64 - LStart < REQUESTS_STOP_TIMEOUT_MS) do
        Sleep(2);
    end;
    FServer.Active := False;
    // Connection threads still ending would use the server after it is freed
    (FServer.Scheduler as TIAM4DCallbackServerScheduler).WaitForThreads(THREADS_STOP_TIMEOUT_MS);
  end;

  FCallback := nil;
end;

function TIAM4DIndyHttpCallbackServer.GetListeningPort: Word;
begin
  if (FServer <> nil) and FServer.Active and (FServer.Bindings.Count > 0) then
    Result := FServer.Bindings[0].Port
  else
    Result := FPort;
end;

end.
