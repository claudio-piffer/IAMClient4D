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
  /// Lifecycle: Call Start before auth flow, Stop when done.
  /// Port binding: Validates port > 0 and automatically adds leading '/' to redirect path.
  /// HTML responses: Generates styled HTML pages for success/error/listening states.
  /// Error handling: OAuth2 error responses (error/error_description) handled automatically.
  /// Favicon: Returns 204 No Content for /favicon.ico requests.
  /// </remarks>
  TIAM4DIndyHttpCallbackServer = class(TInterfacedObject, IIAM4DHttpCallbackServer)
  private
    FServer: TIdHTTPServer;
    FCallback: TProc< TIAM4DCallbackResponseType, string >;
    FPort: Word;
    FRedirectPath: string;
    FPageTexts: TIAM4DCallbackPageTexts;

    procedure DoCommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
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
  IAMClient4D.Common.Constants,
  IAMClient4D.Exceptions;

constructor TIAM4DIndyHttpCallbackServer.Create(const APort: Word; const ARedirectPath: string);
begin
  inherited Create;

  if ARedirectPath.Trim.IsEmpty then
    raise EIAM4DServerCallbackException.Create('RedirectPath cannot be empty');

  FPort := APort;
  FRedirectPath := ARedirectPath;

  if not FRedirectPath.StartsWith('/') then
    FRedirectPath := '/' + FRedirectPath;

  FServer := TIdHTTPServer.Create(nil);
  FServer.DefaultPort := FPort;
  FServer.OnCommandGet := DoCommandGet;
  FPageTexts := TIAM4DCallbackPageTexts.CreateDefault;
end;

destructor TIAM4DIndyHttpCallbackServer.Destroy;
begin
  Stop;
  FServer.Free;

  inherited;
end;

procedure TIAM4DIndyHttpCallbackServer.DoCommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var
  LIsIAMCallback: Boolean;
  LReceivedCode: string;
  LReceivedState: string;
begin
  if ARequestInfo.Document = '/favicon.ico' then
  begin
    AResponseInfo.ResponseNo := 204;
    AResponseInfo.ContentText := '';
    AResponseInfo.FreeContentStream := True;
  end
  else
  begin
    var LFullURL: string := 'http';
    if ARequestInfo.AuthExists then
      LFullURL := LFullURL + 's';

    LFullURL := LFullURL + '://' + ARequestInfo.Host;

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
        if Assigned(FCallback) then
        begin
          try
            FCallback(crtCheckResponseIAM, LFullURL);

            AResponseInfo.ContentType := 'text/html';
            AResponseInfo.ContentText := GetHtmlAuthSuccessPage;
            AResponseInfo.ResponseNo := 200;
          except
            on E: Exception do
            begin
              FCallback(crtOther, E.Message);
              AResponseInfo.ResponseNo := 400;
              AResponseInfo.ContentText := GetHtmlAuthErrorPage(E.Message);
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
        var LErrorHtml: string := GetHtmlAuthErrorPage(Format('%s<br><br>%s', [LErrorCode, LErrorDesc]));
        if Assigned(FCallback) then
          FCallback(crtOther, LErrorCode + ': ' + LErrorDesc);
        AResponseInfo.ResponseNo := 400;
        AResponseInfo.ContentType := 'text/html';
        AResponseInfo.ContentText := LErrorHtml;
      end
      else
      begin
        FCallback(crtOther, FPageTexts.NotIamCallbackBody);
        AResponseInfo.ResponseNo := 200;
        AResponseInfo.ContentText := GetHtmlNotIAMCallbackPage;
        AResponseInfo.ContentType := 'text/html';
      end;
    end
    else if ARequestInfo.Document = '/' then
    begin
      FCallback(crtOther, FPageTexts.AppListeningBody);
      AResponseInfo.ResponseNo := 200;
      AResponseInfo.ContentText := GetHtmlAppListeningPage;
      AResponseInfo.ContentType := 'text/html';
    end
    else
    begin
      FCallback(crtOther, FPageTexts.NotFoundBody);
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
  if FServer.Active then
    FServer.Active := False;

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