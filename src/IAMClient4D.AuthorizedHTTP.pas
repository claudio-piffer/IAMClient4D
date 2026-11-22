{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.AuthorizedHTTP.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2026 Claudio Piffer
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

  HTTP client for an API protected by the access tokens of an IIAM4DClient: every request
  carries a valid bearer, renewed when it expires, and a 401 is retried once with a new one.
}

unit IAMClient4D.AuthorizedHTTP;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Net.URLClient,
  System.Net.HttpClient,
  IAMClient4D.Core;

type
  /// <summary>
  /// HTTP client that sends the access token of an IIAM4DClient as bearer.
  /// </summary>
  /// <remarks>
  /// Each request takes the token from GetAccessToken (renewed when it is about to expire). A 401
  /// answered to that token is retried once: the token is invalidated (InvalidateAccessToken) and
  /// renewed first. A second 401 is returned to the caller, like any other status.
  /// Errors of GetAccessToken propagate: EIAM4DRefreshTokenExpiredException means a new login.
  /// The bearer is sent only over HTTPS (http:// to the loopback excepted, AllowInsecureHTTP for
  /// tests) and redirects are never followed: a 3xx is returned, the token stays on that host.
  /// The THTTPClient is not the one of IIAM4DClient: the pins of Keycloak do not apply to the API.
  /// Configure TLS, proxy and timeouts on HTTPClient, or pass a client to the constructor.
  /// Not thread-safe: one instance per thread (they can share the IIAM4DClient).
  /// A body stream is sent again from its starting position on the retry: it must be seekable.
  /// </remarks>
  TIAM4DAuthorizedHTTPClient = class
  private
    FClient: IIAM4DClient;
    FHTTPClient: THTTPClient;
    FOwnsHTTPClient: Boolean;
    FRetryOnUnauthorized: Boolean;
    FAllowInsecureHTTP: Boolean;
    function Send(const AMethod, AURL, AToken: string; const ABody: TStream;
      const AHeaders: TNetHeaders): IHTTPResponse;
  public
    /// <summary>
    /// AHTTPClient nil creates one (HTTP timeouts of the RTL); a given one is freed with this
    /// object when AOwnsHTTPClient. HandleRedirects is set to False either way, again before each
    /// request.
    /// </summary>
    constructor Create(const AClient: IIAM4DClient; const AHTTPClient: THTTPClient = nil;
      AOwnsHTTPClient: Boolean = True);
    destructor Destroy; override;

    /// <summary>
    /// Request with the bearer; AHeaders must not contain Authorization (EArgumentException).
    /// </summary>
    function Execute(const AMethod, AURL: string; const ABody: TStream = nil;
      const AHeaders: TNetHeaders = nil): IHTTPResponse;

    function Get(const AURL: string; const AHeaders: TNetHeaders = nil): IHTTPResponse;
    function Delete(const AURL: string; const AHeaders: TNetHeaders = nil): IHTTPResponse;
    function Post(const AURL: string; const ABody: TStream; const AHeaders: TNetHeaders = nil): IHTTPResponse; overload;
    function Put(const AURL: string; const ABody: TStream; const AHeaders: TNetHeaders = nil): IHTTPResponse; overload;
    function Patch(const AURL: string; const ABody: TStream; const AHeaders: TNetHeaders = nil): IHTTPResponse; overload;

    /// <summary>AContent sent as UTF-8 with Content-Type AContentType (e.g. application/json)</summary>
    function Post(const AURL, AContent, AContentType: string; const AHeaders: TNetHeaders = nil): IHTTPResponse; overload;
    function Put(const AURL, AContent, AContentType: string; const AHeaders: TNetHeaders = nil): IHTTPResponse; overload;
    function Patch(const AURL, AContent, AContentType: string; const AHeaders: TNetHeaders = nil): IHTTPResponse; overload;

    property Client: IIAM4DClient read FClient;
    /// <summary>The client used for the requests (TLS, proxy, timeouts)</summary>
    property HTTPClient: THTTPClient read FHTTPClient;
    /// <summary>Retry once after a 401 with a renewed token; default True</summary>
    property RetryOnUnauthorized: Boolean read FRetryOnUnauthorized write FRetryOnUnauthorized;
    /// <summary>Bearer over plain HTTP to a host other than the loopback; default False, tests only</summary>
    property AllowInsecureHTTP: Boolean read FAllowInsecureHTTP write FAllowInsecureHTTP;
  end;

implementation

uses
  IAMClient4D.Exceptions;

const
  HTTP_UNAUTHORIZED = 401;
  HEADER_AUTHORIZATION = 'Authorization';
  HEADER_CONTENT_TYPE = 'Content-Type';

{ TIAM4DAuthorizedHTTPClient }

constructor TIAM4DAuthorizedHTTPClient.Create(const AClient: IIAM4DClient; const AHTTPClient: THTTPClient;
  AOwnsHTTPClient: Boolean);
begin
  inherited Create;
  if not Assigned(AClient) then
  begin
    if Assigned(AHTTPClient) and AOwnsHTTPClient then
      AHTTPClient.Free;
    raise EArgumentNilException.Create('AClient cannot be nil');
  end;
  FClient := AClient;
  FRetryOnUnauthorized := True;
  if Assigned(AHTTPClient) then
  begin
    FHTTPClient := AHTTPClient;
    FOwnsHTTPClient := AOwnsHTTPClient;
  end
  else
  begin
    FHTTPClient := THTTPClient.Create;
    FOwnsHTTPClient := True;
  end;
  // A followed redirect would carry the bearer to the host of the Location
  FHTTPClient.HandleRedirects := False;
end;

destructor TIAM4DAuthorizedHTTPClient.Destroy;
begin
  if FOwnsHTTPClient then
    FHTTPClient.Free;
  FClient := nil;
  inherited;
end;

function TIAM4DAuthorizedHTTPClient.Send(const AMethod, AURL, AToken: string; const ABody: TStream;
  const AHeaders: TNetHeaders): IHTTPResponse;
var
  LRequest: IHTTPRequest;
  LHeaders: TNetHeaders;
begin
  LHeaders := Copy(AHeaders);
  LHeaders := LHeaders + [TNetHeader.Create(HEADER_AUTHORIZATION, 'Bearer ' + AToken)];
  // Before each request: HTTPClient is public and may have been changed since the constructor
  FHTTPClient.HandleRedirects := False;
  LRequest := FHTTPClient.GetRequest(AMethod, AURL);
  LRequest.SourceStream := ABody;
  Result := FHTTPClient.Execute(LRequest, nil, LHeaders);
end;

function TIAM4DAuthorizedHTTPClient.Execute(const AMethod, AURL: string; const ABody: TStream;
  const AHeaders: TNetHeaders): IHTTPResponse;
var
  LHeader: TNetHeader;
  LLowerURL: string;
  LToken: string;
  LStart: Int64;
begin
  LLowerURL := AURL.Trim.ToLower;
  if not (LLowerURL.StartsWith('https://') or LLowerURL.StartsWith('http://')) then
    raise EArgumentException.CreateFmt('Not an HTTP(S) URL: %s', [AURL]);
  if (not FAllowInsecureHTTP) and TIAM4DClientConfig.IsInsecureHTTPURL(AURL) then
    raise EIAM4DInvalidConfigurationException.CreateFmt(
      'The access token is not sent over plain HTTP to %s (AllowInsecureHTTP: tests only)', [AURL]);
  for LHeader in AHeaders do
    if SameText(LHeader.Name, HEADER_AUTHORIZATION) then
      raise EArgumentException.Create('AHeaders cannot contain Authorization: the client sets the bearer');

  LStart := 0;
  if Assigned(ABody) then
    LStart := ABody.Position;

  LToken := FClient.GetAccessToken;
  Result := Send(AMethod, AURL, LToken, ABody, AHeaders);
  if (Result.StatusCode <> HTTP_UNAUTHORIZED) or (not FRetryOnUnauthorized) then
    Exit;

  // Refused before its expiry (revoked, keys rotated, clocks apart): renewed once.
  // Another thread may have renewed it already: then GetAccessToken just returns the new one
  FClient.InvalidateAccessToken(LToken);
  LToken := FClient.GetAccessToken;
  if Assigned(ABody) then
    ABody.Position := LStart;
  Result := Send(AMethod, AURL, LToken, ABody, AHeaders);
end;

function TIAM4DAuthorizedHTTPClient.Get(const AURL: string; const AHeaders: TNetHeaders): IHTTPResponse;
begin
  Result := Execute('GET', AURL, nil, AHeaders);
end;

function TIAM4DAuthorizedHTTPClient.Delete(const AURL: string; const AHeaders: TNetHeaders): IHTTPResponse;
begin
  Result := Execute('DELETE', AURL, nil, AHeaders);
end;

function TIAM4DAuthorizedHTTPClient.Post(const AURL: string; const ABody: TStream;
  const AHeaders: TNetHeaders): IHTTPResponse;
begin
  Result := Execute('POST', AURL, ABody, AHeaders);
end;

function TIAM4DAuthorizedHTTPClient.Put(const AURL: string; const ABody: TStream;
  const AHeaders: TNetHeaders): IHTTPResponse;
begin
  Result := Execute('PUT', AURL, ABody, AHeaders);
end;

function TIAM4DAuthorizedHTTPClient.Patch(const AURL: string; const ABody: TStream;
  const AHeaders: TNetHeaders): IHTTPResponse;
begin
  Result := Execute('PATCH', AURL, ABody, AHeaders);
end;

function WithContentType(const AHeaders: TNetHeaders; const AContentType: string): TNetHeaders;
var
  LHeader: TNetHeader;
begin
  Result := nil;
  for LHeader in AHeaders do
    if not SameText(LHeader.Name, HEADER_CONTENT_TYPE) then
      Result := Result + [LHeader];
  if not AContentType.IsEmpty then
    Result := Result + [TNetHeader.Create(HEADER_CONTENT_TYPE, AContentType)];
end;

function TIAM4DAuthorizedHTTPClient.Post(const AURL, AContent, AContentType: string;
  const AHeaders: TNetHeaders): IHTTPResponse;
var
  LBody: TStringStream;
begin
  LBody := TStringStream.Create(AContent, TEncoding.UTF8, False);
  try
    Result := Execute('POST', AURL, LBody, WithContentType(AHeaders, AContentType));
  finally
    LBody.Free;
  end;
end;

function TIAM4DAuthorizedHTTPClient.Put(const AURL, AContent, AContentType: string;
  const AHeaders: TNetHeaders): IHTTPResponse;
var
  LBody: TStringStream;
begin
  LBody := TStringStream.Create(AContent, TEncoding.UTF8, False);
  try
    Result := Execute('PUT', AURL, LBody, WithContentType(AHeaders, AContentType));
  finally
    LBody.Free;
  end;
end;

function TIAM4DAuthorizedHTTPClient.Patch(const AURL, AContent, AContentType: string;
  const AHeaders: TNetHeaders): IHTTPResponse;
var
  LBody: TStringStream;
begin
  LBody := TStringStream.Create(AContent, TEncoding.UTF8, False);
  try
    Result := Execute('PATCH', AURL, LBody, WithContentType(AHeaders, AContentType));
  finally
    LBody.Free;
  end;
end;

end.
