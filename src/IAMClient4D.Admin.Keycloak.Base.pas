{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Admin.Keycloak.Base.pas
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

  Shared plumbing of the Keycloak Admin REST API clients (users, identity
  providers): admin token, admin URL, authenticated HTTP client and JSON requests.

  ---------------------------------------------------------------------------
}

unit IAMClient4D.Admin.Keycloak.Base;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.SyncObjs,
  System.Generics.Collections,
  System.Net.URLClient,
  System.Net.HttpClient,
  IAMClient4D.Core,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// Authentication provider interface for Keycloak Admin API access.
  /// </summary>
  IKeycloakAuthProvider = interface
    ['{8AFF271E-1A31-42CD-992E-7FCE62325685}']
    /// <summary>
    /// Returns access token for Admin API authentication.
    /// </summary>
    function GetAccessToken: string;
    /// <summary>
    /// Creates configured HTTP client for API calls.
    /// </summary>
    function CreateHTTPClient: THTTPClient;
  end;

  /// <summary>
  /// Auth provider using IAM4D client for token management.
  /// </summary>
  /// <remarks>
  /// Token source: Retrieved from IAM4D client (automatic refresh handling).
  /// Use case: When using OAuth2 client for authentication.
  /// </remarks>
  TClientBasedAuthProvider = class(TInterfacedObject, IKeycloakAuthProvider)
  private
    FClient: IIAM4DClient;
  protected
    /// <summary>
    /// Returns access token from client.
    /// </summary>
    function GetAccessToken: string;
    /// <summary>
    /// Creates HTTP client from client configuration.
    /// </summary>
    function CreateHTTPClient: THTTPClient;
  public
    /// <summary>
    /// Creates provider with IAM4D client.
    /// </summary>
    constructor Create(const AClient: IIAM4DClient);
  end;

  /// <summary>
  /// Auth provider using static access token.
  /// </summary>
  /// <remarks>
  /// Token source: Provided directly (no automatic refresh).
  /// Use case: Service accounts, external token management, testing.
  /// </remarks>
  TTokenBasedAuthProvider = class(TInterfacedObject, IKeycloakAuthProvider)
  private
    FAccessToken: string;
    FHTTPConfig: TIAM4DHTTPClientConfig;
  protected
    /// <summary>
    /// Returns the static access token.
    /// </summary>
    function GetAccessToken: string;
    /// <summary>
    /// Creates HTTP client with configured settings.
    /// </summary>
    function CreateHTTPClient: THTTPClient;
  public
    /// <summary>
    /// Creates provider with access token and HTTP configuration.
    /// </summary>
    constructor Create(const AAccessToken: string; const AHTTPConfig: TIAM4DHTTPClientConfig); overload;

    /// <summary>
    /// Creates provider with access token and default HTTP configuration.
    /// </summary>
    constructor Create(const AAccessToken: string); overload;
  end;

  /// <summary>
  /// Reads one item of a JSON array returned by the Admin API.
  /// </summary>
  TIAM4DJSONObjectReader<T> = reference to function(const AJSON: TJSONObject): T;

  /// <summary>
  /// Base class of the Keycloak Admin REST API clients (/admin/realms/{realm}).
  /// </summary>
  /// <remarks>
  /// Each operation borrows an HTTP client from a pool of the instance and gives it back: the
  /// connections (TLS included) are reused by the next operations, and operations of the async
  /// managers run in parallel on clients of their own. The clients of the pool serve only Admin API
  /// requests: the bearer is set on each one when it is borrowed. Keep one instance for a batch or a
  /// service, rather than one per call, to reuse the connections. The clients are made by the auth
  /// provider when first needed: a new SSL configuration of the IAM client applies to a new instance.
  /// Every request of the user and identity provider managers, SendJSONRequest and the ExecuteJSON*
  /// helpers included, goes through TIAM4DHTTPClientFactory.Execute: the ResponseTimeout of the HTTP
  /// configuration bounds each request as a whole, past it EIAM4DNetworkTimeoutException. Descendants
  /// send their requests the same way (THTTPClient.Get and the like only apply the per-operation
  /// timeouts of the platform).
  /// Failed requests (message with operation, status and response; method and URL where known):
  /// 4xx EIAM4DHTTPClientErrorException (StatusCode, ResponseBody), with the descendants
  /// EIAM4DInsufficientPermissionsException (403), EIAM4DHTTPNotFoundException (404) and
  /// EIAM4DHTTPConflictException (409); 5xx EIAM4DHTTPServerErrorException; any other status
  /// (e.g. a redirect: wrong base URL) EIAM4DInvalidConfigurationException.
  /// </remarks>
  TIAM4DKeycloakAdminBase = class(TInterfacedObject)
  private
    FAuthProvider: IKeycloakAuthProvider;
    FBaseURL: string;
    FRealm: string;
    // Idle HTTP clients, under FHTTPClientLock
    FHTTPClientPool: TStack<THTTPClient>;
    FHTTPClientLock: TCriticalSection;
    function AcquireHTTPClient: THTTPClient;
    procedure ReleaseHTTPClient(AClient: THTTPClient);
  protected
    /// <summary>
    /// {BaseURL}/admin/realms/{Realm}
    /// </summary>
    function GetAdminURL: string;
    function GetAccessToken: string;

    /// <summary>
    /// Sets the bearer of AHTTPClient to the current access token of the auth provider: the batch
    /// operations call it before each item, a long batch outlives the token it started with
    /// (TClientBasedAuthProvider refreshes it; a static token stays the same).
    /// </summary>
    procedure RenewAuthorization(const AHTTPClient: THTTPClient);

    /// <summary>
    /// Percent-encodes one URL path segment (IDs, role names, aliases): a space becomes %20, '+', '/',
    /// '?', '#' and '%' are escaped. Not for query values, where '+' is a space.
    /// An empty segment, '.' or '..' would address another resource (an empty user ID turns
    /// brute-force/users/{id} into the reset of the whole realm, '..' climbs to the parent once the
    /// server or a proxy normalizes the path): they are refused.
    /// </summary>
    /// <exception cref="EIAM4DInvalidConfigurationException">AValue is empty, '.' or '..'</exception>
    class function EncodePathSegment(const AValue: string): string; static;

    /// <summary>
    /// Raises the exception of a failed response (see the class remarks).
    /// </summary>
    class procedure RaiseResponseError(const AResponse: IHTTPResponse; const AMessage: string); static;

    procedure EnsureResponseSuccess(const AResponse: IHTTPResponse; const AContext: string); overload;
    procedure EnsureResponseSuccess(const AResponse: IHTTPResponse; const AContext: string; const AURL: string; const AMethod: string); overload;
    /// <summary>
    /// Last segment of the Location header of a create response (the new entity ID).
    /// </summary>
    function ExtractLocationID(const AResponse: IHTTPResponse): string;

    /// <summary>
    /// Sends AJSON (object or array) with POST, PUT or DELETE; the caller checks the response.
    /// </summary>
    function SendJSONRequest(
      const AHTTPClient: THTTPClient;
      const AURL: string;
      const AMethod: string;
      const AJSON: TJSONValue): IHTTPResponse;

    /// <summary>
    /// Sends AJSON (object or array) with POST, PUT or DELETE and validates the response.
    /// </summary>
    function ExecuteJSONRequest(
      const AHTTPClient: THTTPClient;
      const AURL: string;
      const AMethod: string;
      const AJSON: TJSONValue;
      const AContext: string): IHTTPResponse;

    /// <summary>
    /// POSTs AJSON and returns the ID from the Location header.
    /// </summary>
    function ExecuteJSONRequestWithLocation(
      const AHTTPClient: THTTPClient;
      const AURL: string;
      const AJSON: TJSONObject;
      const AContext: string): string;

    /// <summary>
    /// Same as ExecuteJSONRequest (kept for existing descendants).
    /// </summary>
    function ExecuteJSONArrayRequest(
      const AHTTPClient: THTTPClient;
      const AURL: string;
      const AMethod: string;
      const AJSONArray: TJSONArray;
      const AContext: string): IHTTPResponse;

    /// <summary>
    /// Items of the JSON array AContent read with AReader; elements that are not objects are skipped.
    /// </summary>
    /// <param name="AWhat">Response name for the parse error message.</param>
    class function ParseJSONArray<T>(const AContent, AWhat: string;
      const AReader: TIAM4DJSONObjectReader<T>): TArray<T>; static;

    /// <summary>
    /// Runs AOperation with an HTTP client carrying the admin bearer token, then frees the client.
    /// </summary>
    function ExecuteWithAuth<T>(const AOperation: TFunc<THTTPClient, T>): T;
    procedure ExecuteWithAuthVoid(const AOperation: TProc<THTTPClient>);

    property AuthProvider: IKeycloakAuthProvider read FAuthProvider;
    property BaseURL: string read FBaseURL;
    property Realm: string read FRealm;
  public
    /// <summary>
    /// Creates the client with a custom auth provider.
    /// </summary>
    constructor Create(const AAuthProvider: IKeycloakAuthProvider; const ABaseURL: string; const ARealm: string); overload;

    /// <summary>
    /// Creates the client with an IAM4D client (base URL and realm taken from the issuer if not provided).
    /// </summary>
    constructor Create(const AClient: IIAM4DClient; const ABaseURL: string = ''; const ARealm: string = ''); overload;

    /// <summary>
    /// Creates the client with a static access token and custom HTTP configuration.
    /// </summary>
    constructor Create(const AAccessToken: string; const ABaseURL: string; const ARealm: string; const AHTTPConfig: TIAM4DHTTPClientConfig); overload;

    /// <summary>
    /// Creates the client with a static access token and default HTTP configuration.
    /// </summary>
    constructor Create(const AAccessToken: string; const ABaseURL: string; const ARealm: string); overload;
    destructor Destroy; override;
  end;

implementation

uses
  System.NetConsts,
  System.NetEncoding,
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.JSONUtils,
  IAMClient4D.Admin.Keycloak.Constants;

{ TClientBasedAuthProvider }

constructor TClientBasedAuthProvider.Create(const AClient: IIAM4DClient);
begin
  inherited Create;
  if not Assigned(AClient) then
    raise EIAM4DInvalidConfigurationException.Create('Client cannot be nil');
  FClient := AClient;
end;

function TClientBasedAuthProvider.GetAccessToken: string;
begin
  // Already on the caller's thread (a task for the async methods): no second task to wait for
  Result := FClient.GetAccessToken;
end;

function TClientBasedAuthProvider.CreateHTTPClient: THTTPClient;
begin
  Result := FClient.CreateHTTPClient;
end;

{ TTokenBasedAuthProvider }

constructor TTokenBasedAuthProvider.Create(
  const AAccessToken: string;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
begin
  inherited Create;
  if AAccessToken.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Access token cannot be empty');
  FAccessToken := AAccessToken;
  FHTTPConfig := AHTTPConfig;
end;

constructor TTokenBasedAuthProvider.Create(const AAccessToken: string);
begin
  Create(AAccessToken, TIAM4DHTTPClientConfig.Default);
end;

function TTokenBasedAuthProvider.GetAccessToken: string;
begin
  Result := FAccessToken;
end;

function TTokenBasedAuthProvider.CreateHTTPClient: THTTPClient;
begin
  Result := TIAM4DHTTPClientFactory.CreateHTTPClient(FHTTPConfig);
end;

{ TIAM4DKeycloakAdminBase }

constructor TIAM4DKeycloakAdminBase.Create(
  const AAuthProvider: IKeycloakAuthProvider;
  const ABaseURL: string;
  const ARealm: string);
begin
  inherited Create;
  FHTTPClientLock := TCriticalSection.Create;
  FHTTPClientPool := TStack<THTTPClient>.Create;

  if not Assigned(AAuthProvider) then
    raise EIAM4DInvalidConfigurationException.Create('AuthProvider cannot be nil');

  if ABaseURL.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('BaseURL cannot be empty');

  if ARealm.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Realm cannot be empty');

  FAuthProvider := AAuthProvider;
  FBaseURL := ABaseURL.TrimRight(['/']);
  FRealm := ARealm;
end;

constructor TIAM4DKeycloakAdminBase.Create(
  const AClient: IIAM4DClient;
  const ABaseURL: string;
  const ARealm: string);
var
  LAuthProvider: IKeycloakAuthProvider;
  LBaseURL, LRealm: string;
begin
  if not Assigned(AClient) then
    raise EIAM4DInvalidConfigurationException.Create('Client cannot be nil');

  LBaseURL := ABaseURL;
  LRealm := ARealm;

  // Only the missing values come from the issuer: an explicit base URL or realm is kept
  if LBaseURL.IsEmpty or LRealm.IsEmpty then
  begin
    var LIssuer := AClient.Issuer;
    if LIssuer.IsEmpty then
      raise EIAM4DInvalidConfigurationException.Create('Client not configured. Call Configure first.');

    var LRealmsPos := LIssuer.IndexOf('/realms/');
    if LRealmsPos < 0 then
      raise EIAM4DInvalidConfigurationException.Create('Invalid issuer format. Expected: {baseURL}/realms/{realm}');

    if LBaseURL.IsEmpty then
      LBaseURL := LIssuer.Substring(0, LRealmsPos);
    // The issuer has the realm percent-encoded: GetAdminURL encodes it again
    if LRealm.IsEmpty then
      // Percent-decoding only: a '+' stays a plus
      LRealm := TNetEncoding.URL.URLDecode(LIssuer.Substring(LRealmsPos + 8).TrimRight(['/']));
  end;

  LAuthProvider := TClientBasedAuthProvider.Create(AClient);

  Create(LAuthProvider, LBaseURL, LRealm);
end;

constructor TIAM4DKeycloakAdminBase.Create(
  const AAccessToken: string;
  const ABaseURL: string;
  const ARealm: string;
  const AHTTPConfig: TIAM4DHTTPClientConfig);
var
  LAuthProvider: IKeycloakAuthProvider;
begin
  LAuthProvider := TTokenBasedAuthProvider.Create(AAccessToken, AHTTPConfig);
  Create(LAuthProvider, ABaseURL, ARealm);
end;

constructor TIAM4DKeycloakAdminBase.Create(
  const AAccessToken: string;
  const ABaseURL: string;
  const ARealm: string);
var
  LAuthProvider: IKeycloakAuthProvider;
begin
  LAuthProvider := TTokenBasedAuthProvider.Create(AAccessToken);
  Create(LAuthProvider, ABaseURL, ARealm);
end;

function TIAM4DKeycloakAdminBase.GetAdminURL: string;
begin
  // A path segment: a realm name with spaces or reserved characters stays inside it
  Result := FBaseURL + '/admin/realms/' + EncodePathSegment(FRealm);
end;

function TIAM4DKeycloakAdminBase.GetAccessToken: string;
begin
  Result := FAuthProvider.GetAccessToken;
end;

procedure TIAM4DKeycloakAdminBase.RenewAuthorization(const AHTTPClient: THTTPClient);
begin
  AHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + GetAccessToken;
end;

class function TIAM4DKeycloakAdminBase.EncodePathSegment(const AValue: string): string;
begin
  // '.' is unreserved: encoding it does not help, servers decode %2E before normalizing
  if AValue.IsEmpty or (AValue = '.') or (AValue = '..') then
    raise EIAM4DInvalidConfigurationException.Create(Format('Invalid URL path segment: "%s"', [AValue]));
  // TNetEncoding.URL.Encode writes a space as '+' (form encoding) and a literal '+' as %2B:
  // in a path '+' is a plus, so every '+' left is a space
  Result := TNetEncoding.URL.Encode(AValue).Replace('+', '%20');
end;

class procedure TIAM4DKeycloakAdminBase.RaiseResponseError(const AResponse: IHTTPResponse; const AMessage: string);
var
  LStatusCode, LRetryAfter: Integer;
  LClass: EIAM4DHTTPClientErrorExceptionClass;
begin
  LStatusCode := AResponse.StatusCode;

  if (LStatusCode >= 500) and (LStatusCode <= 599) then
  begin
    // Delay-seconds form only (an HTTP date gives 0)
    if not TryStrToInt(AResponse.HeaderValue['Retry-After'].Trim, LRetryAfter) or (LRetryAfter < 0) then
      LRetryAfter := 0;
    raise EIAM4DHTTPServerErrorException.CreateFromResponse(LStatusCode, AResponse.ContentAsString, AMessage,
      LRetryAfter);
  end;

  if (LStatusCode >= 400) and (LStatusCode <= 499) then
  begin
    case LStatusCode of
      403: LClass := EIAM4DInsufficientPermissionsException;
      404: LClass := EIAM4DHTTPNotFoundException;
      409: LClass := EIAM4DHTTPConflictException;
    else
      LClass := EIAM4DHTTPClientErrorException;
    end;
    raise LClass.CreateFromResponse(LStatusCode, AResponse.ContentAsString, AMessage);
  end;

  // Neither success nor error (e.g. a redirect): the base URL does not point to the Admin API
  raise EIAM4DInvalidConfigurationException.Create(AMessage);
end;

procedure TIAM4DKeycloakAdminBase.EnsureResponseSuccess(
  const AResponse: IHTTPResponse;
  const AContext: string);
var
  LErrorMsg: string;
begin
  if AResponse.StatusCode in [IAM4D_HTTP_STATUS_OK, IAM4D_HTTP_STATUS_CREATED, IAM4D_HTTP_STATUS_NO_CONTENT] then
    Exit;

  // The whole body stays in ResponseBody; the message gets a preview
  if AResponse.ContentAsString.Trim.IsEmpty then
    LErrorMsg := AResponse.StatusText
  else if AResponse.ContentAsString.Length > IAM4D_MAX_ERROR_PREVIEW_LENGTH then
    LErrorMsg := AResponse.ContentAsString.Substring(0, IAM4D_MAX_ERROR_PREVIEW_LENGTH) + '...'
  else
    LErrorMsg := AResponse.ContentAsString;

  RaiseResponseError(AResponse, Format('%s failed: %d - %s', [AContext, AResponse.StatusCode, LErrorMsg]));
end;

procedure TIAM4DKeycloakAdminBase.EnsureResponseSuccess(
  const AResponse: IHTTPResponse;
  const AContext: string;
  const AURL: string;
  const AMethod: string);
var
  LErrorMsg: string;
  LResponsePreview: string;
  LURL: string;
begin
  if AResponse.StatusCode in [IAM4D_HTTP_STATUS_OK, IAM4D_HTTP_STATUS_CREATED, IAM4D_HTTP_STATUS_NO_CONTENT] then
    Exit;

  if not AResponse.ContentAsString.Trim.IsEmpty then
  begin
    if AResponse.ContentAsString.Length > IAM4D_MAX_ERROR_PREVIEW_LENGTH then
      LResponsePreview := AResponse.ContentAsString.Substring(0, IAM4D_MAX_ERROR_PREVIEW_LENGTH) + '...'
    else
      LResponsePreview := AResponse.ContentAsString;
  end
  else
    LResponsePreview := AResponse.StatusText;

  // Without the query: searches carry username and email there
  LURL := AURL;
  if LURL.IndexOf('?') >= 0 then
    LURL := LURL.Substring(0, LURL.IndexOf('?'));

  LErrorMsg := Format(
    '%s failed'#13#10 +
    'Request: %s %s'#13#10 +
    'Status: %d %s'#13#10 +
    'Response: %s',
    [AContext, AMethod, LURL, AResponse.StatusCode, AResponse.StatusText, LResponsePreview]);

  RaiseResponseError(AResponse, LErrorMsg);
end;

function TIAM4DKeycloakAdminBase.ExtractLocationID(const AResponse: IHTTPResponse): string;
var
  LLocation: string;
  LLastSlashPos: Integer;
begin
  LLocation := AResponse.HeaderValue['Location'];
  if LLocation.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Location header missing from create response');

  LLastSlashPos := LLocation.LastIndexOf('/');
  if LLastSlashPos < 0 then
    raise EIAM4DInvalidConfigurationException.Create('Invalid Location header format');

  Result := LLocation.Substring(LLastSlashPos + 1);
end;

function TIAM4DKeycloakAdminBase.SendJSONRequest(
  const AHTTPClient: THTTPClient;
  const AURL: string;
  const AMethod: string;
  const AJSON: TJSONValue): IHTTPResponse;
var
  LContent: TStringStream;
begin
  if not (SameText(AMethod, IAM4D_HTTP_METHOD_POST) or SameText(AMethod, IAM4D_HTTP_METHOD_PUT) or
    SameText(AMethod, IAM4D_HTTP_METHOD_DELETE)) then
    raise EIAM4DInvalidConfigurationException.Create(Format('Unsupported HTTP method: %s', [AMethod]));

  AHTTPClient.ContentType := IAM4D_CONTENT_TYPE_JSON;

  LContent := TStringStream.Create(AJSON.ToString, TEncoding.UTF8);
  try
    // Bounded by the ResponseTimeout of the client, as a whole
    Result := TIAM4DHTTPClientFactory.Execute(AHTTPClient, AMethod.ToUpper, AURL, LContent);
  finally
    LContent.Free;
  end;
end;

function TIAM4DKeycloakAdminBase.ExecuteJSONRequest(
  const AHTTPClient: THTTPClient;
  const AURL: string;
  const AMethod: string;
  const AJSON: TJSONValue;
  const AContext: string): IHTTPResponse;
begin
  Result := SendJSONRequest(AHTTPClient, AURL, AMethod, AJSON);
  EnsureResponseSuccess(Result, AContext, AURL, AMethod);
end;

function TIAM4DKeycloakAdminBase.ExecuteJSONRequestWithLocation(
  const AHTTPClient: THTTPClient;
  const AURL: string;
  const AJSON: TJSONObject;
  const AContext: string): string;
var
  LResponse: IHTTPResponse;
begin
  LResponse := ExecuteJSONRequest(AHTTPClient, AURL, IAM4D_HTTP_METHOD_POST, AJSON, AContext);
  Result := ExtractLocationID(LResponse);
end;

function TIAM4DKeycloakAdminBase.ExecuteJSONArrayRequest(
  const AHTTPClient: THTTPClient;
  const AURL: string;
  const AMethod: string;
  const AJSONArray: TJSONArray;
  const AContext: string): IHTTPResponse;
begin
  Result := ExecuteJSONRequest(AHTTPClient, AURL, AMethod, AJSONArray, AContext);
end;

class function TIAM4DKeycloakAdminBase.ParseJSONArray<T>(const AContent, AWhat: string;
  const AReader: TIAM4DJSONObjectReader<T>): TArray<T>;
var
  LJSONArray: TJSONArray;
  LIndex, LCount: Integer;
begin
  LJSONArray := TIAM4DJSONUtils.SafeParseJSONArray(AContent, AWhat);
  try
    SetLength(Result, LJSONArray.Count);
    LCount := 0;
    for LIndex := 0 to LJSONArray.Count - 1 do
      if LJSONArray.Items[LIndex] is TJSONObject then
      begin
        Result[LCount] := AReader(TJSONObject(LJSONArray.Items[LIndex]));
        Inc(LCount);
      end;
    SetLength(Result, LCount);
  finally
    LJSONArray.Free;
  end;
end;

const
  // Idle clients kept for reuse; more concurrent operations create extra clients, freed afterwards
  IAM4D_ADMIN_HTTP_CLIENT_POOL_SIZE = 4;

destructor TIAM4DKeycloakAdminBase.Destroy;
begin
  if Assigned(FHTTPClientPool) then
    while FHTTPClientPool.Count > 0 do
      FHTTPClientPool.Pop.Free;
  FHTTPClientPool.Free;
  FHTTPClientLock.Free;
  inherited;
end;

function TIAM4DKeycloakAdminBase.AcquireHTTPClient: THTTPClient;
begin
  Result := nil;
  FHTTPClientLock.Acquire;
  try
    if FHTTPClientPool.Count > 0 then
      Result := FHTTPClientPool.Pop;
  finally
    FHTTPClientLock.Release;
  end;
  if Result = nil then
  begin
    // Outside the lock: the provider may do I/O (e.g. load certificates)
    Result := FAuthProvider.CreateHTTPClient;
    // The bearer goes with every request of the client: a redirect would send it to the target
    // host (http included) and turn PUT/DELETE into GET on 303. A 3xx raises instead
    Result.HandleRedirects := False;
  end;
end;

procedure TIAM4DKeycloakAdminBase.ReleaseHTTPClient(AClient: THTTPClient);
begin
  // No bearer left on an idle client: the next operation sets its own
  AClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := '';
  FHTTPClientLock.Acquire;
  try
    if FHTTPClientPool.Count < IAM4D_ADMIN_HTTP_CLIENT_POOL_SIZE then
    begin
      FHTTPClientPool.Push(AClient);
      AClient := nil;
    end;
  finally
    FHTTPClientLock.Release;
  end;
  AClient.Free;
end;

function TIAM4DKeycloakAdminBase.ExecuteWithAuth<T>(const AOperation: TFunc<THTTPClient, T>): T;
var
  LToken: string;
  LHTTPClient: THTTPClient;
begin
  LToken := GetAccessToken;
  LHTTPClient := AcquireHTTPClient;
  try
    LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;
    Result := AOperation(LHTTPClient);
  finally
    ReleaseHTTPClient(LHTTPClient);
  end;
end;

procedure TIAM4DKeycloakAdminBase.ExecuteWithAuthVoid(const AOperation: TProc<THTTPClient>);
var
  LToken: string;
  LHTTPClient: THTTPClient;
begin
  LToken := GetAccessToken;
  LHTTPClient := AcquireHTTPClient;
  try
    LHTTPClient.CustomHeaders[IAM4D_HTTP_HEADER_AUTHORIZATION] := IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER + LToken;
    AOperation(LHTTPClient);
  finally
    ReleaseHTTPClient(LHTTPClient);
  end;
end;

end.
