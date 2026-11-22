program IAM4DHTTPTimeoutTest;

{ Runtime test of the HTTP timeouts of IAMClient4D.

  A slow HTTP server (Indy TIdTCPServer on 127.0.0.1, free port) delays the response headers,
  trickles or stalls the body, or does not read the request body, as the first path segment says.
  Every request of the library must end within the ResponseTimeout of its configuration with
  EIAM4DNetworkTimeoutException, without being retried; responses within the time stay as before.

  Usage : IAM4DHTTPTimeoutTest
          IAM4D_TEST_LEAK=1 leaks one object on purpose (the leak report must appear on stderr).
          Builds for Win32, Win64 and Linux64.
  Exit  : number of failed checks (0 = all passed, 98 = a test hung, 99 = startup error). }

{$APPTYPE CONSOLE}

uses
  {$IFDEF MSWINDOWS}
  Winapi.Windows,
  {$ELSE}
  Posix.Unistd,
  {$ENDIF}
  System.SysUtils,
  System.StrUtils,
  System.Classes,
  System.SyncObjs,
  System.JSON,
  System.Diagnostics,
  System.Generics.Collections,
  System.Net.URLClient,
  System.Net.HttpClient,
  IdContext,
  IdIOHandler,
  IdTCPServer,
  IdGlobal,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.Common.Security,
  IAMClient4D.Exceptions,
  IAMClient4D.Config.Builder,
  IAMClient4D.Keycloak,
  IAMClient4D.Admin.Keycloak.Base,
  IAMClient4D.UserManagement.Core,
  IAMClient4D.UserManagement.Helpers,
  IAMClient4D.UserManagement.Keycloak,
  IAMClient4D.UserManagement.Keycloak.Async,
  IAMClient4D.IdentityProvider.Core,
  IAMClient4D.IdentityProvider.Keycloak,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.JWT.JWKS;

const
  REALM = 'test';
  CLIENT_ID = 'iam4d-timeout';
  CLIENT_SECRET = 'secret';
  // Timeout of the library under test and delays of the slow server: wide margins, the machine may be busy
  TIMEOUT_MS = 1000;
  SLOW_MODE = 'hdr6000';
  // A request cut at TIMEOUT_MS must end within this time
  LIMIT_MS = 2500;
  // Trailing bytes of a trickled body, one per interval of the mode (drip200: 30 x 200 ms = 6 s)
  DRIP_BYTES = 30;
  // A test running longer is reported as hung (exit code 98)
  TEST_DEADLINE_MS = 90000;

type
  TRecordedRequest = record
    Method: string;
    Path: string;
    ContentType: string;
    Body: string;
  end;

  /// <summary>
  /// HTTP server whose first path segment chooses the timing: ok, hdr&lt;ms&gt; (headers after ms),
  /// drip&lt;ms&gt; (the last DRIP_BYTES bytes of the body one every ms), stall&lt;ms&gt; (body ms after
  /// the headers), noread&lt;ms&gt; (request body not read, answer after ms), dyn (the mode in DynamicMode).
  /// </summary>
  TSlowServer = class
  private
    FServer: TIdTCPServer;
    FLock: TCriticalSection;
    FStop: TEvent;
    FPort: Word;
    FRequests: TList<TRecordedRequest>;
    FDynamicMode: string;
    FTokenExpiresIn: Integer;
    FTokenSeq: Integer;
    procedure DoExecute(AContext: TIdContext);
    procedure Serve(AIO: TIdIOHandler);
    function Pause(AMs: Integer): Boolean;
    function ResponseBody(const AMethod, AMode, APath: string; out AStatus: Integer;
      out AExtraHeaders: string): string;
    procedure SetDynamicMode(const AValue: string);
    procedure SetTokenExpiresIn(AValue: Integer);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    function URL(const AMode: string; const APath: string = ''): string;
    /// <summary>Requests received whose path contains APathPart</summary>
    function RequestCount(const APathPart: string): Integer;
    function LastRequest: TRecordedRequest;
    property DynamicMode: string write SetDynamicMode;
    property TokenExpiresIn: Integer write SetTokenExpiresIn;
  end;

  /// <summary>How a measured call ended.</summary>
  TOutcome = record
    ElapsedMs: Int64;
    ErrorClass: string;
    ErrorMessage: string;
    ErrorCode: TIAM4DErrorCode;
    TimeoutMs: Integer;
    Endpoint: string;
    function Describe: string;
  end;

var
  GPassed: Integer = 0;
  GFailed: Integer = 0;
  GServer: TSlowServer;
  GLeak: TObject;
  // Watchdog: tick count by which the running test must end (0: none)
  GDeadline: UInt64 = 0;
  GCurrentTest: string;
  GWatchdog: TThread;
  GWatchdogStop: TEvent;

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

procedure Check(const AName: string; ACondition: Boolean; const ADetail: string = '');
begin
  if ACondition then
  begin
    Inc(GPassed);
    Writeln('  PASS  ', AName);
  end
  else
  begin
    Inc(GFailed);
    if ADetail = '' then
      Writeln('  FAIL  ', AName)
    else
      Writeln('  FAIL  ', AName, ' (', ADetail, ')');
  end;
  // A hang shows the last check even when the output is redirected
  Flush(Output);
end;

procedure CheckEquals(const AName, AExpected, AActual: string);
begin
  Check(AName, AExpected = AActual, Format('expected "%s", got "%s"', [AExpected, AActual]));
end;

function TOutcome.Describe: string;
begin
  if ErrorClass = '' then
    Result := Format('no error after %d ms', [ElapsedMs])
  else
    Result := Format('%s after %d ms: %s', [ErrorClass, ElapsedMs, ErrorMessage]);
end;

function Measure(const AProc: TProc): TOutcome;
var
  LWatch: TStopwatch;
begin
  Result := Default(TOutcome);
  LWatch := TStopwatch.StartNew;
  try
    AProc();
  except
    on E: Exception do
    begin
      Result.ErrorClass := E.ClassName;
      Result.ErrorMessage := E.Message.Replace(#13, ' ').Replace(#10, ' ');
      if E is EIAM4DException then
        Result.ErrorCode := EIAM4DException(E).ErrorCode;
      if E is EIAM4DNetworkTimeoutException then
      begin
        Result.TimeoutMs := EIAM4DNetworkTimeoutException(E).TimeoutMs;
        Result.Endpoint := EIAM4DNetworkTimeoutException(E).Endpoint;
      end;
    end;
  end;
  Result.ElapsedMs := LWatch.ElapsedMilliseconds;
end;

function PathOf(const AURL: string): string;
begin
  // http://127.0.0.1:port/... -> /...
  Result := AURL.Substring(AURL.IndexOf('/', Length('http://')));
end;

procedure CheckInTime(const AName: string; const AOutcome: TOutcome);
begin
  Check(Format('%s: ends within %d ms (%d ms)', [AName, LIMIT_MS, AOutcome.ElapsedMs]),
    AOutcome.ElapsedMs <= LIMIT_MS, AOutcome.Describe);
end;

procedure CheckSentOnce(const AName, AURL: string);
var
  LCount: Integer;
begin
  LCount := GServer.RequestCount(PathOf(AURL));
  Check(AName + ': not retried', LCount = 1, Format('%d requests', [LCount]));
end;

/// <summary>AURL without query and fragment, as EIAM4DNetworkTimeoutException reports it</summary>
function WithoutQuery(const AURL: string): string;
begin
  Result := AURL;
  if Result.IndexOfAny(['?', '#']) >= 0 then
    Result := Result.Substring(0, Result.IndexOfAny(['?', '#']));
end;

/// <summary>AOutcome is the deadline of a request to AURL: timeout exception, in time, sent once.</summary>
procedure CheckTimedOut(const AName, AURL: string; const AOutcome: TOutcome);
begin
  Check(AName + ': EIAM4DNetworkTimeoutException', AOutcome.ErrorClass = 'EIAM4DNetworkTimeoutException',
    AOutcome.Describe);
  CheckInTime(AName, AOutcome);
  if AOutcome.ErrorClass = 'EIAM4DNetworkTimeoutException' then
    Check(AName + ': TimeoutMs, Endpoint and ErrorCode',
      // Endpoint without the query: it may carry values that do not belong in a log
      (AOutcome.TimeoutMs = TIMEOUT_MS) and (AOutcome.Endpoint = WithoutQuery(AURL)) and
      (AOutcome.ErrorCode = ecNetworkTimeout) and not AOutcome.Endpoint.Contains('?'),
      Format('%d, %s, %d', [AOutcome.TimeoutMs, AOutcome.Endpoint, Ord(AOutcome.ErrorCode)]));
  CheckSentOnce(AName, AURL);
end;

/// <summary>The JWKS provider reports the timeout of a request to AURL as keys unavailable.</summary>
procedure CheckJWKSUnavailable(const AName, AURL: string; const AOutcome: TOutcome);
begin
  Check(AName + ': EIAM4DJWKSUnavailableException', AOutcome.ErrorClass = 'EIAM4DJWKSUnavailableException',
    AOutcome.Describe);
  CheckInTime(AName, AOutcome);
  Check(AName + ': caused by the timeout',
    AOutcome.ErrorMessage.Contains(Format('Network timeout after %d ms calling %s', [TIMEOUT_MS, AURL])),
    AOutcome.ErrorMessage);
  CheckSentOnce(AName, AURL);
end;

procedure CheckNoError(const AName: string; const AOutcome: TOutcome);
begin
  Check(AName, AOutcome.ErrorClass = '', AOutcome.Describe);
end;

/// <summary>AOutcome is a connection to 127.0.0.1 that failed: the library exception, not THTTPClient's.</summary>
procedure CheckUnreachable(const AName: string; const AOutcome: TOutcome);
begin
  Check(AName + ': EIAM4DNetworkUnreachableException', AOutcome.ErrorClass = 'EIAM4DNetworkUnreachableException',
    AOutcome.Describe);
  Check(AName + ': ecNetworkUnreachable, host in the message',
    (AOutcome.ErrorCode = ecNetworkUnreachable) and AOutcome.ErrorMessage.Contains('127.0.0.1'), AOutcome.Describe);
end;

/// <summary>Checks the timeouts of AClient, then frees it.</summary>
procedure CheckClientTimeouts(const AName: string; AClient: THTTPClient; AConnectionMs, AResponseMs: Integer);
begin
  try
    Check(Format('%s: ConnectionTimeout %d', [AName, AConnectionMs]), AClient.ConnectionTimeout = AConnectionMs,
      IntToStr(AClient.ConnectionTimeout));
    Check(Format('%s: ResponseTimeout %d', [AName, AResponseMs]), AClient.ResponseTimeout = AResponseMs,
      IntToStr(AClient.ResponseTimeout));
    Check(Format('%s: SendTimeout %d', [AName, AResponseMs]), AClient.SendTimeout = AResponseMs,
      IntToStr(AClient.SendTimeout));
  finally
    AClient.Free;
  end;
end;

// ---------------------------------------------------------------------------
// TSlowServer
// ---------------------------------------------------------------------------

constructor TSlowServer.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FStop := TEvent.Create(nil, True, False, '');
  FRequests := TList<TRecordedRequest>.Create;
  FDynamicMode := 'ok';
  FTokenExpiresIn := 300;
  FServer := TIdTCPServer.Create(nil);
  with FServer.Bindings.Add do
  begin
    IP := '127.0.0.1';
    // Free port chosen by the system
    Port := 0;
  end;
  FServer.OnExecute := DoExecute;
  FServer.Active := True;
  FPort := FServer.Bindings[0].Port;
end;

destructor TSlowServer.Destroy;
begin
  // Wakes the connections still waiting: they end without answering
  FStop.SetEvent;
  if Assigned(FServer) then
    FServer.Active := False;
  FServer.Free;
  FRequests.Free;
  FStop.Free;
  FLock.Free;
  inherited;
end;

procedure TSlowServer.Reset;
begin
  FLock.Acquire;
  try
    FRequests.Clear;
    FDynamicMode := 'ok';
    FTokenExpiresIn := 300;
  finally
    FLock.Release;
  end;
end;

procedure TSlowServer.SetDynamicMode(const AValue: string);
begin
  FLock.Acquire;
  try
    FDynamicMode := AValue;
  finally
    FLock.Release;
  end;
end;

procedure TSlowServer.SetTokenExpiresIn(AValue: Integer);
begin
  FLock.Acquire;
  try
    FTokenExpiresIn := AValue;
  finally
    FLock.Release;
  end;
end;

function TSlowServer.URL(const AMode, APath: string): string;
begin
  Result := Format('http://127.0.0.1:%d/%s%s', [FPort, AMode, APath]);
end;

function TSlowServer.RequestCount(const APathPart: string): Integer;
var
  LRequest: TRecordedRequest;
begin
  Result := 0;
  FLock.Acquire;
  try
    for LRequest in FRequests do
      if LRequest.Path.Contains(APathPart) then
        Inc(Result);
  finally
    FLock.Release;
  end;
end;

function TSlowServer.LastRequest: TRecordedRequest;
begin
  FLock.Acquire;
  try
    if FRequests.Count = 0 then
      Result := Default(TRecordedRequest)
    else
      Result := FRequests.Last;
  finally
    FLock.Release;
  end;
end;

function TSlowServer.Pause(AMs: Integer): Boolean;
begin
  // False: the server is stopping
  Result := FStop.WaitFor(AMs) = wrTimeout;
end;

function TSlowServer.ResponseBody(const AMethod, AMode, APath: string; out AStatus: Integer;
  out AExtraHeaders: string): string;
const
  DISCOVERY = '/.well-known/openid-configuration';
var
  LRealmPath, LPath: string;
begin
  AStatus := 200;
  AExtraHeaders := '';
  // Without the query
  LPath := APath;
  if LPath.Contains('?') then
    LPath := LPath.Substring(0, LPath.IndexOf('?'));
  if SameText(AMethod, 'GET') and LPath.Contains('/admin/realms/') and
    (LPath.EndsWith('/users/user-2') or (LPath.EndsWith('/users') and APath.Contains('username=anna'))) then
  begin
    // Required actions not in TIAM4DRequiredAction (Keycloak 24+ VERIFY_PROFILE, a custom one)
    Result := '{"id":"user-2","username":"anna","enabled":true,' +
      '"requiredActions":["UPDATE_PASSWORD","VERIFY_PROFILE","custom-action"]}';
    if LPath.EndsWith('/users') then
      Result := '[' + Result + ']';
  end
  else if SameText(AMethod, 'GET') and LPath.Contains('/admin/realms/') and LPath.EndsWith('/users') then
    Result := '[{"id":"user-1","username":"mario","enabled":true}]'
  else if SameText(AMethod, 'GET') and LPath.EndsWith('/identity-provider/instances') then
    Result := '[]'
  else if SameText(AMethod, 'POST') and LPath.EndsWith('/identity-provider/instances') then
  begin
    AStatus := 201;
    Result := '';
  end
  else if APath.EndsWith(DISCOVERY) then
  begin
    LRealmPath := APath.Substring(0, APath.Length - Length(DISCOVERY));
    Result := Format(
      '{"issuer":"%s","authorization_endpoint":"%s","token_endpoint":"%s","userinfo_endpoint":"%s",' +
      '"end_session_endpoint":"%s","jwks_uri":"%s"}',
      [URL(AMode, LRealmPath), URL('ok', LRealmPath + '/auth'), URL('dyn', LRealmPath + '/token'),
       URL('ok', LRealmPath + '/userinfo'), URL('ok', LRealmPath + '/logout'), URL('ok', LRealmPath + '/jwks')]);
  end
  else if APath.EndsWith('/token') then
  begin
    FLock.Acquire;
    try
      Inc(FTokenSeq);
      Result := Format('{"access_token":"at-%d","token_type":"Bearer","expires_in":%d}',
        [FTokenSeq, FTokenExpiresIn]);
    finally
      FLock.Release;
    end;
  end
  else if APath.EndsWith('/jwks') then
    Result := '{"keys":[]}'
  else if SameText(AMethod, 'POST') and APath.Contains('/admin/realms/') and APath.EndsWith('/users') then
  begin
    AStatus := 201;
    AExtraHeaders := 'Location: ' + URL(AMode, APath + '/new-user-id') + #13#10;
    Result := '';
  end
  else
    Result := '{"ok":true}';
end;

procedure TSlowServer.Serve(AIO: TIdIOHandler);
var
  LLine, LMethod, LPath, LMode, LRest, LContentType, LBody, LExtraHeaders, LHead, LTail: string;
  LParts: TArray<string>;
  LLength, LStatus, LSlash, I: Integer;
  LRecorded: TRecordedRequest;
begin
  LParts := AIO.ReadLn.Split([' ']);
  if Length(LParts) < 2 then
    Exit;
  LMethod := LParts[0];
  LPath := LParts[1];
  LLength := 0;
  LContentType := '';
  repeat
    LLine := AIO.ReadLn;
    if LLine.StartsWith('Content-Length:', True) then
      LLength := StrToIntDef(LLine.Substring(Length('Content-Length:')).Trim, 0)
    else if LLine.StartsWith('Content-Type:', True) then
      LContentType := LLine.Substring(Length('Content-Type:')).Trim;
  until LLine = '';

  // /<mode><rest>
  LSlash := LPath.IndexOf('/', 1);
  if LSlash < 0 then
    LSlash := LPath.Length;
  LMode := LPath.Substring(1, LSlash - 1);
  LRest := LPath.Substring(LSlash);
  if LMode = 'dyn' then
  begin
    FLock.Acquire;
    try
      LMode := FDynamicMode;
    finally
      FLock.Release;
    end;
  end;

  LBody := '';
  if (LLength > 0) and not LMode.StartsWith('noread') then
    LBody := AIO.ReadString(LLength, IndyTextEncoding_UTF8);

  LRecorded.Method := LMethod;
  LRecorded.Path := LPath;
  LRecorded.ContentType := LContentType;
  LRecorded.Body := LBody.Substring(0, 4096);
  FLock.Acquire;
  try
    FRequests.Add(LRecorded);
  finally
    FLock.Release;
  end;

  LBody := ResponseBody(LMethod, LMode, LRest, LStatus, LExtraHeaders);
  // status<code>: that HTTP status, at once
  if LMode.StartsWith('status') then
    LStatus := StrToInt(LMode.Substring(6));
  // Trailing JSON whitespace: the trickled body stays valid
  if LMode.StartsWith('drip') then
    LBody := LBody + StringOfChar(' ', DRIP_BYTES);
  LHead := Format('HTTP/1.1 %d %s'#13#10'Content-Type: application/json'#13#10'Content-Length: %d'#13#10 +
    'Connection: close'#13#10'%s'#13#10,
    [LStatus, IfThen(LStatus = 201, 'Created', 'OK'), TEncoding.UTF8.GetByteCount(LBody), LExtraHeaders]);

  if LMode.StartsWith('hdr') then
  begin
    if Pause(StrToInt(LMode.Substring(3))) then
      AIO.Write(LHead + LBody, IndyTextEncoding_UTF8);
  end
  else if LMode.StartsWith('noread') then
  begin
    if Pause(StrToInt(LMode.Substring(6))) then
      AIO.Write(LHead + LBody, IndyTextEncoding_UTF8);
  end
  else if LMode.StartsWith('stall') then
  begin
    AIO.Write(LHead, IndyTextEncoding_UTF8);
    if Pause(StrToInt(LMode.Substring(5))) then
      AIO.Write(LBody, IndyTextEncoding_UTF8);
  end
  else if LMode.StartsWith('drip') then
  begin
    LTail := LBody.Substring(LBody.Length - DRIP_BYTES);
    AIO.Write(LHead + LBody.Substring(0, LBody.Length - DRIP_BYTES), IndyTextEncoding_UTF8);
    for I := 0 to LTail.Length - 1 do
    begin
      if not Pause(StrToInt(LMode.Substring(4))) then
        Exit;
      AIO.Write(LTail.Substring(I, 1), IndyTextEncoding_UTF8);
    end;
  end
  else
    AIO.Write(LHead + LBody, IndyTextEncoding_UTF8);
end;

procedure TSlowServer.DoExecute(AContext: TIdContext);
begin
  try
    Serve(AContext.Connection.IOHandler);
  except
    // The client gave up (timeout): its connection is closed
  end;
  AContext.Connection.Disconnect;
end;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function HTTPConfig(AResponseMs: Integer = TIMEOUT_MS): TIAM4DHTTPClientConfig;
begin
  Result := TIAM4DHTTPClientConfig.Create(TIMEOUT_MS, AResponseMs, svmStrict);
end;

function ClientCredentialsConfig(const ABaseURL: string; AResponseMs: Integer): TIAM4DClientConfig;
begin
  Result := TIAM4DClientConfig.CreateForClientCredentials(ABaseURL, REALM, CLIENT_ID, CLIENT_SECRET, nil,
    svmStrict, TIMEOUT_MS, AResponseMs);
end;

function BuildClientCredentials(const ABaseURL: string; AResponseMs: Integer;
  ATokenExpiryBufferSeconds: Integer = 120): IIAM4DClient;
begin
  Result := TIAM4DClientConfigBuilder.New
    .ForClientCredentials(ABaseURL, REALM, CLIENT_ID, CLIENT_SECRET)
    .WithTokenExpiryBuffer(ATokenExpiryBufferSeconds)
    .WithTimeouts(TIMEOUT_MS, AResponseMs)
    .Build;
end;

function TokenURL: string;
begin
  // token_endpoint of the discovery document: timing chosen by DynamicMode
  Result := GServer.URL('dyn', '/realms/' + REALM + '/token');
end;

function DiscoveryURL(const AMode: string): string;
begin
  Result := GServer.URL(AMode, '/realms/' + REALM + '/.well-known/openid-configuration');
end;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

procedure TestClientConfiguration;
var
  LProvider: IKeycloakAuthProvider;
begin
  CheckClientTimeouts('factory, HTTP configuration',
    TIAM4DHTTPClientFactory.CreateHTTPClient(TIAM4DHTTPClientConfig.Create(1234, 5678)), 1234, 5678);
  CheckClientTimeouts('factory, client configuration',
    TIAM4DHTTPClientFactory.CreateHTTPClient(TIAM4DClientConfig.CreateForClientCredentials('http://127.0.0.1:1',
      REALM, CLIENT_ID, CLIENT_SECRET, nil, svmStrict, 2345, 6789)), 2345, 6789);
  CheckClientTimeouts('factory, default configuration', TIAM4DHTTPClientFactory.CreateHTTPClient, 30000, 60000);
  LProvider := TTokenBasedAuthProvider.Create('token', TIAM4DHTTPClientConfig.Create(1234, 5678));
  CheckClientTimeouts('Admin API, static token', LProvider.CreateHTTPClient, 1234, 5678);
  LProvider := TTokenBasedAuthProvider.Create('token');
  CheckClientTimeouts('Admin API, static token, default configuration', LProvider.CreateHTTPClient, 30000, 60000);
end;

procedure TestBuilderTimeouts;
var
  LBuilder: IIAM4DClientConfigBuilder;
  LClient: IIAM4DClient;
  LProvider: IKeycloakAuthProvider;
begin
  GServer.Reset;
  LBuilder := TIAM4DClientConfigBuilder.New
    .ForClientCredentials(GServer.URL('ok'), REALM, CLIENT_ID, CLIENT_SECRET)
    .WithTokenExpiryBuffer(7)
    .WithTimeouts(1234, 5678)
    .WithScopes(['scope-a'])
    .WithStrictSSL;
  Check('WithTimeouts: configuration 1234/5678',
    (LBuilder.Config.ConnectionTimeout = 1234) and (LBuilder.Config.ResponseTimeout = 5678),
    Format('%d/%d', [LBuilder.Config.ConnectionTimeout, LBuilder.Config.ResponseTimeout]));
  Check('Client Credentials: WithTimeouts, WithScopes and WithStrictSSL keep the token expiry buffer',
    LBuilder.Config.TokenExpiryBufferSeconds = 7, IntToStr(LBuilder.Config.TokenExpiryBufferSeconds));
  LClient := LBuilder.Build;
  CheckClientTimeouts('Client Credentials client', LClient.CreateHTTPClient, 1234, 5678);
  LProvider := TClientBasedAuthProvider.Create(LClient);
  CheckClientTimeouts('Admin API through the client', LProvider.CreateHTTPClient, 1234, 5678);
  LProvider := nil;

  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GServer.URL('ok'), REALM, CLIENT_ID)
    .WithTimeouts(1234, 5678)
    .Build;
  CheckClientTimeouts('Authorization Code client', LClient.CreateHTTPClient, 1234, 5678);
end;

procedure TestGetWithRetry;
const
  MODES: array[0..2] of string = (SLOW_MODE, 'drip200', 'stall6000');
  NAMES: array[0..2] of string = ('headers after 6 s', 'body trickling, a byte every 200 ms',
    'body 6 s after the headers');
var
  I: Integer;
  LClient: THTTPClient;
  LURL: string;
  LOutcome: TOutcome;
  LResponse: IHTTPResponse;
begin
  LClient := TIAM4DHTTPClientFactory.CreateHTTPClient(HTTPConfig);
  try
    for I := Low(MODES) to High(MODES) do
    begin
      GServer.Reset;
      LURL := GServer.URL(MODES[I], '/data');
      LOutcome := Measure(
        procedure
        begin
          TIAM4DHTTPClientFactory.GetWithRetry(LClient, LURL, nil, 3);
        end);
      CheckTimedOut(NAMES[I], LURL, LOutcome);
    end;

    GServer.Reset;
    LResponse := TIAM4DHTTPClientFactory.GetWithRetry(LClient, GServer.URL('ok', '/data'), nil, 3);
    Check('same client after a timeout: 200', LResponse.StatusCode = 200, IntToStr(LResponse.StatusCode));
  finally
    LClient.Free;
  end;

  // Slow responses within the time are not cut
  LClient := TIAM4DHTTPClientFactory.CreateHTTPClient(HTTPConfig(5000));
  try
    GServer.Reset;
    LOutcome := Measure(
      procedure
      begin
        LResponse := TIAM4DHTTPClientFactory.GetWithRetry(LClient, GServer.URL('drip50', '/data'), nil, 3);
      end);
    CheckNoError('timeout 5 s, body trickling for 1.5 s: no error', LOutcome);
    if LOutcome.ErrorClass = '' then
      CheckEquals('timeout 5 s, body trickling for 1.5 s: whole body', '{"ok":true}' + StringOfChar(' ', DRIP_BYTES),
        LResponse.ContentAsString);
    GServer.Reset;
    LOutcome := Measure(
      procedure
      begin
        TIAM4DHTTPClientFactory.GetWithRetry(LClient, GServer.URL('hdr1500', '/data'), nil, 3);
      end);
    CheckNoError('timeout 5 s, headers after 1.5 s: no error', LOutcome);
  finally
    LClient.Free;
  end;

  // No deadline
  LClient := TIAM4DHTTPClientFactory.CreateHTTPClient(HTTPConfig(-1));
  try
    GServer.Reset;
    LOutcome := Measure(
      procedure
      begin
        TIAM4DHTTPClientFactory.GetWithRetry(LClient, GServer.URL('hdr1500', '/data'), nil, 3);
      end);
    CheckNoError('ResponseTimeout -1 (none), headers after 1.5 s: no error', LOutcome);
  finally
    LClient.Free;
  end;
end;

procedure TestNetworkErrors;
var
  LClient: THTTPClient;
  LURL: string;
  LOutcome: TOutcome;
  LResponse: IHTTPResponse;
  LForm: TStringList;
  LCount: Integer;
begin
  // Nobody listens on port 1: connection refused. A long ResponseTimeout: not a timeout
  LURL := 'http://127.0.0.1:1/data';
  LClient := TIAM4DHTTPClientFactory.CreateHTTPClient(HTTPConfig(20000));
  try
    LOutcome := Measure(
      procedure
      begin
        TIAM4DHTTPClientFactory.Execute(LClient, sHTTPMethodGet, LURL);
      end);
    CheckUnreachable('Execute, connection refused', LOutcome);
    LOutcome := Measure(
      procedure
      begin
        TIAM4DHTTPClientFactory.GetWithRetry(LClient, LURL, nil, 2);
      end);
    CheckUnreachable('GetWithRetry, connection refused', LOutcome);
  finally
    LClient.Free;
  end;

  // A retryable status on every attempt: the last response reaches the caller, no exception
  LClient := TIAM4DHTTPClientFactory.CreateHTTPClient(HTTPConfig);
  try
    GServer.Reset;
    LURL := GServer.URL('status503', '/data');
    LOutcome := Measure(
      procedure
      begin
        LResponse := TIAM4DHTTPClientFactory.GetWithRetry(LClient, LURL, nil, 3);
      end);
    CheckNoError('GetWithRetry, 503 every time: no exception', LOutcome);
    if LOutcome.ErrorClass = '' then
      Check('GetWithRetry, 503 every time: status 503', LResponse.StatusCode = 503, IntToStr(LResponse.StatusCode));
    LCount := GServer.RequestCount(PathOf(LURL));
    Check('GetWithRetry, 503 every time: 3 attempts', LCount = 3, IntToStr(LCount));

    GServer.Reset;
    LURL := GServer.URL('status429', '/form');
    LForm := TStringList.Create;
    try
      LForm.Values['a'] := 'b';
      LOutcome := Measure(
        procedure
        begin
          LResponse := TIAM4DHTTPClientFactory.PostFormUrlEncodedWithRetry(LClient, LURL, LForm, nil, 2);
        end);
    finally
      LForm.Free;
    end;
    CheckNoError('PostFormUrlEncodedWithRetry, 429 every time: no exception', LOutcome);
    if LOutcome.ErrorClass = '' then
      Check('PostFormUrlEncodedWithRetry, 429 every time: status 429', LResponse.StatusCode = 429,
        IntToStr(LResponse.StatusCode));
    LCount := GServer.RequestCount(PathOf(LURL));
    Check('PostFormUrlEncodedWithRetry, 429 every time: 2 attempts', LCount = 2, IntToStr(LCount));
  finally
    LClient.Free;
  end;
end;

procedure TestPostForm;
var
  LClient: THTTPClient;
  LForm: TStringList;
  LURL: string;
  LOutcome: TOutcome;
  LResponse: IHTTPResponse;
begin
  LClient := TIAM4DHTTPClientFactory.CreateHTTPClient(HTTPConfig);
  LForm := TStringList.Create;
  try
    // 1 MB that the server does not read: sending blocks
    LForm.AddPair('data', StringOfChar('x', 1024 * 1024));
    GServer.Reset;
    LURL := GServer.URL('noread6000', '/form');
    LOutcome := Measure(
      procedure
      begin
        TIAM4DHTTPClientFactory.PostFormUrlEncodedWithRetry(LClient, LURL, LForm, nil, 3);
      end);
    CheckTimedOut('request body not read by the server', LURL, LOutcome);

    // Body and Content-Type as THTTPClient.Post(URL, TStrings) sends them
    LForm.Clear;
    LForm.AddPair('a', '1');
    LForm.AddPair('b', 'x y&z');
    GServer.Reset;
    LResponse := TIAM4DHTTPClientFactory.PostFormUrlEncodedWithRetry(LClient, GServer.URL('ok', '/form'), LForm, nil, 3);
    Check('form: 200', LResponse.StatusCode = 200, IntToStr(LResponse.StatusCode));
    CheckEquals('form: Content-Type', 'application/x-www-form-urlencoded; charset=' + TEncoding.UTF8.MIMEName,
      GServer.LastRequest.ContentType);
    CheckEquals('form: body', 'a=1&b=x+y%26z', GServer.LastRequest.Body);
  finally
    LForm.Free;
    LClient.Free;
  end;
end;

procedure TestKeycloakDiscovery;
var
  LClient: IIAM4DClient;
  LOutcome: TOutcome;
begin
  GServer.Reset;
  LClient := TIAM4DKeycloakClient.Create;
  LOutcome := Measure(
    procedure
    begin
      LClient.ConfigureAsync(ClientCredentialsConfig(GServer.URL(SLOW_MODE), TIMEOUT_MS)).Run
        .WaitForCompletion(30000, True);
    end);
  CheckTimedOut('ConfigureAsync, discovery headers after 6 s', DiscoveryURL(SLOW_MODE), LOutcome);
  LClient := nil;

  GServer.Reset;
  LOutcome := Measure(
    procedure
    begin
      BuildClientCredentials(GServer.URL(SLOW_MODE), TIMEOUT_MS);
    end);
  CheckTimedOut('Build, discovery headers after 6 s', DiscoveryURL(SLOW_MODE), LOutcome);
end;

procedure TestKeycloakToken;
var
  LClient: IIAM4DClient;
  LToken: string;
  LOutcome: TOutcome;
begin
  GServer.Reset;
  LClient := BuildClientCredentials(GServer.URL('ok'), TIMEOUT_MS);
  LToken := LClient.AuthenticateClient;
  Check('token request: access token', LToken.StartsWith('at-'), LToken);
  CheckEquals('token request: Content-Type', 'application/x-www-form-urlencoded', GServer.LastRequest.ContentType);
  Check('token request: client_credentials grant', GServer.LastRequest.Body.Contains('grant_type=client_credentials'),
    GServer.LastRequest.Body);

  GServer.Reset;
  GServer.DynamicMode := 'drip200';
  LOutcome := Measure(
    procedure
    begin
      LClient.AuthenticateClient;
    end);
  CheckTimedOut('AuthenticateClient, token response trickling', TokenURL, LOutcome);

  GServer.DynamicMode := 'ok';
  LOutcome := Measure(
    procedure
    begin
      LToken := LClient.AuthenticateClient;
    end);
  CheckNoError('same client after a timeout: new token', LOutcome);
end;

procedure TestKeycloakRenewal;
var
  LClient: IIAM4DClient;
  LToken: string;
  LOutcome: TOutcome;
begin
  GServer.Reset;
  GServer.TokenExpiresIn := 2;
  LClient := BuildClientCredentials(GServer.URL('ok'), TIMEOUT_MS, 0);
  LToken := LClient.AuthenticateClient;
  CheckEquals('token valid for 2 s, no expiry buffer: GetAccessToken reuses it', LToken, LClient.GetAccessToken);
  Sleep(2500);

  GServer.Reset;
  GServer.DynamicMode := SLOW_MODE;
  LOutcome := Measure(
    procedure
    begin
      LClient.GetAccessToken;
    end);
  CheckTimedOut('GetAccessToken renews the expired token, headers after 6 s', TokenURL, LOutcome);
end;

procedure TestKeycloakReconfigure;
var
  LClient: IIAM4DClient;
  LOutcome: TOutcome;
begin
  GServer.Reset;
  LClient := TIAM4DKeycloakClient.Create;
  LClient.ConfigureAsync(ClientCredentialsConfig(GServer.URL('ok'), 30000)).Run.WaitForCompletion(30000, True);
  // The HTTP client of the first configuration is kept for the following requests
  LClient.AuthenticateClient;
  LClient.ConfigureAsync(ClientCredentialsConfig(GServer.URL('ok'), TIMEOUT_MS)).Run.WaitForCompletion(30000, True);

  GServer.Reset;
  GServer.DynamicMode := 'drip200';
  LOutcome := Measure(
    procedure
    begin
      LClient.AuthenticateClient;
    end);
  CheckTimedOut('ConfigureAsync with a shorter timeout, token response trickling', TokenURL, LOutcome);
end;

procedure TestJWKS;
var
  LProviderObj: TIAM4DJWKSProvider;
  LProvider: IIAM4DJWKSProvider;
  LIssuer, LURL: string;
  LOutcome: TOutcome;
begin
  GServer.Reset;
  LProvider := TIAM4DJWKSProvider.Create(HTTPConfig);
  LIssuer := GServer.URL(SLOW_MODE, '/realms/' + REALM);
  LOutcome := Measure(
    procedure
    begin
      LProvider.GetPublicKey(LIssuer, 'kid-1').Free;
    end);
  CheckJWKSUnavailable('discovery headers after 6 s', DiscoveryURL(SLOW_MODE), LOutcome);

  GServer.Reset;
  LProviderObj := TIAM4DJWKSProvider.Create(HTTPConfig);
  LProvider := LProviderObj;
  LIssuer := GServer.URL('ok', '/realms/' + REALM);
  LURL := GServer.URL('drip200', '/jwks');
  LProviderObj.SetJWKSUri(LIssuer, LURL);
  LOutcome := Measure(
    procedure
    begin
      LProvider.GetPublicKey(LIssuer, 'kid-1').Free;
    end);
  CheckJWKSUnavailable('JWKS trickling', LURL, LOutcome);
end;

procedure TestAdminAPI;
var
  LUsers: IIAM4DUserManager;
  LID: string;
  LOutcome: TOutcome;
begin
  GServer.Reset;
  LUsers := TIAM4DKeycloakUserManager.Create('token', GServer.URL(SLOW_MODE), REALM, HTTPConfig);
  LOutcome := Measure(
    procedure
    begin
      LUsers.CreateUser(TIAM4DUser.Create('mario', 'mario@example.com'));
    end);
  CheckTimedOut('CreateUser, headers after 6 s', GServer.URL(SLOW_MODE, '/admin/realms/' + REALM + '/users'),
    LOutcome);

  GServer.Reset;
  LUsers := TIAM4DKeycloakUserManager.Create('token', GServer.URL('ok'), REALM, HTTPConfig);
  LID := LUsers.CreateUser(TIAM4DUser.Create('mario', 'mario@example.com'));
  CheckEquals('CreateUser: ID from Location', 'new-user-id', LID);
  CheckEquals('CreateUser: method', 'POST', GServer.LastRequest.Method);
  CheckEquals('CreateUser: Content-Type', 'application/json', GServer.LastRequest.ContentType);
  Check('CreateUser: user in the body', GServer.LastRequest.Body.Contains('"username":"mario"'),
    GServer.LastRequest.Body);
end;

procedure TestUserManager;
var
  LUsers: IIAM4DUserManager;
  LUsersAsync: IIAM4DUserManagerAsync;
  LUser: TIAM4DUser;
  LOutcome: TOutcome;
begin
  GServer.Reset;
  LUsers := TIAM4DKeycloakUserManager.Create('token', GServer.URL('drip200'), REALM, HTTPConfig);
  LOutcome := Measure(
    procedure
    begin
      LUsers.GetUserByUsername('mario');
    end);
  CheckTimedOut('GetUserByUsername (GET), body trickling',
    GServer.URL('drip200', '/admin/realms/' + REALM + '/users?username=mario&exact=true'), LOutcome);

  // The async manager hands the same exception to the operation
  GServer.Reset;
  LUsersAsync := TIAM4DKeycloakUserManagerAsync.Create(LUsers);
  LOutcome := Measure(
    procedure
    begin
      LUsersAsync.GetUserByUsernameAsync('mario').Run.WaitForCompletion(30000, True);
    end);
  CheckTimedOut('GetUserByUsernameAsync, body trickling',
    GServer.URL('drip200', '/admin/realms/' + REALM + '/users?username=mario&exact=true'), LOutcome);
  LUsersAsync := nil;

  GServer.Reset;
  LUsers := TIAM4DKeycloakUserManager.Create('token', GServer.URL(SLOW_MODE), REALM, HTTPConfig);
  LOutcome := Measure(
    procedure
    begin
      LUsers.DeleteUser('user-1');
    end);
  CheckTimedOut('DeleteUser (DELETE), headers after 6 s',
    GServer.URL(SLOW_MODE, '/admin/realms/' + REALM + '/users/user-1'), LOutcome);

  GServer.Reset;
  LOutcome := Measure(
    procedure
    begin
      LUsers.SendVerifyEmail('user-1');
    end);
  CheckTimedOut('SendVerifyEmail (PUT), headers after 6 s',
    GServer.URL(SLOW_MODE, '/admin/realms/' + REALM + '/users/user-1/send-verify-email'), LOutcome);

  // Requests as before on a normal server
  GServer.Reset;
  LUsers := TIAM4DKeycloakUserManager.Create('token', GServer.URL('ok'), REALM, HTTPConfig);
  LUser := LUsers.GetUserByUsername('mario');
  CheckEquals('GetUserByUsername: user', 'mario', LUser.Username);
  CheckEquals('GetUserByUsername: request', 'GET /ok/admin/realms/' + REALM + '/users?username=mario&exact=true',
    GServer.LastRequest.Method + ' ' + GServer.LastRequest.Path);
  LUsers.SendVerifyEmail('user-1');
  CheckEquals('SendVerifyEmail: request', 'PUT /ok/admin/realms/' + REALM + '/users/user-1/send-verify-email',
    GServer.LastRequest.Method + ' ' + GServer.LastRequest.Path);
  CheckEquals('SendVerifyEmail: empty body', '', GServer.LastRequest.Body);
  LUsers.DeleteUser('user-1');
  CheckEquals('DeleteUser: request', 'DELETE /ok/admin/realms/' + REALM + '/users/user-1',
    GServer.LastRequest.Method + ' ' + GServer.LastRequest.Path);
end;

procedure TestUnknownRequiredActions;
const
  OTHERS = '"VERIFY_PROFILE","custom-action"';
var
  LUsers: IIAM4DUserManager;
  LTry: TIAM4DUserTryResult;
  LUser: TIAM4DUser;
  LActions: TArray<TIAM4DRequiredAction>;
  LJSON: TJSONObject;
  LBody: string;
begin
  GServer.Reset;
  LUsers := TIAM4DKeycloakUserManager.Create('token', GServer.URL('ok'), REALM, HTTPConfig);
  // Reading a user with actions not in TIAM4DRequiredAction does not fail
  LTry := LUsers.TryGetUserByUsername('anna');
  Check('unknown required actions: user read', LTry.Found);
  LUser := LTry.User;
  Check('unknown required actions: known ones in RequiredActions',
    (Length(LUser.RequiredActions) = 1) and LUser.HasRequiredAction(raUpdatePassword));
  CheckEquals('unknown required actions: the others as Keycloak names them', 'VERIFY_PROFILE,custom-action',
    string.Join(',', LUser.OtherRequiredActions));
  LActions := LUsers.GetUserRequiredActions('user-2');
  Check('GetUserRequiredActions: the known ones, no exception',
    (Length(LActions) = 1) and (LActions[0] = raUpdatePassword));

  // The PUT replaces the whole list: the unknown actions stay
  LUsers.RemoveUserRequiredActions('user-2', [raUpdatePassword]);
  CheckEquals('RemoveUserRequiredActions: request', 'PUT /ok/admin/realms/' + REALM + '/users/user-2',
    GServer.LastRequest.Method + ' ' + GServer.LastRequest.Path);
  LBody := GServer.LastRequest.Body;
  Check('RemoveUserRequiredActions: unknown actions kept', LBody.Contains('"requiredActions":[' + OTHERS + ']'),
    LBody);

  // LUpdateJSON owns the array: no double free (EInvalidPointer)
  LUsers.SetUserRequiredActions('user-2', [raVerifyEmail]);
  CheckEquals('SetUserRequiredActions: body', '{"requiredActions":["VERIFY_EMAIL"]}', GServer.LastRequest.Body);

  LUsers.UpdateUser(LUser);
  LBody := GServer.LastRequest.Body;
  Check('UpdateUser: unknown actions sent back',
    LBody.Contains('"requiredActions":["UPDATE_PASSWORD",' + OTHERS + ']'), LBody);

  // TIAM4DUserHelper (FromJSON / ToJSON) as well
  LJSON := TJSONObject.ParseJSONValue('{"id":"user-2","username":"anna","requiredActions":[' + OTHERS + ']}')
    as TJSONObject;
  try
    LUser := TIAM4DUser.FromJSON(LJSON);
  finally
    LJSON.Free;
  end;
  Check('FromJSON: unknown actions in OtherRequiredActions',
    (Length(LUser.RequiredActions) = 0) and (string.Join(',', LUser.OtherRequiredActions) = 'VERIFY_PROFILE,custom-action'));
  LJSON := LUser.ToJSON;
  try
    Check('ToJSON: unknown actions sent', LJSON.ToJSON.Contains('"requiredActions":[' + OTHERS + ']'), LJSON.ToJSON);
  finally
    LJSON.Free;
  end;
end;

procedure TestIdentityProviderManager;
var
  LIdPs: IIAM4DIdentityProviderManager;
  LOutcome: TOutcome;
begin
  GServer.Reset;
  LIdPs := TIAM4DKeycloakIdentityProviderManager.Create('token', GServer.URL('drip200'), REALM, HTTPConfig);
  LOutcome := Measure(
    procedure
    begin
      LIdPs.GetIdentityProviders('', 0, 10);
    end);
  CheckTimedOut('GetIdentityProviders (GET), body trickling',
    GServer.URL('drip200', '/admin/realms/' + REALM + '/identity-provider/instances?first=0&max=10'), LOutcome);

  GServer.Reset;
  LIdPs := TIAM4DKeycloakIdentityProviderManager.Create('token', GServer.URL(SLOW_MODE), REALM, HTTPConfig);
  LOutcome := Measure(
    procedure
    begin
      LIdPs.DeleteIdentityProvider('entra');
    end);
  CheckTimedOut('DeleteIdentityProvider (DELETE), headers after 6 s',
    GServer.URL(SLOW_MODE, '/admin/realms/' + REALM + '/identity-provider/instances/entra'), LOutcome);

  GServer.Reset;
  LOutcome := Measure(
    procedure
    begin
      LIdPs.CreateIdentityProvider(TIAM4DIdentityProvider.Create('entra', IAM4D_IDP_PROVIDER_OIDC));
    end);
  CheckTimedOut('CreateIdentityProvider (POST with JSON), headers after 6 s',
    GServer.URL(SLOW_MODE, '/admin/realms/' + REALM + '/identity-provider/instances'), LOutcome);

  // Requests as before on a normal server
  GServer.Reset;
  LIdPs := TIAM4DKeycloakIdentityProviderManager.Create('token', GServer.URL('ok'), REALM, HTTPConfig);
  Check('GetIdentityProviders: empty list', Length(LIdPs.GetIdentityProviders('', 0, 10)) = 0);
  CheckEquals('GetIdentityProviders: request', 'GET /ok/admin/realms/' + REALM +
    '/identity-provider/instances?first=0&max=10', GServer.LastRequest.Method + ' ' + GServer.LastRequest.Path);
  LIdPs.CreateIdentityProvider(TIAM4DIdentityProvider.Create('entra', IAM4D_IDP_PROVIDER_OIDC));
  CheckEquals('CreateIdentityProvider: Content-Type', 'application/json', GServer.LastRequest.ContentType);
  Check('CreateIdentityProvider: provider in the body', GServer.LastRequest.Body.Contains('"alias":"entra"'),
    GServer.LastRequest.Body);
  LIdPs.DeleteIdentityProvider('entra');
  CheckEquals('DeleteIdentityProvider: request', 'DELETE /ok/admin/realms/' + REALM + '/identity-provider/instances/entra',
    GServer.LastRequest.Method + ' ' + GServer.LastRequest.Path);
end;

procedure TestBuildWaitsForDiscovery;
var
  LClient: IIAM4DClient;
  LOutcome: TOutcome;
begin
  // Build waited at most 30 s, then released the client still being configured
  GServer.Reset;
  LOutcome := Measure(
    procedure
    begin
      LClient := BuildClientCredentials(GServer.URL('hdr31000'), 45000);
    end);
  CheckNoError(Format('timeout 45 s, discovery answering after 31 s: Build succeeds (%d ms)', [LOutcome.ElapsedMs]),
    LOutcome);
  Check('client configured', Assigned(LClient) and (LClient.Issuer = GServer.URL('hdr31000', '/realms/' + REALM)));
end;

// ---------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------

procedure StartWatchdog;
begin
  GWatchdogStop := TEvent.Create(nil, True, False, '');
  GWatchdog := TThread.CreateAnonymousThread(
    procedure
    begin
      while GWatchdogStop.WaitFor(250) = wrTimeout do
      begin
        if (GDeadline <> 0) and (TThread.GetTickCount64 > GDeadline) then
        begin
          Writeln('  FAIL  hang in "', GCurrentTest, '"');
          Flush(Output);
          {$IFDEF MSWINDOWS}
          ExitProcess(98);
          {$ELSE}
          _exit(98);
          {$ENDIF}
        end;
      end;
    end);
  GWatchdog.FreeOnTerminate := False;
  GWatchdog.Start;
end;

procedure StopWatchdog;
begin
  GWatchdogStop.SetEvent;
  GWatchdog.WaitFor;
  FreeAndNil(GWatchdog);
  FreeAndNil(GWatchdogStop);
end;

procedure RunTest(const AName: string; const ATest: TProc);
begin
  Writeln(AName);
  Flush(Output);
  GCurrentTest := AName;
  GDeadline := TThread.GetTickCount64 + TEST_DEADLINE_MS;
  try
    ATest();
  except
    on E: Exception do
    begin
      Inc(GFailed);
      Writeln('  FAIL  unexpected ', E.ClassName, ': ', E.Message);
    end;
  end;
  GDeadline := 0;
end;

begin
  ReportMemoryLeaksOnShutdown := True;
  IsMultiThread := True;

  StartWatchdog;
  try
    try
      GServer := TSlowServer.Create;
    except
      on E: Exception do
      begin
        Writeln('Cannot start the slow server: ', E.Message);
        ExitCode := 99;
        Exit;
      end;
    end;
    try
      Writeln(Format('Slow server on %s, timeouts %d ms', [GServer.URL('ok'), TIMEOUT_MS]));
      RunTest('Timeouts of the HTTP clients', TestClientConfiguration);
      RunTest('Builder WithTimeouts', TestBuilderTimeouts);
      RunTest('GetWithRetry (discovery and JWKS requests)', TestGetWithRetry);
      RunTest('PostFormUrlEncodedWithRetry', TestPostForm);
      RunTest('Network errors and retryable statuses', TestNetworkErrors);
      RunTest('Keycloak client: discovery', TestKeycloakDiscovery);
      RunTest('Keycloak client: token request', TestKeycloakToken);
      RunTest('Keycloak client: token renewal', TestKeycloakRenewal);
      RunTest('Keycloak client: configured again', TestKeycloakReconfigure);
      RunTest('JWKS provider', TestJWKS);
      RunTest('Admin API', TestAdminAPI);
      RunTest('User manager', TestUserManager);
      RunTest('Required actions not in TIAM4DRequiredAction', TestUnknownRequiredActions);
      RunTest('Identity provider manager', TestIdentityProviderManager);
      RunTest('Build waits for a slow discovery (31 s)', TestBuildWaitsForDiscovery);
      // Let pool threads release their closures before the leak report
      Sleep(500);
    finally
      GServer.Free;
      GServer := nil;
    end;
  finally
    StopWatchdog;
  end;

  if GetEnvironmentVariable('IAM4D_TEST_LEAK') = '1' then
  begin
    GLeak := TObject.Create;
    Writeln('IAM4D_TEST_LEAK=1: one ', GLeak.ClassName, ' leaked on purpose');
  end;

  Writeln;
  Writeln(Format('Passed: %d  Failed: %d', [GPassed, GFailed]));
  ExitCode := GFailed;
end.
