program IAM4DKeycloakClientTest;

{ Runtime test of the TIAM4DKeycloakClient login flow (Authorization Code with PKCE).

  A fake OIDC provider (Indy HTTP server on 127.0.0.1, free port) serves discovery, the
  authorization endpoint (302 to redirect_uri with code and state) and the token endpoint.
  TIAM4DPlatformUtils.OpenURLHandler replaces the system browser: a thread GETs the
  authorization URL and follows the redirect to the local callback server of the client.
  No browser and no Keycloak are needed.
  The id_tokens are signed RS256 with a key generated at startup (TestRSASignerU) and published
  at the jwks_uri of the discovery, so the client validates them as it does with Keycloak.

  Usage : IAM4DKeycloakClientTest
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
  System.Hash,
  System.DateUtils,
  System.NetEncoding,
  System.Generics.Collections,
  System.Net.URLClient,
  System.Net.HttpClient,
  IdContext,
  IdCustomHTTPServer,
  IdHTTPServer,
  IdTCPClient,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.Exceptions,
  IAMClient4D.Config.Builder,
  IAMClient4D.Common.Security,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Common.PlatformUtils,
  IAMClient4D.Common.OAuth2URLParser,
  IAMClient4D.Callback.Handler.AppRedirect,
  IAMClient4D.Discovery.Cache,
  IAMClient4D.Security.JWT.JWKS,
  IAMClient4D.AuthorizedHTTP,
  TestRSASignerU in 'TestRSASignerU.pas';

const
  REALM = 'test';
  CLIENT_ID = 'iam4d-test';
  WAIT_MS = 10000;
  SLOW_TOKEN_MS = 1500;
  // External callback with its own query: redirect_uri must be encoded as a whole
  EXTERNAL_CALLBACK = 'https://app.example.com/cb?tenant=a&x=1+2';
  // Redirect URI on a private-use scheme (RFC 8252 7.1), as a mobile app would register it
  APP_REDIRECT = 'it.iam4d.test:/oauth2callback';
  // Characters with a meaning in a query (space, &, =, +, /, %) and non-ASCII ones (e acute, u umlaut, emoji)
  SPECIAL_LOGIN_HINT = 'mario.rossi+test@example.com & a=b Jos'#$00E9' '#$D83D#$DE00' 100%';
  SPECIAL_IDP_HINT = 'a b&c=d+e/'#$00FC'%';
  SPECIAL_SCOPE = 'x&y=z+w';
  NON_ASCII_SCOPE = 'caf'#$00E9;
  SPECIAL_ACR = 'gold&silver=1';
  // error_description of the error responses: markup and characters to escape in the callback page
  ERROR_DESCRIPTION = 'User <b>denied</b> the "consent" & left';
  // A test running longer is reported as hung (exit code 98)
  TEST_DEADLINE_MS = 90000;
  // Probe and Cancel rounds of the Stop stress
  STOP_STRESS_ROUNDS = 40;
  // Stop with an idle connection open: rounds, and bound of their median (Indy alone waits 500 ms)
  STOP_OPEN_CONNECTION_ROUNDS = 5;
  STOP_OPEN_CONNECTION_MAX_MS = 250;
  // Password grant: the only valid user, and users answered with the other Keycloak errors
  PWD_USER = 'mario.rossi';
  // Characters with a meaning in a form (&, =, +, %, space) and non-ASCII: the form must encode them
  PWD_PASSWORD = 'p&ss=w+rd %'#$00E8;
  PWD_USER_SETUP = 'must.update';
  PWD_USER_DISABLED = 'disabled.user';
  PWD_USER_NO_DIRECT_GRANT = 'no.direct.grant';
  PWD_CLIENT_SECRET = 'the-client-secret';
  // Signing key of the fake identity provider (RS256, generated at startup)
  SIGNING_KEY_BITS = 2048;
  SIGNING_KID = 'fake-idp-rs256';
  SUBJECT = 'user-1';

type
  TParam = record
    Name: string;
    Value: string;
  end;

  TParams = TArray<TParam>;

  TTokenMode = (
    tmTokens,
    tmInvalidGrant,
    tmWrongNonce,
    /// <summary>Tokens of the password grant expire at once (expires_in 1): GetAccessToken refreshes</summary>
    tmShortLived,
    /// <summary>The refresh token of the password grant expires at once (refresh_expires_in 1)</summary>
    tmRefreshShortLived,
    /// <summary>Refresh refused: 400 invalid_grant "Session not active" (session closed on Keycloak)</summary>
    tmRefreshRefused,
    /// <summary>Refresh answered 500 (Keycloak failing)</summary>
    tmRefreshServerError,
    /// <summary>Refresh answered without refresh_token and id_token (no rotation), access token stale at once</summary>
    tmRefreshNoRotation);

  /// <summary>What is wrong with the next id_tokens of the token endpoint</summary>
  TIDTokenFault = (
    ifNone,
    /// <summary>A byte of the signature changed</summary>
    ifBadSignature,
    /// <summary>kid not in the JWKS</summary>
    ifUnknownKid,
    /// <summary>alg none, no signature</summary>
    ifAlgNone,
    ifWrongIssuer,
    /// <summary>aud without the client</summary>
    ifWrongAudience,
    /// <summary>aud with the client and another audience, no azp</summary>
    ifMultiAudNoAzp,
    /// <summary>aud with the client and another audience, azp the client (valid)</summary>
    ifMultiAudWithAzp,
    /// <summary>azp another client</summary>
    ifWrongAzp,
    /// <summary>exp beyond the clock skew in the past</summary>
    ifExpired,
    /// <summary>iat beyond the clock skew in the future</summary>
    ifIatInFuture,
    /// <summary>sub another user (refresh: not the user of the login)</summary>
    ifOtherSubject,
    /// <summary>nonce not the one of the login (refresh)</summary>
    ifOtherNonce,
    /// <summary>no nonce claim</summary>
    ifNoNonce,
    /// <summary>typ "Bearer": a Keycloak access token presented as id_token</summary>
    ifAccessTokenTyp,
    /// <summary>iat a day ago, exp still valid: not issued for this token request</summary>
    ifIatTooOld);

  TLogoutMode = (
    /// <summary>204 No Content, as Keycloak also for a session already closed</summary>
    lmNoContent,
    /// <summary>400 invalid_grant "Invalid refresh token"</summary>
    lmInvalidGrant,
    /// <summary>500</summary>
    lmServerError);

  TAuthMode = (
    amCode,
    amWrongState,
    /// <summary>error=access_denied with the state of the request</summary>
    amAccessDenied,
    /// <summary>error=access_denied with another state (forged)</summary>
    amErrorWrongState,
    /// <summary>error=access_denied without state (forged)</summary>
    amErrorNoState);

  /// <summary>iss of the redirect to the client (RFC 9207)</summary>
  TIssMode = (
    imNone,
    imCorrect,
    /// <summary>iss of another issuer (mix-up)</summary>
    imWrong);

  TAuthRequest = record
    Code: string;
    Nonce: string;
    ClientID: string;
    RedirectURI: string;
    Challenge: string;
    ChallengeMethod: string;
    /// <summary>Exchanged once: a second exchange is refused (RFC 6749 4.1.2)</summary>
    Used: Boolean;
  end;

  /// <summary>Answer of the revocation endpoint</summary>
  /// <summary>rvNoEndpoint: no revocation_endpoint in the discovery document</summary>
  TRevokeMode = (rvOK, rvServerError, rvUnsupportedAccessToken, rvNoEndpoint);

  /// <summary>Fake OIDC provider: discovery, authorization and token endpoints of one realm.</summary>
  TFakeIdP = class
  private
    FServer: TIdHTTPServer;
    FLock: TCriticalSection;
    FPort: Word;
    FSeq: Integer;
    FRequests: TList<TAuthRequest>;
    FLastAuth: TParams;
    FLastToken: TParams;
    FLastCode: string;
    FAuthCount: Integer;
    FTokenCount: Integer;
    FTokensInFlight: Integer;
    FMaxTokensInFlight: Integer;
    FTokenDelayMs: Integer;
    // Extra delay of the refresh_token grant only
    FRefreshDelayMs: Integer;
    // RFC 9207: discovery says the redirect carries iss, and what it carries
    FAdvertiseIss: Boolean;
    FIssMode: TIssMode;
    // The token endpoint answers 307 to another URL (a proxy configured badly)
    FTokenRedirect: Boolean;
    FTokenMode: TTokenMode;
    FAuthMode: TAuthMode;
    FTokenRequested: TEvent;
    FTokenResponded: TEvent;
    FLastLogout: TParams;
    FLogoutCount: Integer;
    FLogoutMode: TLogoutMode;
    // Each revocation as token_type_hint|token|client_id
    FRevocations: TList<string>;
    FRevokeMode: TRevokeMode;
    // scope of the password and refresh_token answers ('' omitted); claims added to their id_token
    FGrantedScope: string;
    FExtraIDClaims: string;
    FDiscoveryCount: Integer;
    // kc_action_status sent back when the request has kc_action
    FActionStatus: string;
    // auth_time of the id_token of the code exchange (Unix time); 0: claim omitted
    FAuthTime: Int64;
    FIDTokenFault: TIDTokenFault;
    // nonce of the login of each refresh token (Keycloak repeats it in the refreshed id_token)
    FRefreshNonces: TDictionary<string, string>;
    FJWKSCount: Integer;
    // RSA signing key: modulus, private exponent, modulus length in bytes
    FSigner: TTestRSASigner;
    FSignLock: TCriticalSection;
    /// <summary>RSASSA-PKCS1-v1_5 with SHA-256 (RS256) of AInput</summary>
    function SignRS256(const AInput: string): TBytes;
    function JWKS: string;
    /// <summary>id_token signed RS256 with the current fault; ANonce empty: no nonce claim</summary>
    function MakeIDToken(const ANonce, AExtraClaims: string): string;
    procedure CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
      AResponseInfo: TIdHTTPResponseInfo);
    procedure HandleAuth(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure HandleToken(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    /// <summary>password and refresh_token grants</summary>
    procedure HandleDirectGrant(const AGrant: string; const AParams: TParams; AMode: TTokenMode;
      AResponseInfo: TIdHTTPResponseInfo);
    procedure HandleLogout(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure HandleRevoke(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset(ATokenMode: TTokenMode = tmTokens; AAuthMode: TAuthMode = amCode;
      ATokenDelayMs: Integer = 0);
    /// <summary>Changes the answers without resetting the counters (e.g. after a login)</summary>
    procedure SetBehavior(ATokenMode: TTokenMode; ATokenDelayMs: Integer = 0; ALogoutMode: TLogoutMode = lmNoContent);
    /// <summary>auth_time of the next id_tokens of the code exchange (0: omitted, as after Reset)</summary>
    procedure SetAuthTime(AValue: Int64);
    /// <summary>Fault of the next id_tokens of every grant (Reset: none)</summary>
    procedure SetIDTokenFault(AFault: TIDTokenFault);
    /// <summary>GETs of the JWKS of the realm</summary>
    function JWKSCount: Integer;
    /// <summary>GETs of the discovery document of the realm</summary>
    function DiscoveryCount: Integer;
    function BaseURL: string;
    function RealmURL: string;
    function AuthEndpoint: string;
    function LastAuth: TParams;
    function LastToken: TParams;
    function LastCode: string;
    function AuthCount: Integer;
    function TokenCount: Integer;
    /// <summary>Most token requests served at the same time since Reset or SetBehavior</summary>
    function MaxTokensInFlight: Integer;
    /// <summary>Form of the last POST to the end session endpoint</summary>
    function LastLogout: TParams;
    function LogoutCount: Integer;
    /// <summary>kc_action_status of the next logins with kc_action (Reset: success)</summary>
    procedure SetActionStatus(const AStatus: string);
    /// <summary>Delay of the refresh_token grant only, on top of the token delay (Reset: 0)</summary>
    procedure SetRefreshDelay(AMs: Integer);
    /// <summary>RFC 9207: authorization_response_iss_parameter_supported and the iss of the redirect (Reset: off, none)</summary>
    procedure SetIss(AAdvertise: Boolean; AMode: TIssMode);
    /// <summary>The token endpoint answers 307 Temporary Redirect (Reset: off)</summary>
    procedure SetTokenRedirect(AValue: Boolean);
    /// <summary>Revocations since Reset, as token_type_hint|token|client_id</summary>
    function Revocations: TArray<string>;
    procedure SetRevokeMode(AMode: TRevokeMode);
    /// <summary>scope of the password and refresh_token grants (Reset: openid; '' omitted) and extra id_token claims</summary>
    procedure SetDirectGrantClaims(const AScope, AExtraIDClaims: string);
    property TokenRequested: TEvent read FTokenRequested;
    property TokenResponded: TEvent read FTokenResponded;
  end;

  TBrowserMode = (
    /// <summary>GET the URL on a thread, following the redirect to the callback server</summary>
    bmFollow,
    /// <summary>Accept the URL and do nothing: the user never comes back</summary>
    bmIgnore,
    /// <summary>Report that the browser cannot be opened</summary>
    bmRefuse,
    /// <summary>GET the URL without following the redirect and give its Location to TIAM4DAppRedirect.HandleURL</summary>
    bmAppRedirect);

  /// <summary>Stands for the system browser through TIAM4DPlatformUtils.OpenURLHandler.</summary>
  TFakeBrowser = class
  private
    FLock: TCriticalSection;
    FMode: TBrowserMode;
    FURLs: TList<string>;
    FThreads: TList<TThread>;
    FLastStatus: Integer;
    FLastBody: string;
    FLastLocation: string;
    FLastHandled: Boolean;
    FRedirectGate: TEvent;
  public
    constructor Create;
    destructor Destroy; override;
    function Open(const AURL: string): Boolean;
    procedure Reset(AMode: TBrowserMode);
    /// <summary>bmAppRedirect: the redirects wait for ReleaseRedirects (Reset releases them too)</summary>
    procedure HoldRedirects;
    procedure ReleaseRedirects;
    function URLCount: Integer;
    function LastURL: string;
    /// <summary>Status and body of the last page shown (after the redirects)</summary>
    procedure LastPage(out AStatus: Integer; out ABody: string);
    /// <summary>bmAppRedirect: Location of the last redirect and whether the app took it</summary>
    procedure LastRedirect(out ALocation: string; out AHandled: Boolean);
    /// <summary>Waits for the running GETs</summary>
    procedure WaitIdle;
  end;

  /// <summary>Records the callbacks of a login promise; kept alive by the callbacks themselves.</summary>
  ILoginProbe = interface
    ['{5E0B7A3C-2D41-4F8E-9B6A-7C3D1E2F4A50}']
    procedure HandleSuccess(const AToken: string);
    procedure HandleError(const AException: Exception);
    procedure HandleFinally;
    function WaitDone(ATimeoutMs: Cardinal = WAIT_MS): Boolean;
    function Successes: Integer;
    function Errors: Integer;
    function Finallies: Integer;
    function Token: string;
    function ErrorClass: TClass;
    function ErrorText: string;
    /// <summary>Context value of the EIAM4DException received by OnError</summary>
    function ErrorContext(const AKey: string): string;
    /// <summary>ErrorCode of the EIAM4DException received by OnError (ecUnknown: none)</summary>
    function ErrorCode: TIAM4DErrorCode;
    function Outcome: string;
  end;

  TLoginProbe = class(TInterfacedObject, ILoginProbe)
  private
    FLock: TCriticalSection;
    FDone: TEvent;
    FSuccesses: Integer;
    FErrors: Integer;
    FFinallies: Integer;
    FToken: string;
    FErrorClass: TClass;
    FErrorText: string;
    FErrorContext: TStringList;
    FErrorCode: TIAM4DErrorCode;
  public
    constructor Create;
    destructor Destroy; override;
    procedure HandleSuccess(const AToken: string);
    procedure HandleError(const AException: Exception);
    procedure HandleFinally;
    function WaitDone(ATimeoutMs: Cardinal = WAIT_MS): Boolean;
    function Successes: Integer;
    function Errors: Integer;
    function Finallies: Integer;
    function Token: string;
    function ErrorClass: TClass;
    function ErrorText: string;
    function ErrorContext(const AKey: string): string;
    /// <summary>ErrorCode of the EIAM4DException received by OnError (ecUnknown: none)</summary>
    function ErrorCode: TIAM4DErrorCode;
    function Outcome: string;
  end;

var
  GPassed: Integer = 0;
  GFailed: Integer = 0;
  GIdP: TFakeIdP;
  GBrowser: TFakeBrowser;
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

// Polls ACondition until it holds or ATimeoutMs pass
function WaitUntil(const ACondition: TFunc<Boolean>; ATimeoutMs: Cardinal = WAIT_MS): Boolean;
var
  LStart: UInt64;
begin
  LStart := TThread.GetTickCount64;
  repeat
    if ACondition() then
      Exit(True);
    Sleep(10);
  until TThread.GetTickCount64 - LStart >= ATimeoutMs;
  Result := ACondition();
end;

procedure CheckEquals(const AName, AExpected, AActual: string);
begin
  Check(AName, AExpected = AActual, Format('expected "%s", got "%s"', [AExpected, AActual]));
end;

// ---------------------------------------------------------------------------
// URL and query helpers
// ---------------------------------------------------------------------------

function IsHexDigit(AChar: Char): Boolean;
begin
  Result := CharInSet(AChar, ['0'..'9', 'A'..'F', 'a'..'f']);
end;

/// <summary>
/// Strict application/x-www-form-urlencoded decoding: '+' is a space, %XX are UTF-8 bytes.
/// False on a malformed escape or on a character that must be percent-encoded.
/// </summary>
function FormDecode(const AText: string; out AValue: string): Boolean;
const
  // Allowed unencoded in a query value (RFC 3986 query characters without &, = and +)
  RAW_CHARS = ['A'..'Z', 'a'..'z', '0'..'9', '-', '.', '_', '~', '!', '$', '''', '(', ')', '*',
    ',', ';', ':', '@', '/', '?'];
var
  LBytes: TBytes;
  LCount: Integer;
  I: Integer;
begin
  Result := False;
  AValue := '';
  SetLength(LBytes, Length(AText));
  LCount := 0;
  I := 1;
  while I <= Length(AText) do
  begin
    if AText[I] = '+' then
      LBytes[LCount] := $20
    else if AText[I] = '%' then
    begin
      if (I + 2 > Length(AText)) or (not IsHexDigit(AText[I + 1])) or (not IsHexDigit(AText[I + 2])) then
        Exit;
      LBytes[LCount] := StrToInt('$' + AText[I + 1] + AText[I + 2]);
      Inc(I, 2);
    end
    else if CharInSet(AText[I], RAW_CHARS) then
      LBytes[LCount] := Ord(AText[I])
    else
      Exit;
    Inc(LCount);
    Inc(I);
  end;
  SetLength(LBytes, LCount);
  AValue := TEncoding.UTF8.GetString(LBytes);
  Result := True;
end;

function ParseQuery(const AQuery: string; out AParams: TParams; out AError: string): Boolean;
var
  LPair: string;
  LPos: Integer;
  LParam: TParam;
begin
  Result := False;
  AParams := nil;
  AError := '';
  if AQuery = '' then
    Exit(True);
  for LPair in AQuery.Split(['&']) do
  begin
    LPos := LPair.IndexOf('=');
    if LPos < 1 then
    begin
      AError := 'malformed pair "' + LPair + '"';
      Exit;
    end;
    if (not FormDecode(LPair.Substring(0, LPos), LParam.Name)) or
       (not FormDecode(LPair.Substring(LPos + 1), LParam.Value)) then
    begin
      AError := 'not correctly encoded: "' + LPair + '"';
      Exit;
    end;
    AParams := AParams + [LParam];
  end;
  Result := True;
end;

/// <summary>Splits AURL at the first '?' and parses the query; AError explains a failure.</summary>
function ParseURL(const AURL: string; out ABase: string; out AParams: TParams; out AError: string): Boolean;
var
  LPos: Integer;
begin
  AParams := nil;
  if AURL.Contains('#') then
  begin
    ABase := AURL;
    AError := 'unencoded "#" in "' + AURL + '"';
    Exit(False);
  end;
  LPos := AURL.IndexOf('?');
  if LPos < 0 then
  begin
    ABase := AURL;
    AError := '';
    Exit(True);
  end;
  ABase := AURL.Substring(0, LPos);
  Result := ParseQuery(AURL.Substring(LPos + 1), AParams, AError);
end;

function ParamCount(const AParams: TParams; const AName: string): Integer;
var
  LParam: TParam;
begin
  Result := 0;
  for LParam in AParams do
    if LParam.Name = AName then
      Inc(Result);
end;

function ParamValue(const AParams: TParams; const AName: string): string;
var
  LParam: TParam;
begin
  Result := '';
  for LParam in AParams do
    if LParam.Name = AName then
      Exit(LParam.Value);
end;

function ParamNames(const AParams: TParams): string;
var
  LParam: TParam;
begin
  Result := '';
  for LParam in AParams do
  begin
    if Result <> '' then
      Result := Result + ',';
    Result := Result + LParam.Name;
  end;
end;

function IsHexString(const AValue: string; ALength: Integer): Boolean;
var
  LChar: Char;
begin
  Result := Length(AValue) = ALength;
  if Result then
    for LChar in AValue do
      if not IsHexDigit(LChar) then
        Exit(False);
end;

function IsBase64URL(const AValue: string): Boolean;
var
  LChar: Char;
begin
  Result := AValue <> '';
  for LChar in AValue do
    if not CharInSet(LChar, ['A'..'Z', 'a'..'z', '0'..'9', '-', '_']) then
      Exit(False);
end;

function Base64URLNoPad(const ABytes: TBytes): string;
begin
  Result := TNetEncoding.Base64URL.EncodeBytesToString(ABytes)
    .Replace('=', '').Replace(#13, '').Replace(#10, '');
end;

function Base64URLText(const AText: string): string;
begin
  Result := Base64URLNoPad(TEncoding.UTF8.GetBytes(AText));
end;

/// <summary>RFC 7636 S256: BASE64URL(SHA256(ASCII(code_verifier)))</summary>
function S256(const AVerifier: string): string;
begin
  Result := Base64URLNoPad(THashSHA2.GetHashBytes(AVerifier));
end;

function IsCodeVerifier(const AValue: string): Boolean;
var
  LChar: Char;
begin
  // RFC 7636 4.1: 43 to 128 unreserved characters
  Result := (Length(AValue) >= 43) and (Length(AValue) <= 128);
  if Result then
    for LChar in AValue do
      if not CharInSet(LChar, ['A'..'Z', 'a'..'z', '0'..'9', '-', '.', '_', '~']) then
        Exit(False);
end;

function PortOfURL(const AURL: string): Integer;
begin
  try
    Result := TURI.Create(AURL).Port;
  except
    Result := 0;
  end;
end;

/// <summary>True if something accepts connections on 127.0.0.1:APort</summary>
function IsListening(APort: Integer): Boolean;
var
  LClient: TIdTCPClient;
begin
  Result := False;
  if APort <= 0 then
    Exit;
  LClient := TIdTCPClient.Create(nil);
  try
    LClient.Host := '127.0.0.1';
    LClient.Port := APort;
    // The loopback handshake of a listening socket is immediate; Windows retries a refused one for ~2 s
    LClient.ConnectTimeout := 500;
    try
      LClient.Connect;
      Result := True;
      LClient.Disconnect;
    except
      Result := False;
    end;
  finally
    LClient.Free;
  end;
end;

procedure CheckStopped(const AName: string; APort: Integer);
begin
  Check(AName, (APort > 0) and (not IsListening(APort)), 'port ' + IntToStr(APort));
end;

// ---------------------------------------------------------------------------
// TFakeIdP
// ---------------------------------------------------------------------------

constructor TFakeIdP.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FSignLock := TCriticalSection.Create;
  FRequests := TList<TAuthRequest>.Create;
  FRefreshNonces := TDictionary<string, string>.Create;
  FRevocations := TList<string>.Create;
  FSigner := TTestRSASigner.Create(SIGNING_KEY_BITS);
  FTokenRequested := TEvent.Create(nil, True, False, '');
  FTokenResponded := TEvent.Create(nil, True, False, '');
  FServer := TIdHTTPServer.Create(nil);
  FServer.Bindings.Clear;
  with FServer.Bindings.Add do
  begin
    IP := '127.0.0.1';
    // Free port chosen by the system
    Port := 0;
  end;
  FServer.OnCommandGet := CommandGet;
  FServer.Active := True;
  FPort := FServer.Bindings[0].Port;
end;

destructor TFakeIdP.Destroy;
begin
  if Assigned(FServer) then
    FServer.Active := False;
  FServer.Free;
  FTokenResponded.Free;
  FTokenRequested.Free;
  FRefreshNonces.Free;
  FRevocations.Free;
  FRequests.Free;
  FSigner.Free;
  FSignLock.Free;
  FLock.Free;
  inherited;
end;

function TFakeIdP.SignRS256(const AInput: string): TBytes;
begin
  // The key is shared by the threads of the server
  FSignLock.Acquire;
  try
    Result := FSigner.SignSHA256(THashSHA2.GetHashBytes(AInput));
  finally
    FSignLock.Release;
  end;
end;

function TFakeIdP.JWKS: string;
begin
  Result := Format('{"keys":[{"kty":"RSA","kid":"%s","use":"sig","alg":"RS256","n":"%s","e":"%s"}]}',
    [SIGNING_KID, Base64URLNoPad(FSigner.Modulus), Base64URLNoPad(FSigner.Exponent)]);
end;

function TFakeIdP.MakeIDToken(const ANonce, AExtraClaims: string): string;
var
  LFault: TIDTokenFault;
  LNow, LIat, LExp: Int64;
  LIssuer, LAud, LAzp, LSub, LNonce, LTyp, LHeader, LInput: string;
  LSignature: TBytes;
begin
  FLock.Acquire;
  try
    LFault := FIDTokenFault;
  finally
    FLock.Release;
  end;

  LNow := DateTimeToUnix(TDateTime.NowUTC);
  LIat := LNow;
  LExp := LNow + 300;
  LIssuer := RealmURL;
  LAud := Format('"%s"', [CLIENT_ID]);
  LAzp := Format(',"azp":"%s"', [CLIENT_ID]);
  LSub := SUBJECT;
  LNonce := ANonce;
  LTyp := 'ID';
  case LFault of
    ifWrongIssuer:
      LIssuer := BaseURL + '/realms/other';
    ifWrongAudience:
      LAud := '"other-client"';
    ifMultiAudNoAzp:
      begin
        LAud := Format('["%s","account"]', [CLIENT_ID]);
        LAzp := '';
      end;
    ifMultiAudWithAzp:
      LAud := Format('["%s","account"]', [CLIENT_ID]);
    ifWrongAzp:
      LAzp := ',"azp":"other-client"';
    ifExpired:
      begin
        // Issued 330 s ago with a lifespan of 10 s: expired beyond the clock skew (300 s)
        LIat := LNow - 330;
        LExp := LNow - 320;
      end;
    ifIatInFuture:
      begin
        LIat := LNow + 600;
        LExp := LNow + 900;
      end;
    ifOtherSubject:
      LSub := 'user-2';
    ifOtherNonce:
      LNonce := 'other-nonce';
    ifNoNonce:
      LNonce := '';
    ifAccessTokenTyp:
      LTyp := 'Bearer';
    ifIatTooOld:
      begin
        LIat := LNow - 86400;
        LExp := LNow + 300;
      end;
  end;
  if LNonce <> '' then
    LNonce := Format(',"nonce":"%s"', [LNonce]);

  case LFault of
    ifAlgNone:
      LHeader := '{"alg":"none","typ":"JWT"}';
    ifUnknownKid:
      LHeader := '{"alg":"RS256","typ":"JWT","kid":"unknown-kid"}';
  else
    LHeader := Format('{"alg":"RS256","typ":"JWT","kid":"%s"}', [SIGNING_KID]);
  end;

  LInput := Base64URLText(LHeader) + '.' + Base64URLText(Format(
    '{"iss":"%s","aud":%s%s,"sub":"%s","typ":"%s","iat":%d,"exp":%d%s%s}',
    [LIssuer, LAud, LAzp, LSub, LTyp, LIat, LExp, LNonce, AExtraClaims]));
  if LFault = ifAlgNone then
    Exit(LInput + '.');
  LSignature := SignRS256(LInput);
  if LFault = ifBadSignature then
    LSignature[Length(LSignature) div 2] := LSignature[Length(LSignature) div 2] xor $01;
  Result := LInput + '.' + Base64URLNoPad(LSignature);
end;

procedure TFakeIdP.Reset(ATokenMode: TTokenMode; AAuthMode: TAuthMode; ATokenDelayMs: Integer);
begin
  FLock.Acquire;
  try
    FTokenMode := ATokenMode;
    FAuthMode := AAuthMode;
    FTokenDelayMs := ATokenDelayMs;
    FRefreshDelayMs := 0;
    FAdvertiseIss := False;
    FIssMode := imNone;
    FTokenRedirect := False;
    FAuthCount := 0;
    FTokenCount := 0;
    FMaxTokensInFlight := 0;
    FLogoutCount := 0;
    FLogoutMode := lmNoContent;
    FRevocations.Clear;
    FRevokeMode := rvOK;
    FGrantedScope := 'openid';
    FExtraIDClaims := '';
    FLastAuth := nil;
    FLastToken := nil;
    FLastLogout := nil;
    FLastCode := '';
    // Codes of an earlier test are not exchangeable
    FRequests.Clear;
    FActionStatus := IAM4D_KC_ACTION_STATUS_SUCCESS;
    FAuthTime := 0;
    FIDTokenFault := ifNone;
    FTokenRequested.ResetEvent;
    FTokenResponded.ResetEvent;
  finally
    FLock.Release;
  end;
end;

procedure TFakeIdP.SetBehavior(ATokenMode: TTokenMode; ATokenDelayMs: Integer; ALogoutMode: TLogoutMode);
begin
  FLock.Acquire;
  try
    FTokenMode := ATokenMode;
    FTokenDelayMs := ATokenDelayMs;
    FLogoutMode := ALogoutMode;
    FMaxTokensInFlight := 0;
    FTokenRequested.ResetEvent;
    FTokenResponded.ResetEvent;
  finally
    FLock.Release;
  end;
end;

procedure TFakeIdP.SetRefreshDelay(AMs: Integer);
begin
  FLock.Acquire;
  try
    FRefreshDelayMs := AMs;
  finally
    FLock.Release;
  end;
end;

procedure TFakeIdP.SetIss(AAdvertise: Boolean; AMode: TIssMode);
begin
  FLock.Acquire;
  try
    FAdvertiseIss := AAdvertise;
    FIssMode := AMode;
  finally
    FLock.Release;
  end;
end;

procedure TFakeIdP.SetTokenRedirect(AValue: Boolean);
begin
  FLock.Acquire;
  try
    FTokenRedirect := AValue;
  finally
    FLock.Release;
  end;
end;

procedure TFakeIdP.SetActionStatus(const AStatus: string);
begin
  FLock.Acquire;
  try
    FActionStatus := AStatus;
  finally
    FLock.Release;
  end;
end;

procedure TFakeIdP.SetAuthTime(AValue: Int64);
begin
  FLock.Acquire;
  try
    FAuthTime := AValue;
  finally
    FLock.Release;
  end;
end;

procedure TFakeIdP.SetIDTokenFault(AFault: TIDTokenFault);
begin
  FLock.Acquire;
  try
    FIDTokenFault := AFault;
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.JWKSCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FJWKSCount;
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.DiscoveryCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FDiscoveryCount;
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.BaseURL: string;
begin
  Result := Format('http://127.0.0.1:%d', [FPort]);
end;

function TFakeIdP.RealmURL: string;
begin
  Result := BaseURL + '/realms/' + REALM;
end;

function TFakeIdP.AuthEndpoint: string;
begin
  Result := RealmURL + '/protocol/openid-connect/auth';
end;

function TFakeIdP.LastAuth: TParams;
begin
  FLock.Acquire;
  try
    Result := Copy(FLastAuth);
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.LastToken: TParams;
begin
  FLock.Acquire;
  try
    Result := Copy(FLastToken);
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.LastCode: string;
begin
  FLock.Acquire;
  try
    Result := FLastCode;
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.AuthCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FAuthCount;
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.MaxTokensInFlight: Integer;
begin
  FLock.Acquire;
  try
    Result := FMaxTokensInFlight;
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.TokenCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FTokenCount;
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.LastLogout: TParams;
begin
  FLock.Acquire;
  try
    Result := Copy(FLastLogout);
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.LogoutCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FLogoutCount;
  finally
    FLock.Release;
  end;
end;

procedure TFakeIdP.CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
  AResponseInfo: TIdHTTPResponseInfo);
var
  LRealmPath: string;
begin
  LRealmPath := '/realms/' + REALM;
  AResponseInfo.ContentType := 'application/json';
  AResponseInfo.CharSet := 'utf-8';
  if ARequestInfo.Document = LRealmPath + '/.well-known/openid-configuration' then
  begin
    FLock.Acquire;
    try
      Inc(FDiscoveryCount);
    finally
      FLock.Release;
    end;
    AResponseInfo.ContentText := Format(
      '{"issuer":"%0:s","authorization_endpoint":"%0:s/protocol/openid-connect/auth",' +
      '"token_endpoint":"%0:s/protocol/openid-connect/token",' +
      '"userinfo_endpoint":"%0:s/protocol/openid-connect/userinfo",' +
      '"end_session_endpoint":"%0:s/protocol/openid-connect/logout",' +
      '%2:s' +
      '"jwks_uri":"%0:s/protocol/openid-connect/certs"%1:s}',
      [RealmURL, IfThen(FAdvertiseIss, ',"authorization_response_iss_parameter_supported":true', ''),
      IfThen(FRevokeMode = rvNoEndpoint, '', Format('"revocation_endpoint":"%s/protocol/openid-connect/revoke",',
      [RealmURL]))]);
  end
  else if ARequestInfo.Document = LRealmPath + '/protocol/openid-connect/certs' then
  begin
    FLock.Acquire;
    try
      Inc(FJWKSCount);
    finally
      FLock.Release;
    end;
    AResponseInfo.ContentText := JWKS;
  end
  else if ARequestInfo.Document = LRealmPath + '/protocol/openid-connect/auth' then
    HandleAuth(ARequestInfo, AResponseInfo)
  else if ARequestInfo.Document = LRealmPath + '/protocol/openid-connect/token' then
    HandleToken(ARequestInfo, AResponseInfo)
  else if ARequestInfo.Document = LRealmPath + '/protocol/openid-connect/logout' then
    HandleLogout(ARequestInfo, AResponseInfo)
  else if ARequestInfo.Document = LRealmPath + '/protocol/openid-connect/revoke' then
    HandleRevoke(ARequestInfo, AResponseInfo)
  else
  begin
    AResponseInfo.ResponseNo := 404;
    AResponseInfo.ContentText := '{"error":"not_found"}';
  end;
end;

procedure TFakeIdP.HandleAuth(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var
  LParams: TParams;
  LError, LCode, LState, LRedirect, LSeparator, LActionStatus: string;
  LRequest: TAuthRequest;
  LMode: TAuthMode;
  LIssMode: TIssMode;
  LIss: string;
begin
  if not ParseQuery(ARequestInfo.QueryParams, LParams, LError) then
  begin
    AResponseInfo.ResponseNo := 400;
    AResponseInfo.ContentText := '{"error":"invalid_request"}';
    Exit;
  end;

  FLock.Acquire;
  try
    Inc(FAuthCount);
    Inc(FSeq);
    LCode := Format('code-%d', [FSeq]);
    LRequest.Code := LCode;
    LRequest.Nonce := ParamValue(LParams, 'nonce');
    LRequest.ClientID := ParamValue(LParams, 'client_id');
    LRequest.RedirectURI := ParamValue(LParams, 'redirect_uri');
    LRequest.Challenge := ParamValue(LParams, 'code_challenge');
    LRequest.ChallengeMethod := ParamValue(LParams, 'code_challenge_method');
    LRequest.Used := False;
    FRequests.Add(LRequest);
    FLastAuth := LParams;
    FLastCode := LCode;
    LMode := FAuthMode;
    LActionStatus := FActionStatus;
    LIssMode := FIssMode;
  finally
    FLock.Release;
  end;

  LState := ParamValue(LParams, 'state');
  if LMode in [amWrongState, amErrorWrongState] then
    LState := StringOfChar('0', 32);
  LRedirect := ParamValue(LParams, 'redirect_uri');
  if LRedirect.Contains('?') then
    LSeparator := '&'
  else
    LSeparator := '?';
  case LIssMode of
    imCorrect: LIss := '&iss=' + TNetEncoding.URL.Encode(RealmURL);
    imWrong: LIss := '&iss=' + TNetEncoding.URL.Encode(BaseURL + '/realms/attacker');
  else
    LIss := '';
  end;
  if LMode in [amAccessDenied, amErrorWrongState, amErrorNoState] then
  begin
    LRedirect := LRedirect + LSeparator + 'error=access_denied&error_description=' +
      TNetEncoding.URL.Encode(ERROR_DESCRIPTION) + LIss;
    if LMode <> amErrorNoState then
      LRedirect := LRedirect + '&state=' + TNetEncoding.URL.Encode(LState);
    AResponseInfo.Redirect(LRedirect);
  end
  else
  begin
    LRedirect := LRedirect + LSeparator + 'code=' + TNetEncoding.URL.Encode(LCode) +
      '&state=' + TNetEncoding.URL.Encode(LState) + LIss;
    // Keycloak: outcome of the application initiated action, with the code even when cancelled
    if ParamCount(LParams, 'kc_action') > 0 then
      LRedirect := LRedirect + '&kc_action_status=' + TNetEncoding.URL.Encode(LActionStatus);
    AResponseInfo.Redirect(LRedirect);
  end;
end;

procedure TFakeIdP.HandleToken(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var
  LParams: TParams;
  LError, LCode, LNonce, LIDToken, LGrant, LAuthTimeClaim, LCodeError, LVerifier: string;
  LDelay: Integer;
  LMode: TTokenMode;
  LFound: Boolean;
  LRequest: TAuthRequest;
  LAuthTime: Int64;
  LExpiresIn, LIndex: Integer;
  LRedirectToken: Boolean;
begin
  if not ParseQuery(ARequestInfo.FormParams, LParams, LError) then
    LParams := nil;
  LCode := ParamValue(LParams, 'code');
  LGrant := ParamValue(LParams, 'grant_type');

  FLock.Acquire;
  try
    Inc(FTokenCount);
    Inc(FTokensInFlight);
    if FTokensInFlight > FMaxTokensInFlight then
      FMaxTokensInFlight := FTokensInFlight;
    FLastToken := LParams;
    LDelay := FTokenDelayMs;
    if LGrant = 'refresh_token' then
      Inc(LDelay, FRefreshDelayMs);
    LRedirectToken := FTokenRedirect;
    LMode := FTokenMode;
    LAuthTime := FAuthTime;
    LFound := False;
    for LIndex := 0 to FRequests.Count - 1 do
      if FRequests[LIndex].Code = LCode then
      begin
        LRequest := FRequests[LIndex];
        LFound := not LRequest.Used;
        LNonce := LRequest.Nonce;
        // The first exchange consumes the code, whatever its outcome (as Keycloak)
        if LGrant = 'authorization_code' then
        begin
          LRequest.Used := True;
          FRequests[LIndex] := LRequest;
        end;
        Break;
      end;
  finally
    FLock.Release;
  end;

  FTokenRequested.SetEvent;
  if LDelay > 0 then
    Sleep(LDelay);
  FLock.Acquire;
  try
    // The answer is being written: the request is no longer waiting
    Dec(FTokensInFlight);
  finally
    FLock.Release;
  end;

  if LRedirectToken then
  begin
    // A followed 307 would POST the form (secret, password, refresh token) to that URL in clear text
    AResponseInfo.ResponseNo := 307;
    AResponseInfo.Location := 'http://127.0.0.1:9/elsewhere/token';
    AResponseInfo.ContentText := '';
    FTokenResponded.SetEvent;
    Exit;
  end;

  if (LGrant = 'password') or (LGrant = 'refresh_token') then
  begin
    HandleDirectGrant(LGrant, LParams, LMode, AResponseInfo);
    FTokenResponded.SetEvent;
    Exit;
  end;

  // RFC 6749 4.1.3 and RFC 7636 4.6: the request of the code decides what the exchange must carry
  LCodeError := '';
  if (LMode = tmInvalidGrant) or (not LFound) or (LGrant <> 'authorization_code') then
    LCodeError := 'Code not valid'
  else if (ParamCount(LParams, 'client_id') > 0) and (ParamValue(LParams, 'client_id') <> LRequest.ClientID) then
    LCodeError := 'Code issued to another client'
  else if (LRequest.RedirectURI <> '') and (ParamValue(LParams, 'redirect_uri') <> LRequest.RedirectURI) then
    LCodeError := 'Incorrect redirect_uri'
  else if LRequest.Challenge <> '' then
  begin
    LVerifier := ParamValue(LParams, 'code_verifier');
    if LVerifier = '' then
      LCodeError := 'PKCE code verifier not specified'
    else if (LRequest.ChallengeMethod = 'S256') and (S256(LVerifier) <> LRequest.Challenge) then
      LCodeError := 'PKCE verification failed'
    else if (LRequest.ChallengeMethod <> 'S256') and (LVerifier <> LRequest.Challenge) then
      LCodeError := 'PKCE verification failed';
  end;

  if LCodeError <> '' then
  begin
    AResponseInfo.ResponseNo := 400;
    AResponseInfo.ContentText := Format('{"error":"invalid_grant","error_description":"%s"}', [LCodeError]);
  end
  else
  begin
    if LMode = tmWrongNonce then
      LNonce := 'x' + LNonce;
    LAuthTimeClaim := '';
    if LAuthTime <> 0 then
      LAuthTimeClaim := Format(',"auth_time":%d', [LAuthTime]);
    // Signed RS256 with the key of the JWKS, as Keycloak does
    LIDToken := MakeIDToken(LNonce, LAuthTimeClaim);
    FLock.Acquire;
    try
      FRefreshNonces.AddOrSetValue('rt-' + LCode, LNonce);
    finally
      FLock.Release;
    end;
    // tmShortLived: the access token is stale at once, GetAccessToken refreshes it
    if LMode = tmShortLived then
      LExpiresIn := 1
    else
      LExpiresIn := 300;
    AResponseInfo.ContentText := Format(
      '{"access_token":"at-%0:s","refresh_token":"rt-%0:s","token_type":"Bearer","expires_in":%2:d,' +
      '"refresh_expires_in":1800,"scope":"openid","id_token":"%1:s"}', [LCode, LIDToken, LExpiresIn]);
  end;
  FTokenResponded.SetEvent;
end;

procedure TFakeIdP.HandleDirectGrant(const AGrant: string; const AParams: TParams; AMode: TTokenMode;
  AResponseInfo: TIdHTTPResponseInfo);

  procedure Error(AStatus: Integer; const AError, ADescription: string);
  begin
    AResponseInfo.ResponseNo := AStatus;
    AResponseInfo.ContentText := Format('{"error":"%s","error_description":"%s"}', [AError, ADescription]);
  end;

var
  LUser, LId, LIDToken, LNonce, LScope, LExtra: string;
  LExpiresIn, LRefreshExpiresIn: Integer;
begin
  if AGrant = 'password' then
  begin
    // Answers of Keycloak to the Resource Owner Password Credentials grant
    LUser := ParamValue(AParams, 'username');
    if LUser = PWD_USER_SETUP then
      Error(400, 'invalid_grant', 'Account is not fully set up')
    else if LUser = PWD_USER_DISABLED then
      Error(400, 'invalid_grant', 'Account disabled')
    else if LUser = PWD_USER_NO_DIRECT_GRANT then
      Error(400, 'unauthorized_client', 'Client not allowed for direct access grants')
    else if (LUser <> PWD_USER) or (ParamValue(AParams, 'password') <> PWD_PASSWORD) then
      Error(401, 'invalid_grant', 'Invalid user credentials');
    if AResponseInfo.ResponseNo >= 400 then
      Exit;
  end
  else if not ParamValue(AParams, 'refresh_token').StartsWith('rt-') then
  begin
    Error(400, 'invalid_grant', 'Invalid refresh token');
    Exit;
  end
  else if AMode = tmRefreshRefused then
  begin
    // Keycloak: the session of the refresh token was closed (admin, SSO timeouts, restart)
    Error(400, 'invalid_grant', 'Session not active');
    Exit;
  end
  else if AMode = tmRefreshServerError then
  begin
    Error(500, 'server_error', 'Unexpected error');
    Exit;
  end;

  FLock.Acquire;
  try
    Inc(FSeq);
    LId := Format('%s-%d', [AGrant, FSeq]);
    // Keycloak: the refreshed id_token repeats the nonce of the login (none for the password grant)
    LNonce := '';
    if AGrant = 'refresh_token' then
      FRefreshNonces.TryGetValue(ParamValue(AParams, 'refresh_token'), LNonce);
    if LNonce <> '' then
      FRefreshNonces.AddOrSetValue('rt-' + LId, LNonce);
  finally
    FLock.Release;
  end;

  if (AGrant = 'password') and (AMode = tmShortLived) then
    LExpiresIn := 1
  else
    LExpiresIn := 300;
  if (AGrant = 'password') and (AMode = tmRefreshShortLived) then
    LRefreshExpiresIn := 1
  else
    LRefreshExpiresIn := 1800;
  if (AGrant = 'refresh_token') and (AMode = tmRefreshNoRotation) then
  begin
    AResponseInfo.ContentText := Format(
      '{"access_token":"at-%s","token_type":"Bearer","expires_in":1,"scope":"openid"}', [LId]);
    Exit;
  end;
  FLock.Acquire;
  try
    LScope := FGrantedScope;
    LExtra := FExtraIDClaims;
  finally
    FLock.Release;
  end;
  if LScope <> '' then
    LScope := Format(',"scope":"%s"', [LScope]);
  LIDToken := MakeIDToken(LNonce, Format(',"preferred_username":"%s"', [PWD_USER]) + LExtra);
  AResponseInfo.ContentText := Format(
    '{"access_token":"at-%0:s","refresh_token":"rt-%0:s","token_type":"Bearer","expires_in":%2:d,' +
    '"refresh_expires_in":%3:d%4:s,"id_token":"%1:s"}', [LId, LIDToken, LExpiresIn, LRefreshExpiresIn, LScope]);
end;

procedure TFakeIdP.HandleLogout(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var
  LParams: TParams;
  LError: string;
  LMode: TLogoutMode;
begin
  if not ParseQuery(ARequestInfo.FormParams, LParams, LError) then
    LParams := nil;
  FLock.Acquire;
  try
    Inc(FLogoutCount);
    FLastLogout := LParams;
    LMode := FLogoutMode;
  finally
    FLock.Release;
  end;
  if LMode = lmInvalidGrant then
  begin
    AResponseInfo.ResponseNo := 400;
    AResponseInfo.ContentText := '{"error":"invalid_grant","error_description":"Invalid refresh token"}';
  end
  else if LMode = lmServerError then
  begin
    AResponseInfo.ResponseNo := 500;
    AResponseInfo.ContentText := '{"error":"server_error"}';
  end
  // Keycloak: back-channel logout with the refresh token answers 204 No Content
  else if (ARequestInfo.CommandType = hcPOST) and ParamValue(LParams, 'refresh_token').StartsWith('rt-') then
  begin
    AResponseInfo.ResponseNo := 204;
    AResponseInfo.ContentText := '';
  end
  else
  begin
    AResponseInfo.ResponseNo := 400;
    AResponseInfo.ContentText := '{"error":"invalid_request"}';
  end;
end;

procedure TFakeIdP.HandleRevoke(ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
var
  LParams: TParams;
  LError, LHint: string;
  LMode: TRevokeMode;
begin
  if not ParseQuery(ARequestInfo.FormParams, LParams, LError) then
    LParams := nil;
  LHint := ParamValue(LParams, 'token_type_hint');
  FLock.Acquire;
  try
    FRevocations.Add(LHint + '|' + ParamValue(LParams, 'token') + '|' + ParamValue(LParams, 'client_id'));
    LMode := FRevokeMode;
  finally
    FLock.Release;
  end;
  if LMode = rvServerError then
  begin
    AResponseInfo.ResponseNo := 500;
    AResponseInfo.ContentText := '{"error":"server_error"}';
  end
  else if (LMode = rvUnsupportedAccessToken) and (LHint = 'access_token') then
  begin
    AResponseInfo.ResponseNo := 400;
    AResponseInfo.ContentText := '{"error":"unsupported_token_type"}';
  end
  else
  begin
    AResponseInfo.ResponseNo := 200;
    AResponseInfo.ContentText := '';
  end;
end;

procedure TFakeIdP.SetDirectGrantClaims(const AScope, AExtraIDClaims: string);
begin
  FLock.Acquire;
  try
    FGrantedScope := AScope;
    FExtraIDClaims := AExtraIDClaims;
  finally
    FLock.Release;
  end;
end;

function TFakeIdP.Revocations: TArray<string>;
begin
  FLock.Acquire;
  try
    Result := FRevocations.ToArray;
  finally
    FLock.Release;
  end;
end;

procedure TFakeIdP.SetRevokeMode(AMode: TRevokeMode);
begin
  FLock.Acquire;
  try
    FRevokeMode := AMode;
  finally
    FLock.Release;
  end;
end;

// ---------------------------------------------------------------------------
// TFakeBrowser
// ---------------------------------------------------------------------------

constructor TFakeBrowser.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FURLs := TList<string>.Create;
  FThreads := TList<TThread>.Create;
  FRedirectGate := TEvent.Create(nil, True, True, '');
end;

destructor TFakeBrowser.Destroy;
begin
  ReleaseRedirects;
  WaitIdle;
  FThreads.Free;
  FURLs.Free;
  FRedirectGate.Free;
  FLock.Free;
  inherited;
end;

procedure TFakeBrowser.HoldRedirects;
begin
  FRedirectGate.ResetEvent;
end;

procedure TFakeBrowser.ReleaseRedirects;
begin
  FRedirectGate.SetEvent;
end;

function TFakeBrowser.Open(const AURL: string): Boolean;
var
  LMode: TBrowserMode;
  LThread: TThread;
begin
  FLock.Acquire;
  try
    FURLs.Add(AURL);
    LMode := FMode;
  finally
    FLock.Release;
  end;

  // Only the fake identity provider is ever contacted
  if (not Assigned(GIdP)) or (not AURL.StartsWith(GIdP.AuthEndpoint + '?')) then
    Exit(False);

  case LMode of
    bmIgnore:
      Exit(True);
    bmRefuse:
      Exit(False);
  end;

  LThread := TThread.CreateAnonymousThread(
    procedure
    var
      LHTTP: THTTPClient;
      LResponse: IHTTPResponse;
      LLocation: string;
      LHandled: Boolean;
    begin
      LHTTP := THTTPClient.Create;
      try
        LHTTP.HandleRedirects := LMode <> bmAppRedirect;
        LHTTP.ConnectionTimeout := 5000;
        LHTTP.ResponseTimeout := 10000;
        try
          LResponse := LHTTP.Get(AURL);
          if LMode = bmAppRedirect then
          begin
            // The operating system hands the redirect to the app (when the test lets it)
            FRedirectGate.WaitFor(WAIT_MS);
            LLocation := LResponse.HeaderValue['Location'];
            LHandled := TIAM4DAppRedirect.HandleURL(LLocation);
            FLock.Acquire;
            try
              FLastLocation := LLocation;
              FLastHandled := LHandled;
            finally
              FLock.Release;
            end;
          end;
          FLock.Acquire;
          try
            FLastStatus := LResponse.StatusCode;
            FLastBody := LResponse.ContentAsString(TEncoding.UTF8);
          finally
            FLock.Release;
          end;
        except
          // The callback server may be stopped meanwhile (cancel tests)
        end;
      finally
        LHTTP.Free;
      end;
    end);
  LThread.FreeOnTerminate := False;
  FLock.Acquire;
  try
    FThreads.Add(LThread);
  finally
    FLock.Release;
  end;
  LThread.Start;
  Result := True;
end;

procedure TFakeBrowser.Reset(AMode: TBrowserMode);
begin
  ReleaseRedirects;
  WaitIdle;
  FLock.Acquire;
  try
    FMode := AMode;
    FURLs.Clear;
    FLastStatus := 0;
    FLastBody := '';
    FLastLocation := '';
    FLastHandled := False;
  finally
    FLock.Release;
  end;
end;

procedure TFakeBrowser.LastRedirect(out ALocation: string; out AHandled: Boolean);
begin
  FLock.Acquire;
  try
    ALocation := FLastLocation;
    AHandled := FLastHandled;
  finally
    FLock.Release;
  end;
end;

procedure TFakeBrowser.LastPage(out AStatus: Integer; out ABody: string);
begin
  FLock.Acquire;
  try
    AStatus := FLastStatus;
    ABody := FLastBody;
  finally
    FLock.Release;
  end;
end;

function TFakeBrowser.URLCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FURLs.Count;
  finally
    FLock.Release;
  end;
end;

function TFakeBrowser.LastURL: string;
begin
  FLock.Acquire;
  try
    if FURLs.Count > 0 then
      Result := FURLs.Last
    else
      Result := '';
  finally
    FLock.Release;
  end;
end;

procedure TFakeBrowser.WaitIdle;
var
  LThreads: TArray<TThread>;
  LThread: TThread;
begin
  FLock.Acquire;
  try
    LThreads := FThreads.ToArray;
    FThreads.Clear;
  finally
    FLock.Release;
  end;
  for LThread in LThreads do
  begin
    LThread.WaitFor;
    LThread.Free;
  end;
end;

// ---------------------------------------------------------------------------
// TLoginProbe
// ---------------------------------------------------------------------------

constructor TLoginProbe.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FDone := TEvent.Create(nil, True, False, '');
  FErrorContext := TStringList.Create;
end;

destructor TLoginProbe.Destroy;
begin
  FErrorContext.Free;
  FDone.Free;
  FLock.Free;
  inherited;
end;

procedure TLoginProbe.HandleSuccess(const AToken: string);
begin
  FLock.Acquire;
  try
    Inc(FSuccesses);
    FToken := AToken;
  finally
    FLock.Release;
  end;
end;

procedure TLoginProbe.HandleError(const AException: Exception);
begin
  FLock.Acquire;
  try
    Inc(FErrors);
    FErrorClass := AException.ClassType;
    FErrorText := AException.ClassName + ': ' + AException.Message;
    if AException is EIAM4DException then
    begin
      FErrorCode := EIAM4DException(AException).ErrorCode;
      for var LPair in EIAM4DException(AException).Context do
        FErrorContext.Values[LPair.Key] := LPair.Value;
    end;
  finally
    FLock.Release;
  end;
end;

procedure TLoginProbe.HandleFinally;
begin
  FLock.Acquire;
  try
    Inc(FFinallies);
  finally
    FLock.Release;
  end;
  FDone.SetEvent;
end;

function TLoginProbe.WaitDone(ATimeoutMs: Cardinal): Boolean;
begin
  Result := FDone.WaitFor(ATimeoutMs) = wrSignaled;
end;

function TLoginProbe.Successes: Integer;
begin
  FLock.Acquire;
  try
    Result := FSuccesses;
  finally
    FLock.Release;
  end;
end;

function TLoginProbe.Errors: Integer;
begin
  FLock.Acquire;
  try
    Result := FErrors;
  finally
    FLock.Release;
  end;
end;

function TLoginProbe.Finallies: Integer;
begin
  FLock.Acquire;
  try
    Result := FFinallies;
  finally
    FLock.Release;
  end;
end;

function TLoginProbe.Token: string;
begin
  FLock.Acquire;
  try
    Result := FToken;
  finally
    FLock.Release;
  end;
end;

function TLoginProbe.ErrorClass: TClass;
begin
  FLock.Acquire;
  try
    Result := FErrorClass;
  finally
    FLock.Release;
  end;
end;

function TLoginProbe.ErrorText: string;
begin
  FLock.Acquire;
  try
    Result := FErrorText;
  finally
    FLock.Release;
  end;
end;

function TLoginProbe.ErrorContext(const AKey: string): string;
begin
  FLock.Acquire;
  try
    Result := FErrorContext.Values[AKey];
  finally
    FLock.Release;
  end;
end;

function TLoginProbe.ErrorCode: TIAM4DErrorCode;
begin
  FLock.Acquire;
  try
    Result := FErrorCode;
  finally
    FLock.Release;
  end;
end;

function TLoginProbe.Outcome: string;
begin
  FLock.Acquire;
  try
    Result := Format('success %d, error %d, finally %d', [FSuccesses, FErrors, FFinallies]);
    if FErrorText <> '' then
      Result := Result + ', ' + FErrorText;
  finally
    FLock.Release;
  end;
end;

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

function NewLocalClient(const AConfigIdpHint: string = ''): IIAM4DClient;
var
  LBuilder: IIAM4DClientConfigBuilder;
begin
  LBuilder := TIAM4DClientConfigBuilder.New.ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID);
  if AConfigIdpHint <> '' then
    LBuilder.WithIdentityProvider(AConfigIdpHint);
  Result := LBuilder.Build;
end;

function NewExternalClient(const AConfigIdpHint: string = ''): IIAM4DClient;
var
  LBuilder: IIAM4DClientConfigBuilder;
begin
  LBuilder := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithExternalCallback(EXTERNAL_CALLBACK);
  if AConfigIdpHint <> '' then
    LBuilder.WithIdentityProvider(AConfigIdpHint);
  Result := LBuilder.Build;
end;

function NewAppClient: IIAM4DClient;
begin
  Result := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithAppRedirect(APP_REDIRECT)
    .Build;
end;

/// <summary>GET without following the redirect: the Location of the answer (the redirect of the app)</summary>
function FetchRedirect(const AURL: string): string;
var
  LHTTP: THTTPClient;
  LResponse: IHTTPResponse;
begin
  LHTTP := THTTPClient.Create;
  try
    LHTTP.HandleRedirects := False;
    LResponse := LHTTP.Get(AURL);
    Result := LResponse.HeaderValue['Location'];
  finally
    LHTTP.Free;
  end;
end;

function StartLogin(const AClient: IIAM4DClient; const AProbe: ILoginProbe;
  const AIdpHint: string = ''): IAsyncOperation<string>;
begin
  Result := AClient.StartAuthorizationFlowAsync(AIdpHint)
    .OnSuccess(
      procedure(const AToken: string)
      begin
        AProbe.HandleSuccess(AToken);
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        AProbe.HandleError(AException);
      end)
    .OnFinally(
      procedure
      begin
        AProbe.HandleFinally;
      end)
    .DispatchMode(TAsyncCallbackDispatchMode.dmInline)
    .Run;
end;

function IsCancelledOnce(const AProbe: ILoginProbe): Boolean;
begin
  Result := (AProbe.Finallies = 1) and (AProbe.Successes = 0) and (AProbe.Errors = 0);
end;

/// <summary>Redirect URI sent by the last login, as seen by the browser</summary>
function LastRedirectURI: string;
var
  LBase, LError: string;
  LParams: TParams;
begin
  if ParseURL(GBrowser.LastURL, LBase, LParams, LError) then
    Result := ParamValue(LParams, 'redirect_uri')
  else
    Result := '';
end;

/// <summary>Checks the kc_idp_hint of an authorization request: AExpected empty means absent.</summary>
procedure CheckIdpHint(const AName: string; const AParams: TParams; const AExpected: string);
begin
  if AExpected = '' then
    Check(AName + ': no kc_idp_hint', ParamCount(AParams, 'kc_idp_hint') = 0,
      'kc_idp_hint=' + ParamValue(AParams, 'kc_idp_hint'))
  else
    Check(AName + ': kc_idp_hint=' + AExpected,
      (ParamCount(AParams, 'kc_idp_hint') = 1) and (ParamValue(AParams, 'kc_idp_hint') = AExpected),
      'got ' + IntToStr(ParamCount(AParams, 'kc_idp_hint')) + ' "' + ParamValue(AParams, 'kc_idp_hint') + '"');
end;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

procedure TestOpenURLHandler;
var
  LSaved: TIAM4DOpenURLHandler;
  LCalls: Integer;
  LSeen: string;
  LAnswer: Boolean;
begin
  LSaved := TIAM4DPlatformUtils.OpenURLHandler;
  // Precondition: the fake browser of GBrowser is installed, no test reaches the real browser
  Check('fake browser handler installed', Assigned(LSaved));
  LCalls := 0;
  LAnswer := True;
  TIAM4DPlatformUtils.OpenURLHandler :=
    function(const AURL: string): Boolean
    begin
      Inc(LCalls);
      LSeen := AURL;
      if AURL.EndsWith('raise') then
        raise Exception.Create('handler failure');
      Result := LAnswer;
    end;
  try
    Check('OpenURL returns True from the handler',
      TIAM4DPlatformUtils.OpenURL('https://idp.invalid/auth?a=1&b=%20') and (LCalls = 1));
    CheckEquals('handler receives the URL unchanged', 'https://idp.invalid/auth?a=1&b=%20', LSeen);
    LAnswer := False;
    Check('OpenURL returns False from the handler',
      (not TIAM4DPlatformUtils.OpenURL('https://idp.invalid/auth')) and (LCalls = 2));
    Check('handler exception: OpenURL returns False',
      (not TIAM4DPlatformUtils.OpenURL('https://idp.invalid/raise')) and (LCalls = 3));
    Check('only http(s): file:, javascript:, data:, ms-*:, custom, no scheme and empty never reach the handler',
      (not TIAM4DPlatformUtils.OpenURL('file:///etc/passwd')) and
      (not TIAM4DPlatformUtils.OpenURL('search-ms:query=x')) and
      (not TIAM4DPlatformUtils.OpenURL('ms-settings:privacy')) and
      (not TIAM4DPlatformUtils.OpenURL('myapp://run')) and
      (not TIAM4DPlatformUtils.OpenURL('javascript:alert(1)')) and
      (not TIAM4DPlatformUtils.OpenURL('data:text/html,x')) and
      (not TIAM4DPlatformUtils.OpenURL('no-scheme')) and
      (not TIAM4DPlatformUtils.OpenURL('')) and
      (LCalls = 3), 'calls ' + IntToStr(LCalls));
  finally
    // Never nil here: the next tests must not reach the real browser
    TIAM4DPlatformUtils.OpenURLHandler := LSaved;
  end;
end;

procedure TestLoginPKCE;
var
  LClient: IIAM4DClient;
  LProbe, LSecond: ILoginProbe;
  LOp, LOp2: IAsyncOperation<string>;
  LAuth, LToken, LSent: TParams;
  LBase, LError, LCode, LRedirect, LChallenge, LVerifier, LBody: string;
  LStatus: Integer;
begin
  GIdP.Reset;
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('completes', LProbe.WaitDone);
  GBrowser.WaitIdle;
  LCode := GIdP.LastCode;
  Check('OnSuccess and OnFinally once', (LProbe.Successes = 1) and (LProbe.Errors = 0) and
    (LProbe.Finallies = 1), LProbe.Outcome);
  CheckEquals('access token of the exchanged code', 'at-' + LCode, LProbe.Token);
  Check('authenticated', LClient.IsAuthenticated);
  Check('operation completed', LOp.State = TAsyncOperationState.Completed);

  // Authorization request: the URL given to the browser is the one the identity provider received
  Check('browser opened once', GBrowser.URLCount = 1, IntToStr(GBrowser.URLCount));
  Check('authorization URL parses', ParseURL(GBrowser.LastURL, LBase, LSent, LError), LError);
  CheckEquals('authorization endpoint', GIdP.AuthEndpoint, LBase);
  LAuth := GIdP.LastAuth;
  Check('one authorization request', GIdP.AuthCount = 1);
  CheckEquals('state received as sent', ParamValue(LSent, 'state'), ParamValue(LAuth, 'state'));
  CheckEquals('response_type', 'code', ParamValue(LAuth, 'response_type'));
  CheckEquals('client_id', CLIENT_ID, ParamValue(LAuth, 'client_id'));
  LRedirect := ParamValue(LAuth, 'redirect_uri');
  Check('redirect_uri on the loopback callback server',
    LRedirect.StartsWith('http://localhost:') and LRedirect.EndsWith('/oauth2callback'), LRedirect);
  Check('scope has openid', (' ' + ParamValue(LAuth, 'scope') + ' ').Contains(' openid '),
    ParamValue(LAuth, 'scope'));
  Check('state: 32 hex digits', IsHexString(ParamValue(LAuth, 'state'), 32), ParamValue(LAuth, 'state'));
  Check('nonce: 32 hex digits', IsHexString(ParamValue(LAuth, 'nonce'), 32), ParamValue(LAuth, 'nonce'));
  Check('nonce differs from state', ParamValue(LAuth, 'nonce') <> ParamValue(LAuth, 'state'));
  CheckEquals('code_challenge_method', 'S256', ParamValue(LAuth, 'code_challenge_method'));
  LChallenge := ParamValue(LAuth, 'code_challenge');
  Check('code_challenge: 43 base64url characters', (Length(LChallenge) = 43) and IsBase64URL(LChallenge),
    LChallenge);
  CheckIdpHint('no hint configured', LAuth, '');

  // Token request
  LToken := GIdP.LastToken;
  Check('one token request', GIdP.TokenCount = 1, IntToStr(GIdP.TokenCount));
  CheckEquals('grant_type', 'authorization_code', ParamValue(LToken, 'grant_type'));
  CheckEquals('code', LCode, ParamValue(LToken, 'code'));
  CheckEquals('token redirect_uri equals the authorization one', LRedirect, ParamValue(LToken, 'redirect_uri'));
  CheckEquals('token client_id', CLIENT_ID, ParamValue(LToken, 'client_id'));
  LVerifier := ParamValue(LToken, 'code_verifier');
  Check('code_verifier: 43-128 unreserved characters', IsCodeVerifier(LVerifier), LVerifier);
  CheckEquals('S256(code_verifier) = code_challenge', LChallenge, S256(LVerifier));
  Check('no client_secret for a public client', ParamCount(LToken, 'client_secret') = 0);

  CheckStopped('callback server stopped', PortOfURL(LRedirect));
  // The exchange stops the server at once: the page must still reach the browser
  GBrowser.LastPage(LStatus, LBody);
  Check('browser got the success page', (LStatus = 200) and LBody.Contains('Authorization Successful'),
    IntToStr(LStatus));

  // A second login gets new state, nonce and PKCE pair
  LSecond := TLoginProbe.Create;
  LOp2 := StartLogin(LClient, LSecond);
  Check('second login completes', LSecond.WaitDone and (LSecond.Successes = 1), LSecond.Outcome);
  GBrowser.WaitIdle;
  Check('new state, nonce and code_challenge',
    (ParamValue(GIdP.LastAuth, 'state') <> ParamValue(LAuth, 'state')) and
    (ParamValue(GIdP.LastAuth, 'nonce') <> ParamValue(LAuth, 'nonce')) and
    (ParamValue(GIdP.LastAuth, 'code_challenge') <> LChallenge));
  Check('first promise settled once', (LProbe.Successes = 1) and (LProbe.Errors = 0) and
    (LProbe.Finallies = 1), LProbe.Outcome);
  LOp := nil;
  LOp2 := nil;
  LClient := nil;
end;

procedure TestIdpHintLogin;
type
  TCase = record
    Config: string;
    Arg: string;
    Expected: string;
  end;
const
  CASES: array[0..5] of TCase = (
    (Config: ''; Arg: ''; Expected: ''),
    (Config: ''; Arg: 'entra'; Expected: 'entra'),
    (Config: 'spid-test'; Arg: ''; Expected: 'spid-test'),
    (Config: 'spid-test'; Arg: 'cie'; Expected: 'cie'),
    (Config: 'spid-test'; Arg: '  '; Expected: 'spid-test'),
    (Config: 'spid-test'; Arg: IAM4D_IDP_HINT_NONE; Expected: ''));
var
  LCase: TCase;
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LName, LBase, LError: string;
  LSent: TParams;
begin
  for LCase in CASES do
  begin
    LName := Format('config "%s", argument "%s"', [LCase.Config, LCase.Arg]);
    GIdP.Reset;
    GBrowser.Reset(bmFollow);
    LClient := NewLocalClient(LCase.Config);
    LProbe := TLoginProbe.Create;
    LOp := StartLogin(LClient, LProbe, LCase.Arg);
    Check(LName + ': login completes', LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
    GBrowser.WaitIdle;
    CheckIdpHint(LName + ' (identity provider)', GIdP.LastAuth, LCase.Expected);
    if ParseURL(GBrowser.LastURL, LBase, LSent, LError) then
      CheckIdpHint(LName + ' (browser URL)', LSent, LCase.Expected)
    else
      Check(LName + ' (browser URL parses)', False, LError);
    LOp := nil;
    LClient := nil;
  end;
end;

procedure TestIdpHintGenerateAuthURL;
type
  TCase = record
    Config: string;
    Arg: string;
    Expected: string;
  end;
const
  CASES: array[0..8] of TCase = (
    (Config: ''; Arg: ''; Expected: ''),
    (Config: ''; Arg: 'entra'; Expected: 'entra'),
    (Config: ''; Arg: IAM4D_IDP_HINT_NONE; Expected: ''),
    (Config: 'spid-test'; Arg: ''; Expected: 'spid-test'),
    (Config: 'spid-test'; Arg: 'cie'; Expected: 'cie'),
    (Config: 'spid-test'; Arg: ' cie '; Expected: 'cie'),
    (Config: 'spid-test'; Arg: IAM4D_IDP_HINT_NONE; Expected: ''),
    (Config: IAM4D_IDP_HINT_NONE; Arg: ''; Expected: ''),
    (Config: IAM4D_IDP_HINT_NONE; Arg: 'cie'; Expected: 'cie'));
var
  LCase: TCase;
  LClient: IIAM4DClient;
  LName, LBase, LError: string;
  LParams: TParams;
  LRaised: Boolean;
begin
  GIdP.Reset;
  LClient := NewExternalClient;
  LRaised := False;
  try
    LClient.GenerateAuthURL;
  except
    on E: EIAM4DException do
      LRaised := True;
  end;
  Check('GenerateAuthURL before InitializeAuthorizationFlow raises', LRaised);

  for LCase in CASES do
  begin
    LName := Format('config "%s", argument "%s"', [LCase.Config, LCase.Arg]);
    LClient := NewExternalClient(LCase.Config);
    LClient.InitializeAuthorizationFlow;
    if ParseURL(LClient.GenerateAuthURL('', LCase.Arg), LBase, LParams, LError) then
      CheckIdpHint(LName, LParams, LCase.Expected)
    else
      Check(LName + ': URL parses', False, LError);
  end;
  Check('no request to the authorization endpoint', GIdP.AuthCount = 0);
  LClient := nil;
end;

procedure TestEncoding;
const
  EXPECTED_NAMES: array[0..10] of string = ('client_id', 'redirect_uri', 'response_type', 'scope', 'state',
    'nonce', 'login_hint', 'acr_values', 'kc_idp_hint', 'code_challenge', 'code_challenge_method');
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LURL, LBase, LError, LName: string;
  LParams: TParams;
  LNamesOK: Boolean;
begin
  GIdP.Reset;
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithScopes(['openid', 'profile', SPECIAL_SCOPE, NON_ASCII_SCOPE])
    .WithAcrValues(['urn:keycloak:acr:2fa', SPECIAL_ACR])
    .WithExternalCallback(EXTERNAL_CALLBACK)
    .Build;
  LClient.InitializeAuthorizationFlow;
  LURL := LClient.GenerateAuthURL(SPECIAL_LOGIN_HINT, SPECIAL_IDP_HINT);

  Check('GenerateAuthURL: query correctly encoded', ParseURL(LURL, LBase, LParams, LError), LError + ' in ' + LURL);
  CheckEquals('GenerateAuthURL: endpoint', GIdP.AuthEndpoint, LBase);
  LNamesOK := Length(LParams) = Length(EXPECTED_NAMES);
  for LName in EXPECTED_NAMES do
    LNamesOK := LNamesOK and (ParamCount(LParams, LName) = 1);
  Check('GenerateAuthURL: each parameter once, nothing split by & or =', LNamesOK, ParamNames(LParams));
  CheckEquals('login_hint (space, &, =, +, %, non-ASCII, emoji)', SPECIAL_LOGIN_HINT,
    ParamValue(LParams, 'login_hint'));
  CheckEquals('kc_idp_hint (space, &, =, +, /, %, non-ASCII)', SPECIAL_IDP_HINT, ParamValue(LParams, 'kc_idp_hint'));
  CheckEquals('scope (spaces between scopes, &, =, +, non-ASCII)',
    'openid profile ' + SPECIAL_SCOPE + ' ' + NON_ASCII_SCOPE, ParamValue(LParams, 'scope'));
  CheckEquals('acr_values', 'urn:keycloak:acr:2fa ' + SPECIAL_ACR, ParamValue(LParams, 'acr_values'));
  CheckEquals('redirect_uri with its own query', EXTERNAL_CALLBACK, ParamValue(LParams, 'redirect_uri'));
  CheckEquals('client_id', CLIENT_ID, ParamValue(LParams, 'client_id'));
  LClient := nil;

  // The URL handed to the browser by StartAuthorizationFlowAsync
  GBrowser.Reset(bmIgnore);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe, SPECIAL_IDP_HINT);
  Check('login URL: query correctly encoded', ParseURL(GBrowser.LastURL, LBase, LParams, LError),
    LError + ' in ' + GBrowser.LastURL);
  CheckEquals('login URL: kc_idp_hint', SPECIAL_IDP_HINT, ParamValue(LParams, 'kc_idp_hint'));
  LOp.Cancel;
  Check('login cancelled', LProbe.WaitDone and IsCancelledOnce(LProbe), LProbe.Outcome);
  LOp := nil;
  LClient := nil;
end;

procedure TestExternalCallback;
var
  LClient: IIAM4DClient;
  LHTTP: THTTPClient;
  LResponse: IHTTPResponse;
  LLocation, LBase, LError, LCode, LState, LToken, LChallenge: string;
  LParams: TParams;
  LRaised: Boolean;
begin
  GIdP.Reset;
  LClient := NewExternalClient;
  LClient.InitializeAuthorizationFlow;

  // The browser part: the identity provider redirects to the web application
  LHTTP := THTTPClient.Create;
  try
    LHTTP.HandleRedirects := False;
    LResponse := LHTTP.Get(LClient.GenerateAuthURL);
    Check('302 from the authorization endpoint', LResponse.StatusCode = 302, IntToStr(LResponse.StatusCode));
    LLocation := LResponse.HeaderValue['Location'];
  finally
    LHTTP.Free;
  end;
  LChallenge := ParamValue(GIdP.LastAuth, 'code_challenge');
  Check('redirect to the external callback', LLocation.StartsWith(EXTERNAL_CALLBACK + '&code='), LLocation);
  Check('callback URL parses', ParseURL(LLocation, LBase, LParams, LError), LError);
  CheckEquals('callback keeps its own parameters', 'a', ParamValue(LParams, 'tenant'));
  LCode := ParamValue(LParams, 'code');
  LState := ParamValue(LParams, 'state');

  LRaised := False;
  try
    LClient.CompleteAuthorizationFlow(LCode, StringOfChar('0', 32));
  except
    on E: EIAM4DStateMismatchException do
      LRaised := True;
  end;
  Check('wrong state: EIAM4DStateMismatchException', LRaised);
  Check('wrong state: no token request', GIdP.TokenCount = 0);
  Check('wrong state: not authenticated', not LClient.IsAuthenticated);

  LToken := LClient.CompleteAuthorizationFlow(LCode, LState);
  CheckEquals('CompleteAuthorizationFlow returns the access token', 'at-' + LCode, LToken);
  Check('authenticated', LClient.IsAuthenticated);
  CheckEquals('token redirect_uri', EXTERNAL_CALLBACK, ParamValue(GIdP.LastToken, 'redirect_uri'));
  CheckEquals('S256(code_verifier) = code_challenge', LChallenge,
    S256(ParamValue(GIdP.LastToken, 'code_verifier')));

  // The same callback again (reload): the context was taken, the code is not exchanged twice
  LRaised := False;
  try
    LClient.CompleteAuthorizationFlow(LCode, LState);
  except
    on E: EIAM4DException do
      LRaised := E.Message.Contains('No authorization flow is waiting');
  end;
  Check('repeated external callback refused', LRaised);
  Check('repeated external callback: one token request', GIdP.TokenCount = 1, IntToStr(GIdP.TokenCount));
  Check('repeated external callback: still authenticated', LClient.IsAuthenticated);
  LClient := nil;
end;

procedure CheckLoginError(const AName: string; ATokenMode: TTokenMode; AAuthMode: TAuthMode;
  const AMessagePart: string; AExpectTokenRequest: Boolean; AExpectedClass: ExceptClass = nil;
  AExpectedCode: TIAM4DErrorCode = ecUnknown);
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
begin
  GIdP.Reset(ATokenMode, AAuthMode);
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check(AName + ': ends', LProbe.WaitDone);
  GBrowser.WaitIdle;
  Sleep(100);
  Check(AName + ': OnError and OnFinally once', (LProbe.Errors = 1) and (LProbe.Successes = 0) and
    (LProbe.Finallies = 1), LProbe.Outcome);
  if AExpectedClass = nil then
    AExpectedClass := EIAM4DException;
  Check(AName + ': ' + AExpectedClass.ClassName, Assigned(LProbe.ErrorClass) and
    LProbe.ErrorClass.InheritsFrom(AExpectedClass), LProbe.ErrorText);
  Check(AName + ': message', LProbe.ErrorText.Contains(AMessagePart), LProbe.ErrorText);
  if AExpectedCode <> ecUnknown then
    Check(AName + ': error code', LProbe.ErrorCode = AExpectedCode, IntToStr(Ord(LProbe.ErrorCode)));
  Check(AName + ': operation faulted', LOp.State = TAsyncOperationState.Faulted);
  Check(AName + ': not authenticated', not LClient.IsAuthenticated);
  if AExpectTokenRequest then
    Check(AName + ': one token request', GIdP.TokenCount = 1)
  else
    Check(AName + ': no token request', GIdP.TokenCount = 0);
  CheckStopped(AName + ': callback server stopped', PortOfURL(LastRedirectURI));
  LOp := nil;
  LClient := nil;
end;

/// <summary>
/// The token endpoint of the fake refuses what Keycloak refuses: otherwise every login test
/// would pass also with a wrong code_verifier or redirect_uri.
/// </summary>
procedure TestFakeTokenEndpoint;
const
  VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  REDIRECT = 'http://127.0.0.1:9/cb';

  function NewCode(AHTTP: THTTPClient; const AChallenge: string): string;
  var
    LResponse: IHTTPResponse;
    LLocation: string;
    LParams: TParams;
    LError: string;
  begin
    LResponse := AHTTP.Get(GIdP.RealmURL + '/protocol/openid-connect/auth?response_type=code&client_id=' +
      CLIENT_ID + '&redirect_uri=' + TNetEncoding.URL.Encode(REDIRECT) + '&state=s&nonce=n' +
      '&code_challenge=' + AChallenge + '&code_challenge_method=S256');
    LLocation := LResponse.HeaderValue['Location'];
    Result := '';
    if ParseQuery(LLocation.Substring(LLocation.IndexOf('?') + 1), LParams, LError) then
      Result := ParamValue(LParams, 'code');
  end;

  function Exchange(AHTTP: THTTPClient; const ACode, AVerifier, ARedirect: string; out ABody: string): Integer;
  var
    LForm: TStringList;
    LResponse: IHTTPResponse;
  begin
    LForm := TStringList.Create;
    try
      LForm.AddPair('grant_type', 'authorization_code');
      LForm.AddPair('client_id', CLIENT_ID);
      LForm.AddPair('code', ACode);
      LForm.AddPair('redirect_uri', ARedirect);
      if AVerifier <> '' then
        LForm.AddPair('code_verifier', AVerifier);
      LResponse := AHTTP.Post(GIdP.RealmURL + '/protocol/openid-connect/token', LForm);
      ABody := LResponse.ContentAsString;
      Result := LResponse.StatusCode;
    finally
      LForm.Free;
    end;
  end;

var
  LHTTP: THTTPClient;
  LCode, LBody: string;
begin
  GIdP.Reset;
  LHTTP := THTTPClient.Create;
  try
    LHTTP.HandleRedirects := False;

    LCode := NewCode(LHTTP, S256(VERIFIER));
    Check('fake: code issued', LCode <> '');
    Check('fake: wrong code_verifier refused', (Exchange(LHTTP, LCode, VERIFIER + 'x', REDIRECT, LBody) = 400) and
      LBody.Contains('PKCE verification failed'), LBody);
    Check('fake: code consumed by the failed exchange', (Exchange(LHTTP, LCode, VERIFIER, REDIRECT, LBody) = 400) and
      LBody.Contains('Code not valid'), LBody);

    LCode := NewCode(LHTTP, S256(VERIFIER));
    Check('fake: missing code_verifier refused', (Exchange(LHTTP, LCode, '', REDIRECT, LBody) = 400) and
      LBody.Contains('code verifier not specified'), LBody);

    LCode := NewCode(LHTTP, S256(VERIFIER));
    Check('fake: other redirect_uri refused', (Exchange(LHTTP, LCode, VERIFIER, REDIRECT + 'x', LBody) = 400) and
      LBody.Contains('Incorrect redirect_uri'), LBody);

    LCode := NewCode(LHTTP, S256(VERIFIER));
    Check('fake: right verifier and redirect_uri accepted', Exchange(LHTTP, LCode, VERIFIER, REDIRECT, LBody) = 200,
      LBody);
    Check('fake: code used once', (Exchange(LHTTP, LCode, VERIFIER, REDIRECT, LBody) = 400) and
      LBody.Contains('Code not valid'), LBody);

    LCode := NewCode(LHTTP, S256(VERIFIER));
    GIdP.Reset;
    Check('fake: codes of an earlier test refused', (Exchange(LHTTP, LCode, VERIFIER, REDIRECT, LBody) = 400) and
      LBody.Contains('Code not valid'), LBody);
  finally
    LHTTP.Free;
  end;
end;

procedure TestLoginErrors;
begin
  CheckLoginError('token endpoint error', tmInvalidGrant, amCode, 'invalid_grant', True);
  CheckLoginError('nonce mismatch', tmWrongNonce, amCode, 'Nonce mismatch', True,
    EIAM4DSecurityValidationException, ecNonceValidationFailed);
end;

/// <summary>
/// A discovery document that cannot be read raises EIAM4DDiscoveryFailedException (ecDiscoveryFailed)
/// from Build: here a realm the fake does not know (404).
/// </summary>
procedure TestDiscoveryFailure;
var
  LClass: string;
  LCode: TIAM4DErrorCode;
  LText: string;
begin
  LClass := '';
  LCode := ecUnknown;
  LText := '';
  try
    TIAM4DClientConfigBuilder.New.ForAuthorizationCode(GIdP.BaseURL, 'missing', CLIENT_ID).Build;
  except
    on E: EIAM4DException do
    begin
      LClass := E.ClassName;
      LCode := E.ErrorCode;
      LText := E.Message;
    end;
  end;
  Check('unknown realm: EIAM4DDiscoveryFailedException', LClass = EIAM4DDiscoveryFailedException.ClassName,
    LClass + ': ' + LText);
  Check('unknown realm: ecDiscoveryFailed', LCode = ecDiscoveryFailed, IntToStr(Ord(LCode)));
  Check('unknown realm: URL and status in the message',
    LText.Contains('/realms/missing/.well-known/openid-configuration') and LText.Contains('404'), LText);
end;

/// <summary>
/// Login through the local callback server with max_age AMaxAge (IAM4D_MAX_AGE_NONE: not
/// configured), the identity provider sending auth_time AAuthTime (0: omitted). AMessagePart
/// empty: the login succeeds; otherwise it fails with EIAM4DSecurityValidationException.
/// </summary>
procedure CheckAuthTimeLogin(const AName: string; AMaxAge: Integer; AAuthTime: Int64; const AMessagePart: string);
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
begin
  GIdP.Reset;
  GIdP.SetAuthTime(AAuthTime);
  GBrowser.Reset(bmFollow);
  if AMaxAge = IAM4D_MAX_AGE_NONE then
    LClient := NewLocalClient
  else
    LClient := TIAM4DClientConfigBuilder.New
      .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
      .WithMaxAge(AMaxAge)
      .Build;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check(AName + ': ends', LProbe.WaitDone);
  GBrowser.WaitIdle;
  if AMessagePart = '' then
  begin
    Check(AName + ': logged in', (LProbe.Successes = 1) and (LProbe.Errors = 0), LProbe.Outcome);
    Check(AName + ': authenticated', LClient.IsAuthenticated);
  end
  else
  begin
    Check(AName + ': OnError', (LProbe.Errors = 1) and (LProbe.Successes = 0), LProbe.Outcome);
    Check(AName + ': EIAM4DSecurityValidationException', Assigned(LProbe.ErrorClass) and
      LProbe.ErrorClass.InheritsFrom(EIAM4DSecurityValidationException), LProbe.ErrorText);
    Check(AName + ': message', LProbe.ErrorText.Contains(AMessagePart), LProbe.ErrorText);
    CheckEquals(AName + ': max_age in the Context', IntToStr(AMaxAge), LProbe.ErrorContext('max_age'));
    Check(AName + ': one token request', GIdP.TokenCount = 1);
    Check(AName + ': tokens discarded', not LClient.IsAuthenticated);
  end;
  LOp := nil;
  LClient := nil;
end;

procedure TestAuthTime;
var
  LNow: Int64;
  LClient: IIAM4DClient;
  LHTTP: THTTPClient;
  LLocation, LBase, LError: string;
  LParams: TParams;
  LRaised: Boolean;
begin
  LNow := DateTimeToUnix(TDateTime.NowUTC);
  CheckAuthTimeLogin('max_age=0, fresh auth_time', 0, LNow, '');
  CheckAuthTimeLogin('max_age=0, auth_time within the clock skew', 0,
    LNow - IAM4D_AUTH_TIME_CLOCK_SKEW_SECONDS + 60, '');
  CheckAuthTimeLogin('max_age=0, no auth_time', 0, 0, 'Missing auth_time');
  // max_age removed from the URL: Keycloak reuses the SSO session of an hour ago
  CheckAuthTimeLogin('max_age=0, SSO session of an hour ago', 0, LNow - 3600, 'Authentication too old');
  CheckAuthTimeLogin('max_age=3600, authentication 30 minutes ago', 3600, LNow - 1800, '');
  CheckAuthTimeLogin('max_age=600, authentication 30 minutes ago', 600, LNow - 1800, 'Authentication too old');
  // Without max_age auth_time is neither required nor checked
  CheckAuthTimeLogin('no max_age, no auth_time', IAM4D_MAX_AGE_NONE, 0, '');
  CheckAuthTimeLogin('no max_age, auth_time of yesterday', IAM4D_MAX_AGE_NONE, LNow - 86400, '');

  // External callback: CompleteAuthorizationFlow checks auth_time as well
  GIdP.Reset;
  GIdP.SetAuthTime(LNow - 3600);
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithMaxAge(0)
    .WithExternalCallback(EXTERNAL_CALLBACK)
    .Build;
  LClient.InitializeAuthorizationFlow;
  LHTTP := THTTPClient.Create;
  try
    LHTTP.HandleRedirects := False;
    LLocation := LHTTP.Get(LClient.GenerateAuthURL).HeaderValue['Location'];
  finally
    LHTTP.Free;
  end;
  Check('external: callback URL parses', ParseURL(LLocation, LBase, LParams, LError), LError);
  LRaised := False;
  try
    LClient.CompleteAuthorizationFlow(ParamValue(LParams, 'code'), ParamValue(LParams, 'state'));
  except
    on E: EIAM4DSecurityValidationException do
      LRaised := E.Message.Contains('Authentication too old');
  end;
  Check('external: old auth_time refused', LRaised);
  Check('external: tokens discarded', not LClient.IsAuthenticated);
end;

procedure TestBrowserRefused;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LRaised: Boolean;
  LMessage: string;
begin
  GIdP.Reset;
  GBrowser.Reset(bmRefuse);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LRaised := False;
  try
    StartLogin(LClient, LProbe);
  except
    on E: EIAM4DException do
    begin
      LRaised := True;
      LMessage := E.Message;
    end;
  end;
  Check('StartAuthorizationFlowAsync raises EIAM4DException', LRaised and LMessage.Contains('Failed to open browser'),
    LMessage);
  Check('no callback', LProbe.Finallies = 0, LProbe.Outcome);
  CheckStopped('callback server stopped', PortOfURL(LastRedirectURI));

  // The client is still usable
  GBrowser.Reset(bmFollow);
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('next login completes', LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
  GBrowser.WaitIdle;
  LOp := nil;
  LClient := nil;
end;

procedure TestCancelWhileWaiting;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LPort: Integer;
begin
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  LPort := PortOfURL(LastRedirectURI);
  // The probe connection is accepted while Cancel stops the server
  Check('callback server listening', IsListening(LPort));
  LOp.Cancel;
  Check('ends', LProbe.WaitDone(5000));
  Sleep(100);
  Check('cancelled: OnFinally once, no OnSuccess/OnError', IsCancelledOnce(LProbe), LProbe.Outcome);
  Check('operation cancelled', LOp.State = TAsyncOperationState.Cancelled);
  CheckStopped('callback server stopped', LPort);
  Check('not authenticated', not LClient.IsAuthenticated);
  LOp := nil;
  LClient := nil;
end;

procedure TestCancelAuthorizationFlow;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
begin
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  LClient.CancelAuthorizationFlow;
  Check('ends', LProbe.WaitDone(5000));
  Sleep(100);
  Check('cancelled: OnFinally once, no OnSuccess/OnError', IsCancelledOnce(LProbe), LProbe.Outcome);
  CheckStopped('callback server stopped', PortOfURL(LastRedirectURI));
  LOp := nil;
  LClient := nil;
end;

procedure TestDestroyWhileWaiting;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
begin
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  LClient := nil;
  Check('ends', LProbe.WaitDone(5000));
  Sleep(100);
  Check('cancelled: OnFinally once, no OnSuccess/OnError', IsCancelledOnce(LProbe), LProbe.Outcome);
  CheckStopped('callback server stopped', PortOfURL(LastRedirectURI));
  LOp := nil;
end;

procedure TestSecondLoginCancelsFirst;
var
  LClient: IIAM4DClient;
  LFirst, LSecond: ILoginProbe;
  LOp1, LOp2: IAsyncOperation<string>;
begin
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewLocalClient;
  LFirst := TLoginProbe.Create;
  LOp1 := StartLogin(LClient, LFirst);
  GBrowser.Reset(bmFollow);
  LSecond := TLoginProbe.Create;
  LOp2 := StartLogin(LClient, LSecond);
  Check('first ends', LFirst.WaitDone(5000));
  Check('second completes', LSecond.WaitDone);
  GBrowser.WaitIdle;
  Sleep(100);
  Check('first cancelled once', IsCancelledOnce(LFirst), LFirst.Outcome);
  Check('second succeeds once', (LSecond.Successes = 1) and (LSecond.Finallies = 1) and (LSecond.Errors = 0),
    LSecond.Outcome);
  Check('authenticated', LClient.IsAuthenticated);
  LOp1 := nil;
  LOp2 := nil;
  LClient := nil;
end;

procedure TestCancelDuringExchange;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
begin
  GIdP.Reset(tmTokens, amCode, SLOW_TOKEN_MS);
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('token endpoint reached', GIdP.TokenRequested.WaitFor(WAIT_MS) = wrSignaled);
  LOp.Cancel;
  Check('ends at once', LProbe.WaitDone(1000));
  Check('token response sent afterwards', GIdP.TokenResponded.WaitFor(WAIT_MS) = wrSignaled);
  GBrowser.WaitIdle;
  Sleep(300);
  Check('cancelled once: the late tokens settle nothing', IsCancelledOnce(LProbe), LProbe.Outcome);
  Check('tokens discarded: not authenticated', not LClient.IsAuthenticated);
  LOp := nil;
  LClient := nil;
end;

procedure TestDestroyDuringExchange;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LResponded: Boolean;
begin
  GIdP.Reset(tmTokens, amCode, SLOW_TOKEN_MS);
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('token endpoint reached', GIdP.TokenRequested.WaitFor(WAIT_MS) = wrSignaled);
  // The destructor waits for the running exchange, which discards its tokens
  LClient := nil;
  LResponded := GIdP.TokenResponded.WaitFor(0) = wrSignaled;
  Check('destructor waited for the exchange', LResponded);
  Check('ends', LProbe.WaitDone(5000));
  GBrowser.WaitIdle;
  Sleep(300);
  Check('cancelled once', IsCancelledOnce(LProbe), LProbe.Outcome);
  LOp := nil;
end;

procedure TestCancelAfterCompletion;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
begin
  GIdP.Reset;
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('completes', LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
  GBrowser.WaitIdle;
  LOp.Cancel;
  LClient.CancelAuthorizationFlow;
  Sleep(200);
  Check('outcome unchanged', (LProbe.Successes = 1) and (LProbe.Errors = 0) and (LProbe.Finallies = 1),
    LProbe.Outcome);
  Check('operation still completed', LOp.State = TAsyncOperationState.Completed);
  Check('still authenticated', LClient.IsAuthenticated);
  LOp := nil;
  LClient := nil;
end;

procedure TestErrorResponse;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LStatus: Integer;
  LBody: string;
begin
  GIdP.Reset(tmTokens, amAccessDenied);
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('ends', LProbe.WaitDone);
  GBrowser.WaitIdle;
  Sleep(100);
  Check('OnError and OnFinally once', (LProbe.Errors = 1) and (LProbe.Successes = 0) and
    (LProbe.Finallies = 1), LProbe.Outcome);
  Check('EIAM4DOAuth2CallbackException', LProbe.ErrorClass = EIAM4DOAuth2CallbackException, LProbe.ErrorText);
  CheckEquals('Context error', 'access_denied', LProbe.ErrorContext('error'));
  CheckEquals('Context error_description', ERROR_DESCRIPTION, LProbe.ErrorContext('error_description'));
  Check('message', LProbe.ErrorText.Contains('access_denied'), LProbe.ErrorText);
  Check('operation faulted', LOp.State = TAsyncOperationState.Faulted);
  Check('not authenticated', not LClient.IsAuthenticated);
  Check('no token request', GIdP.TokenCount = 0);
  CheckStopped('callback server stopped', PortOfURL(LastRedirectURI));
  GBrowser.LastPage(LStatus, LBody);
  Check('page: 400 with error and escaped description', (LStatus = 400) and LBody.Contains('access_denied') and
    LBody.Contains('User &lt;b&gt;denied&lt;/b&gt; the &quot;consent&quot; &amp; left'), IntToStr(LStatus));
  Check('page: no markup from the request', not LBody.Contains('<b>denied'));
  LOp := nil;
  LClient := nil;
end;

procedure CheckForgedError(const AName: string; AAuthMode: TAuthMode);
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LStatus: Integer;
  LBody, LBase, LError, LRedirect: string;
  LSent: TParams;
  LHTTP: THTTPClient;
begin
  GIdP.Reset(tmTokens, AAuthMode);
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  // The browser GET ends with the page of the callback server
  GBrowser.WaitIdle;
  Check(AName + ': the login keeps waiting', not LProbe.WaitDone(500), LProbe.Outcome);
  GBrowser.LastPage(LStatus, LBody);
  Check(AName + ': error page, nothing reflected', (LStatus = 400) and (not LBody.Contains('denied')) and
    LBody.ToLower.Contains('state'), IntToStr(LStatus));
  LRedirect := LastRedirectURI;
  Check(AName + ': callback server still listening', IsListening(PortOfURL(LRedirect)));

  // The callback of the authorization server still completes the login
  if ParseURL(GBrowser.LastURL, LBase, LSent, LError) then
  begin
    LHTTP := THTTPClient.Create;
    try
      LHTTP.Get(LRedirect + '?code=' + TNetEncoding.URL.Encode(GIdP.LastCode) + '&state=' +
        TNetEncoding.URL.Encode(ParamValue(LSent, 'state')));
    finally
      LHTTP.Free;
    end;
  end;
  Check(AName + ': the real callback then completes it', LProbe.WaitDone and (LProbe.Successes = 1) and
    (LProbe.Errors = 0) and (LProbe.Finallies = 1), LProbe.Outcome);
  Check(AName + ': authenticated', LClient.IsAuthenticated);
  LOp := nil;
  LClient := nil;
end;

procedure TestForgedErrors;
begin
  // Any web page can call the loopback URL: without the state of the flow nothing ends the login
  CheckForgedError('code with another state', amWrongState);
  CheckForgedError('error with another state', amErrorWrongState);
  CheckForgedError('error without state', amErrorNoState);
end;

// The same callback twice (reload, double request): one code exchange, and a foreign Host is refused
procedure TestRepeatedCallback;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LStatus: Integer;
  LBody, LBase, LError, LRedirect, LCallbackURL: string;
  LSent: TParams;
  LHTTP: THTTPClient;
  LResponse: IHTTPResponse;
begin
  // The exchange of the first callback is still running when the second arrives
  GIdP.Reset(tmTokens, amCode, 800);
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  GBrowser.WaitIdle;
  GBrowser.LastPage(LStatus, LBody);
  Check('repeated callback: the first is accepted', LStatus = 200, IntToStr(LStatus));
  LRedirect := LastRedirectURI;
  if ParseURL(GBrowser.LastURL, LBase, LSent, LError) then
  begin
    LCallbackURL := LRedirect + '?code=' + TNetEncoding.URL.Encode(GIdP.LastCode) + '&state=' +
      TNetEncoding.URL.Encode(ParamValue(LSent, 'state'));
    LHTTP := THTTPClient.Create;
    try
      LResponse := LHTTP.Get(LCallbackURL);
      Check('repeated callback: the second is refused', (LResponse.StatusCode = 400) and
        LResponse.ContentAsString.Contains('already received'), IntToStr(LResponse.StatusCode));
      Check('callback pages: no-store', LResponse.HeaderValue['Cache-Control'] = 'no-store',
        LResponse.HeaderValue['Cache-Control']);
      LHTTP.CustomHeaders['Host'] := 'attacker.example';
      LResponse := LHTTP.Get(LCallbackURL);
      Check('callback with a foreign Host: 400', LResponse.StatusCode = 400, IntToStr(LResponse.StatusCode));
    finally
      LHTTP.Free;
    end;
  end;
  Check('repeated callback: the login completes once', LProbe.WaitDone and (LProbe.Successes = 1) and
    (LProbe.Errors = 0), LProbe.Outcome);
  Check('repeated callback: one code exchange', GIdP.TokenCount = 1, IntToStr(GIdP.TokenCount));
  LOp := nil;
  LClient := nil;
end;

procedure TestStopWhileAccepting;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LRound, LCancelled: Integer;
  LStart, LSlowest: UInt64;
begin
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewLocalClient;
  LCancelled := 0;
  LSlowest := 0;
  for LRound := 1 to STOP_STRESS_ROUNDS do
  begin
    LProbe := TLoginProbe.Create;
    LOp := StartLogin(LClient, LProbe);
    // Connection still being accepted when Cancel stops the server (it used to hang there)
    IsListening(PortOfURL(LastRedirectURI));
    LStart := TThread.GetTickCount64;
    LOp.Cancel;
    if TThread.GetTickCount64 - LStart > LSlowest then
      LSlowest := TThread.GetTickCount64 - LStart;
    if LProbe.WaitDone(5000) and IsCancelledOnce(LProbe) then
      Inc(LCancelled);
    LOp := nil;
  end;
  Check(Format('%d rounds: every login cancelled once (slowest Cancel %d ms)', [STOP_STRESS_ROUNDS, LSlowest]),
    LCancelled = STOP_STRESS_ROUNDS, IntToStr(LCancelled));
  LClient := nil;
end;

procedure TestStopWithOpenConnection;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LConnection: TIdTCPClient;
  LTimes: TArray<UInt64>;
  LRound, LCancelled: Integer;
  LStart: UInt64;
begin
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewLocalClient;
  LCancelled := 0;
  SetLength(LTimes, STOP_OPEN_CONNECTION_ROUNDS);
  for LRound := 0 to High(LTimes) do
  begin
    LProbe := TLoginProbe.Create;
    LOp := StartLogin(LClient, LProbe);
    LConnection := TIdTCPClient.Create(nil);
    try
      LConnection.Host := '127.0.0.1';
      LConnection.Port := PortOfURL(LastRedirectURI);
      LConnection.ConnectTimeout := 2000;
      LConnection.Connect;
      // Idle connection, like a browser preconnect: accepted, its thread waits for a request
      Sleep(300);
      LStart := TThread.GetTickCount64;
      LClient.CancelAuthorizationFlow;
      LTimes[LRound] := TThread.GetTickCount64 - LStart;
    finally
      LConnection.Free;
    end;
    if LProbe.WaitDone(5000) and IsCancelledOnce(LProbe) then
      Inc(LCancelled);
    LOp := nil;
  end;
  Check(Format('%d rounds: every login cancelled once', [STOP_OPEN_CONNECTION_ROUNDS]),
    LCancelled = STOP_OPEN_CONNECTION_ROUNDS, IntToStr(LCancelled));
  TArray.Sort<UInt64>(LTimes);
  Check(Format('Stop does not wait 500 ms for the connection thread (median %d ms, at most %d)',
    [LTimes[Length(LTimes) div 2], STOP_OPEN_CONNECTION_MAX_MS]),
    LTimes[Length(LTimes) div 2] <= STOP_OPEN_CONNECTION_MAX_MS);
  LClient := nil;
end;

function NewPasswordClient(const AClientSecret: string = ''): IIAM4DClient;
begin
  Result := TIAM4DClientConfigBuilder.New.ForPassword(GIdP.BaseURL, REALM, CLIENT_ID, AClientSecret).Build;
end;

/// <summary>Class of the exception raised by AuthenticatePassword (nil: none)</summary>
function PasswordLoginError(const AClient: IIAM4DClient; const AUser, APassword: string;
  out AMessage: string): TClass;
begin
  Result := nil;
  AMessage := '';
  try
    AClient.AuthenticatePassword(AUser, APassword);
  except
    on E: Exception do
    begin
      Result := E.ClassType;
      AMessage := E.Message;
    end;
  end;
end;

procedure TestPasswordGrant;
var
  LClient: IIAM4DClient;
  LToken: string;
  LParams: TParams;
begin
  GIdP.Reset;
  LClient := NewPasswordClient;
  Check('not authenticated before the login', not LClient.IsAuthenticated);
  CheckEquals('no redirect URI for the password grant', '', LClient.RedirectURI);
  LToken := LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  Check('access token returned', LToken.StartsWith('at-password-'), LToken);
  Check('authenticated', LClient.IsAuthenticated);
  CheckEquals('GetAccessToken returns the stored token', LToken, LClient.GetAccessToken);
  Check('one token request, no authorization request', (GIdP.TokenCount = 1) and (GIdP.AuthCount = 0),
    Format('%d token, %d auth', [GIdP.TokenCount, GIdP.AuthCount]));

  LParams := GIdP.LastToken;
  CheckEquals('grant_type', 'password', ParamValue(LParams, 'grant_type'));
  CheckEquals('client_id', CLIENT_ID, ParamValue(LParams, 'client_id'));
  CheckEquals('username', PWD_USER, ParamValue(LParams, 'username'));
  CheckEquals('password (&, =, +, %, space, non-ASCII) encoded in the form', PWD_PASSWORD,
    ParamValue(LParams, 'password'));
  Check('scope has openid (id_token for the logout)', (' ' + ParamValue(LParams, 'scope') + ' ').Contains(' openid '),
    ParamValue(LParams, 'scope'));
  Check('no client_secret for a public client', ParamCount(LParams, 'client_secret') = 0);
  Check('no PKCE nor redirect_uri', (ParamCount(LParams, 'code_verifier') = 0) and
    (ParamCount(LParams, 'redirect_uri') = 0));

  // Confidential client
  GIdP.Reset;
  LClient := NewPasswordClient(PWD_CLIENT_SECRET);
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  CheckEquals('client_secret of a confidential client', PWD_CLIENT_SECRET,
    ParamValue(GIdP.LastToken, 'client_secret'));

  // Async
  GIdP.Reset;
  LToken := LClient.AuthenticatePasswordAsync(PWD_USER, PWD_PASSWORD).Run.WaitForResult(WAIT_MS);
  Check('AuthenticatePasswordAsync returns the access token', LToken.StartsWith('at-password-'), LToken);
  LClient := nil;
end;

procedure TestPasswordGrantErrors;
type
  TCase = record
    Name: string;
    User: string;
    Password: string;
    Expected: TClass;
  end;
var
  LCases: TArray<TCase>;
  LCase: TCase;
  LClient: IIAM4DClient;
  LClass: TClass;
  LMessage: string;
  LCode: TIAM4DErrorCode;

  function NewCase(const AName, AUser, APassword: string; AExpected: TClass): TCase;
  begin
    Result.Name := AName;
    Result.User := AUser;
    Result.Password := APassword;
    Result.Expected := AExpected;
  end;

begin
  LCases := [
    NewCase('wrong password', PWD_USER, 'wrong', EIAM4DInvalidCredentialsException),
    NewCase('unknown user', 'nobody', PWD_PASSWORD, EIAM4DInvalidCredentialsException),
    NewCase('empty username (no request)', '  ', PWD_PASSWORD, EIAM4DInvalidCredentialsException),
    NewCase('required action pending', PWD_USER_SETUP, PWD_PASSWORD, EIAM4DAccountNotFullySetUpException),
    NewCase('account disabled', PWD_USER_DISABLED, PWD_PASSWORD, EIAM4DAccountDisabledException)];

  for LCase in LCases do
  begin
    GIdP.Reset;
    LClient := NewPasswordClient;
    LClass := PasswordLoginError(LClient, LCase.User, LCase.Password, LMessage);
    Check(LCase.Name + ': ' + LCase.Expected.ClassName, LClass = LCase.Expected, LMessage);
    Check(LCase.Name + ': not authenticated', not LClient.IsAuthenticated);
  end;
  GIdP.Reset;
  LClient := NewPasswordClient;
  PasswordLoginError(LClient, '', PWD_PASSWORD, LMessage);
  Check('empty username: no token request', GIdP.TokenCount = 0, IntToStr(GIdP.TokenCount));

  // Error codes, for callers that do not know the classes (e.g. across a DLL boundary)
  GIdP.Reset;
  LClient := NewPasswordClient;
  LCode := ecUnknown;
  try
    LClient.AuthenticatePassword(PWD_USER_SETUP, PWD_PASSWORD);
  except
    on E: EIAM4DException do
      LCode := E.ErrorCode;
  end;
  Check('required action pending: ecAccountNotFullySetUp', LCode = ecAccountNotFullySetUp);

  // Another OAuth2 error: a plain EIAM4DException carrying the answer
  LClass := PasswordLoginError(LClient, PWD_USER_NO_DIRECT_GRANT, PWD_PASSWORD, LMessage);
  Check('direct grants disabled: EIAM4DException', Assigned(LClass) and LClass.InheritsFrom(EIAM4DException) and
    not LClass.InheritsFrom(EIAM4DInvalidCredentialsException), LMessage);
  Check('direct grants disabled: message has the error', LMessage.Contains('unauthorized_client'), LMessage);

  // A failed login keeps the tokens of the previous one
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  PasswordLoginError(LClient, PWD_USER, 'wrong', LMessage);
  Check('failed login keeps the previous session', LClient.IsAuthenticated);

  // The other grants refuse it
  GIdP.Reset;
  LClient := NewLocalClient;
  LClass := PasswordLoginError(LClient, PWD_USER, PWD_PASSWORD, LMessage);
  Check('Authorization Code client refuses AuthenticatePassword', Assigned(LClass) and
    LClass.InheritsFrom(EIAM4DException) and (GIdP.TokenCount = 0), LMessage);
  LClient := nil;
end;

procedure TestPasswordRefreshAndLogout;
var
  LClient: IIAM4DClient;
  LFirst, LSecond: string;
  LToken, LLogout: TParams;
begin
  GIdP.Reset(tmShortLived);
  LClient := NewPasswordClient;
  LFirst := LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  // expires_in 1 is within the expiry buffer: the access token is already stale
  LSecond := LClient.GetAccessToken;
  Check('GetAccessToken refreshes an expired token', LSecond.StartsWith('at-refresh_token-'), LSecond);
  Check('refreshed token differs', LSecond <> LFirst);
  LToken := GIdP.LastToken;
  CheckEquals('refresh: grant_type', 'refresh_token', ParamValue(LToken, 'grant_type'));
  CheckEquals('refresh: refresh token of the login', 'rt-' + LFirst.Substring(3),
    ParamValue(LToken, 'refresh_token'));
  CheckEquals('refresh: client_id', CLIENT_ID, ParamValue(LToken, 'client_id'));
  Check('still authenticated', LClient.IsAuthenticated);

  LClient.Logout;
  Check('logout: one POST to the end session endpoint', GIdP.LogoutCount = 1, IntToStr(GIdP.LogoutCount));
  LLogout := GIdP.LastLogout;
  CheckEquals('logout: refresh token of the session', 'rt-' + LSecond.Substring(3),
    ParamValue(LLogout, 'refresh_token'));
  CheckEquals('logout: client_id', CLIENT_ID, ParamValue(LLogout, 'client_id'));
  Check('logout: not authenticated', not LClient.IsAuthenticated);

  // Nothing to end: no request
  LClient.Logout;
  Check('logout without session: no request', GIdP.LogoutCount = 1, IntToStr(GIdP.LogoutCount));

  // A new login after the logout
  CheckEquals('login again after logout', 'at-password-', LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD).Substring(0, 12));
  Check('authenticated again', LClient.IsAuthenticated);
  LClient := nil;
end;

procedure TestAuthCodeLogout;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LCode: string;
begin
  GIdP.Reset;
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('login completes', LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
  GBrowser.WaitIdle;
  LCode := GIdP.LastCode;
  LClient.Logout;
  Check('logout: one POST to the end session endpoint', GIdP.LogoutCount = 1, IntToStr(GIdP.LogoutCount));
  CheckEquals('logout: refresh token of the login', 'rt-' + LCode, ParamValue(GIdP.LastLogout, 'refresh_token'));
  CheckEquals('logout: client_id', CLIENT_ID, ParamValue(GIdP.LastLogout, 'client_id'));
  Check('logout: not authenticated', not LClient.IsAuthenticated);
  LOp := nil;
  LClient := nil;
end;

procedure TestAuthRequestOptions;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LBase, LError: string;
  LParams: TParams;
begin
  GIdP.Reset;
  // Not configured: neither prompt nor max_age
  LClient := NewExternalClient;
  LClient.InitializeAuthorizationFlow;
  Check('default URL parses', ParseURL(LClient.GenerateAuthURL, LBase, LParams, LError), LError);
  Check('default: no prompt, no max_age, no login_hint', (ParamCount(LParams, 'prompt') = 0) and
    (ParamCount(LParams, 'max_age') = 0) and (ParamCount(LParams, 'login_hint') = 0), ParamNames(LParams));

  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithPrompt(IAM4D_PROMPT_LOGIN)
    .WithMaxAge(0)
    .WithExternalCallback(EXTERNAL_CALLBACK)
    .WithScopes(['openid', 'profile'])
    .Build;
  LClient.InitializeAuthorizationFlow;
  Check('URL parses', ParseURL(LClient.GenerateAuthURL, LBase, LParams, LError), LError);
  CheckEquals('prompt=login (kept by the later With* calls)', IAM4D_PROMPT_LOGIN, ParamValue(LParams, 'prompt'));
  CheckEquals('max_age=0', '0', ParamValue(LParams, 'max_age'));
  Check('prompt and max_age once', (ParamCount(LParams, 'prompt') = 1) and (ParamCount(LParams, 'max_age') = 1));

  // login_hint of StartAuthorizationFlowAsync
  GBrowser.Reset(bmIgnore);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := LClient.StartAuthorizationFlowAsync('entra', SPECIAL_LOGIN_HINT)
    .OnFinally(
      procedure
      begin
        LProbe.HandleFinally;
      end)
    .DispatchMode(TAsyncCallbackDispatchMode.dmInline)
    .Run;
  Check('login URL parses', ParseURL(GBrowser.LastURL, LBase, LParams, LError), LError);
  CheckEquals('login_hint in the login URL', SPECIAL_LOGIN_HINT, ParamValue(LParams, 'login_hint'));
  CheckIdpHint('login with login_hint', LParams, 'entra');
  LOp.Cancel;
  Check('login cancelled', LProbe.WaitDone and IsCancelledOnce(LProbe), LProbe.Outcome);
  LOp := nil;
  LClient := nil;
end;

/// <summary>True when AProc raises EArgumentException</summary>
function RaisesArgument(const AProc: TProc): Boolean;
begin
  Result := False;
  try
    AProc();
  except
    on EArgumentException do
      Result := True;
  end;
end;

/// <summary>Local login with AOptions, the identity provider sending auth_time AAuthTime</summary>
procedure CheckOptionsLogin(const AName: string; const AClient: IIAM4DClient;
  const AOptions: TIAM4DAuthRequestOptions; AAuthTime: Int64; const AMessagePart, AMaxAge: string);
var
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
begin
  GIdP.Reset;
  GIdP.SetAuthTime(AAuthTime);
  GBrowser.Reset(bmFollow);
  LProbe := TLoginProbe.Create;
  LOp := AClient.StartAuthorizationFlowAsync(AOptions)
    .OnSuccess(
      procedure(const AToken: string)
      begin
        LProbe.HandleSuccess(AToken);
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        LProbe.HandleError(AException);
      end)
    .OnFinally(
      procedure
      begin
        LProbe.HandleFinally;
      end)
    .DispatchMode(TAsyncCallbackDispatchMode.dmInline)
    .Run;
  Check(AName + ': ends', LProbe.WaitDone);
  GBrowser.WaitIdle;
  if AMessagePart = '' then
    Check(AName + ': logged in', (LProbe.Successes = 1) and (LProbe.Errors = 0), LProbe.Outcome)
  else
  begin
    Check(AName + ': OnError', (LProbe.Errors = 1) and (LProbe.Successes = 0), LProbe.Outcome);
    Check(AName + ': message', LProbe.ErrorText.Contains(AMessagePart), LProbe.ErrorText);
    CheckEquals(AName + ': max_age in the Context', AMaxAge, LProbe.ErrorContext('max_age'));
  end;
  LOp := nil;
end;

procedure TestPerLoginOptions;
var
  LClient: IIAM4DClient;
  LOptions: TIAM4DAuthRequestOptions;
  LHTTP: THTTPClient;
  LNow: Int64;
  LLocation, LBase, LError, LLoginURL: string;
  LParams: TParams;
  LRaised: Boolean;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LWaited: Cardinal;
begin
  LNow := DateTimeToUnix(TDateTime.NowUTC);

  // Values that would break the request are refused when set
  Check('prompt not in the OIDC list refused', RaisesArgument(procedure
    begin TIAM4DAuthRequestOptions.Create.WithPrompt('bogus'); end));
  Check('prompt none with another value refused', RaisesArgument(procedure
    begin TIAM4DAuthRequestOptions.Create.WithPrompt('none login'); end));
  Check('prompt login consent accepted', not RaisesArgument(procedure
    begin TIAM4DAuthRequestOptions.Create.WithPrompt(' login  consent '); end));
  Check('max_age below IAM4D_MAX_AGE_CONFIGURED refused', RaisesArgument(procedure
    begin TIAM4DAuthRequestOptions.Create.WithMaxAge(-3); end));
  Check('acr value with a space refused', RaisesArgument(procedure
    begin TIAM4DAuthRequestOptions.Create.WithAcrValues(['gold silver']); end));
  Check('empty ui_locales value refused', RaisesArgument(procedure
    begin TIAM4DAuthRequestOptions.Create.WithUILocales(['it', ' ']); end));
  Check('reserved parameter refused', RaisesArgument(procedure
    begin TIAM4DAuthRequestOptions.Create.WithParameter('state', 'x'); end));
  Check('reserved parameter of another case refused', RaisesArgument(procedure
    begin TIAM4DAuthRequestOptions.Create.WithParameter('Redirect_URI', 'https://evil.example'); end));
  Check('parameter name with "&" refused', RaisesArgument(procedure
    begin TIAM4DAuthRequestOptions.Create.WithParameter('a&b', 'x'); end));
  Check('default MaxAge keeps the configuration',
    TIAM4DAuthRequestOptions.Create.MaxAge = IAM4D_MAX_AGE_CONFIGURED);
  Check('a local without With* has the defaults', LOptions.MaxAge = IAM4D_MAX_AGE_CONFIGURED);
  LOptions := TIAM4DAuthRequestOptions.Create.WithParameter('Tenant', 'a').WithParameter('tenant', 'b')
    .WithParameter('tenant', 'c');
  Check('parameter names are case-sensitive: same case replaced, other case kept',
    (Length(LOptions.ParameterNames) = 2) and (LOptions.ParameterValues[0] = 'a') and
    (LOptions.ParameterValues[1] = 'c'), string.Join(',', LOptions.ParameterNames));

  // The options replace the configured values for one login
  GIdP.Reset;
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithPrompt(IAM4D_PROMPT_LOGIN)
    .WithMaxAge(0)
    .WithAcrValues(['silver'])
    .WithExternalCallback(EXTERNAL_CALLBACK)
    .Build;
  LOptions := TIAM4DAuthRequestOptions.Create
    .WithAcrValues(['gold', 'silver'])
    .WithPrompt(IAM4D_PROMPT_CONSENT)
    .WithMaxAge(IAM4D_MAX_AGE_NONE)
    .WithUILocales(['it', 'en'])
    .WithParameter('kc_theme', 'dark')
    .WithParameter('kc_theme', 'light & more');
  LClient.InitializeAuthorizationFlow(LOptions);
  Check('options: URL parses', ParseURL(LClient.GenerateAuthURL, LBase, LParams, LError), LError);
  CheckEquals('options: acr_values of the login', 'gold silver', ParamValue(LParams, 'acr_values'));
  CheckEquals('options: prompt of the login', IAM4D_PROMPT_CONSENT, ParamValue(LParams, 'prompt'));
  Check('options: max_age not sent', ParamCount(LParams, 'max_age') = 0, ParamNames(LParams));
  CheckEquals('options: ui_locales', 'it en', ParamValue(LParams, 'ui_locales'));
  CheckEquals('options: same parameter twice keeps the last value', 'light & more', ParamValue(LParams, 'kc_theme'));
  Check('options: each parameter once', (ParamCount(LParams, 'kc_theme') = 1) and
    (ParamCount(LParams, 'acr_values') = 1) and (ParamCount(LParams, 'prompt') = 1), ParamNames(LParams));
  Check('options: login_hint of GenerateAuthURL added', ParseURL(LClient.GenerateAuthURL('mario'), LBase,
    LParams, LError) and (ParamValue(LParams, 'login_hint') = 'mario') and
    (ParamValue(LParams, 'acr_values') = 'gold silver'), ParamNames(LParams));

  // A new flow without options is back to the configuration
  LClient.InitializeAuthorizationFlow;
  Check('configuration: URL parses', ParseURL(LClient.GenerateAuthURL, LBase, LParams, LError), LError);
  CheckEquals('configuration: acr_values', 'silver', ParamValue(LParams, 'acr_values'));
  CheckEquals('configuration: prompt', IAM4D_PROMPT_LOGIN, ParamValue(LParams, 'prompt'));
  CheckEquals('configuration: max_age', '0', ParamValue(LParams, 'max_age'));
  Check('configuration: no ui_locales, no kc_theme', (ParamCount(LParams, 'ui_locales') = 0) and
    (ParamCount(LParams, 'kc_theme') = 0), ParamNames(LParams));

  // auth_time is checked against the max_age of the login, not the configured one
  LClient := NewLocalClient;
  CheckOptionsLogin('max_age=600 of the login, authentication 30 minutes ago', LClient,
    TIAM4DAuthRequestOptions.Create.WithMaxAge(600), LNow - 1800, 'Authentication too old', '600');
  Check('max_age=600 of the login: in the login URL', ParseURL(GBrowser.LastURL, LBase, LParams, LError) and
    (ParamValue(LParams, 'max_age') = '600'), GBrowser.LastURL);
  CheckOptionsLogin('max_age=3600 of the login, authentication 30 minutes ago', LClient,
    TIAM4DAuthRequestOptions.Create.WithMaxAge(3600), LNow - 1800, '', '');
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithMaxAge(0)
    .Build;
  CheckOptionsLogin('max_age=0 configured, none for the login, authentication of yesterday', LClient,
    TIAM4DAuthRequestOptions.Create.WithMaxAge(IAM4D_MAX_AGE_NONE), LNow - 86400, '', '');
  CheckOptionsLogin('max_age=0 configured, kept by the options, authentication of yesterday', LClient,
    TIAM4DAuthRequestOptions.Create.WithAcrValues(['gold']), LNow - 86400, 'Authentication too old', '0');
  LClient := nil;

  // External callback: GenerateAuthURL(AOptions) changes the max_age the flow checks
  GIdP.Reset;
  GIdP.SetAuthTime(LNow - 1800);
  LClient := NewExternalClient;
  LClient.InitializeAuthorizationFlow;
  LHTTP := THTTPClient.Create;
  try
    LHTTP.HandleRedirects := False;
    LLocation := LHTTP.Get(LClient.GenerateAuthURL(TIAM4DAuthRequestOptions.Create.WithMaxAge(600)))
      .HeaderValue['Location'];
  finally
    LHTTP.Free;
  end;
  Check('external options: callback URL parses', ParseURL(LLocation, LBase, LParams, LError), LError);
  LRaised := False;
  try
    LClient.CompleteAuthorizationFlow(ParamValue(LParams, 'code'), ParamValue(LParams, 'state'));
  except
    on E: EIAM4DSecurityValidationException do
      LRaised := E.Message.Contains('Authentication too old');
  end;
  Check('external options: max_age of GenerateAuthURL checked', LRaised);
  Check('external options: tokens discarded', not LClient.IsAuthenticated);
  // The context consumed by that exchange is not brought back by another URL
  LClient.GenerateAuthURL(TIAM4DAuthRequestOptions.Create.WithMaxAge(60));
  LRaised := False;
  try
    LClient.CompleteAuthorizationFlow(ParamValue(LParams, 'code'), ParamValue(LParams, 'state'));
  except
    on E: EIAM4DException do
      LRaised := True;
  end;
  Check('external options: consumed state stays consumed', LRaised);
  LClient := nil;

  // Local server: a URL built during a login does not relax the max_age that login checks
  GIdP.Reset;
  GIdP.SetAuthTime(LNow - 86400);
  GBrowser.Reset(bmIgnore);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := LClient.StartAuthorizationFlowAsync(TIAM4DAuthRequestOptions.Create.WithMaxAge(0))
    .OnSuccess(
      procedure(const AToken: string)
      begin
        LProbe.HandleSuccess(AToken);
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        LProbe.HandleError(AException);
      end)
    .OnFinally(
      procedure
      begin
        LProbe.HandleFinally;
      end)
    .DispatchMode(TAsyncCallbackDispatchMode.dmInline)
    .Run;
  LWaited := 0;
  while (GBrowser.URLCount = 0) and (LWaited < WAIT_MS) do
  begin
    Sleep(10);
    Inc(LWaited, 10);
  end;
  LLoginURL := GBrowser.LastURL;
  LClient.GenerateAuthURL(TIAM4DAuthRequestOptions.Create.WithMaxAge(IAM4D_MAX_AGE_NONE));
  GBrowser.Reset(bmFollow);
  GBrowser.Open(LLoginURL);
  Check('local login, URL built meanwhile: ends', LProbe.WaitDone);
  GBrowser.WaitIdle;
  Check('local login, URL built meanwhile: max_age=0 still checked', (LProbe.Errors = 1) and
    LProbe.ErrorText.Contains('Authentication too old'), LProbe.Outcome + ' ' + LProbe.ErrorText);
  LOp := nil;
  LClient := nil;
end;

type
  /// <summary>
  /// Resource server: records the bearer and body of each request, answers 401 to the refused
  /// tokens, 302 on /redirect, 200 with the bearer otherwise.
  /// </summary>
  TFakeAPI = class
  private
    FServer: TIdHTTPServer;
    FLock: TCriticalSection;
    FBearers: TList<string>;
    FBodies: TList<string>;
    FRefused: TList<string>;
    FRefuseAll: Boolean;
    FDelayMs: Integer;
    procedure CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
      AResponseInfo: TIdHTTPResponseInfo);
    procedure ParseAuthentication(AContext: TIdContext; const AAuthType, AAuthData: string;
      var VUsername, VPassword: string; var VHandled: Boolean);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure Refuse(const AToken: string);
    procedure SetRefuseAll(AValue: Boolean);
    procedure SetDelay(AMs: Integer);
    function URL(const APath: string): string;
    function Count: Integer;
    function Bearer(AIndex: Integer): string;
    function Body(AIndex: Integer): string;
  end;

constructor TFakeAPI.Create;
begin
  inherited;
  FLock := TCriticalSection.Create;
  FBearers := TList<string>.Create;
  FBodies := TList<string>.Create;
  FRefused := TList<string>.Create;
  FServer := TIdHTTPServer.Create(nil);
  FServer.Bindings.Clear;
  with FServer.Bindings.Add do
  begin
    IP := '127.0.0.1';
    Port := 0;
  end;
  FServer.OnCommandGet := CommandGet;
  FServer.OnCommandOther := CommandGet;
  // Indy answers 401 itself to a scheme other than Basic
  FServer.OnParseAuthentication := ParseAuthentication;
  FServer.Active := True;
end;

procedure TFakeAPI.ParseAuthentication(AContext: TIdContext; const AAuthType, AAuthData: string;
  var VUsername, VPassword: string; var VHandled: Boolean);
begin
  VHandled := True;
end;

destructor TFakeAPI.Destroy;
begin
  FServer.Active := False;
  FServer.Free;
  FRefused.Free;
  FBodies.Free;
  FBearers.Free;
  FLock.Free;
  inherited;
end;

procedure TFakeAPI.Reset;
begin
  FLock.Acquire;
  try
    FBearers.Clear;
    FBodies.Clear;
    FRefused.Clear;
    FRefuseAll := False;
    FDelayMs := 0;
  finally
    FLock.Release;
  end;
end;

procedure TFakeAPI.Refuse(const AToken: string);
begin
  FLock.Acquire;
  try
    FRefused.Add(AToken);
  finally
    FLock.Release;
  end;
end;

procedure TFakeAPI.SetRefuseAll(AValue: Boolean);
begin
  FLock.Acquire;
  try
    FRefuseAll := AValue;
  finally
    FLock.Release;
  end;
end;

procedure TFakeAPI.SetDelay(AMs: Integer);
begin
  FLock.Acquire;
  try
    FDelayMs := AMs;
  finally
    FLock.Release;
  end;
end;

function TFakeAPI.URL(const APath: string): string;
begin
  Result := Format('http://127.0.0.1:%d%s', [FServer.Bindings[0].Port, APath]);
end;

function TFakeAPI.Count: Integer;
begin
  FLock.Acquire;
  try
    Result := FBearers.Count;
  finally
    FLock.Release;
  end;
end;

function TFakeAPI.Bearer(AIndex: Integer): string;
begin
  FLock.Acquire;
  try
    Result := FBearers[AIndex];
  finally
    FLock.Release;
  end;
end;

function TFakeAPI.Body(AIndex: Integer): string;
begin
  FLock.Acquire;
  try
    Result := FBodies[AIndex];
  finally
    FLock.Release;
  end;
end;

procedure TFakeAPI.CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
  AResponseInfo: TIdHTTPResponseInfo);
var
  LAuthorization, LToken, LBody: string;
  LRefused: Boolean;
  LDelay, LCount, I: Integer;
  LBytes: TBytes;
begin
  LAuthorization := ARequestInfo.RawHeaders.Values['Authorization'];
  LToken := '';
  if LAuthorization.StartsWith('Bearer ') then
    LToken := LAuthorization.Substring(7);
  // Exactly one Authorization header
  LCount := 0;
  for I := 0 to ARequestInfo.RawHeaders.Count - 1 do
    if SameText(ARequestInfo.RawHeaders.Names[I], 'Authorization') then
      Inc(LCount);
  if LCount > 1 then
    LToken := 'DUPLICATE';
  LBody := '';
  if Assigned(ARequestInfo.PostStream) and (ARequestInfo.PostStream.Size > 0) then
  begin
    SetLength(LBytes, ARequestInfo.PostStream.Size);
    ARequestInfo.PostStream.Position := 0;
    ARequestInfo.PostStream.ReadBuffer(LBytes, Length(LBytes));
    LBody := TEncoding.UTF8.GetString(LBytes);
  end;
  FLock.Acquire;
  try
    FBearers.Add(LToken);
    FBodies.Add(LBody);
    LRefused := FRefuseAll or FRefused.Contains(LToken) or LToken.IsEmpty;
    LDelay := FDelayMs;
  finally
    FLock.Release;
  end;
  if LDelay > 0 then
    Sleep(LDelay);
  if ARequestInfo.Document = '/redirect' then
  begin
    AResponseInfo.ResponseNo := 302;
    AResponseInfo.Location := URL('/elsewhere');
  end
  else if LRefused then
  begin
    AResponseInfo.ResponseNo := 401;
    AResponseInfo.CustomHeaders.Values['WWW-Authenticate'] := 'Bearer error="invalid_token"';
  end
  else
  begin
    AResponseInfo.ResponseNo := 200;
    AResponseInfo.ContentType := 'text/plain';
    AResponseInfo.ContentText := 'ok ' + LToken;
  end;
end;

/// <summary>Class of the exception AProc raises (nil: none)</summary>
function ProcRaisedClass(const AProc: TProc): ExceptClass;
begin
  Result := nil;
  try
    AProc();
  except
    on E: Exception do
      Result := ExceptClass(E.ClassType);
  end;
end;

procedure TestSessionClaims;
var
  LClient: IIAM4DClient;
  LClaims: TIAM4DIDTokenClaims;
  LScopes: TArray<string>;
  LRaised: Boolean;
begin
  // Nothing before the login
  GIdP.Reset;
  LClient := NewPasswordClient;
  Check('not authenticated: claims empty', LClient.GetIDTokenClaims.IsEmpty);
  Check('not authenticated: no granted scope', Length(LClient.GetGrantedScopes) = 0);

  GIdP.SetDirectGrantClaims('openid email roles',
    ',"acr":"gold","amr":["pwd","otp"],"sid":"sess-1","auth_time":1700000000,"email":"mario@example.com",' +
    '"name":"Mario Rossi","tenant":{"id":7}');
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  LClaims := LClient.GetIDTokenClaims;
  Check('claims: not empty', not LClaims.IsEmpty);
  CheckEquals('claims: sub', 'user-1', LClaims.Subject);
  CheckEquals('claims: iss', GIdP.RealmURL, LClaims.Issuer);
  Check('claims: aud', (Length(LClaims.Audience) = 1) and (LClaims.Audience[0] = CLIENT_ID));
  CheckEquals('claims: azp', CLIENT_ID, LClaims.AuthorizedParty);
  CheckEquals('claims: acr', 'gold', LClaims.Acr);
  Check('claims: amr', (Length(LClaims.Amr) = 2) and (LClaims.Amr[1] = 'otp'), string.Join(',', LClaims.Amr));
  CheckEquals('claims: sid', 'sess-1', LClaims.SessionID);
  CheckEquals('claims: auth_time', '1700000000', IntToStr(LClaims.AuthTime));
  Check('claims: iat and exp', (LClaims.IssuedAt > 0) and (LClaims.ExpiresAt > LClaims.IssuedAt));
  CheckEquals('claims: preferred_username', PWD_USER, LClaims.PreferredUsername);
  CheckEquals('claims: email', 'mario@example.com', LClaims.Email);
  CheckEquals('claims: name', 'Mario Rossi', LClaims.Name);
  CheckEquals('claims: custom object claim as JSON', '{"id":7}', LClaims.GetClaim('tenant'));
  Check('claims: HasClaim', LClaims.HasClaim('tenant') and not LClaims.HasClaim('missing'));
  CheckEquals('claims: missing claim empty', '', LClaims.GetClaim('missing'));

  LScopes := LClient.GetGrantedScopes;
  CheckEquals('granted scopes of the token response', 'openid email roles', string.Join(' ', LScopes));
  Check('HasGrantedScope', LClient.HasGrantedScope('email') and not LClient.HasGrantedScope('EMAIL') and
    not LClient.HasGrantedScope('profile'));

  // A refresh without scope keeps the granted ones (RFC 6749 5.1); the new id_token is read
  GIdP.SetDirectGrantClaims('', ',"acr":"silver"');
  LClient.InvalidateAccessToken(LClient.GetAccessToken);
  LClient.GetAccessToken;
  CheckEquals('refresh without scope: granted scopes kept', 'openid email roles',
    string.Join(' ', LClient.GetGrantedScopes));
  CheckEquals('refresh: claims of the refreshed id_token', 'silver', LClient.GetIDTokenClaims.Acr);

  // Login without scope in the answer: the requested scopes
  GIdP.Reset;
  GIdP.SetDirectGrantClaims('', '');
  LClient := TIAM4DClientConfigBuilder.New.ForPassword(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithScopes(['openid', 'profile'])
    .Build;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  Check('no scope in the answer: the requested ones', LClient.HasGrantedScope('profile'),
    string.Join(' ', LClient.GetGrantedScopes));

  LClient.Logout;
  Check('after Logout: claims empty, no scope', LClient.GetIDTokenClaims.IsEmpty and
    (Length(LClient.GetGrantedScopes) = 0));

  // Decoding without a client
  Check('FromIDToken of an empty token: empty', TIAM4DIDTokenClaims.FromIDToken('').IsEmpty);
  LRaised := False;
  try
    TIAM4DIDTokenClaims.FromIDToken('not-a-jwt');
  except
    on EIAM4DException do
      LRaised := True;
  end;
  Check('FromIDToken of a malformed token raises', LRaised);
  // NumericDate with a fraction or an exponent (accepted by the validation): read, not an error
  LClaims := TIAM4DIDTokenClaims.FromIDToken(
    TNetEncoding.Base64URL.Encode('{"alg":"none"}') + '.' +
    TNetEncoding.Base64URL.Encode('{"sub":"s","auth_time":1700000000.75,"iat":1.7E9,"exp":17000006E2}') + '.x');
  Check('FromIDToken: fractional and exponent NumericDate', (LClaims.AuthTime = 1700000000) and
    (LClaims.IssuedAt = 1700000000) and (LClaims.ExpiresAt = 1700000600),
    Format('%d %d %d', [LClaims.AuthTime, LClaims.IssuedAt, LClaims.ExpiresAt]));
  LClient := nil;
end;

procedure TestRevokeAndLogoutURL;
var
  LClient: IIAM4DClient;
  LAccess: string;
  LRevocations: TArray<string>;
  LClass: ExceptClass;
  LBase, LError: string;
  LParams: TParams;
begin
  // Refresh token first, then access token, then cleared
  GIdP.Reset;
  LClient := NewPasswordClient;
  LAccess := LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  LClient.RevokeTokens;
  LRevocations := GIdP.Revocations;
  Check('RevokeTokens: two revocations', Length(LRevocations) = 2, string.Join(', ', LRevocations));
  if Length(LRevocations) = 2 then
  begin
    Check('RevokeTokens: refresh token first, with client_id',
      LRevocations[0].StartsWith('refresh_token|rt-') and LRevocations[0].EndsWith('|' + CLIENT_ID), LRevocations[0]);
    CheckEquals('RevokeTokens: then the access token', 'access_token|' + LAccess + '|' + CLIENT_ID, LRevocations[1]);
  end;
  Check('RevokeTokens: tokens cleared', not LClient.IsAuthenticated);
  Check('RevokeTokens: no logout request', GIdP.LogoutCount = 0);

  // Nothing stored: nothing sent
  LClient.RevokeTokens;
  Check('RevokeTokens without tokens: no request', Length(GIdP.Revocations) = 2);

  // A server that cannot revoke access tokens is not an error
  GIdP.Reset;
  GIdP.SetRevokeMode(rvUnsupportedAccessToken);
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  LClass := ProcRaisedClass(procedure begin LClient.RevokeTokens; end);
  Check('unsupported_token_type for the access token: no error', LClass = nil);
  Check('unsupported_token_type: tokens cleared', not LClient.IsAuthenticated);

  // An error answer raises, the tokens go anyway
  GIdP.Reset;
  GIdP.SetRevokeMode(rvServerError);
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  LClass := ProcRaisedClass(procedure begin LClient.RevokeTokens; end);
  Check('revocation endpoint 500: EIAM4DException', Assigned(LClass) and LClass.InheritsFrom(EIAM4DException));
  Check('revocation endpoint 500: tokens cleared anyway', not LClient.IsAuthenticated);
  LRevocations := GIdP.Revocations;
  Check('revocation endpoint 500: the access token revoked too', (Length(LRevocations) = 2) and
    LRevocations[1].StartsWith('access_token|'), string.Join(', ', LRevocations));

  // No revocation endpoint: nothing sent, the tokens kept, Logout still ends the session
  GIdP.Reset;
  GIdP.SetRevokeMode(rvNoEndpoint);
  TIAM4DDiscoveryCache.Clear;
  try
    LClient := NewPasswordClient;
    LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
    LClass := ProcRaisedClass(procedure begin LClient.RevokeTokens; end);
    Check('no revocation endpoint: EIAM4DException', Assigned(LClass) and LClass.InheritsFrom(EIAM4DException));
    Check('no revocation endpoint: nothing sent, tokens kept',
      (Length(GIdP.Revocations) = 0) and LClient.IsAuthenticated);
    LClient.Logout;
    Check('no revocation endpoint: Logout ends the session', (GIdP.LogoutCount = 1) and not LClient.IsAuthenticated);
  finally
    GIdP.SetRevokeMode(rvOK);
    TIAM4DDiscoveryCache.Clear;
  end;
  LClient := NewPasswordClient;

  // Logout URL for the browser
  GIdP.Reset;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  Check('logout URL parses', ParseURL(LClient.GenerateLogoutURL('https://app.example.com/bye?x=1&y=2', 'st-1'),
    LBase, LParams, LError), LError);
  CheckEquals('logout URL: end session endpoint', GIdP.RealmURL + '/protocol/openid-connect/logout', LBase);
  CheckEquals('logout URL: client_id', CLIENT_ID, ParamValue(LParams, 'client_id'));
  Check('logout URL: id_token_hint of the session', ParamValue(LParams, 'id_token_hint').CountChar('.') = 2,
    ParamValue(LParams, 'id_token_hint'));
  CheckEquals('logout URL: post_logout_redirect_uri encoded', 'https://app.example.com/bye?x=1&y=2',
    ParamValue(LParams, 'post_logout_redirect_uri'));
  CheckEquals('logout URL: state', 'st-1', ParamValue(LParams, 'state'));
  Check('logout URL: nothing sent', GIdP.LogoutCount = 0);
  Check('logout URL: plain HTTP to the loopback accepted', ProcRaisedClass(procedure
    begin LClient.GenerateLogoutURL('http://127.0.0.1:8080/bye'); end) = nil);
  LClass := ProcRaisedClass(procedure begin LClient.GenerateLogoutURL('http://app.example.com/bye'); end);
  Check('logout URL: plain HTTP to another host refused',
    Assigned(LClass) and LClass.InheritsFrom(EIAM4DInvalidConfigurationException));
  LClass := ProcRaisedClass(procedure begin LClient.GenerateLogoutURL('javascript:alert(1)'); end);
  Check('logout URL: scheme other than HTTP(S) refused',
    Assigned(LClass) and LClass.InheritsFrom(EIAM4DInvalidConfigurationException));
  LClient.Logout;
  Check('logout URL without tokens parses', ParseURL(LClient.GenerateLogoutURL, LBase, LParams, LError), LError);
  Check('logout URL without tokens: no id_token_hint, no state', (ParamCount(LParams, 'id_token_hint') = 0) and
    (ParamCount(LParams, 'state') = 0) and (ParamCount(LParams, 'post_logout_redirect_uri') = 0), ParamNames(LParams));
  LClient := nil;
end;

/// <summary>Thread doing one GET with its own authorized client; AStatus[AIndex]: status, -1 on exception</summary>
function StartAuthorizedGet(const AClient: IIAM4DClient; const AURL: string; const AStatus: TArray<Integer>;
  AIndex: Integer): TThread;
begin
  Result := TThread.CreateAnonymousThread(
    procedure
    var
      LOwn: TIAM4DAuthorizedHTTPClient;
    begin
      LOwn := TIAM4DAuthorizedHTTPClient.Create(AClient);
      try
        try
          AStatus[AIndex] := LOwn.Get(AURL).StatusCode;
        except
          AStatus[AIndex] := -1;
        end;
      finally
        LOwn.Free;
      end;
    end);
  Result.FreeOnTerminate := False;
  Result.Start;
end;

procedure TestAuthorizedHTTPClient;
const
  THREADS = 8;
  // Not ASCII: the body goes as UTF-8
  JSON_BODY = '{"citt' + #$00E0 + '":"Trento"}';
var
  LAPI: TFakeAPI;
  LClient: IIAM4DClient;
  LHTTP: TIAM4DAuthorizedHTTPClient;
  LResponse: IHTTPResponse;
  LToken1, LToken2, LToken3: string;
  LTokens: Integer;
  LClass: ExceptClass;
  LTasks: TArray<TThread>;
  LStatus: TArray<Integer>;
  I, LOK: Integer;
begin
  LAPI := TFakeAPI.Create;
  try
    GIdP.Reset;
    LClient := NewPasswordClient;
    LToken1 := LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
    LHTTP := TIAM4DAuthorizedHTTPClient.Create(LClient);
    try
      // Bearer of the client, no renewal while the token is valid
      LTokens := GIdP.TokenCount;
      LResponse := LHTTP.Get(LAPI.URL('/api'));
      CheckEquals('GET: 200', '200', IntToStr(LResponse.StatusCode));
      CheckEquals('GET: bearer of the client', LToken1, LAPI.Bearer(0));
      CheckEquals('GET: body of the API', 'ok ' + LToken1, LResponse.ContentAsString);
      Check('GET: no token request', GIdP.TokenCount = LTokens);

      // 401 to a valid token (revoked): renewed once, the request sent again
      LAPI.Reset;
      LAPI.Refuse(LToken1);
      LResponse := LHTTP.Get(LAPI.URL('/api'));
      CheckEquals('401 then retry: 200', '200', IntToStr(LResponse.StatusCode));
      CheckEquals('401 then retry: two requests', '2', IntToStr(LAPI.Count));
      LToken2 := LClient.GetAccessToken;
      Check('401 then retry: token renewed', (LToken2 <> LToken1) and (LAPI.Bearer(1) = LToken2),
        LToken1 + ' / ' + LToken2);
      CheckEquals('401 then retry: one token request', IntToStr(LTokens + 1), IntToStr(GIdP.TokenCount));
      Check('401 then retry: session kept', LClient.IsAuthenticated);

      // The body is sent again from its start
      LAPI.Reset;
      LAPI.Refuse(LToken2);
      LResponse := LHTTP.Post(LAPI.URL('/api'), JSON_BODY, 'application/json');
      CheckEquals('POST retry: 200', '200', IntToStr(LResponse.StatusCode));
      Check('POST retry: same body twice', (LAPI.Count = 2) and (LAPI.Body(0) = JSON_BODY) and
        (LAPI.Body(1) = LAPI.Body(0)), LAPI.Body(0));
      LToken3 := LClient.GetAccessToken;

      // A second 401 is returned: one retry only
      LAPI.Reset;
      LAPI.SetRefuseAll(True);
      LTokens := GIdP.TokenCount;
      LResponse := LHTTP.Get(LAPI.URL('/api'));
      CheckEquals('always 401: returned', '401', IntToStr(LResponse.StatusCode));
      CheckEquals('always 401: two requests', '2', IntToStr(LAPI.Count));
      CheckEquals('always 401: one renewal', IntToStr(LTokens + 1), IntToStr(GIdP.TokenCount));
      LAPI.Reset;
      LAPI.SetRefuseAll(True);
      LHTTP.RetryOnUnauthorized := False;
      LResponse := LHTTP.Get(LAPI.URL('/api'));
      Check('RetryOnUnauthorized False: one request, 401',
        (LAPI.Count = 1) and (LResponse.StatusCode = 401), IntToStr(LAPI.Count));
      LHTTP.RetryOnUnauthorized := True;

      // A redirect is not followed: the bearer stays on the host that got it
      LAPI.Reset;
      LResponse := LHTTP.Get(LAPI.URL('/redirect'));
      Check('302 returned, not followed', (LResponse.StatusCode = 302) and (LAPI.Count = 1),
        IntToStr(LResponse.StatusCode) + ' / ' + IntToStr(LAPI.Count));
      // Also when HTTPClient is set to follow redirects after the constructor
      LAPI.Reset;
      LHTTP.HTTPClient.HandleRedirects := True;
      LResponse := LHTTP.Get(LAPI.URL('/redirect'));
      Check('HandleRedirects set later: 302 returned, not followed', (LResponse.StatusCode = 302) and
        (LAPI.Count = 1), IntToStr(LResponse.StatusCode) + ' / ' + IntToStr(LAPI.Count));

      // An Authorization in HTTPClient.CustomHeaders is replaced by the bearer: one header
      LAPI.Reset;
      LHTTP.HTTPClient.CustomHeaders['Authorization'] := 'Basic dXNlcjpwYXNz';
      LResponse := LHTTP.Get(LAPI.URL('/api'));
      CheckEquals('CustomHeaders Authorization: 200', '200', IntToStr(LResponse.StatusCode));
      CheckEquals('CustomHeaders Authorization: one header, the bearer', LClient.GetAccessToken, LAPI.Bearer(0));
      FreeAndNil(LHTTP);
      LHTTP := TIAM4DAuthorizedHTTPClient.Create(LClient);

      // Requests refused before sending anything
      LAPI.Reset;
      LClass := ProcRaisedClass(procedure
        begin
          LHTTP.Get(LAPI.URL('/api'), [TNetHeader.Create('authorization', 'Bearer other')]);
        end);
      Check('Authorization in AHeaders: EArgumentException', LClass = EArgumentException);
      LClass := ProcRaisedClass(procedure
        begin
          LHTTP.Get('http://api.example.com/data');
        end);
      Check('bearer over plain HTTP to another host refused',
        Assigned(LClass) and LClass.InheritsFrom(EIAM4DInvalidConfigurationException));
      LClass := ProcRaisedClass(procedure
        begin
          LHTTP.Get('ftp://127.0.0.1/data');
        end);
      Check('not HTTP(S): EArgumentException', LClass = EArgumentException);
      CheckEquals('refused requests: nothing sent', '0', IntToStr(LAPI.Count));
    finally
      LHTTP.Free;
    end;

    // InvalidateAccessToken leaves another token alone
    LTokens := GIdP.TokenCount;
    LToken3 := LClient.GetAccessToken;
    LClient.InvalidateAccessToken('at-not-the-current-one');
    LClient.InvalidateAccessToken('');
    Check('InvalidateAccessToken of another token: same token, no renewal',
      (LClient.GetAccessToken = LToken3) and (GIdP.TokenCount = LTokens));
    LClient.InvalidateAccessToken(LToken3);
    Check('InvalidateAccessToken of the current token: renewed once',
      (LClient.GetAccessToken <> LToken3) and (GIdP.TokenCount = LTokens + 1) and LClient.IsAuthenticated);

    // Concurrent 401s to the same token: one renewal, every request retried with the new token
    LAPI.Reset;
    LToken3 := LClient.GetAccessToken;
    LAPI.Refuse(LToken3);
    LAPI.SetDelay(50);
    LTokens := GIdP.TokenCount;
    SetLength(LTasks, THREADS);
    SetLength(LStatus, THREADS);
    for I := 0 to THREADS - 1 do
      LTasks[I] := StartAuthorizedGet(LClient, LAPI.URL('/api'), LStatus, I);
    LOK := 0;
    for I := 0 to THREADS - 1 do
    begin
      LTasks[I].WaitFor;
      LTasks[I].Free;
      if LStatus[I] = 200 then
        Inc(LOK);
    end;
    CheckEquals('concurrent 401s: every request 200', IntToStr(THREADS), IntToStr(LOK));
    CheckEquals('concurrent 401s: one renewal', IntToStr(LTokens + 1), IntToStr(GIdP.TokenCount));
    LClient := nil;
  finally
    LAPI.Free;
  end;
end;

/// <summary>A TCP port nobody listens on (bound and released at once)</summary>
function FreePort: Integer;
var
  LServer: TIdHTTPServer;
begin
  LServer := TIdHTTPServer.Create(nil);
  try
    LServer.Bindings.Clear;
    with LServer.Bindings.Add do
    begin
      IP := '127.0.0.1';
      Port := 0;
    end;
    LServer.Active := True;
    Result := LServer.Bindings[0].Port;
    LServer.Active := False;
  finally
    LServer.Free;
  end;
end;

procedure TestCallbackPort;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LPort: Integer;
begin
  GIdP.Reset;
  GBrowser.Reset(bmFollow);
  LPort := FreePort;
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithCallbackPort(LPort)
    .Build;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('login on the fixed port completes', LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
  GBrowser.WaitIdle;
  CheckEquals('redirect_uri on the configured port', Format('http://localhost:%d/oauth2callback', [LPort]),
    ParamValue(GIdP.LastAuth, 'redirect_uri'));
  LOp := nil;
  LClient := nil;
end;

procedure TestLoopbackRedirectHost;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LPort: Integer;
  LRaised: Boolean;
begin
  GIdP.Reset;
  GBrowser.Reset(bmFollow);
  LPort := FreePort;
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithCallbackPort(LPort)
    .WithLoopbackRedirectHost(lrhLoopbackIP)
    .Build;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('login with the loopback IP redirect completes', LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
  GBrowser.WaitIdle;
  CheckEquals('redirect_uri on 127.0.0.1', Format('http://127.0.0.1:%d/oauth2callback', [LPort]),
    ParamValue(GIdP.LastAuth, 'redirect_uri'));
  CheckEquals('the token request repeats it', Format('http://127.0.0.1:%d/oauth2callback', [LPort]),
    ParamValue(GIdP.LastToken, 'redirect_uri'));
  LOp := nil;
  LClient := nil;

  LRaised := False;
  try
    TIAM4DClientConfigBuilder.New.ForPassword(GIdP.BaseURL, REALM, CLIENT_ID)
      .WithLoopbackRedirectHost(lrhLoopbackIP);
  except
    on EInvalidOpException do
      LRaised := True;
  end;
  Check('password grant: loopback redirect host refused', LRaised);
end;

procedure TestAppActivation;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LMode: TIAM4DAppActivation;
  {$IFDEF MSWINDOWS}
  LWindow: HWND;
  LError: string;
  {$ENDIF}
begin
  // Without a visible window of the process, or with one: it never raises
  for LMode := Low(TIAM4DAppActivation) to High(TIAM4DAppActivation) do
    TIAM4DPlatformUtils.ActivateApplication(LMode);
  {$IFDEF MSWINDOWS}
  LWindow := CreateWindowEx(0, 'STATIC', 'IAM4D activation test', WS_OVERLAPPEDWINDOW or WS_VISIBLE,
    0, 0, 200, 100, 0, 0, HInstance, nil);
  try
    Check('test window created', LWindow <> 0);
    LError := '';
    for LMode := Low(TIAM4DAppActivation) to High(TIAM4DAppActivation) do
      try
        TIAM4DPlatformUtils.ActivateApplication(LMode);
      except
        on E: Exception do
          LError := LError + Format('mode %d: %s %s; ', [Ord(LMode), E.ClassName, E.Message]);
      end;
    Check('activation with a window: every mode returns without raising', LError = '', LError);
  finally
    if LWindow <> 0 then
      DestroyWindow(LWindow);
  end;
  {$ENDIF}

  // The login with the local server completes with each mode
  for LMode := Low(TIAM4DAppActivation) to High(TIAM4DAppActivation) do
  begin
    GIdP.Reset;
    GBrowser.Reset(bmFollow);
    LClient := TIAM4DClientConfigBuilder.New
      .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
      .WithAppActivation(LMode)
      .Build;
    LProbe := TLoginProbe.Create;
    LOp := StartLogin(LClient, LProbe);
    Check(Format('login with app activation %d completes', [Ord(LMode)]),
      LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
    GBrowser.WaitIdle;
    LOp := nil;
    LClient := nil;
  end;
end;

procedure TestKeycloakAction;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LBase, LError: string;
  LParams: TParams;
begin
  GIdP.Reset;
  GBrowser.Reset(bmFollow);
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithKeycloakAction(IAM4D_KC_ACTION_UPDATE_PASSWORD)
    .WithScopes(['openid', 'profile'])
    .Build;
  CheckEquals('no status before a login', '', LClient.KeycloakActionStatus);
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('login with kc_action completes', LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
  GBrowser.WaitIdle;
  CheckEquals('kc_action in the login URL (kept by the later With* calls)', IAM4D_KC_ACTION_UPDATE_PASSWORD,
    ParamValue(GIdP.LastAuth, 'kc_action'));
  Check('kc_action once', ParamCount(GIdP.LastAuth, 'kc_action') = 1);
  CheckEquals('kc_action_status success', IAM4D_KC_ACTION_STATUS_SUCCESS, LClient.KeycloakActionStatus);

  // Cancelled on the Keycloak page: the login succeeds anyway, only the status tells
  GIdP.SetActionStatus(IAM4D_KC_ACTION_STATUS_CANCELLED);
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('login with the action cancelled completes', LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
  GBrowser.WaitIdle;
  CheckEquals('kc_action_status cancelled', IAM4D_KC_ACTION_STATUS_CANCELLED, LClient.KeycloakActionStatus);

  // A login cancelled by the user before the callback leaves no status of the previous one
  GBrowser.Reset(bmIgnore);
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  CheckEquals('status cleared when a flow starts', '', LClient.KeycloakActionStatus);
  LOp.Cancel;
  Check('login cancelled', LProbe.WaitDone and IsCancelledOnce(LProbe), LProbe.Outcome);
  CheckEquals('no status after a cancelled flow', '', LClient.KeycloakActionStatus);

  // Without kc_action: nothing sent, no status
  GIdP.Reset;
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('login without kc_action completes', LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
  GBrowser.WaitIdle;
  Check('no kc_action by default', ParamCount(GIdP.LastAuth, 'kc_action') = 0, ParamNames(GIdP.LastAuth));
  CheckEquals('no status without kc_action', '', LClient.KeycloakActionStatus);

  // External callback: GenerateAuthURL carries kc_action too
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithExternalCallback(EXTERNAL_CALLBACK)
    .WithKeycloakAction(IAM4D_KC_ACTION_UPDATE_PASSWORD)
    .Build;
  LClient.InitializeAuthorizationFlow;
  Check('external URL parses', ParseURL(LClient.GenerateAuthURL, LBase, LParams, LError), LError);
  CheckEquals('kc_action in GenerateAuthURL', IAM4D_KC_ACTION_UPDATE_PASSWORD, ParamValue(LParams, 'kc_action'));
  LOp := nil;
  LClient := nil;
end;

procedure TestBuilderPassword;
var
  LBuilder: IIAM4DClientConfigBuilder;
  LConfig: TIAM4DClientConfig;

  function Raises(const AProc: TProc): Boolean;
  begin
    Result := False;
    try
      AProc();
    except
      on E: EInvalidOpException do
        Result := True;
    end;
  end;

begin
  LBuilder := TIAM4DClientConfigBuilder.New
    .ForPassword('https://idp.invalid', REALM, CLIENT_ID, PWD_CLIENT_SECRET)
    .WithScopes(['openid', 'profile'])
    .WithTimeouts(1234, 5678)
    .WithAllowSelfSignedSSL
    .WithTokenExpiryBuffer(7);
  LConfig := LBuilder.Config;
  Check('grant type stays gtPassword', LConfig.GrantType = gtPassword);
  CheckEquals('client secret kept', PWD_CLIENT_SECRET, LConfig.ClientSecret);
  Check('scopes applied', Length(LConfig.Scopes) = 2);
  Check('timeouts applied', (LConfig.ConnectionTimeout = 1234) and (LConfig.ResponseTimeout = 5678));
  Check('SSL mode applied', LConfig.SSLValidationMode = svmAllowSelfSigned);
  Check('expiry buffer applied', LConfig.TokenExpiryBufferSeconds = 7);
  Check('WithPrompt refused', Raises(procedure begin LBuilder.WithPrompt('login') end));
  Check('WithMaxAge refused', Raises(procedure begin LBuilder.WithMaxAge(0) end));
  Check('WithCallbackPort refused', Raises(procedure begin LBuilder.WithCallbackPort(8080) end));
  Check('WithAppActivation refused', Raises(procedure begin LBuilder.WithAppActivation(aaFlash) end));
  Check('WithIdentityProvider refused', Raises(procedure begin LBuilder.WithIdentityProvider('x') end));
  Check('WithKeycloakAction refused', Raises(procedure begin LBuilder.WithKeycloakAction('UPDATE_PASSWORD') end));

  // Authorization Code: prompt, max_age and port survive the other With* calls
  LConfig := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode('https://idp.invalid', REALM, CLIENT_ID, PWD_CLIENT_SECRET)
    .WithPrompt(IAM4D_PROMPT_LOGIN)
    .WithMaxAge(60)
    .WithCallbackPort(8765)
    .WithAppActivation(aaFlash)
    .WithTimeouts(1000, 2000)
    .WithIdentityProvider('spid')
    .Config;
  Check('authorization code keeps prompt, max_age, port, secret and hint',
    (LConfig.Prompt = IAM4D_PROMPT_LOGIN) and (LConfig.MaxAge = 60) and (LConfig.CallbackPort = 8765) and
    (LConfig.ClientSecret = PWD_CLIENT_SECRET) and (LConfig.IdpHint = 'spid') and (LConfig.ResponseTimeout = 2000));
  Check('app activation survives the other With* calls', LConfig.AppActivation = aaFlash);
  Check('app activation default: none', TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode('https://idp.invalid', REALM, CLIENT_ID).Config.AppActivation = aaNone);
  Check('max_age default: not sent', TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode('https://idp.invalid', REALM, CLIENT_ID).Config.MaxAge = IAM4D_MAX_AGE_NONE);
end;

/// <summary>Class of the exception raised by AProc (nil: none), with its message</summary>
function RaisedClass(const AProc: TProc; out AMessage: string; out ADescription: string): TClass;
begin
  Result := nil;
  AMessage := '';
  ADescription := '';
  try
    AProc();
  except
    on E: Exception do
    begin
      Result := E.ClassType;
      AMessage := E.Message;
      if (E is EIAM4DException) and EIAM4DException(E).Context.ContainsKey('error_description') then
        ADescription := EIAM4DException(E).Context['error_description'];
    end;
  end;
end;

procedure TestRefreshErrors;
var
  LClient: IIAM4DClient;
  LClass: TClass;
  LMessage, LDescription, LToken: string;
begin
  // Keycloak refuses the refresh token: the session is over
  GIdP.Reset(tmShortLived);
  LClient := NewPasswordClient;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  GIdP.SetBehavior(tmRefreshRefused);
  LClass := RaisedClass(procedure begin LClient.GetAccessToken end, LMessage, LDescription);
  Check('refused refresh: EIAM4DRefreshTokenExpiredException', LClass = EIAM4DRefreshTokenExpiredException,
    LMessage);
  CheckEquals('refused refresh: Keycloak''s reason in the context', 'Session not active', LDescription);
  Check('refused refresh: tokens cleared', not LClient.IsAuthenticated);

  // Keycloak failing (500): the tokens stay
  GIdP.Reset(tmShortLived);
  LClient := NewPasswordClient;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  GIdP.SetBehavior(tmRefreshServerError);
  LClass := RaisedClass(procedure begin LClient.GetAccessToken end, LMessage, LDescription);
  Check('server error on refresh: an EIAM4DException, not RefreshTokenExpired', Assigned(LClass) and
    LClass.InheritsFrom(EIAM4DException) and not LClass.InheritsFrom(EIAM4DRefreshTokenExpiredException), LMessage);
  Check('server error on refresh: still authenticated', LClient.IsAuthenticated);
  GIdP.SetBehavior(tmShortLived);
  LToken := LClient.GetAccessToken;
  Check('server error on refresh: the next call refreshes', LToken.StartsWith('at-refresh_token-'), LToken);

  // Network error (response timeout): the tokens stay
  GIdP.Reset(tmShortLived);
  LClient := TIAM4DClientConfigBuilder.New.ForPassword(GIdP.BaseURL, REALM, CLIENT_ID).WithTimeouts(2000, 400).Build;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  GIdP.SetBehavior(tmShortLived, 1500);
  LClass := RaisedClass(procedure begin LClient.GetAccessToken end, LMessage, LDescription);
  Check('timeout on refresh: EIAM4DNetworkTimeoutException', LClass = EIAM4DNetworkTimeoutException, LMessage);
  Check('timeout on refresh: still authenticated', LClient.IsAuthenticated);
  // The delayed answer of the fake identity provider must not overlap the next request
  GIdP.TokenResponded.WaitFor(5000);
  GIdP.SetBehavior(tmShortLived);
  LToken := LClient.GetAccessToken;
  Check('timeout on refresh: the next call refreshes', LToken.StartsWith('at-refresh_token-'), LToken);

  // No refresh_token in the refresh response (RFC 6749 6): the one of the login is kept
  GIdP.Reset(tmShortLived);
  LClient := NewPasswordClient;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  GIdP.SetBehavior(tmRefreshNoRotation);
  LToken := LClient.GetAccessToken;
  Check('refresh without rotation: refreshed', LToken.StartsWith('at-refresh_token-'), LToken);
  LClass := RaisedClass(procedure begin LToken := LClient.GetAccessToken end, LMessage, LDescription);
  Check('refresh without rotation: the next refresh uses the kept refresh token', (LClass = nil) and
    LToken.StartsWith('at-refresh_token-'), LMessage + LToken);
  Check('refresh without rotation: still authenticated', LClient.IsAuthenticated);
  LClient := nil;
end;

procedure TestLogoutErrors;
var
  LClient: IIAM4DClient;
  LClass: TClass;
  LMessage, LDescription: string;
begin
  // Refresh token refused at logout (already ended, revoked): nothing to end, no error
  GIdP.Reset;
  LClient := NewPasswordClient;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  GIdP.SetBehavior(tmTokens, 0, lmInvalidGrant);
  LClass := RaisedClass(procedure begin LClient.Logout end, LMessage, LDescription);
  Check('logout refused (invalid_grant): no exception', LClass = nil, LMessage);
  Check('logout refused: one request', GIdP.LogoutCount = 1, IntToStr(GIdP.LogoutCount));
  Check('logout refused: not authenticated', not LClient.IsAuthenticated);

  // Keycloak failing: the error is raised, the tokens go anyway
  GIdP.Reset;
  LClient := NewPasswordClient;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  GIdP.SetBehavior(tmTokens, 0, lmServerError);
  LClass := RaisedClass(procedure begin LClient.Logout end, LMessage, LDescription);
  Check('logout with a server error: EIAM4DException', Assigned(LClass) and LClass.InheritsFrom(EIAM4DException),
    LMessage);
  Check('logout with a server error: tokens cleared anyway', not LClient.IsAuthenticated);
  GIdP.SetBehavior(tmTokens);
  LClient.Logout;
  Check('logout again: no request (no tokens)', GIdP.LogoutCount = 1, IntToStr(GIdP.LogoutCount));

  // Refresh token already expired here: Keycloak would refuse it, no request
  GIdP.Reset(tmRefreshShortLived);
  LClient := NewPasswordClient;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  LClass := RaisedClass(procedure begin LClient.Logout end, LMessage, LDescription);
  Check('logout with an expired refresh token: no exception', LClass = nil, LMessage);
  Check('logout with an expired refresh token: no request', GIdP.LogoutCount = 0, IntToStr(GIdP.LogoutCount));
  Check('logout with an expired refresh token: not authenticated', not LClient.IsAuthenticated);
  LClient := nil;
end;

procedure TestScopesAfterLogout;
var
  LClient: IIAM4DClient;

  function Scope: string;
  begin
    Result := ' ' + ParamValue(GIdP.LastToken, 'scope') + ' ';
  end;

begin
  GIdP.Reset;
  LClient := TIAM4DClientConfigBuilder.New.ForPassword(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithScopes(['openid', 'profile', 'roles-ris']).Build;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  Check('first login: configured scopes', Scope.Contains(' profile ') and Scope.Contains(' roles-ris '), Scope);
  LClient.Logout;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  Check('login after logout: configured scopes kept', Scope.Contains(' profile ') and Scope.Contains(' roles-ris ') and
    Scope.Contains(' openid '), Scope);
  LClient := nil;
end;

procedure TestPasswordLoginAgain;
var
  LClient: IIAM4DClient;
  LFirst, LSecond: string;
begin
  GIdP.Reset;
  LClient := NewPasswordClient;
  LFirst := LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  LSecond := LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  Check('second login: the first session is ended', GIdP.LogoutCount = 1, IntToStr(GIdP.LogoutCount));
  CheckEquals('second login: refresh token of the first session', 'rt-' + LFirst.Substring(3),
    ParamValue(GIdP.LastLogout, 'refresh_token'));
  CheckEquals('second login: tokens of the second one', LSecond, LClient.GetAccessToken);

  // Ending the previous session fails: the new login counts anyway
  GIdP.SetBehavior(tmTokens, 0, lmServerError);
  LSecond := LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  Check('previous session not ended (500): the login succeeds', LSecond.StartsWith('at-password-') and
    LClient.IsAuthenticated, LSecond);

  // A failed login ends nothing
  GIdP.SetBehavior(tmTokens);
  PasswordLoginError(LClient, PWD_USER, 'wrong', LFirst);
  Check('failed login: the session is not ended', (GIdP.LogoutCount = 2) and LClient.IsAuthenticated,
    IntToStr(GIdP.LogoutCount));
  LClient := nil;
end;

procedure TestBuilderNoInheritedState;
var
  LConfig: TIAM4DClientConfig;
begin
  LConfig := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode('https://a.invalid', REALM, CLIENT_ID)
    .WithIdentityProvider('spid')
    .WithAcrValues(['gold'])
    .ForAuthorizationCode('https://b.invalid', REALM, CLIENT_ID)
    .WithScopes(['openid'])
    .Config;
  Check('a second ForAuthorizationCode does not inherit the identity provider', LConfig.IdpHint = '', LConfig.IdpHint);
  Check('a second ForAuthorizationCode does not inherit the ACR values', Length(LConfig.AcrValues) = 0);

  LConfig := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode('https://a.invalid', REALM, CLIENT_ID)
    .WithIdentityProvider('spid')
    .ForPassword('https://b.invalid', REALM, CLIENT_ID)
    .WithTimeouts(1000, 2000)
    .Config;
  Check('ForPassword after an identity provider: no hint', LConfig.IdpHint = '', LConfig.IdpHint);

  LConfig := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode('https://a.invalid', REALM, CLIENT_ID)
    .WithAcrValues(['gold', 'silver'])
    .WithIdentityProvider(' cie ')
    .WithTimeouts(1000, 2000)
    .Config;
  Check('ACR values and identity provider kept by later With* calls', (Length(LConfig.AcrValues) = 2) and
    (LConfig.AcrValues[1] = 'silver') and (LConfig.IdpHint = 'cie'));
end;

procedure TestDiscoveryCache;
var
  LClient: IIAM4DClient;
  LCount: Integer;
  LFailed: Boolean;
begin
  GIdP.Reset;
  TIAM4DDiscoveryCache.Clear;
  LCount := GIdP.DiscoveryCount;
  LClient := NewPasswordClient;
  LClient := NewPasswordClient;
  LClient := NewLocalClient;
  Check('three clients of the realm: one discovery request', GIdP.DiscoveryCount = LCount + 1,
    IntToStr(GIdP.DiscoveryCount - LCount));
  CheckEquals('cached endpoints work', 'at-password-',
    NewPasswordClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD).Substring(0, 12));

  // Pinned public keys: always the client's own request, and nothing stored
{$IFDEF LINUX}
  // Not supported on Linux (see TestCertificatePinning): a discovery of its own keeps the counts below
  TIAM4DDiscoveryCache.Clear;
  NewPasswordClient;
{$ELSE}
  LClient := TIAM4DClientConfigBuilder.New.ForPassword(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithPinnedPublicKeys([StringOfChar('a', 64)]).Build;
{$ENDIF}
  Check('pinned keys: own discovery request', GIdP.DiscoveryCount = LCount + 2, IntToStr(GIdP.DiscoveryCount - LCount));

  // Another SSL validation mode: another entry
  LClient := TIAM4DClientConfigBuilder.New.ForPassword(GIdP.BaseURL, REALM, CLIENT_ID).WithAllowSelfSignedSSL.Build;
  Check('other SSL mode: own entry', GIdP.DiscoveryCount = LCount + 3, IntToStr(GIdP.DiscoveryCount - LCount));

  // A failed discovery is not stored
  LCount := TIAM4DDiscoveryCache.Count;
  LFailed := False;
  try
    TIAM4DClientConfigBuilder.New.ForPassword(GIdP.BaseURL, 'missing', CLIENT_ID).Build;
  except
    LFailed := True;
  end;
  Check('unknown realm: Build fails, nothing stored', LFailed and (TIAM4DDiscoveryCache.Count = LCount),
    IntToStr(TIAM4DDiscoveryCache.Count));

  // Disabled, then expired
  LCount := GIdP.DiscoveryCount;
  TIAM4DDiscoveryCache.Enabled := False;
  try
    LClient := NewPasswordClient;
    LClient := NewPasswordClient;
    Check('disabled: a request per client', GIdP.DiscoveryCount = LCount + 2, IntToStr(GIdP.DiscoveryCount - LCount));
  finally
    TIAM4DDiscoveryCache.Enabled := True;
  end;
  TIAM4DDiscoveryCache.TimeToLiveSeconds := 1;
  try
    LClient := NewPasswordClient;
    LCount := GIdP.DiscoveryCount;
    // Well past the TTL of 1 s: a slow machine does not turn the expiry into a cache hit
    Sleep(1600);
    LClient := NewPasswordClient;
    Check('expired entry: fetched again', GIdP.DiscoveryCount = LCount + 1, IntToStr(GIdP.DiscoveryCount - LCount));
  finally
    TIAM4DDiscoveryCache.TimeToLiveSeconds := TIAM4DDiscoveryCache.DEFAULT_TIME_TO_LIVE_SECONDS;
  end;
  LClient := nil;
end;

function TestCertificate(const APublicKey: string; AExpired: Boolean = False): TCertificate;
begin
  Result := Default(TCertificate);
  Result.Subject := 'CN=idp.example.com';
  Result.Start := Now - 1;
  if AExpired then
    Result.Expiry := Now - 0.5
  else
    Result.Expiry := Now + 1;
  Result.PublicKey := APublicKey;
end;

/// <summary>
/// The HTTP calls of one client run in parallel (pool of HTTP clients, no lock held during the request)
/// </summary>
procedure TestHTTPClientConcurrency;
const
  DELAY_MS = 700;
var
  LClient: IIAM4DClient;
  LThreads: array[0..1] of TThread;
  LErrors, LTokensBefore, LMaxInFlight, I: Integer;
  LStart, LElapsed: UInt64;
begin
  GIdP.Reset;
  LClient := NewPasswordClient;
  // Discovery and the first pooled client
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  GIdP.SetBehavior(tmTokens, DELAY_MS);
  LTokensBefore := GIdP.TokenCount;
  LErrors := 0;
  LStart := TThread.GetTickCount64;
  for I := Low(LThreads) to High(LThreads) do
  begin
    LThreads[I] := TThread.CreateAnonymousThread(
      procedure
      begin
        try
          LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
        except
          AtomicIncrement(LErrors);
        end;
      end);
    LThreads[I].FreeOnTerminate := False;
    LThreads[I].Start;
  end;
  for I := Low(LThreads) to High(LThreads) do
  begin
    LThreads[I].WaitFor;
    LThreads[I].Free;
  end;
  LElapsed := TThread.GetTickCount64 - LStart;
  // Before SetBehavior, which resets it
  LMaxInFlight := GIdP.MaxTokensInFlight;
  GIdP.SetBehavior(tmTokens);

  Check('concurrent logins succeed', LErrors = 0, Format('%d errors', [LErrors]));
  Check('two token requests', GIdP.TokenCount - LTokensBefore = 2,
    Format('%d', [GIdP.TokenCount - LTokensBefore]));
  // Measured by the identity provider, not by the clock: serialized they would never be two at once
  Check('the two requests overlap (served at the same time)', LMaxInFlight = 2,
    Format('%d at most, %d ms', [LMaxInFlight, LElapsed]));

  // A new configuration while the pool holds clients: the next call uses the new one
  LClient.ConfigureAsync(TIAM4DClientConfigBuilder.New.ForPassword(GIdP.BaseURL, REALM, CLIENT_ID).GetConfig)
    .Run.WaitForCompletion(WAIT_MS);
  Check('works after a new configuration', LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD).StartsWith('at-password-'));
end;

procedure TestCertificatePinning;
const
  // RSA modulus in uppercase hex, as THTTPClient reports it on Windows and Android
  SERVER_KEY = 'C3A1F00D5EEDBEEF0123456789ABCDEF';
  OTHER_KEY = 'D4B2E11E6FFECFF01234567890ABCDEF';
var
  LValidator: IIAM4DSSLCertificateValidator;
  LPin: string;
{$IFDEF LINUX}
  LRaised: Boolean;
{$ELSE}
  LClient: IIAM4DClient;
  LHTTP: THTTPClient;
{$ENDIF}
begin
  LValidator := TIAM4DSSLCertificateValidator.Create;
  // CalculatePublicKeyHash returns uppercase hex; the pins are compared in any case
  LPin := TIAM4DSSLCertificateValidator.CalculatePublicKeyHash(SERVER_KEY);

  Check('strict, no pins: system verdict accepted', LValidator.ValidateCertificate(TestCertificate(OTHER_KEY), True));
  Check('strict, no pins: system verdict refused', not LValidator.ValidateCertificate(TestCertificate(SERVER_KEY), False));
{$IFDEF ANDROID}
  // Android: the RTL ignores a refused chain without a callback, so a strict client always has one
  Check('strict, no pins: callback needed on Android',
    TIAM4DHTTPClientSSLHelper.IsCallbackNeeded(svmStrict, LValidator));
{$ELSE}
  Check('strict, no pins: no callback needed',
    not TIAM4DHTTPClientSSLHelper.IsCallbackNeeded(svmStrict, LValidator));
{$ENDIF}
  Check('self-signed: callback needed', TIAM4DHTTPClientSSLHelper.IsCallbackNeeded(svmAllowSelfSigned, LValidator));

{$IFDEF LINUX}
  LRaised := False;
  try
    LValidator.AddPinnedPublicKeys([LPin]);
  except
    on ENotSupportedException do
      LRaised := True;
  end;
  Check('Linux: pinning refused', LRaised and not LValidator.HasPinnedPublicKeys);
{$ELSE}
  LValidator.AddPinnedPublicKeys([LPin]);
  Check('pin added (uppercase hash)', LValidator.HasPinnedPublicKeys);
  Check('strict with pins: callback needed', TIAM4DHTTPClientSSLHelper.IsCallbackNeeded(svmStrict, LValidator));

  Check('strict: pinned key accepted', LValidator.ValidateCertificate(TestCertificate(SERVER_KEY), True));
  Check('strict: other key refused although the system accepts it',
    not LValidator.ValidateCertificate(TestCertificate(OTHER_KEY), True));
  Check('strict: pinned key refused when the system refuses it',
    not LValidator.ValidateCertificate(TestCertificate(SERVER_KEY), False));
  Check('strict: no public key reported (not RSA) refused, no exception',
    not LValidator.ValidateCertificate(TestCertificate(''), True));

  LValidator.SetValidationMode(svmAllowSelfSigned);
  Check('self-signed: pinned key accepted without the system', LValidator.ValidateCertificate(TestCertificate(SERVER_KEY), False));
  Check('self-signed: other key refused', not LValidator.ValidateCertificate(TestCertificate(OTHER_KEY), False));
  Check('self-signed: expired certificate refused', not LValidator.ValidateCertificate(TestCertificate(SERVER_KEY, True), False));

  LValidator.SetValidationMode(svmStrict);
  LValidator.ClearPinnedPublicKeys;
  Check('pins cleared: system verdict again', LValidator.ValidateCertificate(TestCertificate(OTHER_KEY), True) and
    not LValidator.HasPinnedPublicKeys);

  // A strict client calls the validator only when it has pins
  GIdP.Reset;
  LClient := TIAM4DClientConfigBuilder.New.ForPassword(GIdP.BaseURL, REALM, CLIENT_ID).Build;
  LHTTP := LClient.CreateHTTPClient;
  try
    Check('strict client without pins: platform validation only',
      {$IFDEF ANDROID}Assigned{$ELSE}not Assigned{$ENDIF}(LHTTP.OnValidateServerCertificate));
  finally
    LHTTP.Free;
  end;
  LClient.AddPinnedPublicKeys([LPin]);
  LHTTP := LClient.CreateHTTPClient;
  try
    Check('strict client with pins: validator called', Assigned(LHTTP.OnValidateServerCertificate));
  finally
    LHTTP.Free;
  end;
  CheckEquals('pinned client still works over HTTP', 'at-password-',
    LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD).Substring(0, 12));
  LClient.ClearPinnedPublicKeys;
  LHTTP := LClient.CreateHTTPClient;
  try
    Check('pins cleared: platform validation only',
      {$IFDEF ANDROID}Assigned{$ELSE}not Assigned{$ENDIF}(LHTTP.OnValidateServerCertificate));
  finally
    LHTTP.Free;
  end;
  LClient := nil;
{$ENDIF}
end;

procedure TestReleaseDuringAsync;
var
  LClient: IIAM4DClient;
  LOp: IAsyncOperation<string>;
  LStart: UInt64;
  LReleaseMs: UInt64;
  LToken: string;
begin
  GIdP.Reset(tmTokens, amCode, SLOW_TOKEN_MS);
  LClient := NewPasswordClient;
  LOp := LClient.AuthenticatePasswordAsync(PWD_USER, PWD_PASSWORD).Run;
  Check('token endpoint reached', GIdP.TokenRequested.WaitFor(WAIT_MS) = wrSignaled);
  // The task holds a reference: releasing the last one of the caller frees nothing in use
  LStart := TThread.GetTickCount64;
  LClient := nil;
  LReleaseMs := TThread.GetTickCount64 - LStart;
  Check('release does not wait for the request', LReleaseMs < SLOW_TOKEN_MS div 2, IntToStr(LReleaseMs) + ' ms');
  try
    LToken := LOp.WaitForResult(WAIT_MS);
  except
    on E: Exception do
      LToken := E.ClassName + ': ' + E.Message;
  end;
  Check('operation completes with the token', LToken.StartsWith('at-password-'), LToken);
  LOp := nil;
end;

type
  /// <summary>Keeps its lines on Clear while Hold: what SecureZeroStrings left in them can be read</summary>
  TKeepingStringList = class(TStringList)
  public
    Hold: Boolean;
    ClearCalls: Integer;
    procedure Clear; override;
  end;

procedure TKeepingStringList.Clear;
begin
  Inc(ClearCalls);
  if not Hold then
    inherited;
end;

procedure TestSecureZeroStrings;
var
  LList: TStringList;
  LKeeping: TKeepingStringList;
  LShared, LLine: string;
  LPasswordLength: Integer;
begin
  LList := TStringList.Create;
  try
    LList.AddPair('client_id', CLIENT_ID);
    LList.AddPair('password', PWD_PASSWORD);
    LShared := LList[0];
    SecureZeroStrings(LList);
    Check('list cleared', LList.Count = 0);
    CheckEquals('a line shared with another variable is not overwritten', 'client_id=' + CLIENT_ID, LShared);
  finally
    LList.Free;
  end;

  // The memory of a line held by the list alone is zeroed before Clear
  LKeeping := TKeepingStringList.Create;
  try
    LKeeping.Hold := True;
    LKeeping.AddPair('client_id', CLIENT_ID);
    LKeeping.AddPair('password', PWD_PASSWORD);
    LPasswordLength := Length('password=' + PWD_PASSWORD);
    LShared := LKeeping[0];
    SecureZeroStrings(LKeeping);
    LLine := LKeeping[1];
    Check('Clear called', LKeeping.ClearCalls = 1);
    CheckEquals('the line held by the list alone is zeroed', StringOfChar(#0, LPasswordLength), LLine);
    CheckEquals('the shared line keeps its value', 'client_id=' + CLIENT_ID, LKeeping[0]);
    LLine := '';
    LKeeping.Hold := False;
  finally
    LKeeping.Free;
  end;
end;

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

// ---------------------------------------------------------------------------
// App redirect (private-use URI scheme, mobile apps)
// ---------------------------------------------------------------------------

function RaisesClass(const AProc: TProc; AClass: ExceptClass): Boolean;
begin
  Result := False;
  try
    AProc();
  except
    on E: Exception do
      Result := E.InheritsFrom(AClass);
  end;
end;

function IsValidAppRedirect(const AURI: string): Boolean;
var
  LError: string;
begin
  Result := TIAM4DAppRedirectCallbackHandler.IsValidRedirectURI(AURI, LError);
end;

procedure TestAppRedirectValidation;
var
  LURIs: TArray<string>;
  LURI, LError: string;
  LClient: IIAM4DClient;
begin
  LURIs := ['it.iam4d.identitybrokering:/oauth2callback', 'com.example.app:/cb', 'com.example.app://cb',
    'a.b:/x', 'com.example.app:/', 'com.example-app+x.y2:/cb'];
  for LURI in LURIs do
    Check('valid: ' + LURI, IsValidAppRedirect(LURI));

  LURIs := ['', '   ', 'http://localhost/cb', 'https://app.example.com/cb', 'com.example.app:/cb?x=1',
    'com.example.app:/cb#f', 'noscheme', ':/cb', 'myapp:/cb', 'Com.Example.App:/cb', 'com..example:/cb',
    '.com.example:/cb', 'com.example.:/cb', 'com.example.app:cb', '1com.example:/cb', 'com.exa mple:/cb',
    'com.example_x.app:/cb'];
  for LURI in LURIs do
    Check('invalid: "' + LURI + '"', not IsValidAppRedirect(LURI));

  Check('http: the message points to WithExternalCallback',
    (not TIAM4DAppRedirectCallbackHandler.IsValidRedirectURI('http://localhost/cb', LError)) and
    LError.Contains('WithExternalCallback'), LError);
  Check('no dot: the message says reverse domain name',
    (not TIAM4DAppRedirectCallbackHandler.IsValidRedirectURI('myapp:/cb', LError)) and
    LError.Contains('reverse domain'), LError);

  Check('builder, password grant: EInvalidOpException',
    RaisesClass(
      procedure
      begin
        TIAM4DClientConfigBuilder.New.ForPassword('https://idp.invalid', REALM, CLIENT_ID)
          .WithAppRedirect(APP_REDIRECT);
      end, EInvalidOpException));
  Check('builder, http URI: EArgumentException',
    RaisesClass(
      procedure
      begin
        TIAM4DClientConfigBuilder.New.ForAuthorizationCode('https://idp.invalid', REALM, CLIENT_ID)
          .WithAppRedirect('http://localhost/cb');
      end, EArgumentException));
  Check('builder, empty URI: EArgumentException',
    RaisesClass(
      procedure
      begin
        TIAM4DClientConfigBuilder.New.ForAuthorizationCode('https://idp.invalid', REALM, CLIENT_ID)
          .WithAppRedirect('');
      end, EArgumentException));
  Check('handler, invalid URI: EIAM4DCallbackHandlerException',
    RaisesClass(
      procedure
      begin
        TIAM4DAppRedirectCallbackHandler.Create('http://localhost/cb');
      end, EIAM4DCallbackHandlerException));

  LClient := NewAppClient;
  Check('builder, valid URI: client built', Assigned(LClient));
  LClient := nil;
  Check('cbmExternal: StartAuthorizationFlowAsync still raises',
    RaisesClass(
      procedure
      var
        LExternal: IIAM4DClient;
      begin
        LExternal := NewExternalClient;
        LExternal.StartAuthorizationFlowAsync('');
      end, EIAM4DException));
end;

procedure TestAppRedirectParser;
var
  LResult: TIAM4DOAuth2CallbackResult;
  LURL: string;
begin
  LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback(
    'it.iam4d.test:/oauth2callback?code=a%2Bb%2Fc%3D&state=s%20t');
  CheckEquals('scheme:/path: code decoded', 'a+b/c=', LResult.Code);
  CheckEquals('scheme:/path: state decoded', 's t', LResult.State);
  Check('scheme:/path: success', LResult.IsSuccess);

  LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback(
    'it.iam4d.test:/oauth2callback?error=access_denied&error_description=No%20way%20%26%20out&state=s1');
  CheckEquals('error', 'access_denied', LResult.Error);
  CheckEquals('error_description decoded', 'No way & out', LResult.ErrorDescription);
  CheckEquals('error: state', 's1', LResult.State);
  Check('error: IsError', LResult.IsError);

  LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback('it.iam4d.test:/oauth2callback?code=c1&state=s1#frag');
  Check('fragment ends the query', (LResult.Code = 'c1') and (LResult.State = 's1'), LResult.State);

  LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback('it.iam4d.test:/oauth2callback#code=c1&state=s1');
  Check('parameters in the fragment are not read', (LResult.Code = '') and (LResult.State = ''));

  LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback(
    'it.iam4d.test:/oauth2callback?code=c1&state=s1&session_state=zz&iss=https%3A%2F%2Fidp.example.com');
  Check('session_state and iss do not disturb', (LResult.Code = 'c1') and (LResult.State = 's1'));

  LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback(
    'it.iam4d.test:/oauth2callback?code=c1&state=s1&kc_action_status=success');
  CheckEquals('kc_action_status', 'success', LResult.KeycloakActionStatus);

  LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback('it.iam4d.test:/oauth2callback');
  Check('no query', (LResult.Code = '') and (LResult.State = '') and (not LResult.IsError));

  LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback('it.iam4d.test://oauth2callback?code=c1&state=s1');
  Check('scheme://path', (LResult.Code = 'c1') and (LResult.State = 's1'));

  LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback('http://localhost:18080/oauth2callback?code=c1&state=s1');
  Check('http unchanged', (LResult.Code = 'c1') and (LResult.State = 's1'));

  for LURL in ['', 'garbage', '/cb?code=c1&state=s1', '1bad:/x?code=c1', 'http://host:abc/cb?code=c1'] do
    Check('malformed URL "' + LURL + '": EIAM4DOAuth2CallbackException',
      RaisesClass(
        procedure
        begin
          TIAM4DOAuth2URLParser.ParseOAuth2Callback(LURL);
        end, EIAM4DOAuth2CallbackException));
end;

procedure TestAppRedirectLogin;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LAuth, LToken: TParams;
  LLocation, LCode: string;
  LHandled: Boolean;
begin
  GIdP.Reset;
  GBrowser.Reset(bmAppRedirect);
  LClient := NewAppClient;
  LProbe := TLoginProbe.Create;
  // The redirect is held: the login must be waiting for it, not done
  GBrowser.HoldRedirects;
  LOp := StartLogin(LClient, LProbe);
  Check('login waits for the redirect', WaitUntil(
    function: Boolean
    begin
      Result := TIAM4DAppRedirect.IsWaiting;
    end) and not LProbe.WaitDone(200));
  GBrowser.ReleaseRedirects;
  Check('completes', LProbe.WaitDone);
  GBrowser.WaitIdle;
  LCode := GIdP.LastCode;
  Check('OnSuccess and OnFinally once', (LProbe.Successes = 1) and (LProbe.Errors = 0) and
    (LProbe.Finallies = 1), LProbe.Outcome);
  CheckEquals('access token of the exchanged code', 'at-' + LCode, LProbe.Token);
  Check('authenticated', LClient.IsAuthenticated);
  Check('operation completed', LOp.State = TAsyncOperationState.Completed);

  LAuth := GIdP.LastAuth;
  CheckEquals('redirect_uri is the app URI', APP_REDIRECT, ParamValue(LAuth, 'redirect_uri'));
  CheckEquals('code_challenge_method', 'S256', ParamValue(LAuth, 'code_challenge_method'));
  Check('state: 32 hex digits', IsHexString(ParamValue(LAuth, 'state'), 32), ParamValue(LAuth, 'state'));
  LToken := GIdP.LastToken;
  Check('one token request', GIdP.TokenCount = 1, IntToStr(GIdP.TokenCount));
  CheckEquals('token redirect_uri equals the authorization one', APP_REDIRECT, ParamValue(LToken, 'redirect_uri'));
  CheckEquals('code', LCode, ParamValue(LToken, 'code'));
  CheckEquals('S256(code_verifier) = code_challenge', ParamValue(LAuth, 'code_challenge'),
    S256(ParamValue(LToken, 'code_verifier')));

  GBrowser.LastRedirect(LLocation, LHandled);
  Check('the redirect reached the app and was taken', LHandled and LLocation.StartsWith(APP_REDIRECT + '?code='),
    LLocation);
  Check('no login waits afterwards', not TIAM4DAppRedirect.IsWaiting);
  Check('replay of the redirect is not taken', not TIAM4DAppRedirect.HandleURL(LLocation));
  Sleep(200);
  Check('replay: no second token request', GIdP.TokenCount = 1, IntToStr(GIdP.TokenCount));
  Check('replay: settled once', (LProbe.Successes = 1) and (LProbe.Finallies = 1), LProbe.Outcome);
  LOp := nil;
  LClient := nil;
end;

procedure TestAppRedirectConcurrent;
const
  DELIVERIES = 4;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LLocation: string;
  LTaken: Integer;
  LGate: TEvent;
  LThreads: array[0..DELIVERIES - 1] of TThread;
  I: Integer;
begin
  GIdP.Reset(tmTokens, amCode, SLOW_TOKEN_MS);
  GBrowser.Reset(bmIgnore);
  LClient := NewAppClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  LLocation := FetchRedirect(GBrowser.LastURL);
  LTaken := 0;
  LGate := TEvent.Create;
  try
    for I := 0 to DELIVERIES - 1 do
    begin
      LThreads[I] := TThread.CreateAnonymousThread(
        procedure
        begin
          LGate.WaitFor(WAIT_MS);
          if TIAM4DAppRedirect.HandleURL(LLocation) then
            TInterlocked.Increment(LTaken);
        end);
      LThreads[I].FreeOnTerminate := False;
      LThreads[I].Start;
    end;
    LGate.SetEvent;
    for I := 0 to DELIVERIES - 1 do
    begin
      LThreads[I].WaitFor;
      LThreads[I].Free;
    end;
  finally
    LGate.Free;
  end;
  Check('concurrent deliveries: taken once', LTaken = 1, IntToStr(LTaken));
  Check('completes', LProbe.WaitDone and (LProbe.Successes = 1) and (LProbe.Finallies = 1), LProbe.Outcome);
  Check('one token request', GIdP.TokenCount = 1, IntToStr(GIdP.TokenCount));
  LOp := nil;
  LClient := nil;
end;

procedure TestAppRedirectAccessDenied;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
begin
  GIdP.Reset(tmTokens, amAccessDenied);
  GBrowser.Reset(bmAppRedirect);
  LClient := NewAppClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('ends', LProbe.WaitDone);
  GBrowser.WaitIdle;
  Sleep(100);
  Check('OnError and OnFinally once', (LProbe.Errors = 1) and (LProbe.Successes = 0) and
    (LProbe.Finallies = 1), LProbe.Outcome);
  Check('EIAM4DOAuth2CallbackException', LProbe.ErrorClass = EIAM4DOAuth2CallbackException, LProbe.ErrorText);
  CheckEquals('Context error', 'access_denied', LProbe.ErrorContext('error'));
  CheckEquals('Context error_description', ERROR_DESCRIPTION, LProbe.ErrorContext('error_description'));
  Check('operation faulted', LOp.State = TAsyncOperationState.Faulted);
  Check('not authenticated', not LClient.IsAuthenticated);
  Check('no token request', GIdP.TokenCount = 0);
  Check('no login waits afterwards', not TIAM4DAppRedirect.IsWaiting);
  LOp := nil;
  LClient := nil;
end;

procedure TestAppRedirectForged;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LReal, LBase, LError, LState, LZeros: string;
  LSent: TParams;
begin
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewAppClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check('a login waits', TIAM4DAppRedirect.IsWaiting);
  Check('authorization URL parses', ParseURL(GBrowser.LastURL, LBase, LSent, LError), LError);
  LState := ParamValue(LSent, 'state');
  LReal := FetchRedirect(GBrowser.LastURL);
  Check('the identity provider redirects to the app URI', LReal.StartsWith(APP_REDIRECT + '?code='), LReal);
  LZeros := StringOfChar('0', 32);

  Check('code with another state', not TIAM4DAppRedirect.HandleURL(APP_REDIRECT + '?code=x&state=' + LZeros));
  Check('error with another state',
    not TIAM4DAppRedirect.HandleURL(APP_REDIRECT + '?error=access_denied&state=' + LZeros));
  Check('error without state', not TIAM4DAppRedirect.HandleURL(APP_REDIRECT + '?error=access_denied'));
  Check('code without state', not TIAM4DAppRedirect.HandleURL(APP_REDIRECT + '?code=x'));
  Check('state too long', not TIAM4DAppRedirect.HandleURL(APP_REDIRECT + '?code=x&state=' + StringOfChar('a', 300)));
  Check('another scheme with the state of the flow',
    not TIAM4DAppRedirect.HandleURL('it.other.app:/oauth2callback?code=x&state=' + LState));
  Check('another path with the state of the flow',
    not TIAM4DAppRedirect.HandleURL('it.iam4d.test:/other?code=x&state=' + LState));
  Check('http URL with the state of the flow',
    not TIAM4DAppRedirect.HandleURL('http://localhost/oauth2callback?code=x&state=' + LState));
  Check('malformed', not TIAM4DAppRedirect.HandleURL('garbage'));
  Check('empty', not TIAM4DAppRedirect.HandleURL(''));

  Check('the login keeps waiting', (not LProbe.WaitDone(500)) and TIAM4DAppRedirect.IsWaiting, LProbe.Outcome);
  Check('no token request', GIdP.TokenCount = 0);

  Check('the real redirect is taken', TIAM4DAppRedirect.HandleURL(LReal));
  Check('then it completes', LProbe.WaitDone and (LProbe.Successes = 1) and (LProbe.Errors = 0) and
    (LProbe.Finallies = 1), LProbe.Outcome);
  Check('authenticated', LClient.IsAuthenticated);
  LOp := nil;
  LClient := nil;
end;

procedure TestAppRedirectCancel;
var
  LClient: IIAM4DClient;
  LProbe, LSecond: ILoginProbe;
  LOp, LOp2: IAsyncOperation<string>;
  LLate: string;
begin
  // Cancel on the operation
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewAppClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  LLate := FetchRedirect(GBrowser.LastURL);
  Check('Cancel: a login waits', TIAM4DAppRedirect.IsWaiting);
  LOp.Cancel;
  Check('Cancel: ends', LProbe.WaitDone(5000));
  Sleep(100);
  Check('Cancel: OnFinally once, no OnSuccess/OnError', IsCancelledOnce(LProbe), LProbe.Outcome);
  Check('Cancel: operation cancelled', LOp.State = TAsyncOperationState.Cancelled);
  Check('Cancel: no login waits', not TIAM4DAppRedirect.IsWaiting);
  Check('Cancel: a late redirect is not taken', not TIAM4DAppRedirect.HandleURL(LLate));
  Sleep(200);
  Check('Cancel: no token request, not authenticated', (GIdP.TokenCount = 0) and (not LClient.IsAuthenticated));
  Check('Cancel: still cancelled once', IsCancelledOnce(LProbe), LProbe.Outcome);
  LOp := nil;
  LClient := nil;

  // CancelAuthorizationFlow
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewAppClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  LClient.CancelAuthorizationFlow;
  Check('CancelAuthorizationFlow: ends', LProbe.WaitDone(5000));
  Sleep(100);
  Check('CancelAuthorizationFlow: cancelled once', IsCancelledOnce(LProbe), LProbe.Outcome);
  Check('CancelAuthorizationFlow: no login waits', not TIAM4DAppRedirect.IsWaiting);
  LOp := nil;
  LClient := nil;

  // Client released while waiting
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewAppClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  LClient := nil;
  Check('released: ends', LProbe.WaitDone(5000));
  Sleep(100);
  Check('released: cancelled once', IsCancelledOnce(LProbe), LProbe.Outcome);
  Check('released: no login waits', not TIAM4DAppRedirect.IsWaiting);
  LOp := nil;

  // A second login cancels the first one
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient := NewAppClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  GBrowser.Reset(bmAppRedirect);
  LSecond := TLoginProbe.Create;
  LOp2 := StartLogin(LClient, LSecond);
  Check('second login: first ends', LProbe.WaitDone(5000));
  Check('second login: second completes', LSecond.WaitDone);
  GBrowser.WaitIdle;
  Sleep(100);
  Check('second login: first cancelled once', IsCancelledOnce(LProbe), LProbe.Outcome);
  Check('second login: second succeeds once', (LSecond.Successes = 1) and (LSecond.Finallies = 1) and
    (LSecond.Errors = 0), LSecond.Outcome);
  Check('second login: authenticated', LClient.IsAuthenticated);
  LOp := nil;
  LOp2 := nil;
  LClient := nil;
end;

procedure TestAppRedirectNoLogin;
begin
  Check('no login: IsWaiting is False', not TIAM4DAppRedirect.IsWaiting);
  Check('no login: the redirect is not taken',
    not TIAM4DAppRedirect.HandleURL(APP_REDIRECT + '?code=x&state=' + StringOfChar('a', 32)));
  Check('no login: still not waiting', not TIAM4DAppRedirect.IsWaiting);
end;

procedure TestAppRedirectTwoClients;
var
  LClient1, LClient2: IIAM4DClient;
  LProbe1, LProbe2: ILoginProbe;
  LOp1, LOp2: IAsyncOperation<string>;
  LLocation1, LLocation2: string;
begin
  // Same redirect URI: the state tells the logins apart
  GIdP.Reset;
  GBrowser.Reset(bmIgnore);
  LClient1 := NewAppClient;
  LProbe1 := TLoginProbe.Create;
  LOp1 := StartLogin(LClient1, LProbe1);
  LLocation1 := FetchRedirect(GBrowser.LastURL);
  LClient2 := NewAppClient;
  LProbe2 := TLoginProbe.Create;
  LOp2 := StartLogin(LClient2, LProbe2);
  LLocation2 := FetchRedirect(GBrowser.LastURL);
  Check('two redirects', LLocation1 <> LLocation2);

  Check('redirect of the second client is taken', TIAM4DAppRedirect.HandleURL(LLocation2));
  Check('second completes', LProbe2.WaitDone and (LProbe2.Successes = 1), LProbe2.Outcome);
  Check('first keeps waiting', (not LProbe1.WaitDone(300)) and TIAM4DAppRedirect.IsWaiting, LProbe1.Outcome);
  Check('only the second is authenticated', LClient2.IsAuthenticated and (not LClient1.IsAuthenticated));

  Check('redirect of the first client is taken', TIAM4DAppRedirect.HandleURL(LLocation1));
  Check('first completes', LProbe1.WaitDone and (LProbe1.Successes = 1), LProbe1.Outcome);
  Check('each client got its own tokens', LProbe1.Token <> LProbe2.Token);
  Check('no login waits afterwards', not TIAM4DAppRedirect.IsWaiting);
  LOp1 := nil;
  LOp2 := nil;
  LClient1 := nil;
  LClient2 := nil;
end;

// ---------------------------------------------------------------------------
// id_token validation
// ---------------------------------------------------------------------------

/// <summary>
/// True if AProc raises EIAM4DSecurityValidationException with an error code (ecTokenInvalid, or the one of
/// the JWT validator such as ecJWTExpired) and a message
/// containing AMessagePart and not the token (a JWT part starts with "eyJ")
/// </summary>
function IDTokenRefused(const AProc: TProc; const AMessagePart: string; out AMessage: string): Boolean;
begin
  Result := False;
  AMessage := 'no exception';
  try
    AProc();
  except
    on E: EIAM4DSecurityValidationException do
    begin
      AMessage := Format('%s (code %d): %s', [E.ClassName, Ord(E.ErrorCode), E.Message]);
      Result := (E.ErrorCode <> ecUnknown) and E.Message.Contains(AMessagePart) and
        not E.Message.Contains('eyJ');
    end;
    on E: Exception do
      AMessage := E.ClassName + ': ' + E.Message;
  end;
end;

/// <summary>
/// Login through the local callback server with the id_tokens of AFault. AMessagePart empty: the
/// login succeeds; otherwise it fails with EIAM4DSecurityValidationException (ErrorCode ACode)
/// </summary>
procedure CheckIDTokenLogin(const AName: string; AFault: TIDTokenFault; const AMessagePart: string;
  ACode: TIAM4DErrorCode = ecTokenInvalid);
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
begin
  GIdP.Reset;
  GIdP.SetIDTokenFault(AFault);
  GBrowser.Reset(bmFollow);
  LClient := NewLocalClient;
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(LClient, LProbe);
  Check(AName + ': ends', LProbe.WaitDone);
  GBrowser.WaitIdle;
  Sleep(100);
  if AMessagePart = '' then
  begin
    Check(AName + ': OnSuccess and OnFinally once', (LProbe.Successes = 1) and (LProbe.Errors = 0) and
      (LProbe.Finallies = 1), LProbe.Outcome);
    Check(AName + ': authenticated', LClient.IsAuthenticated);
  end
  else
  begin
    Check(AName + ': OnError and OnFinally once', (LProbe.Errors = 1) and (LProbe.Successes = 0) and
      (LProbe.Finallies = 1), LProbe.Outcome);
    Check(AName + ': EIAM4DSecurityValidationException, error code ' + IntToStr(Ord(ACode)),
      Assigned(LProbe.ErrorClass) and LProbe.ErrorClass.InheritsFrom(EIAM4DSecurityValidationException) and
      (LProbe.ErrorCode = ACode), IntToStr(Ord(LProbe.ErrorCode)) + ' ' + LProbe.ErrorText);
    Check(AName + ': reason in the message', LProbe.ErrorText.Contains(AMessagePart), LProbe.ErrorText);
    Check(AName + ': token not in the message', not LProbe.ErrorText.Contains('eyJ'), LProbe.ErrorText);
    Check(AName + ': operation faulted', LOp.State = TAsyncOperationState.Faulted);
    Check(AName + ': one token request', GIdP.TokenCount = 1, IntToStr(GIdP.TokenCount));
    Check(AName + ': tokens discarded', not LClient.IsAuthenticated);
    CheckStopped(AName + ': callback server stopped', PortOfURL(LastRedirectURI));
  end;
  LOp := nil;
  LClient := nil;
end;

procedure TestIDTokenLogin;
begin
  CheckIDTokenLogin('RS256, one audience', ifNone, '');
  CheckIDTokenLogin('several audiences with azp', ifMultiAudWithAzp, '');
  CheckIDTokenLogin('altered signature', ifBadSignature, 'signature verification failed', ecJWTSignatureInvalid);
  CheckIDTokenLogin('unknown kid', ifUnknownKid, 'kid "unknown-kid"', ecJWKSKeyNotFound);
  CheckIDTokenLogin('alg none', ifAlgNone, 'alg=none');
  CheckIDTokenLogin('other issuer', ifWrongIssuer, 'Invalid issuer', ecJWTIssuerMismatch);
  CheckIDTokenLogin('audience without the client', ifWrongAudience, 'Invalid audience', ecJWTAudienceMismatch);
  CheckIDTokenLogin('several audiences without azp', ifMultiAudNoAzp, 'Authorized party (azp) is required');
  CheckIDTokenLogin('azp of another client', ifWrongAzp, 'authorized party (azp) is not the client');
  CheckIDTokenLogin('expired', ifExpired, 'Token expired', ecJWTExpired);
  CheckIDTokenLogin('iat in the future', ifIatInFuture, 'iat claim is in the future');
  CheckIDTokenLogin('iat a day ago, exp valid', ifIatTooOld, 'Token is too old');
  CheckIDTokenLogin('access token as id_token (typ Bearer)', ifAccessTokenTyp, 'is not the expected token type');
  CheckIDTokenLogin('nonce of another login', ifOtherNonce, 'Nonce mismatch', ecNonceValidationFailed);
  CheckIDTokenLogin('no nonce', ifNoNonce, 'Missing nonce', ecNonceValidationFailed);
end;

procedure TestIDTokenKeys;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LDiscovery, LJWKS, I: Integer;

  procedure LoginWith(const AClient: IIAM4DClient; const AName: string);
  begin
    LProbe := TLoginProbe.Create;
    LOp := StartLogin(AClient, LProbe);
    Check(AName + ' completes', LProbe.WaitDone and (LProbe.Successes = 1), LProbe.Outcome);
    GBrowser.WaitIdle;
  end;

begin
  GIdP.Reset;
  GBrowser.Reset(bmFollow);
  // Keys fetched by earlier tests forgotten: the first login downloads them
  TIAM4DSharedJWKSProviders.Clear;
  LClient := NewLocalClient;
  LDiscovery := GIdP.DiscoveryCount;
  LJWKS := GIdP.JWKSCount;
  for I := 1 to 2 do
    LoginWith(LClient, Format('login %d', [I]));
  Check('keys from the jwks_uri of the discovery, fetched once for two logins', GIdP.JWKSCount = LJWKS + 1,
    IntToStr(GIdP.JWKSCount - LJWKS));
  Check('no second discovery request for the keys', GIdP.DiscoveryCount = LDiscovery,
    IntToStr(GIdP.DiscoveryCount - LDiscovery));

  // A client per login (uniGUI, DLL): the keys of the process, no download per client
  LJWKS := GIdP.JWKSCount;
  for I := 1 to 3 do
  begin
    LClient := NewLocalClient;
    LoginWith(LClient, Format('new client %d', [I]));
  end;
  Check('a new client per login: keys shared in the process, no JWKS request', GIdP.JWKSCount = LJWKS,
    IntToStr(GIdP.JWKSCount - LJWKS));
  Check('one shared provider for one HTTP configuration', TIAM4DSharedJWKSProviders.Count = 1,
    IntToStr(TIAM4DSharedJWKSProviders.Count));

  // Disabled: every client its own provider, its first id_token downloads the keys
  TIAM4DSharedJWKSProviders.Enabled := False;
  try
    LJWKS := GIdP.JWKSCount;
    LClient := NewLocalClient;
    LoginWith(LClient, 'sharing disabled');
    Check('sharing disabled: the client downloads the keys', GIdP.JWKSCount = LJWKS + 1,
      IntToStr(GIdP.JWKSCount - LJWKS));
    Check('sharing disabled: no shared provider', TIAM4DSharedJWKSProviders.Count = 0,
      IntToStr(TIAM4DSharedJWKSProviders.Count));
  finally
    TIAM4DSharedJWKSProviders.Enabled := True;
  end;
  LOp := nil;
  LClient := nil;
end;

procedure TestIDTokenExternalAndPassword;
var
  LClient: IIAM4DClient;
  LHTTP: THTTPClient;
  LLocation, LBase, LError, LMessage: string;
  LParams: TParams;
begin
  // External callback: CompleteAuthorizationFlow validates the id_token too
  GIdP.Reset;
  GIdP.SetIDTokenFault(ifBadSignature);
  LClient := NewExternalClient;
  LClient.InitializeAuthorizationFlow;
  LHTTP := THTTPClient.Create;
  try
    LHTTP.HandleRedirects := False;
    LLocation := LHTTP.Get(LClient.GenerateAuthURL).HeaderValue['Location'];
  finally
    LHTTP.Free;
  end;
  Check('external: callback URL parses', ParseURL(LLocation, LBase, LParams, LError), LError);
  Check('external: altered signature refused',
    IDTokenRefused(
      procedure
      begin
        LClient.CompleteAuthorizationFlow(ParamValue(LParams, 'code'), ParamValue(LParams, 'state'));
      end, 'signature verification failed', LMessage), LMessage);
  Check('external: tokens discarded', not LClient.IsAuthenticated);

  // Password grant: refused id_token, no session
  GIdP.Reset;
  GIdP.SetIDTokenFault(ifWrongIssuer);
  LClient := NewPasswordClient;
  Check('password: other issuer refused',
    IDTokenRefused(
      procedure
      begin
        LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
      end, 'Invalid issuer', LMessage), LMessage);
  Check('password: not authenticated', not LClient.IsAuthenticated);

  // Password grant on a client with a session: the refused login keeps it
  GIdP.Reset;
  LClient := NewPasswordClient;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  GIdP.SetIDTokenFault(ifExpired);
  Check('password again: expired id_token refused',
    IDTokenRefused(
      procedure
      begin
        LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
      end, 'Token expired', LMessage), LMessage);
  Check('password again: previous session kept', LClient.IsAuthenticated);
  Check('password again: previous session not ended', GIdP.LogoutCount = 0, IntToStr(GIdP.LogoutCount));
  LClient := nil;
end;

/// <summary>Authorization Code login through the local callback server; True if it succeeded</summary>
function LocalLogin(const AClient: IIAM4DClient): Boolean;
var
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
begin
  GBrowser.Reset(bmFollow);
  LProbe := TLoginProbe.Create;
  LOp := StartLogin(AClient, LProbe);
  Result := LProbe.WaitDone and (LProbe.Successes = 1);
  GBrowser.WaitIdle;
  LOp := nil;
end;

procedure TestIDTokenRefresh;
type
  TCase = record
    Name: string;
    Password: Boolean;
    Fault: TIDTokenFault;
    MessagePart: string;
  end;
const
  CASES: array[0..5] of TCase = (
    (Name: 'other subject'; Password: True; Fault: ifOtherSubject; MessagePart: 'subject (sub)'),
    (Name: 'other audience'; Password: True; Fault: ifMultiAudWithAzp; MessagePart: 'audience (aud)'),
    (Name: 'nonce after a login without nonce'; Password: True; Fault: ifOtherNonce; MessagePart: 'nonce'),
    (Name: 'altered signature'; Password: True; Fault: ifBadSignature; MessagePart: 'signature verification failed'),
    (Name: 'authorization code, other nonce'; Password: False; Fault: ifOtherNonce; MessagePart: 'nonce'),
    (Name: 'authorization code, other subject'; Password: False; Fault: ifOtherSubject; MessagePart: 'subject (sub)'));
var
  LClient: IIAM4DClient;
  LToken, LMessage: string;
  LCase: TCase;
begin
  // Authorization Code: the refreshed id_token repeats sub, aud and nonce of the login
  GIdP.Reset(tmShortLived);
  LClient := NewLocalClient;
  Check('authorization code: login', LocalLogin(LClient));
  LToken := LClient.GetAccessToken;
  Check('authorization code: refresh accepted (same sub, aud and nonce)', LToken.StartsWith('at-refresh_token-'),
    LToken);
  Check('authorization code: still authenticated', LClient.IsAuthenticated);

  // Password grant: no nonce at the login nor in the refresh
  GIdP.Reset(tmShortLived);
  LClient := NewPasswordClient;
  LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  LToken := LClient.GetAccessToken;
  Check('password: refresh accepted', LToken.StartsWith('at-refresh_token-'), LToken);

  for LCase in CASES do
  begin
    GIdP.Reset(tmShortLived);
    if LCase.Password then
    begin
      LClient := NewPasswordClient;
      LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
    end
    else
    begin
      LClient := NewLocalClient;
      Check(LCase.Name + ': login', LocalLogin(LClient));
    end;
    GIdP.SetIDTokenFault(LCase.Fault);
    Check(LCase.Name + ': refresh refused',
      IDTokenRefused(
        procedure
        begin
          LClient.GetAccessToken;
        end, LCase.MessagePart, LMessage), LMessage);
    Check(LCase.Name + ': tokens cleared', not LClient.IsAuthenticated);
  end;
  LClient := nil;
end;

procedure TestRedirectNotFollowed;
var
  LClient: IIAM4DClient;
  LClass: TClass;
  LMessage, LDescription: string;
begin
  // A 3xx of the token endpoint is an error: never followed with the form (password, secret)
  GIdP.Reset;
  LClient := NewPasswordClient(PWD_CLIENT_SECRET);
  GIdP.SetTokenRedirect(True);
  LClass := RaisedClass(
    procedure
    begin
      LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
    end, LMessage, LDescription);
  Check('307 of the token endpoint: login fails', LClass <> nil, LMessage);
  Check('307: the message names the redirect not followed', LMessage.Contains('307') and
    LMessage.Contains('not followed') and LMessage.Contains('127.0.0.1:9/elsewhere'), LMessage);
  Check('307: one token request, no second POST', GIdP.TokenCount = 1, IntToStr(GIdP.TokenCount));
  Check('307: not authenticated', not LClient.IsAuthenticated);
  LClient := nil;
end;

procedure TestInsecureHTTP;
var
  LClass: TClass;
  LMessage, LDescription: string;
begin
  // http:// to a host that is not the loopback: refused without the explicit opt-in
  for var LURL in ['http://localhost:8080', 'http://127.0.0.1', 'http://127.10.0.1:8080/', 'http://[::1]:8080',
    'https://keycloak.example.com', 'it.iam4d.test:/cb', ''] do
    Check('not insecure: ' + LURL, not TIAM4DClientConfig.IsInsecureHTTPURL(LURL));
  for var LURL in ['http://keycloak.example.com', 'HTTP://192.168.1.10:8080', 'http://10.0.2.2:8080',
    'http://localhost.example.com', 'http://127.0.0.1.example.com'] do
    Check('insecure: ' + LURL, TIAM4DClientConfig.IsInsecureHTTPURL(LURL));

  LClass := RaisedClass(
    procedure
    begin
      TIAM4DClientConfigBuilder.New.ForAuthorizationCode('http://iam4d-test.invalid:8080', REALM, CLIENT_ID).Build;
    end, LMessage, LDescription);
  Check('http BaseURL on the LAN refused', (LClass = EIAM4DInvalidConfigurationException) and
    LMessage.Contains('plain HTTP'), LMessage);

  LClass := RaisedClass(
    procedure
    begin
      TIAM4DClientConfigBuilder.New.ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
        .WithExternalCallback('http://app.example.com/cb').Build;
    end, LMessage, LDescription);
  Check('http external callback refused', (LClass = EIAM4DInvalidConfigurationException) and
    LMessage.Contains('Redirect URL'), LMessage);

  // With the opt-in the configuration is accepted: the discovery then fails on the network
  LClass := RaisedClass(
    procedure
    begin
      TIAM4DClientConfigBuilder.New.ForAuthorizationCode('http://iam4d-test.invalid:8080', REALM, CLIENT_ID)
        .WithAllowInsecureHTTP.Build;
    end, LMessage, LDescription);
  Check('opt-in: not refused as plain HTTP', (LClass <> nil) and not LMessage.Contains('plain HTTP'), LMessage);

  Check('opt-in kept by later builder calls', TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GIdP.BaseURL, REALM, CLIENT_ID)
    .WithAllowInsecureHTTP
    .WithExternalCallback('http://app.example.com/cb')
    .Build <> nil);
end;

procedure TestIssParameter;
var
  LClient: IIAM4DClient;
  LProbe: ILoginProbe;
  LOp: IAsyncOperation<string>;
  LLocation, LBase, LError: string;
  LParams: TParams;
  LClass: TClass;
  LMessage, LDescription: string;

  function LocalLoginWith(AAdvertise: Boolean; AMode: TIssMode): ILoginProbe;
  begin
    GIdP.Reset;
    GIdP.SetIss(AAdvertise, AMode);
    GBrowser.Reset(bmFollow);
    // The discovery document changes between the cases
    TIAM4DDiscoveryCache.Clear;
    LClient := NewLocalClient;
    Result := TLoginProbe.Create;
    LOp := StartLogin(LClient, Result);
    Result.WaitDone;
    GBrowser.WaitIdle;
  end;

begin
  try
    LProbe := LocalLoginWith(True, imCorrect);
    Check('iss of the issuer: login succeeds', LProbe.Successes = 1, LProbe.Outcome);

    LProbe := LocalLoginWith(True, imWrong);
    Check('iss of another issuer: login fails (mix-up)', (LProbe.Errors = 1) and
      LProbe.ErrorText.Contains('mix-up'), LProbe.Outcome);
    Check('iss of another issuer: no token request', GIdP.TokenCount = 0, IntToStr(GIdP.TokenCount));

    LProbe := LocalLoginWith(True, imNone);
    Check('iss missing while the discovery says it is sent: login fails', (LProbe.Errors = 1) and
      LProbe.ErrorText.Contains('Missing iss'), LProbe.Outcome);

    LProbe := LocalLoginWith(False, imNone);
    Check('iss missing, not announced by the discovery: login succeeds', LProbe.Successes = 1, LProbe.Outcome);

    LProbe := LocalLoginWith(False, imWrong);
    Check('iss of another issuer, not announced: still refused', LProbe.Errors = 1, LProbe.Outcome);

    // External callback: the application passes iss when it has it
    GIdP.Reset;
    GIdP.SetIss(True, imWrong);
    TIAM4DDiscoveryCache.Clear;
    LClient := NewExternalClient;
    LClient.InitializeAuthorizationFlow;
    LLocation := FetchRedirect(LClient.GenerateAuthURL);
    Check('external: callback URL parses', ParseURL(LLocation, LBase, LParams, LError), LError);
    LClass := RaisedClass(
      procedure
      begin
        LClient.CompleteAuthorizationFlow(ParamValue(LParams, 'code'), ParamValue(LParams, 'state'),
          ParamValue(LParams, 'iss'));
      end, LMessage, LDescription);
    Check('external: iss of another issuer refused', (LClass <> nil) and LMessage.Contains('mix-up'), LMessage);
    Check('external: no token request', GIdP.TokenCount = 0, IntToStr(GIdP.TokenCount));

    GIdP.SetIss(True, imCorrect);
    LClient.InitializeAuthorizationFlow;
    LLocation := FetchRedirect(LClient.GenerateAuthURL);
    ParseURL(LLocation, LBase, LParams, LError);
    CheckEquals('external: iss of the issuer accepted', 'at-' + ParamValue(LParams, 'code'),
      LClient.CompleteAuthorizationFlow(ParamValue(LParams, 'code'), ParamValue(LParams, 'state'),
        ParamValue(LParams, 'iss')));

    GIdP.SetIss(True, imNone);
    LClient.InitializeAuthorizationFlow;
    LLocation := FetchRedirect(LClient.GenerateAuthURL);
    ParseURL(LLocation, LBase, LParams, LError);
    CheckEquals('external: without iss accepted (the application may not forward it)',
      'at-' + ParamValue(LParams, 'code'),
      LClient.CompleteAuthorizationFlow(ParamValue(LParams, 'code'), ParamValue(LParams, 'state')));
  finally
    LOp := nil;
    LClient := nil;
    TIAM4DDiscoveryCache.Clear;
  end;
end;

procedure TestRefreshDuringLogin;
var
  LClient: IIAM4DClient;
  LFirst, LSecond, LRefreshResult, LRefreshError: string;
  LThread: TThread;
begin
  // A refresh still running when a new login is stored must not overwrite the new tokens
  GIdP.Reset(tmShortLived);
  LClient := NewPasswordClient;
  LFirst := LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
  GIdP.SetRefreshDelay(SLOW_TOKEN_MS);
  GIdP.TokenRequested.ResetEvent;
  LRefreshResult := '';
  LRefreshError := '';
  LThread := TThread.CreateAnonymousThread(
    procedure
    begin
      try
        // expires_in 1: stale at once, this call refreshes
        LRefreshResult := LClient.GetAccessToken;
      except
        on E: Exception do
          LRefreshError := E.ClassName + ': ' + E.Message;
      end;
    end);
  LThread.FreeOnTerminate := False;
  LThread.Start;
  try
    Check('refresh request sent', GIdP.TokenRequested.WaitFor(WAIT_MS) = wrSignaled);
    // Second login while the refresh waits for its answer: tokens that stay valid
    GIdP.SetBehavior(tmTokens);
    LSecond := LClient.AuthenticatePassword(PWD_USER, PWD_PASSWORD);
    LThread.WaitFor;
  finally
    LThread.Free;
  end;
  Check('second login: tokens of a password grant', LSecond.StartsWith('at-password-'), LSecond);
  CheckEquals('the late refresh did not overwrite the new login', LSecond, LClient.GetAccessToken);
  CheckEquals('the refreshing call got the token of the new login', LSecond, LRefreshResult + LRefreshError);
  LClient := nil;
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
  GBrowser.WaitIdle;
  GDeadline := 0;
end;

begin
  ReportMemoryLeaksOnShutdown := True;
  IsMultiThread := True;

  // First of all: no test may open the real browser
  GBrowser := TFakeBrowser.Create;
  StartWatchdog;
  TIAM4DPlatformUtils.OpenURLHandler := GBrowser.Open;
  try
    try
      GIdP := TFakeIdP.Create;
    except
      on E: Exception do
      begin
        Writeln('Cannot start the fake identity provider: ', E.Message);
        ExitCode := 99;
        Exit;
      end;
    end;
    try
      Writeln('Fake identity provider on ', GIdP.BaseURL);
      RunTest('OpenURL handler', TestOpenURLHandler);
      RunTest('Login with PKCE, state and nonce', TestLoginPKCE);
      RunTest('kc_idp_hint in the login', TestIdpHintLogin);
      RunTest('kc_idp_hint in GenerateAuthURL', TestIdpHintGenerateAuthURL);
      RunTest('Authorization URL encoding', TestEncoding);
      RunTest('External callback (web application)', TestExternalCallback);
      RunTest('Fake token endpoint: PKCE, redirect_uri, one-time code', TestFakeTokenEndpoint);
      RunTest('Login errors', TestLoginErrors);
      RunTest('Discovery failure', TestDiscoveryFailure);
      RunTest('Error response of the authorization server', TestErrorResponse);
      RunTest('Forged callbacks are ignored', TestForgedErrors);
      RunTest('Repeated callback: one code exchange', TestRepeatedCallback);
      RunTest('Browser cannot be opened', TestBrowserRefused);
      RunTest('Cancel while waiting for the browser', TestCancelWhileWaiting);
      RunTest('CancelAuthorizationFlow while waiting for the browser', TestCancelAuthorizationFlow);
      RunTest('Client released while waiting for the browser', TestDestroyWhileWaiting);
      RunTest('A second login cancels the first one', TestSecondLoginCancelsFirst);
      RunTest('Cancel while the code is being exchanged', TestCancelDuringExchange);
      RunTest('Client released while the code is being exchanged', TestDestroyDuringExchange);
      RunTest('Cancel after the login completed', TestCancelAfterCompletion);
      RunTest('Cancel while the callback server accepts a connection', TestStopWhileAccepting);
      RunTest('Cancel with an idle connection open', TestStopWithOpenConnection);
      RunTest('App redirect: URI validation and builder', TestAppRedirectValidation);
      RunTest('App redirect: URL parser for scheme:/path', TestAppRedirectParser);
      RunTest('App redirect: login with PKCE', TestAppRedirectLogin);
      RunTest('App redirect: concurrent deliveries', TestAppRedirectConcurrent);
      RunTest('App redirect: error response', TestAppRedirectAccessDenied);
      RunTest('App redirect: forged redirects are ignored', TestAppRedirectForged);
      RunTest('App redirect: cancel, release, second login', TestAppRedirectCancel);
      RunTest('App redirect: no login waiting', TestAppRedirectNoLogin);
      RunTest('App redirect: two clients, same URI', TestAppRedirectTwoClients);
      RunTest('Password grant', TestPasswordGrant);
      RunTest('Password grant errors', TestPasswordGrantErrors);
      RunTest('Password grant: refresh and logout', TestPasswordRefreshAndLogout);
      RunTest('Logout after an authorization code login', TestAuthCodeLogout);
      RunTest('prompt, max_age and login_hint', TestAuthRequestOptions);
      RunTest('Options of one login (acr_values, prompt, max_age, ui_locales, parameters)', TestPerLoginOptions);
      RunTest('Authorized HTTP client (bearer, retry after 401, redirects)', TestAuthorizedHTTPClient);
      RunTest('Token revocation (RFC 7009) and logout URL', TestRevokeAndLogoutURL);
      RunTest('id_token claims and granted scopes of the session', TestSessionClaims);
      RunTest('auth_time of the id_token with max_age', TestAuthTime);
      RunTest('id_token validation in the login', TestIDTokenLogin);
      RunTest('id_token keys from the jwks_uri', TestIDTokenKeys);
      RunTest('id_token validation: external callback and password grant', TestIDTokenExternalAndPassword);
      RunTest('id_token validation on refresh', TestIDTokenRefresh);
      RunTest('Fixed callback port', TestCallbackPort);
      RunTest('Loopback IP redirect host', TestLoopbackRedirectHost);
      RunTest('App activation on the callback', TestAppActivation);
      RunTest('kc_action and kc_action_status', TestKeycloakAction);
      RunTest('Builder with the password grant', TestBuilderPassword);
      RunTest('Refresh errors: refused, server error, timeout', TestRefreshErrors);
      RunTest('Logout errors and expired refresh token', TestLogoutErrors);
      RunTest('Configured scopes after a logout', TestScopesAfterLogout);
      RunTest('Password login on a client with a session', TestPasswordLoginAgain);
      RunTest('Builder: no state from a previous configuration', TestBuilderNoInheritedState);
      RunTest('Discovery cache', TestDiscoveryCache);
      RunTest('Certificate pinning', TestCertificatePinning);
      RunTest('HTTP calls of a client in parallel', TestHTTPClientConcurrency);
      RunTest('Client released while an async operation runs', TestReleaseDuringAsync);
      RunTest('SecureZeroStrings', TestSecureZeroStrings);
      RunTest('Redirects of the back-channel not followed', TestRedirectNotFollowed);
      RunTest('Plain HTTP to a host other than the loopback', TestInsecureHTTP);
      RunTest('iss of the authorization response (RFC 9207)', TestIssParameter);
      RunTest('Refresh answered after a new login', TestRefreshDuringLogin);
      // Let pool threads release their closures before the leak report
      Sleep(500);
    finally
      GIdP.Free;
      GIdP := nil;
    end;
  finally
    // Refuses every URL from now on: still no real browser
    TIAM4DPlatformUtils.OpenURLHandler :=
      function(const AURL: string): Boolean
      begin
        Result := False;
      end;
    GBrowser.Free;
    StopWatchdog;
  end;

  Writeln;
  Writeln(Format('Passed: %d  Failed: %d', [GPassed, GFailed]));
  ExitCode := GFailed;
end.
