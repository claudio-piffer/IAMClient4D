unit Calculator.Web.Sessions;

{ Server-side sessions of the web client (Backend For Frontend): the browser
  only holds an opaque, HttpOnly session cookie; access and refresh tokens stay
  in the IIAM4DClient of the session, in this process.

  Login: BeginLogin builds a client for the Authorization Code flow with PKCE
  and an external callback (this app's /auth/callback) and keeps it, keyed by
  the OAuth2 state, until the callback arrives. CompleteLogin exchanges the code
  with the client secret and turns the client into a session. }

interface

uses
  System.SysUtils,
  System.SyncObjs,
  System.Generics.Collections,
  JsonDataObjects,
  IAMClient4D.Core,
  Calculator.Web.Settings;

type
  /// <summary>The session is gone: never created, logged out, idle, or refresh token expired.</summary>
  ESessionExpired = class(Exception);

  ICalculatorSession = interface
    ['{6A2E5C1B-0F4D-4B7E-9A3C-8D1F2E7B6C40}']
    function Id: string;
    function CreatedAt: TDateTime;
    function UserName: string;
    function DisplayName: string;
    function Email: string;
    /// <summary>Client roles of the audience, as the access token carries them.</summary>
    function Roles: TArray<string>;
    function HasRole(const ARole: string): Boolean;
    /// <summary>Access token expiry (UTC), from its exp claim.</summary>
    function AccessTokenExpiresAt: TDateTime;
    /// <summary>Claims of the access token, pretty printed JSON (profile page).</summary>
    function AccessTokenClaims: string;
    function GetBackend: TCalculatorBackend;
    procedure SetBackend(const AValue: TCalculatorBackend);
    /// <summary>A valid access token, refreshed when needed. Raises ESessionExpired.</summary>
    function AccessToken: string;
    property Backend: TCalculatorBackend read GetBackend write SetBackend;
  end;

  TLoginRequest = record
    AuthorizationURL: string;
    State: string;
  end;

  TCalculatorSessionStore = class
  private type
    TPendingLogin = record
      Client: IIAM4DClient;
      ReturnTo: string;
      CreatedAt: TDateTime;
    end;
  private
    FLock: TCriticalSection;
    FSessions: TDictionary<string, ICalculatorSession>;
    FLastSeen: TDictionary<string, TDateTime>;
    FPending: TDictionary<string, TPendingLogin>;
    FLastPurge: TDateTime;
    procedure PurgeExpired;
    function IdleTimeout: TDateTime;
  public
    constructor Create;
    destructor Destroy; override;
    /// <summary>Authorization URL for the browser; AReturnTo must be a local path.</summary>
    function BeginLogin(const AReturnTo: string): TLoginRequest;
    /// <summary>
    /// Exchanges the code of the callback. Raises EIAM4D* on a state mismatch
    /// or a refused code, ESessionExpired when the login is unknown or too old.
    /// </summary>
    function CompleteLogin(const AState, ACode, AIss: string; out AReturnTo: string): ICalculatorSession;
    /// <summary>The live session with this id, or nil. Marks it as used.</summary>
    function Find(const AId: string): ICalculatorSession;
    /// <summary>
    /// Removes the session and ends it on Keycloak (back-channel logout). Returns the end session
    /// URL for the browser (RP-Initiated Logout, back to APostLogoutRedirectURI); empty when there
    /// is no such session or Keycloak has no end session endpoint.
    /// </summary>
    function Logout(const AId, APostLogoutRedirectURI: string): string;
    /// <summary>Removes the session without telling Keycloak (refresh token already gone).</summary>
    procedure Drop(const AId: string);
  end;

const
  // Time to complete a login at Keycloak (pending login, login cookie)
  LOGIN_TIMEOUT_MINUTES = 10;

function Sessions: TCalculatorSessionStore;

implementation

uses
  System.DateUtils,
  System.NetEncoding,
  MVCFramework.Commons,
  MVCFramework.Logger,
  IAMClient4D.Exceptions,
  IAMClient4D.Config.Builder,
  IAMClient4D.Common.OAuth2URLParser,
  IAMClient4D.Common.CryptoUtils;

const
  MAX_PENDING_LOGINS = 500;

type
  TCalculatorSession = class(TInterfacedObject, ICalculatorSession)
  private
    FId: string;
    FCreatedAt: TDateTime;
    FClient: IIAM4DClient;
    FLock: TCriticalSection;
    // Identity, from the last access token seen
    FToken: string;
    FUserName: string;
    FDisplayName: string;
    FEmail: string;
    FRoles: TArray<string>;
    FExpiresAt: TDateTime;
    FClaims: string;
    FBackend: TCalculatorBackend;
    procedure ReadClaims(const AToken: string);
  public
    constructor Create(const AId: string; const AClient: IIAM4DClient);
    destructor Destroy; override;
    function Id: string;
    function CreatedAt: TDateTime;
    function UserName: string;
    function DisplayName: string;
    function Email: string;
    function Roles: TArray<string>;
    function HasRole(const ARole: string): Boolean;
    function AccessTokenExpiresAt: TDateTime;
    function AccessTokenClaims: string;
    function GetBackend: TCalculatorBackend;
    procedure SetBackend(const AValue: TCalculatorBackend);
    function AccessToken: string;
    function Logout(const APostLogoutRedirectURI: string): string;
  end;

var
  GSessions: TCalculatorSessionStore;

function Sessions: TCalculatorSessionStore;
begin
  Result := GSessions;
end;

function NewSessionId: string;
begin
  Result := BytesToHex(TIAM4DCryptoUtils.GenerateSecureRandomBytes(32));
end;

// Payload of a JWT, not verified: the token comes straight from the Keycloak token
// endpoint over TLS and is used here only to show who is logged in. The API servers
// verify it on every call.
function DecodeJWTPayload(const AToken: string): TJsonObject;
var
  LParts: TArray<string>;
  LJson: TJsonBaseObject;
begin
  LParts := AToken.Split(['.']);
  if Length(LParts) <> 3 then
    raise EArgumentException.Create('Not a JWT');
  LJson := TJsonObject.Parse(TEncoding.UTF8.GetString(TNetEncoding.Base64URL.DecodeStringToBytes(LParts[1])));
  if not (LJson is TJsonObject) then
  begin
    LJson.Free;
    raise EArgumentException.Create('JWT payload is not an object');
  end;
  Result := TJsonObject(LJson);
end;

{ TCalculatorSession }

constructor TCalculatorSession.Create(const AId: string; const AClient: IIAM4DClient);
begin
  inherited Create;
  FId := AId;
  FClient := AClient;
  FCreatedAt := TDateTime.NowUTC;
  FLock := TCriticalSection.Create;
  FBackend := cbControllers;
  ReadClaims(FClient.GetAccessToken);
end;

destructor TCalculatorSession.Destroy;
begin
  FClient := nil;
  FLock.Free;
  inherited;
end;

procedure TCalculatorSession.ReadClaims(const AToken: string);
var
  LClaims: TJsonObject;
  LRoles: TJsonArray;
  I: Integer;
begin
  FToken := AToken;
  LClaims := DecodeJWTPayload(AToken);
  try
    FUserName := LClaims.S['preferred_username'];
    if FUserName.IsEmpty then
      FUserName := LClaims.S['sub'];
    FDisplayName := LClaims.S['name'];
    if FDisplayName.IsEmpty then
      FDisplayName := FUserName;
    FEmail := LClaims.S['email'];
    FExpiresAt := UnixToDateTime(LClaims.L['exp'], True);
    FRoles := nil;
    if LClaims.O['resource_access'].Contains(Settings.Audience) then
    begin
      LRoles := LClaims.O['resource_access'].O[Settings.Audience].A['roles'];
      SetLength(FRoles, LRoles.Count);
      for I := 0 to LRoles.Count - 1 do
        FRoles[I] := LRoles.S[I];
    end;
    FClaims := LClaims.ToJSON(False);
  finally
    LClaims.Free;
  end;
end;

function TCalculatorSession.AccessToken: string;
begin
  FLock.Enter;
  try
    try
      Result := FClient.GetAccessToken;
    except
      on E: EIAM4DRefreshTokenExpiredException do
        raise ESessionExpired.Create('The Keycloak session has ended: ' + E.Message);
    end;
    if Result <> FToken then
      ReadClaims(Result);
  finally
    FLock.Leave;
  end;
end;

function TCalculatorSession.Logout(const APostLogoutRedirectURI: string): string;
begin
  FLock.Enter;
  try
    // Before Logout: the URL carries the id_token as id_token_hint, cleared by Logout
    try
      Result := FClient.GenerateLogoutURL(APostLogoutRedirectURI);
    except
      // No end session endpoint: the back-channel logout below is all there is
      on E: EIAM4DException do
        Result := '';
    end;
    FClient.Logout;
  finally
    FLock.Leave;
  end;
end;

function TCalculatorSession.AccessTokenClaims: string;
begin
  FLock.Enter;
  try
    Result := FClaims;
  finally
    FLock.Leave;
  end;
end;

function TCalculatorSession.AccessTokenExpiresAt: TDateTime;
begin
  FLock.Enter;
  try
    Result := FExpiresAt;
  finally
    FLock.Leave;
  end;
end;

function TCalculatorSession.CreatedAt: TDateTime;
begin
  Result := FCreatedAt;
end;

function TCalculatorSession.DisplayName: string;
begin
  FLock.Enter;
  try
    Result := FDisplayName;
  finally
    FLock.Leave;
  end;
end;

function TCalculatorSession.Email: string;
begin
  FLock.Enter;
  try
    Result := FEmail;
  finally
    FLock.Leave;
  end;
end;

function TCalculatorSession.GetBackend: TCalculatorBackend;
begin
  FLock.Enter;
  try
    Result := FBackend;
  finally
    FLock.Leave;
  end;
end;

procedure TCalculatorSession.SetBackend(const AValue: TCalculatorBackend);
begin
  FLock.Enter;
  try
    FBackend := AValue;
  finally
    FLock.Leave;
  end;
end;

function TCalculatorSession.HasRole(const ARole: string): Boolean;
var
  LRole: string;
begin
  for LRole in Roles do
    if LRole = ARole then
      Exit(True);
  Result := False;
end;

function TCalculatorSession.Id: string;
begin
  Result := FId;
end;

function TCalculatorSession.Roles: TArray<string>;
begin
  FLock.Enter;
  try
    Result := Copy(FRoles);
  finally
    FLock.Leave;
  end;
end;

function TCalculatorSession.UserName: string;
begin
  FLock.Enter;
  try
    Result := FUserName;
  finally
    FLock.Leave;
  end;
end;

{ TCalculatorSessionStore }

constructor TCalculatorSessionStore.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FSessions := TDictionary<string, ICalculatorSession>.Create;
  FLastSeen := TDictionary<string, TDateTime>.Create;
  FPending := TDictionary<string, TPendingLogin>.Create;
  FLastPurge := Now;
end;

destructor TCalculatorSessionStore.Destroy;
begin
  FPending.Free;
  FLastSeen.Free;
  FSessions.Free;
  FLock.Free;
  inherited;
end;

function TCalculatorSessionStore.IdleTimeout: TDateTime;
begin
  Result := Settings.SessionIdleMinutes * OneMinute;
end;

// Under FLock
procedure TCalculatorSessionStore.PurgeExpired;
var
  LNow: TDateTime;
  LPair: TPair<string, TDateTime>;
  LPending: TPair<string, TPendingLogin>;
  LExpired: TList<string>;
  LId: string;
begin
  LNow := Now;
  LExpired := TList<string>.Create;
  try
    for LPair in FLastSeen do
      if LNow - LPair.Value > IdleTimeout then
        LExpired.Add(LPair.Key);
    for LId in LExpired do
    begin
      FSessions.Remove(LId);
      FLastSeen.Remove(LId);
    end;
    LExpired.Clear;
    for LPending in FPending do
      if LNow - LPending.Value.CreatedAt > LOGIN_TIMEOUT_MINUTES * OneMinute then
        LExpired.Add(LPending.Key);
    for LId in LExpired do
      FPending.Remove(LId);
  finally
    LExpired.Free;
  end;
  FLastPurge := LNow;
end;

function TCalculatorSessionStore.BeginLogin(const AReturnTo: string): TLoginRequest;
var
  LBuilder: IIAM4DClientConfigBuilder;
  LPending: TPendingLogin;
begin
  // Discovery happens here, outside the lock (TIAM4DDiscoveryCache keeps it)
  LBuilder := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(Settings.KeycloakBaseURL, Settings.Realm, Settings.ClientId, Settings.ClientSecret)
    .WithExternalCallback(Settings.RedirectURI);
  if Settings.AllowSelfSigned then
    LBuilder := LBuilder.WithAllowSelfSignedSSL
  else
    LBuilder := LBuilder.WithStrictSSL;
  LPending.Client := LBuilder.Build;
  LPending.Client.InitializeAuthorizationFlow;
  LPending.ReturnTo := AReturnTo;
  LPending.CreatedAt := Now;

  Result.AuthorizationURL := LPending.Client.GenerateAuthURL;
  Result.State := TIAM4DOAuth2URLParser.ParseOAuth2Callback(Result.AuthorizationURL).State;
  if Result.State.IsEmpty then
    raise EIAM4DException.Create('No state in the authorization URL');

  FLock.Enter;
  try
    PurgeExpired;
    if FPending.Count >= MAX_PENDING_LOGINS then
      raise EIAM4DException.Create('Too many logins in progress, try again later');
    FPending.Add(Result.State, LPending);
  finally
    FLock.Leave;
  end;
end;

function TCalculatorSessionStore.CompleteLogin(const AState, ACode, AIss: string; out AReturnTo: string): ICalculatorSession;
var
  LPending: TPendingLogin;
  LFound: Boolean;
begin
  // One shot: the pending login is removed before the exchange
  FLock.Enter;
  try
    LFound := FPending.TryGetValue(AState, LPending);
    if LFound then
      FPending.Remove(AState);
  finally
    FLock.Leave;
  end;
  if not LFound then
    raise ESessionExpired.Create('Unknown or already used login: start again');
  if Now - LPending.CreatedAt > LOGIN_TIMEOUT_MINUTES * OneMinute then
    raise ESessionExpired.Create('The login took too long: start again');

  // State check, code exchange (client secret + PKCE verifier) and ID token check
  // iss of the redirect (RFC 9207): refused when it names another issuer
  LPending.Client.CompleteAuthorizationFlow(ACode, AState, AIss);
  AReturnTo := LPending.ReturnTo;
  Result := TCalculatorSession.Create(NewSessionId, LPending.Client);

  FLock.Enter;
  try
    FSessions.Add(Result.Id, Result);
    FLastSeen.Add(Result.Id, Now);
  finally
    FLock.Leave;
  end;
  LogI(Format('Login of %s', [Result.UserName]));
end;

function TCalculatorSessionStore.Find(const AId: string): ICalculatorSession;
var
  LLastSeen: TDateTime;
begin
  Result := nil;
  if AId.IsEmpty then
    Exit;
  FLock.Enter;
  try
    if Now - FLastPurge > OneMinute then
      PurgeExpired;
    if FLastSeen.TryGetValue(AId, LLastSeen) and (Now - LLastSeen <= IdleTimeout) and
      FSessions.TryGetValue(AId, Result) then
      FLastSeen[AId] := Now
    else
      Result := nil;
  finally
    FLock.Leave;
  end;
end;

procedure TCalculatorSessionStore.Drop(const AId: string);
begin
  FLock.Enter;
  try
    FSessions.Remove(AId);
    FLastSeen.Remove(AId);
  finally
    FLock.Leave;
  end;
end;

function TCalculatorSessionStore.Logout(const AId, APostLogoutRedirectURI: string): string;
var
  LSession: ICalculatorSession;
begin
  Result := '';
  FLock.Enter;
  try
    if FSessions.TryGetValue(AId, LSession) then
    begin
      FSessions.Remove(AId);
      FLastSeen.Remove(AId);
    end;
  finally
    FLock.Leave;
  end;
  if LSession = nil then
    Exit;
  try
    Result := (LSession as TCalculatorSession).Logout(APostLogoutRedirectURI);
    LogI(Format('Logout of %s', [LSession.UserName]));
  except
    // The local session is gone anyway; the browser logout, if any, still ends the Keycloak one
    on E: Exception do
      LogW(Format('Keycloak logout of %s failed: %s', [LSession.UserName, E.Message]));
  end;
end;

initialization
  GSessions := TCalculatorSessionStore.Create;

finalization
  FreeAndNil(GSessions);

end.
