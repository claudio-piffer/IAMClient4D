unit MainModule;

interface

uses
  uniGUIMainModule,
  SysUtils,
  Classes,
  IAMClient4D.Core,
  ServerModule;

const
  /// <summary>Callback registered on the Keycloak client (valid redirect URI).</summary>
  CALLBACK_URL = 'http://localhost:8077/?oauthcallback=keycloak';
  /// <summary>HttpOnly cookie with the state of the login started by the browser.</summary>
  LOGIN_COOKIE = 'iam4d_login_state';

type
  TUniMainModule = class(TUniGUIMainModule)
    procedure UniGUIMainModuleBeforeLogin(Sender: TObject; var Handled: Boolean);
  private
    FIAMClient: IIAM4DClient;
    FAuthURL: string;
    FLoginError: string;
    function GetIAMClientManager: TIAMClientManager;
    procedure SetLoginCookie(const AValue: string);
    procedure StartLogin;
    function CompleteLogin(const AParams: TStrings): Boolean;
  public
    /// <summary>Client of the logged-in user; nil before the login.</summary>
    property IAMClient: IIAM4DClient read FIAMClient;
    /// <summary>Keycloak login page of the login started by this session; empty if it could not start.</summary>
    property AuthURL: string read FAuthURL;
    /// <summary>Why the login failed or could not start; empty otherwise.</summary>
    property LoginError: string read FLoginError;
    property IAMClientManager: TIAMClientManager read GetIAMClientManager;
  end;

function UniMainModule: TUniMainModule;

implementation

{$R *.dfm}

uses
  System.Hash,
  UniGUIVars,
  uniGUIApplication,
  IAMClient4D.Config.Builder,
  IAMClient4D.Common.OAuth2URLParser;

function UniMainModule: TUniMainModule;
begin
  Result := TUniMainModule(UniApplication.UniMainModule)
end;

function TUniMainModule.GetIAMClientManager: TIAMClientManager;
begin
  Result := UniServerModule.IAMClientManager;
end;

procedure TUniMainModule.SetLoginCookie(const AValue: string);
begin
  // Session cookie (the server lets the login expire); SameSite=Lax: sent on the redirect from Keycloak.
  // Secure is added by uniGUI over HTTPS (Cookies.SecureOverSSL)
  TUniGUIApplication(UniApplication).Cookies.SetCookie(LOGIN_COOKIE, AValue, 0, False, True, '/', '', 'Lax');
end;

procedure TUniMainModule.StartLogin;
var
  LClient: IIAM4DClient;
  LAuthURL, LState: string;
begin
  FAuthURL := '';
  // A client (and an OIDC discovery) per login: refuse before building it when too many wait
  if not IAMClientManager.HasRoom then
  begin
    FLoginError := 'Too many logins in progress: try again in a few minutes.';
    Exit;
  end;

  try
    // The Keycloak of the samples (Docker\start.cmd): realm iamclient4d, public client
    // iam4d-sample-unigui (PKCE), user demo / demo.
    // The Keycloak login page offers the identity providers of the realm too (SPID spid-test, CIE...)
    LClient := TIAM4DClientConfigBuilder.New
      .ForAuthorizationCode(
      'http://localhost:18180/auth',
      'iamclient4d',
      'iam4d-sample-unigui')
      .WithExternalCallback(CALLBACK_URL)
      .Build;

    LClient.InitializeAuthorizationFlow;
    LAuthURL := LClient.GenerateAuthURL;
    LState := TIAM4DOAuth2URLParser.ParseOAuth2Callback(LAuthURL).State;
    if not IAMClientManager.TryAddClient(LState, LClient) then
      raise Exception.Create('too many logins in progress, try again in a few minutes.');

    // Binds the login to this browser: the callback is accepted only with the same state in the cookie
    SetLoginCookie(LState);
    FAuthURL := LAuthURL;
  except
    on E: Exception do
      FLoginError := 'The login cannot start: ' + E.Message;
  end;
end;

function TUniMainModule.CompleteLogin(const AParams: TStrings): Boolean;
var
  LState, LCookieState: string;
  LClient: IIAM4DClient;
begin
  Result := False;
  LState := AParams.Values['state'];
  LCookieState := TUniGUIApplication(UniApplication).Cookies.Values[LOGIN_COOKIE];
  SetLoginCookie('');

  // Login CSRF: a callback opened in another browser (e.g. a link with the code of someone else's
  // login) has no cookie with its state. The pending login is removed before the exchange
  if LState.IsEmpty or
    not THashSHA2.GetHashString(LState).Equals(THashSHA2.GetHashString(LCookieState)) or
    not IAMClientManager.TryTakeClient(LState, LClient) then
  begin
    FLoginError := 'The login expired or was started in another browser.';
    Exit;
  end;

  // Error response of Keycloak (RFC 6749 4.1.2.1), e.g. access_denied
  if AParams.Values['error'] <> '' then
  begin
    FLoginError := Format('Keycloak refused the login: %s %s',
      [AParams.Values['error'], AParams.Values['error_description']]);
    Exit;
  end;

  try
    // iss (RFC 9207): refused when it names another issuer
    LClient.CompleteAuthorizationFlow(AParams.Values['code'], LState, AParams.Values['iss']);
    FIAMClient := LClient;
    Result := True;
  except
    on E: Exception do
      FLoginError := 'Login failed: ' + E.Message;
  end;
end;

procedure TUniMainModule.UniGUIMainModuleBeforeLogin(Sender: TObject; var Handled: Boolean);
var
  LParams: TStrings;
begin
  // BeforeLogin runs in the page request: the cookie goes out as an HttpOnly Set-Cookie header
  // (in an Ajax request, such as a timer event, uniGUI writes cookies with document.cookie)
  LParams := TUniGUIApplication(UniApplication).Parameters;
  if LParams.Values['oauthcallback'] = 'keycloak' then
    Handled := CompleteLogin(LParams)
  else
    StartLogin;
end;

initialization
  RegisterMainModuleClass(TUniMainModule);
end.
