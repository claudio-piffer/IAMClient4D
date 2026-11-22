unit Calculator.Web.Controllers.Auth;

{ Login and logout through Keycloak, Authorization Code flow with PKCE and
  client secret, done by IAMClient4D on the server (Backend For Frontend).

  GET  /login           builds the authorization request, binds its state to
                        this browser (calcweb_login cookie), 302 to Keycloak
  GET  /auth/callback   checks the state against the cookie, exchanges the code,
                        creates the session (new id: no session fixation)
  POST /logout          ends the local session and the Keycloak one (back-channel),
                        then sends the browser to the Keycloak end session endpoint
                        (RP-Initiated Logout), which clears its Keycloak cookies and
                        comes back to the home page (post-logout redirect URI) }

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  Calculator.Web.Controllers.Base;

type
  [MVCPath]
  TAuthController = class(TWebController)
  protected
    function RequiresSession: Boolean; override;
  public
    [MVCPath('/login')]
    [MVCHTTPMethod([httpGET])]
    function Login(const [MVCFromQueryString('next', '/')] ANext: string): string;

    [MVCPath('/auth/callback')]
    [MVCHTTPMethod([httpGET])]
    function Callback: string;

    [MVCPath('/logout')]
    [MVCHTTPMethod([httpPOST])]
    procedure Logout;
  end;

implementation

uses
  System.SysUtils,
  System.Hash,
  System.DateUtils,
  MVCFramework.HTMX,
  MVCFramework.Logger,
  IAMClient4D.Exceptions,
  Calculator.Web.Settings,
  Calculator.Web.Sessions,
  Calculator.Web.Formatting;

function TAuthController.RequiresSession: Boolean;
begin
  Result := False;
end;

function TAuthController.Login(const ANext: string): string;
var
  LRequest: TLoginRequest;
begin
  Result := '';
  if Assigned(Session) then
  begin
    Redirect(SafeLocalPath(ANext));
    Exit;
  end;
  try
    LRequest := Sessions.BeginLogin(SafeLocalPath(ANext));
  except
    on E: Exception do
    begin
      LogE('Login not started: ' + E.ClassName + ': ' + E.Message);
      Context.Response.StatusCode := HTTP_STATUS.ServiceUnavailable;
      ViewData['page_id'] := 'login';
      ViewData['title'] := Text('auth.keycloak_unreachable');
      ViewData['detail'] := Text('auth.cannot_start', ['reason', E.Message]);
      Exit(RenderView('auth/failed'));
    end;
  end;
  // Login CSRF: the callback is accepted only by the browser that started the login
  SetCookie(LOGIN_COOKIE, LRequest.State, CALLBACK_PATH, IncMinute(Now, LOGIN_TIMEOUT_MINUTES));
  Redirect(LRequest.AuthorizationURL);
end;

function TAuthController.Callback: string;
var
  LState, LCode, LError, LReturnTo, LCookieState: string;
  LSession: ICalculatorSession;
begin
  LState := Context.Request.QueryStringParam('state');
  LCode := Context.Request.QueryStringParam('code');
  LError := Context.Request.QueryStringParam('error');
  LCookieState := Context.Request.Cookie(LOGIN_COOKIE);
  DeleteCookie(LOGIN_COOKIE, CALLBACK_PATH);

  ViewData['page_id'] := 'login';
  if not LError.IsEmpty then
  begin
    // e.g. access_denied, or the user went back from the Keycloak page
    ViewData['title'] := Text('auth.not_completed');
    ViewData['detail'] := Context.Request.QueryStringParam('error_description');
    ViewData['error_code'] := LError;
    Exit(RenderView('auth/failed'));
  end;

  if LState.IsEmpty or LCode.IsEmpty or LCookieState.IsEmpty or
    not THashSHA2.GetHashString(LState).Equals(THashSHA2.GetHashString(LCookieState)) then
  begin
    LogW('Callback refused: state missing or not started by this browser');
    Context.Response.StatusCode := HTTP_STATUS.BadRequest;
    ViewData['title'] := Text('auth.refused');
    ViewData['detail'] := Text('auth.refused_detail');
    Exit(RenderView('auth/failed'));
  end;

  try
    LSession := Sessions.CompleteLogin(LState, LCode, Context.Request.QueryStringParam('iss'), LReturnTo);
  except
    on E: Exception do
    begin
      LogW('Login failed: ' + E.ClassName + ': ' + E.Message);
      Context.Response.StatusCode := HTTP_STATUS.BadRequest;
      ViewData['title'] := Text('auth.failed');
      ViewData['detail'] := Text('auth.failed_detail');
      Exit(RenderView('auth/failed'));
    end;
  end;

  // Far expiry: the session lifetime is the idle timeout of the store
  SetCookie(SESSION_COOKIE, LSession.Id, '/', EncodeDate(2099, 12, 31));
  Redirect(SafeLocalPath(LReturnTo));
  Result := '';
end;

procedure TAuthController.Logout;
var
  LLocation: string;
begin
  LLocation := '';
  // The post-logout redirect URI must be registered in the client (calculator-web)
  if Assigned(Session) then
    LLocation := Sessions.Logout(Session.Id, Settings.PublicURL + '/');
  if LLocation.IsEmpty then
    LLocation := '/';
  DeleteCookie(SESSION_COOKIE, '/');
  if Context.Request.IsHTMX then
    Context.Response.HXSetRedirect(LLocation)
  else
  begin
    Context.Response.StatusCode := HTTP_STATUS.SeeOther;
    Context.Response.SetCustomHeader('Location', LLocation);
  end;
end;

end.
