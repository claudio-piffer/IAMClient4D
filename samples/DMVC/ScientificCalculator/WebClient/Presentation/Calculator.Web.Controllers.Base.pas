unit Calculator.Web.Controllers.Base;

{ Base of every web controller: finds the session of the cookie, fills what
  baselayout.html needs, sends to the login the requests of protected pages
  without a session, and calls the API on the backend chosen by the user. }

interface

uses
  System.Generics.Collections,
  JsonDataObjects,
  MVCFramework,
  MVCFramework.Commons,
  Calculator.Web.Settings,
  Calculator.Web.Sessions,
  Calculator.Web.ApiClient;

const
  SESSION_COOKIE = 'calcweb_session';
  LOGIN_COOKIE = 'calcweb_login';
  ROLE_CALCULATOR_USER = 'calculator-user';
  ROLE_CALCULATOR_ADVANCED = 'calculator-advanced';

type
  TWebController = class(TMVCController)
  private
    FSession: ICalculatorSession;
    FInputErrors: TList<string>;
    procedure SetLayoutData(const AActionName: string);
  protected
    procedure OnBeforeAction(AContext: TWebContext; const AActionName: string; var AHandled: Boolean); override;
    /// <summary>False for the pages anybody can open.</summary>
    function RequiresSession: Boolean; virtual;
    /// <summary>Navigation item of the pages of this controller.</summary>
    function PageId: string; virtual;
    /// <summary>Path of the page the user is on (for a fragment: the page that asked for it).</summary>
    function CurrentPage: string;
    procedure SendToLogin(const AReturnTo: string);
    /// <summary>HttpOnly, SameSite=Lax cookie. Always with an Expires: a zero one goes out as 1899.</summary>
    procedure SetCookie(const AName, AValue, APath: string; const AExpires: TDateTime);
    procedure DeleteCookie(const AName, APath: string);
    function Backend: TCalculatorBackend;
    /// <summary>The API call with the access token of the session; the caller owns the result.</summary>
    function Api(const AMethod: TMVCHTTPMethodType; const AResource: string;
      const AQuery: TArray<TQueryParam> = nil; const ABody: TJsonObject = nil): TJsonObject;
    /// <summary>Renders AView with the view model as "r" and frees it.</summary>
    function RenderResult(const AView: string; const AResult: TJsonObject): string;
    // Form fields: a wrong value is collected in the input errors
    function FieldNumber(const AName, ALabel: string; out AValue: string): Boolean;
    function FieldInteger(const AName, ALabel: string; out AValue: Int64): Boolean;
    function HasInputErrors: Boolean;
    /// <summary>A text of i18n\<lang>.json; AArgs: name, value pairs of the {name} placeholders.</summary>
    function Text(const AKey: string; const AArgs: array of string): string; overload;
    function Text(const AKey: string): string; overload;
    function RenderInputErrors(const AView: string): string;
    property Session: ICalculatorSession read FSession;
  public
    destructor Destroy; override;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  System.NetEncoding,
  Web.HTTPApp,
  MVCFramework.HTMX,
  MVCFramework.Filters,
  MVCFramework.Logger,
  Calculator.Web.Formatting,
  Calculator.Web.Texts;

destructor TWebController.Destroy;
begin
  FInputErrors.Free;
  inherited;
end;

function TWebController.RequiresSession: Boolean;
begin
  Result := True;
end;

function TWebController.PageId: string;
begin
  Result := '';
end;

function TWebController.CurrentPage: string;
begin
  // A fragment comes back to its page after the login
  if Context.Request.IsHTMX then
    Result := Context.Request.Headers['HX-Current-URL']
  else
    Result := Context.Request.PathInfo;
  if Result.StartsWith(Settings.PublicURL, True) then
    Result := Result.Substring(Settings.PublicURL.Length);
end;

procedure TWebController.OnBeforeAction(AContext: TWebContext; const AActionName: string; var AHandled: Boolean);
begin
  inherited;
  FSession := Sessions.Find(AContext.Request.Cookie(SESSION_COOKIE));
  if (FSession = nil) and RequiresSession then
  begin
    SendToLogin(CurrentPage);
    AHandled := True;
    Exit;
  end;
  SetLayoutData(AActionName);
end;

procedure TWebController.SetLayoutData(const AActionName: string);
var
  LBackend: TCalculatorBackend;
begin
  // Texts of the request language (LanguageHTTPFilter): the controller has a view data of its own
  ViewData['t'] := Context.ViewData['t'];
  ViewData['lang'] := Context.ViewData['lang'];
  ViewData['js_texts'] := Context.ViewData['js_texts'];
  ViewData['app_name'] := APP_NAME;
  ViewData['dmvc_version'] := DMVCFRAMEWORK_VERSION;
  ViewData['current_year'] := YearOf(Now);
  ViewData['page_id'] := PageId;
  ViewData['keycloak_url'] := Settings.Issuer;
  for LBackend := Low(TCalculatorBackend) to High(TCalculatorBackend) do
    ViewData[BACKEND_IDS[LBackend].Replace('-', '_') + '_url'] := Settings.BackendURLs[LBackend];
  ViewData['backend'] := BACKEND_IDS[Backend];
  ViewData['backend_label'] := BACKEND_LABELS[Backend];
  ViewData['is_authenticated'] := Assigned(FSession);
  if Assigned(FSession) then
  begin
    ViewData['user_name'] := FSession.UserName;
    ViewData['display_name'] := FSession.DisplayName;
    ViewData['can_calculate'] := FSession.HasRole(ROLE_CALCULATOR_USER);
    ViewData['can_advanced'] := FSession.HasRole(ROLE_CALCULATOR_ADVANCED);
    ViewData['csrf_token'] := CSRFToken(Settings.CsrfSecret, FSession.Id);
  end;
end;

procedure TWebController.SendToLogin(const AReturnTo: string);
var
  LURL: string;
begin
  LURL := '/login?next=' + TNetEncoding.URL.EncodeQuery(SafeLocalPath(AReturnTo));
  if Context.Request.IsHTMX then
  begin
    // A 302 would be followed by the XMLHttpRequest, up to Keycloak: full page redirect instead
    Context.Response.HXSetRedirect(LURL);
    Context.Response.StatusCode := HTTP_STATUS.OK;
  end
  else
    Redirect(LURL);
end;

procedure TWebController.SetCookie(const AName, AValue, APath: string; const AExpires: TDateTime);
var
  LCookie: TCookie;
begin
  LCookie := Context.Response.Cookies.Add;
  LCookie.Name := AName;
  LCookie.Value := AValue;
  LCookie.Path := APath;
  LCookie.HttpOnly := True;
  LCookie.Secure := Settings.CookieSecure;
  // Lax: sent on the top-level navigation back from Keycloak, not on cross-site POSTs
  LCookie.SameSite := 'Lax';
  LCookie.Expires := AExpires;
end;

procedure TWebController.DeleteCookie(const AName, APath: string);
begin
  SetCookie(AName, '', APath, EncodeDate(1970, 1, 1));
end;

function TWebController.Backend: TCalculatorBackend;
begin
  if Assigned(FSession) then
    Result := FSession.Backend
  else
    Result := cbControllers;
end;

function TWebController.Api(const AMethod: TMVCHTTPMethodType; const AResource: string;
  const AQuery: TArray<TQueryParam>; const ABody: TJsonObject): TJsonObject;
var
  LToken: string;
begin
  LToken := '';
  if Assigned(FSession) then
  try
    LToken := FSession.AccessToken;
  except
    on E: ESessionExpired do
    begin
      // Refresh token gone (Keycloak session ended): sign in again
      Sessions.Drop(FSession.Id);
      DeleteCookie(SESSION_COOKIE, '/');
      if Context.Request.IsHTMX then
        SendToLogin(CurrentPage);
      LogW('Session ended: ' + E.Message);
      Result := TCalculatorApi.InputError(Backend, Text('input.session_ended'));
      Result.O['error'].S['kind'] := 'session';
      Exit;
    end;
  end;
  Result := TCalculatorApi.Call(Backend, LToken, AMethod, AResource, AQuery, ABody);
end;

function TWebController.RenderResult(const AView: string; const AResult: TJsonObject): string;
begin
  try
    ViewData['r'] := AResult;
    Result := RenderView(AView);
  finally
    AResult.Free;
  end;
end;

function TWebController.FieldNumber(const AName, ALabel: string; out AValue: string): Boolean;
var
  LNumber: Double;
begin
  Result := TryParseNumber(Context.Request.ContentParam(AName), LNumber);
  if Result then
    AValue := ApiNumber(LNumber)
  else
  begin
    if FInputErrors = nil then
      FInputErrors := TList<string>.Create;
    FInputErrors.Add(Text('input.not_number', ['field', ALabel, 'value', Context.Request.ContentParam(AName)]));
  end;
end;

function TWebController.FieldInteger(const AName, ALabel: string; out AValue: Int64): Boolean;
begin
  Result := TryParseInteger(Context.Request.ContentParam(AName), AValue);
  if not Result then
  begin
    if FInputErrors = nil then
      FInputErrors := TList<string>.Create;
    FInputErrors.Add(Text('input.not_integer', ['field', ALabel, 'value', Context.Request.ContentParam(AName)]));
  end;
end;

function TWebController.HasInputErrors: Boolean;
begin
  Result := Assigned(FInputErrors) and (FInputErrors.Count > 0);
end;

function TWebController.Text(const AKey: string; const AArgs: array of string): string;
begin
  Result := Calculator.Web.Texts.Text(Context, AKey, AArgs);
end;

function TWebController.Text(const AKey: string): string;
begin
  Result := Text(AKey, []);
end;

function TWebController.RenderInputErrors(const AView: string): string;
begin
  Result := RenderResult(AView, TCalculatorApi.InputError(Backend, string.Join('; ', FInputErrors.ToArray)));
end;

end.
