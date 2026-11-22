unit Calculator.Web.Controllers.Account;

{ What belongs to the signed-in user: the history kept by the chosen server
  (each server has its own, in memory), the profile the API sees (/api/me) next
  to the claims of the access token, and the choice of the server. }

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  Calculator.Web.Controllers.Base;

type
  [MVCPath]
  TAccountController = class(TWebController)
  public
    [MVCPath('/history')]
    [MVCHTTPMethod([httpGET])]
    function History: string;

    /// <summary>The last calculations, for the side panel of the calculator pages.</summary>
    [MVCPath('/history/recent')]
    [MVCHTTPMethod([httpGET])]
    function RecentHistory: string;

    [MVCPath('/history')]
    [MVCHTTPMethod([httpDELETE])]
    function ClearHistory: string;

    [MVCPath('/profile')]
    [MVCHTTPMethod([httpGET])]
    function Profile: string;

    [MVCPath('/settings/backend')]
    [MVCHTTPMethod([httpPOST])]
    function ChooseBackend: string;
  end;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  JsonDataObjects,
  MVCFramework.HTMX,
  Calculator.Web.Settings,
  Calculator.Web.ApiClient;

const
  RECENT_ITEMS = 5;

function TAccountController.History: string;
begin
  ViewData['page_id'] := 'history';
  Result := RenderResult('history/index', Api(httpGET, '/api/history'));
end;

function TAccountController.RecentHistory: string;
var
  LResult: TJsonObject;
  LItems: TJsonArray;
begin
  LResult := Api(httpGET, '/api/history');
  if LResult.B['ok'] then
  begin
    LItems := LResult.O['data'].A['items'];
    while LItems.Count > RECENT_ITEMS do
      LItems.Delete(LItems.Count - 1);
  end;
  Result := RenderResult('history/_recent', LResult);
end;

function TAccountController.ClearHistory: string;
var
  LResult: TJsonObject;
begin
  LResult := Api(httpDELETE, '/api/history');
  if LResult.B['ok'] then
  begin
    LResult.Free;
    Context.Response.HXTriggerClientEvent('historyChanged');
    Result := RenderResult('history/_table', Api(httpGET, '/api/history'));
  end
  else
    Result := RenderResult('history/_table', LResult);
end;

function TAccountController.Profile: string;
begin
  ViewData['page_id'] := 'profile';
  ViewData['session_created'] := DateToISO8601(Session.CreatedAt, True);
  ViewData['token_expires'] := DateToISO8601(Session.AccessTokenExpiresAt, True);
  ViewData['token_claims'] := Session.AccessTokenClaims;
  ViewData['token_roles'] := string.Join(', ', Session.Roles);
  ViewData['audience'] := Settings.Audience;
  Result := RenderResult('profile/index', Api(httpGET, '/api/me'));
end;

function TAccountController.ChooseBackend: string;
var
  LBackend: TCalculatorBackend;
begin
  if not TryBackendFromId(Context.Request.ContentParam('backend'), LBackend) then
    raise EMVCException.Create(HTTP_STATUS.BadRequest, 'Unknown server');
  Session.Backend := LBackend;
  // The page reloads what it shows from the other server
  Context.Response.HXSetPageRefresh;
  Result := '';
end;

end.
