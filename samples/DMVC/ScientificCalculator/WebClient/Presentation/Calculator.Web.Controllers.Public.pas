unit Calculator.Web.Controllers.Public;

{ Pages anybody can open: the home page and its fragments, which call the
  public endpoints of the API (/api/info, /api/constants) without a token. }

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  Calculator.Web.Controllers.Base;

type
  [MVCPath]
  TPublicController = class(TWebController)
  protected
    function RequiresSession: Boolean; override;
    function PageId: string; override;
  public
    [MVCPath('/')]
    [MVCHTTPMethod([httpGET])]
    function Home: string;

    /// <summary>GET /api/info of both servers: is each one up?</summary>
    [MVCPath('/fragments/servers')]
    [MVCHTTPMethod([httpGET])]
    function Servers: string;

    [MVCPath('/fragments/constants')]
    [MVCHTTPMethod([httpGET])]
    function Constants: string;
  end;

implementation

uses
  System.SysUtils,
  JsonDataObjects,
  Calculator.Web.Settings,
  Calculator.Web.ApiClient;

function TPublicController.RequiresSession: Boolean;
begin
  Result := False;
end;

function TPublicController.PageId: string;
begin
  Result := 'home';
end;

function TPublicController.Home: string;
begin
  Result := RenderView('home/index');
end;

function TPublicController.Servers: string;
var
  LServers: TJsonObject;
  LBackend: TCalculatorBackend;
begin
  LServers := TJsonObject.Create;
  try
    for LBackend := Low(TCalculatorBackend) to High(TCalculatorBackend) do
      LServers.A['items'].Add(TCalculatorApi.Call(LBackend, '', httpGET, '/api/info', nil, nil, 2000));
    ViewData['servers'] := LServers;
    Result := RenderView('home/_servers');
  finally
    LServers.Free;
  end;
end;

function TPublicController.Constants: string;
begin
  Result := RenderResult('home/_constants', TCalculatorApi.Call(Backend, '', httpGET, '/api/constants'));
end;

end.
