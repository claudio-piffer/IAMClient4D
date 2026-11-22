unit Calculator.Controllers.Account;

{ Presentation layer (controllers): the caller's identity and history.
  Any valid token is enough: no role check. }

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  MVCFramework.Swagger.Commons,
  Calculator.Application.DTO,
  Calculator.Application.UseCases,
  Calculator.Presentation.Security;

type
  [MVCPath('/api')]
  TAccountController = class(TMVCController)
  private
    FCalculator: ICalculatorService;
  public
    [MVCInject]
    constructor Create(const ACalculator: ICalculatorService); reintroduce;

    [MVCDoc('Who the token says you are, and the roles the API sees.')]
    [MVCSwagResponses(200, 'OK', TUserProfile, False, True)]
    [MVCPath('/me')]
    [MVCHTTPMethod([httpGET])]
    function GetMe: IMVCResponse;

    [MVCDoc('Your last calculations, most recent first (kept in memory).')]
    [MVCSwagResponses(200, 'OK', THistoryReport, False, True)]
    [MVCPath('/history')]
    [MVCHTTPMethod([httpGET])]
    function GetHistory: IMVCResponse;

    [MVCDoc('Deletes your history.')]
    [MVCSwagResponses(200, 'OK', TClearHistoryReport, False, True)]
    [MVCPath('/history')]
    [MVCHTTPMethod([httpDELETE])]
    function ClearHistory: IMVCResponse;
  end;

implementation

constructor TAccountController.Create(const ACalculator: ICalculatorService);
begin
  inherited Create;
  FCalculator := ACalculator;
end;

function TAccountController.GetMe: IMVCResponse;
begin
  Result := OKResponse(UserProfileOf(Context));
end;

function TAccountController.GetHistory: IMVCResponse;
begin
  Result := OKResponse(FCalculator.History(CallerOf(Context)));
end;

function TAccountController.ClearHistory: IMVCResponse;
begin
  Result := OKResponse(FCalculator.ClearHistory(CallerOf(Context)));
end;

end.
