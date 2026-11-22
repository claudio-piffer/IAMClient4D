unit Calculator.Controllers.Public;

{ Presentation layer (controllers): endpoints open to everybody.
  [IAM4DPublic] on the class: IAM4DJWTBundle does not ask for a token. }

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  MVCFramework.Swagger.Commons,
  IAMClient4D.DMVC.Attributes,
  Calculator.Application.DTO,
  Calculator.Application.UseCases,
  Calculator.Presentation.Settings;

type
  [MVCPath('/api')]
  [IAM4DPublic]
  TPublicController = class(TMVCController)
  private
    FCalculator: ICalculatorService;
  public
    [MVCInject]
    constructor Create(const ACalculator: ICalculatorService); reintroduce;

    [MVCDoc('Service description: where to get a token and which roles the API checks. No token needed.')]
    [MVCSwagResponses(200, 'OK', TServiceInfo, False, True)]
    [MVCPath('/info')]
    [MVCHTTPMethod([httpGET])]
    function GetInfo: IMVCResponse;

    [MVCDoc('Mathematical constants. No token needed.')]
    [MVCSwagResponses(200, 'OK', TConstantsReport, False, True)]
    [MVCPath('/constants')]
    [MVCHTTPMethod([httpGET])]
    function GetConstants: IMVCResponse;
  end;

implementation

uses
  Calculator.Presentation.Composition;

constructor TPublicController.Create(const ACalculator: ICalculatorService);
begin
  inherited Create;
  FCalculator := ACalculator;
end;

function TPublicController.GetInfo: IMVCResponse;
begin
  Result := OKResponse(TServiceInfo.Create(Settings, 'controllers'));
end;

function TPublicController.GetConstants: IMVCResponse;
begin
  Result := OKResponse(FCalculator.Constants);
end;

end.
