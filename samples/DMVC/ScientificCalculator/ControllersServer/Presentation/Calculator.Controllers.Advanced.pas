unit Calculator.Controllers.Advanced;

{ Presentation layer (controllers): statistics and equations, for the
  calculator-advanced role only. }

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  MVCFramework.Swagger.Commons,
  Calculator.Application.DTO,
  Calculator.Application.UseCases;

type
  [MVCPath('/api')]
  TAdvancedController = class(TMVCController)
  private
    FCalculator: ICalculatorService;
  protected
    procedure OnBeforeAction(AContext: TWebContext; const AActionName: string;
      var AHandled: Boolean); override;
  public
    [MVCInject]
    constructor Create(const ACalculator: ICalculatorService); reintroduce;

    [MVCDoc('Count, sum, mean, median, min, max, variance and standard deviation. ' +
      'sample = true: sample statistics (n - 1). Role: calculator-advanced.')]
    [MVCSwagParam(plBody, 'body', 'Values and kind of statistics', TStatisticsRequest)]
    [MVCSwagResponses(200, 'OK', TStatisticsReport, False, True)]
    [MVCPath('/statistics/describe')]
    [MVCHTTPMethod([httpPOST])]
    function Describe: IMVCResponse;

    [MVCDoc('Real or complex roots of a x^2 + b x + c = 0. Role: calculator-advanced.')]
    [MVCSwagResponses(200, 'OK', TQuadraticReport, False, True)]
    [MVCPath('/equations/quadratic')]
    [MVCHTTPMethod([httpPOST])]
    function Quadratic(const [MVCFromBody] ARequest: TQuadraticRequest): IMVCResponse;
  end;

implementation

uses
  IAMClient4D.DMVC.Helpers,
  Calculator.Presentation.Security,
  Calculator.Presentation.Requests;

constructor TAdvancedController.Create(const ACalculator: ICalculatorService);
begin
  inherited Create;
  FCalculator := ACalculator;
end;

procedure TAdvancedController.OnBeforeAction(AContext: TWebContext; const AActionName: string;
  var AHandled: Boolean);
begin
  inherited;
  AContext.RequireAnyRole([ROLE_CALCULATOR_ADVANCED]);
end;

function TAdvancedController.Describe: IMVCResponse;
var
  LRequest: TStatisticsRequest;
begin
  // Body read by hand: see Calculator.Presentation.Requests
  LRequest := StatisticsRequestFromBody(Context);
  try
    Result := OKResponse(FCalculator.DescribeStatistics(CallerOf(Context), LRequest));
  finally
    LRequest.Free;
  end;
end;

function TAdvancedController.Quadratic(const ARequest: TQuadraticRequest): IMVCResponse;
begin
  Result := OKResponse(FCalculator.SolveQuadratic(CallerOf(Context), ARequest));
end;

end.
