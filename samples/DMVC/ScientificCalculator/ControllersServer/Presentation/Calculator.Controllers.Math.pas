unit Calculator.Controllers.Math;

{ Presentation layer (controllers): elementary math, trigonometry, expressions
  and number theory. IAM4DJWTBundle asks for a valid token (401); OnBeforeAction
  asks for the calculator-user role (403) on every action of the class. }

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  MVCFramework.Swagger.Commons,
  Calculator.Application.DTO,
  Calculator.Application.UseCases;

type
  [MVCPath('/api')]
  TMathController = class(TMVCController)
  private
    FCalculator: ICalculatorService;
  protected
    procedure OnBeforeAction(AContext: TWebContext; const AActionName: string;
      var AHandled: Boolean); override;
  public
    [MVCInject]
    constructor Create(const ACalculator: ICalculatorService); reintroduce;

    [MVCDoc('base ^ exponent. Role: calculator-user.')]
    [MVCSwagResponses(200, 'OK', TOperationResult, False, True)]
    [MVCPath('/elementary/power')]
    [MVCHTTPMethod([httpGET])]
    function Power(const [MVCFromQueryString('base')] ABase: Double;
      const [MVCFromQueryString('exponent')] AExponent: Double): IMVCResponse;

    [MVCDoc('Real root of the given degree (odd roots of negative numbers too). Role: calculator-user.')]
    [MVCSwagResponses(200, 'OK', TOperationResult, False, True)]
    [MVCPath('/elementary/root')]
    [MVCHTTPMethod([httpGET])]
    function Root(const [MVCFromQueryString('value')] AValue: Double;
      const [MVCFromQueryString('degree', 2)] ADegree: Integer): IMVCResponse;

    [MVCDoc('Logarithm in the given base (default 10). Role: calculator-user.')]
    [MVCSwagResponses(200, 'OK', TOperationResult, False, True)]
    [MVCPath('/elementary/log')]
    [MVCHTTPMethod([httpGET])]
    function Logarithm(const [MVCFromQueryString('value')] AValue: Double;
      const [MVCFromQueryString('base', 10)] ABase: Double): IMVCResponse;

    [MVCDoc('n! for n between 0 and 170. Role: calculator-user.')]
    [MVCSwagResponses(200, 'OK', TOperationResult, False, True)]
    [MVCPath('/elementary/factorial/($n)')]
    [MVCHTTPMethod([httpGET])]
    function Factorial(const n: Integer): IMVCResponse;

    [MVCDoc('sin, cos, tan of an angle; asin, acos, atan return an angle. unit: deg (default) or rad. Role: calculator-user.')]
    [MVCSwagResponses(200, 'OK', TOperationResult, False, True)]
    [MVCPath('/trigonometry/($fn)')]
    [MVCHTTPMethod([httpGET])]
    function Trigonometric(const fn: string; const [MVCFromQueryString('value')] AValue: Double;
      const [MVCFromQueryString('unit', 'deg')] AUnit: string): IMVCResponse;

    [MVCDoc('Value of an arithmetic expression: numbers (decimal point, 1.5E3), + - * / ^, unary minus, ' +
      'parentheses, postfix !, implicit multiplication (2pi), constants pi e tau phi, functions ' +
      'sin cos tan asin acos atan sqrt cbrt ln log abs exp. Body {"expression": "2 + 3 * sin(30)", "unit": "deg"}; ' +
      'unit deg (default) or rad. Role: calculator-user.')]
    [MVCSwagResponses(200, 'OK', TOperationResult, False, True)]
    [MVCPath('/expressions/evaluate')]
    [MVCHTTPMethod([httpPOST])]
    function Evaluate(const [MVCFromBody] ARequest: TExpressionRequest): IMVCResponse;

    [MVCDoc('Primality and prime factors of n (2 to 10^12). Role: calculator-user.')]
    [MVCSwagResponses(200, 'OK', TPrimeAnalysis, False, True)]
    [MVCPath('/number-theory/prime/($n)')]
    [MVCHTTPMethod([httpGET])]
    function Prime(const n: Int64): IMVCResponse;

    [MVCDoc('Combinations and permutations of k out of n (n up to 1000). Role: calculator-user.')]
    [MVCSwagResponses(200, 'OK', TCombinatorics, False, True)]
    [MVCPath('/number-theory/combinatorics')]
    [MVCHTTPMethod([httpGET])]
    function Combinatorics(const [MVCFromQueryString('n')] AN: Integer;
      const [MVCFromQueryString('k')] AK: Integer): IMVCResponse;
  end;

implementation

uses
  IAMClient4D.DMVC.Helpers,
  Calculator.Presentation.Security;

constructor TMathController.Create(const ACalculator: ICalculatorService);
begin
  inherited Create;
  FCalculator := ACalculator;
end;

procedure TMathController.OnBeforeAction(AContext: TWebContext; const AActionName: string;
  var AHandled: Boolean);
begin
  inherited;
  // One policy for the whole controller: 403 + WWW-Authenticate insufficient_scope
  AContext.RequireAnyRole([ROLE_CALCULATOR_USER]);
end;

function TMathController.Power(const ABase, AExponent: Double): IMVCResponse;
begin
  Result := OKResponse(FCalculator.Power(CallerOf(Context), ABase, AExponent));
end;

function TMathController.Root(const AValue: Double; const ADegree: Integer): IMVCResponse;
begin
  Result := OKResponse(FCalculator.Root(CallerOf(Context), AValue, ADegree));
end;

function TMathController.Logarithm(const AValue, ABase: Double): IMVCResponse;
begin
  Result := OKResponse(FCalculator.Logarithm(CallerOf(Context), AValue, ABase));
end;

function TMathController.Factorial(const n: Integer): IMVCResponse;
begin
  Result := OKResponse(FCalculator.Factorial(CallerOf(Context), n));
end;

function TMathController.Trigonometric(const fn: string; const AValue: Double;
  const AUnit: string): IMVCResponse;
begin
  Result := OKResponse(FCalculator.Trigonometric(CallerOf(Context), fn, AValue, AUnit));
end;

function TMathController.Evaluate(const ARequest: TExpressionRequest): IMVCResponse;
begin
  Result := OKResponse(FCalculator.Evaluate(CallerOf(Context), ARequest));
end;

function TMathController.Prime(const n: Int64): IMVCResponse;
begin
  Result := OKResponse(FCalculator.AnalyzeNumber(CallerOf(Context), n));
end;

function TMathController.Combinatorics(const AN, AK: Integer): IMVCResponse;
begin
  Result := OKResponse(FCalculator.Combinatorics(CallerOf(Context), AN, AK));
end;

end.
