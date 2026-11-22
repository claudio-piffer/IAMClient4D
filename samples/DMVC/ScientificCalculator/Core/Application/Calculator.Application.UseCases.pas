unit Calculator.Application.UseCases;

{ Application layer: the use cases. They apply the domain rules, record each
  calculation in the history of the caller and return DTOs. No framework,
  no token: authentication and roles are checked by the presentation layer. }

interface

uses
  Calculator.Application.Caller,
  Calculator.Application.DTO,
  Calculator.Application.Ports;

type
  ICalculatorService = interface
    ['{C5D1A7E3-6B2F-4C98-8E4A-1D7F3B9C2E65}']
    function Power(const ACaller: TCaller; const ABase, AExponent: Double): TOperationResult;
    function Root(const ACaller: TCaller; const AValue: Double; const ADegree: Integer): TOperationResult;
    function Logarithm(const ACaller: TCaller; const AValue, ABase: Double): TOperationResult;
    function Factorial(const ACaller: TCaller; const AN: Integer): TOperationResult;
    /// <summary>AFunction: sin, cos, tan, asin, acos, atan; AUnit: deg or rad.</summary>
    function Trigonometric(const ACaller: TCaller; const AFunction: string; const AValue: Double;
      const AUnit: string): TOperationResult;
    /// <summary>An arithmetic expression with functions and constants (Calculator.Domain.Expressions).</summary>
    function Evaluate(const ACaller: TCaller; const ARequest: TExpressionRequest): TOperationResult;
    function AnalyzeNumber(const ACaller: TCaller; const AN: Int64): TPrimeAnalysis;
    function Combinatorics(const ACaller: TCaller; const AN, AK: Integer): TCombinatorics;
    function DescribeStatistics(const ACaller: TCaller; const ARequest: TStatisticsRequest): TStatisticsReport;
    function SolveQuadratic(const ACaller: TCaller; const ARequest: TQuadraticRequest): TQuadraticReport;
    function History(const ACaller: TCaller): THistoryReport;
    function ClearHistory(const ACaller: TCaller): TClearHistoryReport;
    function Constants: TConstantsReport;
  end;

  TCalculatorService = class(TInterfacedObject, ICalculatorService)
  private
    FHistory: ICalculationHistory;
    FClock: IClock;
    procedure Track(const ACaller: TCaller; const AOperation, AExpression, AOutcome: string);
    function OperationResult(const ACaller: TCaller; const AOperation, AExpression: string;
      const AValue: Double): TOperationResult;
  public
    constructor Create(const AHistory: ICalculationHistory; const AClock: IClock);
    function Power(const ACaller: TCaller; const ABase, AExponent: Double): TOperationResult;
    function Root(const ACaller: TCaller; const AValue: Double; const ADegree: Integer): TOperationResult;
    function Logarithm(const ACaller: TCaller; const AValue, ABase: Double): TOperationResult;
    function Factorial(const ACaller: TCaller; const AN: Integer): TOperationResult;
    function Trigonometric(const ACaller: TCaller; const AFunction: string; const AValue: Double;
      const AUnit: string): TOperationResult;
    function Evaluate(const ACaller: TCaller; const ARequest: TExpressionRequest): TOperationResult;
    function AnalyzeNumber(const ACaller: TCaller; const AN: Int64): TPrimeAnalysis;
    function Combinatorics(const ACaller: TCaller; const AN, AK: Integer): TCombinatorics;
    function DescribeStatistics(const ACaller: TCaller; const ARequest: TStatisticsRequest): TStatisticsReport;
    function SolveQuadratic(const ACaller: TCaller; const ARequest: TQuadraticRequest): TQuadraticReport;
    function History(const ACaller: TCaller): THistoryReport;
    function ClearHistory(const ACaller: TCaller): TClearHistoryReport;
    function Constants: TConstantsReport;
  end;

implementation

uses
  System.SysUtils,
  System.StrUtils,
  System.DateUtils,
  Calculator.Domain.Errors,
  Calculator.Domain.Elementary,
  Calculator.Domain.Expressions,
  Calculator.Domain.NumberTheory,
  Calculator.Domain.Statistics,
  Calculator.Domain.Equations,
  Calculator.Domain.Constants,
  Calculator.Domain.Calculation;

// Numbers in expressions: '.' as decimal separator, whatever the server locale
function Num(const AValue: Double): string;
begin
  Result := FloatToStr(AValue, TFormatSettings.Invariant);
end;

function JoinFactors(const AFactors: TArray<Int64>): string;
var
  LIndex: Integer;
begin
  Result := '';
  for LIndex := 0 to High(AFactors) do
  begin
    if LIndex > 0 then
      Result := Result + ' x ';
    Result := Result + IntToStr(AFactors[LIndex]);
  end;
end;

function ComplexToText(const AValue: TComplexNumber): string;
begin
  if AValue.Im = 0 then
    Result := Num(AValue.Re)
  else if AValue.Im > 0 then
    Result := Num(AValue.Re) + ' + ' + Num(AValue.Im) + 'i'
  else
    Result := Num(AValue.Re) + ' - ' + Num(-AValue.Im) + 'i';
end;

procedure RequireBody(const ARequest: TObject; const AOperation: string);
begin
  if not Assigned(ARequest) then
    raise ECalculatorDomainError.CreateFmt('%s: the request body is required', [AOperation]);
end;

{ TCalculatorService }

constructor TCalculatorService.Create(const AHistory: ICalculationHistory; const AClock: IClock);
begin
  inherited Create;
  if not Assigned(AHistory) or not Assigned(AClock) then
    raise EArgumentNilException.Create('TCalculatorService: history and clock are required');
  FHistory := AHistory;
  FClock := AClock;
end;

procedure TCalculatorService.Track(const ACaller: TCaller; const AOperation, AExpression, AOutcome: string);
begin
  FHistory.Add(ACaller.Subject, TCalculation.Create(AOperation, AExpression, AOutcome, FClock.NowUTC));
end;

function TCalculatorService.OperationResult(const ACaller: TCaller; const AOperation, AExpression: string;
  const AValue: Double): TOperationResult;
begin
  // History first: the DTO is created only when nothing else can fail
  Track(ACaller, AOperation, AExpression, Num(AValue));
  Result := TOperationResult.Create;
  Result.Operation := AOperation;
  Result.Expression := AExpression;
  Result.Value := AValue;
end;

function TCalculatorService.Power(const ACaller: TCaller; const ABase, AExponent: Double): TOperationResult;
begin
  Result := OperationResult(ACaller, 'power', Num(ABase) + '^' + Num(AExponent),
    TElementaryMath.Power(ABase, AExponent));
end;

function TCalculatorService.Root(const ACaller: TCaller; const AValue: Double;
  const ADegree: Integer): TOperationResult;
begin
  Result := OperationResult(ACaller, 'root', Format('root(%s, %d)', [Num(AValue), ADegree]),
    TElementaryMath.Root(AValue, ADegree));
end;

function TCalculatorService.Logarithm(const ACaller: TCaller; const AValue, ABase: Double): TOperationResult;
begin
  Result := OperationResult(ACaller, 'log', Format('log(%s, base %s)', [Num(AValue), Num(ABase)]),
    TElementaryMath.Logarithm(AValue, ABase));
end;

function TCalculatorService.Factorial(const ACaller: TCaller; const AN: Integer): TOperationResult;
begin
  Result := OperationResult(ACaller, 'factorial', IntToStr(AN) + '!', TElementaryMath.Factorial(AN));
end;

function TCalculatorService.Trigonometric(const ACaller: TCaller; const AFunction: string;
  const AValue: Double; const AUnit: string): TOperationResult;
var
  LFunction: TTrigFunction;
  LUnit: TAngleUnit;
  LExpression: string;
begin
  LFunction := TTrigFunction.Parse(AFunction);
  LUnit := TAngleUnit.Parse(AUnit);
  if LFunction.IsInverse then
    LExpression := Format('%s(%s) in %s', [LFunction.Name, Num(AValue), LUnit.Name])
  else
    LExpression := Format('%s(%s %s)', [LFunction.Name, Num(AValue), LUnit.Name]);
  Result := OperationResult(ACaller, LFunction.Name, LExpression,
    TElementaryMath.Trigonometric(LFunction, AValue, LUnit));
end;

function TCalculatorService.Evaluate(const ACaller: TCaller;
  const ARequest: TExpressionRequest): TOperationResult;
var
  LUnit: TAngleUnit;
  LExpression, LShown: string;
begin
  RequireBody(ARequest, 'expression');
  LUnit := TAngleUnit.Parse(IfThen(ARequest.&Unit.Trim.IsEmpty, 'deg', ARequest.&Unit));
  LExpression := ARequest.Expression.Trim;
  // The unit matters only to the trigonometric functions
  LShown := LExpression;
  if LExpression.ToLower.Contains('sin') or LExpression.ToLower.Contains('cos') or
    LExpression.ToLower.Contains('tan') then
    LShown := LExpression + ' [' + LUnit.Name + ']';
  Result := OperationResult(ACaller, 'expression', LShown, TExpressionEvaluator.Evaluate(LExpression, LUnit));
end;

function TCalculatorService.AnalyzeNumber(const ACaller: TCaller; const AN: Int64): TPrimeAnalysis;
var
  LIsPrime: Boolean;
  LFactors: TArray<Int64>;
begin
  LIsPrime := TNumberTheory.IsPrime(AN);
  LFactors := TNumberTheory.PrimeFactors(AN);
  Track(ACaller, 'prime', IntToStr(AN), IfThen(LIsPrime, 'prime', JoinFactors(LFactors)));
  Result := TPrimeAnalysis.Create;
  Result.Number := AN;
  Result.IsPrime := LIsPrime;
  Result.Factors := LFactors;
end;

function TCalculatorService.Combinatorics(const ACaller: TCaller; const AN, AK: Integer): TCombinatorics;
var
  LCombinations, LPermutations: Double;
begin
  LCombinations := TNumberTheory.Combinations(AN, AK);
  LPermutations := TNumberTheory.Permutations(AN, AK);
  Track(ACaller, 'combinatorics', Format('C(%d, %d), P(%d, %d)', [AN, AK, AN, AK]),
    Num(LCombinations) + ', ' + Num(LPermutations));
  Result := TCombinatorics.Create;
  Result.N := AN;
  Result.K := AK;
  Result.Combinations := LCombinations;
  Result.Permutations := LPermutations;
end;

function TCalculatorService.DescribeStatistics(const ACaller: TCaller;
  const ARequest: TStatisticsRequest): TStatisticsReport;
var
  LStats: TDescriptiveStatistics;
begin
  RequireBody(ARequest, 'statistics');
  LStats := TStatistics.Describe(ARequest.Values, ARequest.Sample);
  Track(ACaller, 'statistics', Format('%d values (%s)', [LStats.Count, IfThen(LStats.IsSample, 'sample', 'population')]),
    'mean ' + Num(LStats.Mean) + ', sd ' + Num(LStats.StandardDeviation));
  Result := TStatisticsReport.Create;
  Result.Count := LStats.Count;
  Result.Sum := LStats.Sum;
  Result.Mean := LStats.Mean;
  Result.Median := LStats.Median;
  Result.Minimum := LStats.Minimum;
  Result.Maximum := LStats.Maximum;
  Result.Variance := LStats.Variance;
  Result.StandardDeviation := LStats.StandardDeviation;
  Result.Sample := LStats.IsSample;
end;

function TCalculatorService.SolveQuadratic(const ACaller: TCaller;
  const ARequest: TQuadraticRequest): TQuadraticReport;
var
  LSolution: TQuadraticSolution;
  LRoot: TComplexNumber;
  LEquation: string;
begin
  RequireBody(ARequest, 'quadratic');
  LSolution := TEquations.SolveQuadratic(ARequest.A, ARequest.B, ARequest.C);
  LEquation := Format('%sx^2 + %sx + %s = 0', [Num(ARequest.A), Num(ARequest.B), Num(ARequest.C)]);
  Track(ACaller, 'quadratic', LEquation,
    ComplexToText(LSolution.Roots[0]) + '; ' + ComplexToText(LSolution.Roots[1]));
  Result := TQuadraticReport.Create;
  try
    Result.Equation := LEquation;
    Result.Discriminant := LSolution.Discriminant;
    Result.Kind := QUADRATIC_ROOTS_KIND_NAMES[LSolution.Kind];
    for LRoot in LSolution.Roots do
      Result.Roots.Add(TComplexValue.Create(LRoot.Re, LRoot.Im));
  except
    Result.Free;
    raise;
  end;
end;

function TCalculatorService.History(const ACaller: TCaller): THistoryReport;
var
  LCalculation: TCalculation;
  LItem: TCalculationItem;
begin
  Result := THistoryReport.Create;
  try
    Result.UserName := ACaller.UserName;
    for LCalculation in FHistory.List(ACaller.Subject) do
    begin
      LItem := TCalculationItem.Create;
      Result.Items.Add(LItem);
      LItem.Operation := LCalculation.Operation;
      LItem.Expression := LCalculation.Expression;
      LItem.Outcome := LCalculation.Outcome;
      LItem.PerformedAt := DateToISO8601(LCalculation.PerformedAt, True);
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TCalculatorService.ClearHistory(const ACaller: TCaller): TClearHistoryReport;
var
  LRemoved: Integer;
begin
  LRemoved := FHistory.Clear(ACaller.Subject);
  Result := TClearHistoryReport.Create;
  Result.Removed := LRemoved;
end;

function TCalculatorService.Constants: TConstantsReport;
var
  LConstant: TMathConstant;
  LItem: TConstantItem;
begin
  Result := TConstantsReport.Create;
  try
    for LConstant in MathConstants do
    begin
      LItem := TConstantItem.Create;
      Result.Items.Add(LItem);
      LItem.Name := LConstant.Name;
      LItem.Symbol := LConstant.Symbol;
      LItem.Value := LConstant.Value;
      LItem.Description := LConstant.Description;
    end;
  except
    Result.Free;
    raise;
  end;
end;

end.
