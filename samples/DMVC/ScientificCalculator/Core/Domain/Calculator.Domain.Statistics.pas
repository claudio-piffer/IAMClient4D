unit Calculator.Domain.Statistics;

{ Domain layer: descriptive statistics of a sample or of a population. }

interface

type
  TDescriptiveStatistics = record
    Count: Integer;
    Sum: Double;
    Mean: Double;
    Median: Double;
    Minimum: Double;
    Maximum: Double;
    Variance: Double;
    StandardDeviation: Double;
    /// <summary>True: sample (n - 1 degrees of freedom); False: population.</summary>
    IsSample: Boolean;
  end;

  TStatistics = record
  public const
    MAX_VALUES = 10000;
  public
    class function Describe(const AValues: TArray<Double>; const AIsSample: Boolean): TDescriptiveStatistics; static;
  end;

implementation

uses
  System.SysUtils,
  System.Math,
  System.Generics.Collections,
  Calculator.Domain.Errors;

class function TStatistics.Describe(const AValues: TArray<Double>; const AIsSample: Boolean): TDescriptiveStatistics;
var
  LSorted: TArray<Double>;
  LValue, LSquares: Double;
  LCount: Integer;
begin
  LCount := Length(AValues);
  if LCount = 0 then
    raise ECalculatorDomainError.Create('statistics: at least one value is required');
  if LCount > MAX_VALUES then
    raise ECalculatorDomainError.CreateFmt('statistics: at most %d values', [MAX_VALUES]);
  if AIsSample and (LCount < 2) then
    raise ECalculatorDomainError.Create('statistics: a sample needs at least two values');
  for LValue in AValues do
    EnsureFinite(LValue, 'statistics');

  LSorted := Copy(AValues);
  TArray.Sort<Double>(LSorted);

  Result.Count := LCount;
  Result.IsSample := AIsSample;
  Result.Minimum := LSorted[0];
  Result.Maximum := LSorted[LCount - 1];
  if Odd(LCount) then
    Result.Median := LSorted[LCount div 2]
  else
    Result.Median := (LSorted[LCount div 2 - 1] + LSorted[LCount div 2]) / 2;

  Result.Sum := 0;
  for LValue in AValues do
    Result.Sum := Result.Sum + LValue;
  Result.Mean := EnsureFinite(Result.Sum / LCount, 'statistics');

  // Two-pass variance: no cancellation of large sums of squares
  LSquares := 0;
  for LValue in AValues do
    LSquares := LSquares + Sqr(LValue - Result.Mean);
  if AIsSample then
    Result.Variance := LSquares / (LCount - 1)
  else
    Result.Variance := LSquares / LCount;
  Result.Variance := EnsureFinite(Result.Variance, 'statistics');
  Result.StandardDeviation := Sqrt(Result.Variance);
end;

end.
