unit Calculator.Domain.Equations;

{ Domain layer: roots of a x^2 + b x + c = 0, real or complex. }

interface

type
  TComplexNumber = record
    Re: Double;
    Im: Double;
    class function Create(const ARe, AIm: Double): TComplexNumber; static;
  end;

  TQuadraticRootsKind = (qrkTwoReal, qrkOneReal, qrkComplex);

  TQuadraticSolution = record
    Discriminant: Double;
    Kind: TQuadraticRootsKind;
    /// <summary>Two roots, equal when Kind = qrkOneReal.</summary>
    Roots: TArray<TComplexNumber>;
  end;

  TEquations = record
    class function SolveQuadratic(const AA, AB, AC: Double): TQuadraticSolution; static;
  end;

const
  QUADRATIC_ROOTS_KIND_NAMES: array[TQuadraticRootsKind] of string = ('two-real', 'one-real', 'complex');

implementation

uses
  System.Math,
  Calculator.Domain.Errors;

{ TComplexNumber }

class function TComplexNumber.Create(const ARe, AIm: Double): TComplexNumber;
begin
  Result.Re := ARe;
  Result.Im := AIm;
end;

{ TEquations }

class function TEquations.SolveQuadratic(const AA, AB, AC: Double): TQuadraticSolution;
var
  LSqrt, LQ: Double;
begin
  EnsureFinite(AA, 'quadratic');
  EnsureFinite(AB, 'quadratic');
  EnsureFinite(AC, 'quadratic');
  if AA = 0 then
    raise ECalculatorDomainError.Create('quadratic: a must be different from 0');

  Result.Discriminant := EnsureFinite(AB * AB - 4 * AA * AC, 'quadratic');

  if Result.Discriminant > 0 then
  begin
    Result.Kind := qrkTwoReal;
    LSqrt := Sqrt(Result.Discriminant);
    // Numerically stable: no subtraction of close values
    if AB >= 0 then
      LQ := -0.5 * (AB + LSqrt)
    else
      LQ := -0.5 * (AB - LSqrt);
    Result.Roots := [TComplexNumber.Create(LQ / AA, 0), TComplexNumber.Create(AC / LQ, 0)];
  end
  else if Result.Discriminant = 0 then
  begin
    Result.Kind := qrkOneReal;
    Result.Roots := [TComplexNumber.Create(-AB / (2 * AA), 0), TComplexNumber.Create(-AB / (2 * AA), 0)];
  end
  else
  begin
    Result.Kind := qrkComplex;
    LSqrt := Sqrt(-Result.Discriminant) / (2 * AA);
    Result.Roots := [TComplexNumber.Create(-AB / (2 * AA), LSqrt), TComplexNumber.Create(-AB / (2 * AA), -LSqrt)];
  end;
end;

end.
