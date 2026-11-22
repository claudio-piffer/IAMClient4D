unit Calculator.Domain.Errors;

{ Domain layer: errors of the mathematical rules. No framework dependency. }

interface

uses
  System.SysUtils;

type
  /// <summary>
  /// Raised when an operation is asked for values outside its domain
  /// (log of a negative number, factorial of 200, ...). The presentation
  /// layer answers it with 422 Unprocessable Content.
  /// </summary>
  ECalculatorDomainError = class(Exception);

/// <summary>Raises ECalculatorDomainError when AValue is NaN or infinite.</summary>
function EnsureFinite(const AValue: Double; const AOperation: string): Double;

implementation

uses
  System.Math;

function EnsureFinite(const AValue: Double; const AOperation: string): Double;
begin
  if IsNan(AValue) or IsInfinite(AValue) then
    raise ECalculatorDomainError.CreateFmt('%s: the result is not a finite number', [AOperation]);
  Result := AValue;
end;

end.
