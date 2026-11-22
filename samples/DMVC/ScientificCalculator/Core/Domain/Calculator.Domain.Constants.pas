unit Calculator.Domain.Constants;

{ Domain layer: well-known mathematical constants. }

interface

type
  TMathConstant = record
    Name: string;
    Symbol: string;
    Value: Double;
    Description: string;
  end;

function MathConstants: TArray<TMathConstant>;

implementation

function Constant(const AName, ASymbol: string; const AValue: Double; const ADescription: string): TMathConstant;
begin
  Result.Name := AName;
  Result.Symbol := ASymbol;
  Result.Value := AValue;
  Result.Description := ADescription;
end;

function MathConstants: TArray<TMathConstant>;
begin
  Result := [
    Constant('pi', #$03C0, Pi, 'Ratio of a circle''s circumference to its diameter'),
    Constant('tau', #$03C4, 2 * Pi, 'Ratio of a circle''s circumference to its radius'),
    Constant('e', 'e', Exp(1), 'Base of the natural logarithm'),
    Constant('phi', #$03C6, (1 + Sqrt(5)) / 2, 'Golden ratio'),
    Constant('sqrt2', #$221A'2', Sqrt(2), 'Pythagoras'' constant'),
    Constant('ln2', 'ln 2', Ln(2), 'Natural logarithm of 2'),
    Constant('gamma', #$03B3, 0.57721566490153286, 'Euler-Mascheroni constant')];
end;

end.
