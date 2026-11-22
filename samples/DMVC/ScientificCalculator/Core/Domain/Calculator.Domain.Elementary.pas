unit Calculator.Domain.Elementary;

{ Domain layer: powers, roots, logarithms, factorial and trigonometry. }

interface

type
  TAngleUnit = (auRadians, auDegrees);

  TTrigFunction = (tfSin, tfCos, tfTan, tfAsin, tfAcos, tfAtan);

  TAngleUnitHelper = record helper for TAngleUnit
    /// <summary>'rad'/'radians' or 'deg'/'degrees' (case-insensitive).</summary>
    class function Parse(const AName: string): TAngleUnit; static;
    function Name: string;
  end;

  TTrigFunctionHelper = record helper for TTrigFunction
    /// <summary>sin, cos, tan, asin, acos, atan (case-insensitive).</summary>
    class function Parse(const AName: string): TTrigFunction; static;
    function Name: string;
    /// <summary>asin, acos, atan: the argument is a number, the result an angle.</summary>
    function IsInverse: Boolean;
  end;

  TElementaryMath = record
  public const
    MAX_FACTORIAL = 170; // 171! does not fit a Double
    MAX_ROOT_DEGREE = 1000;
  public
    class function Power(const ABase, AExponent: Double): Double; static;
    class function Root(const AValue: Double; const ADegree: Integer): Double; static;
    class function Logarithm(const AValue, ABase: Double): Double; static;
    class function Factorial(const AN: Integer): Double; static;
    /// <summary>
    /// Direct functions take an angle in AUnit; inverse functions take a number
    /// and return the angle in AUnit.
    /// </summary>
    class function Trigonometric(const AFunction: TTrigFunction; const AValue: Double;
      const AUnit: TAngleUnit): Double; static;
  end;

implementation

uses
  System.SysUtils,
  System.Math,
  Calculator.Domain.Errors;

const
  TRIG_NAMES: array[TTrigFunction] of string = ('sin', 'cos', 'tan', 'asin', 'acos', 'atan');
  // Below this |cos| the tangent is treated as undefined (odd multiples of 90 degrees)
  TAN_POLE_EPSILON = 1E-12;

{ TAngleUnitHelper }

class function TAngleUnitHelper.Parse(const AName: string): TAngleUnit;
var
  LName: string;
begin
  LName := AName.Trim.ToLower;
  if (LName = 'rad') or (LName = 'radians') then
    Exit(auRadians);
  if (LName = 'deg') or (LName = 'degrees') then
    Exit(auDegrees);
  raise ECalculatorDomainError.CreateFmt('Unknown angle unit "%s": use deg or rad', [AName]);
end;

function TAngleUnitHelper.Name: string;
begin
  if Self = auDegrees then
    Result := 'deg'
  else
    Result := 'rad';
end;

{ TTrigFunctionHelper }

class function TTrigFunctionHelper.Parse(const AName: string): TTrigFunction;
var
  LName: string;
  LFunction: TTrigFunction;
begin
  LName := AName.Trim.ToLower;
  for LFunction := Low(TTrigFunction) to High(TTrigFunction) do
    if TRIG_NAMES[LFunction] = LName then
      Exit(LFunction);
  raise ECalculatorDomainError.CreateFmt('Unknown trigonometric function "%s": use %s',
    [AName, string.Join(', ', TRIG_NAMES)]);
end;

function TTrigFunctionHelper.Name: string;
begin
  Result := TRIG_NAMES[Self];
end;

function TTrigFunctionHelper.IsInverse: Boolean;
begin
  Result := Self in [tfAsin, tfAcos, tfAtan];
end;

{ TElementaryMath }

class function TElementaryMath.Power(const ABase, AExponent: Double): Double;
begin
  if (ABase = 0) and (AExponent < 0) then
    raise ECalculatorDomainError.Create('power: 0 cannot be raised to a negative exponent');
  if (ABase < 0) and (Frac(AExponent) <> 0) then
    raise ECalculatorDomainError.Create('power: a negative base needs an integer exponent');
  Result := EnsureFinite(System.Math.Power(ABase, AExponent), 'power');
end;

class function TElementaryMath.Root(const AValue: Double; const ADegree: Integer): Double;
begin
  if (ADegree < 1) or (ADegree > MAX_ROOT_DEGREE) then
    raise ECalculatorDomainError.CreateFmt('root: the degree must be between 1 and %d', [MAX_ROOT_DEGREE]);
  if AValue >= 0 then
    Exit(System.Math.Power(AValue, 1 / ADegree));
  if not Odd(ADegree) then
    raise ECalculatorDomainError.Create('root: an even root of a negative number is not real');
  // Odd root of a negative number: real and negative
  Result := -System.Math.Power(-AValue, 1 / ADegree);
end;

class function TElementaryMath.Logarithm(const AValue, ABase: Double): Double;
begin
  if AValue <= 0 then
    raise ECalculatorDomainError.Create('log: the value must be greater than 0');
  if (ABase <= 0) or (ABase = 1) then
    raise ECalculatorDomainError.Create('log: the base must be greater than 0 and different from 1');
  Result := EnsureFinite(Ln(AValue) / Ln(ABase), 'log');
end;

class function TElementaryMath.Factorial(const AN: Integer): Double;
var
  LIndex: Integer;
begin
  if (AN < 0) or (AN > MAX_FACTORIAL) then
    raise ECalculatorDomainError.CreateFmt('factorial: n must be between 0 and %d', [MAX_FACTORIAL]);
  Result := 1;
  for LIndex := 2 to AN do
    Result := Result * LIndex;
end;

class function TElementaryMath.Trigonometric(const AFunction: TTrigFunction; const AValue: Double;
  const AUnit: TAngleUnit): Double;
var
  LRadians: Double;
begin
  EnsureFinite(AValue, AFunction.Name);

  if AFunction.IsInverse then
  begin
    if (AFunction in [tfAsin, tfAcos]) and ((AValue < -1) or (AValue > 1)) then
      raise ECalculatorDomainError.CreateFmt('%s: the value must be between -1 and 1', [AFunction.Name]);
    case AFunction of
      tfAsin: Result := ArcSin(AValue);
      tfAcos: Result := ArcCos(AValue);
    else
      Result := ArcTan(AValue);
    end;
    if AUnit = auDegrees then
      Result := RadToDeg(Result);
    Exit;
  end;

  if AUnit = auDegrees then
    LRadians := DegToRad(AValue)
  else
    LRadians := AValue;

  case AFunction of
    tfSin: Result := Sin(LRadians);
    tfCos: Result := Cos(LRadians);
  else
    begin
      if Abs(Cos(LRadians)) < TAN_POLE_EPSILON then
        raise ECalculatorDomainError.Create('tan: undefined for odd multiples of 90 degrees');
      Result := Tan(LRadians);
    end;
  end;
end;

end.
