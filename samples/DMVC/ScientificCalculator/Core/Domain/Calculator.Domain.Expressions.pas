unit Calculator.Domain.Expressions;

(* Domain layer: arithmetic expressions such as 2 + 3 * sin(30) or (1 + sqrt(5)) / 2.
  A recursive descent parser, no eval of any kind:
    numbers      12, 0.5, .5, 1.5E3 (decimal point; exponent with an uppercase E)
    constants    pi, e, tau, phi (also the Greek letters)
    operators    + - * / ^, the Unicode minus, times, dot and division signs,
                 unary minus, postfix ! and the superscripts 2 and 3
    precedence   ( ) > postfix > ^ (right associative) > unary minus > * / > + -
                 so -2^2 = -4 and 2^3^2 = 512; 2pi and 3(4 + 1) multiply
    functions    sin cos tan asin acos atan (in the angle unit of the request),
                 sqrt (also the radical sign, prefix), cbrt, ln, log (base 10), abs, exp
  Each operation follows the rules of TElementaryMath (log of 0, odd roots of
  negative numbers, 171!, ...); errors are ECalculatorDomainError. *)

interface

uses
  Calculator.Domain.Elementary;

type
  TExpressionEvaluator = record
  public const
    MAX_LENGTH = 256;
    // Nesting of parentheses and unary signs
    MAX_DEPTH = 64;
  public
    /// <summary>
    /// The value of AExpression. Raises ECalculatorDomainError for a syntax
    /// error (with its position, 1-based) or a value outside a domain.
    /// </summary>
    class function Evaluate(const AExpression: string; const AUnit: TAngleUnit): Double; static;
  end;

implementation

uses
  System.SysUtils,
  System.Math,
  Calculator.Domain.Errors;

const
  MINUS_SIGN = #$2212;
  TIMES_SIGN = #$00D7;
  DOT_OPERATOR = #$00B7;
  DIVISION_SIGN = #$00F7;
  SQUARE_ROOT = #$221A;
  SUPERSCRIPT_TWO = #$00B2;
  SUPERSCRIPT_THREE = #$00B3;
  PI_SIGN = #$03C0;
  TAU_SIGN = #$03C4;
  PHI_SIGN = #$03C6;

type
  TParser = class
  private
    FText: string;
    FPos: Integer; // 1-based, next character
    FUnit: TAngleUnit;
    FDepth: Integer;
    function Peek: Char;
    procedure Fail(const AMessage: string);
    procedure Unexpected;
    procedure Expect(const AChar: Char);
    function StartsImplicitFactor(const AChar: Char): Boolean;
    function ParseSum: Double;
    function ParseProduct: Double;
    function ParseUnary: Double;
    function ParsePower: Double;
    function ParsePostfix: Double;
    function ParsePrimary: Double;
    function ParseNumber: Double;
    function ParseName: Double;
    function ApplyFunction(const AName: string; const AArgument: Double): Double;
  public
    constructor Create(const AText: string; const AUnit: TAngleUnit);
    function Parse: Double;
  end;

function IsDigit(const AChar: Char): Boolean;
begin
  Result := CharInSet(AChar, ['0' .. '9']);
end;

function IsLetter(const AChar: Char): Boolean;
begin
  Result := CharInSet(AChar, ['a' .. 'z', 'A' .. 'Z']);
end;

{ TParser }

constructor TParser.Create(const AText: string; const AUnit: TAngleUnit);
begin
  inherited Create;
  FText := AText;
  FPos := 1;
  FUnit := AUnit;
end;

// The next character after spaces, #0 at the end
function TParser.Peek: Char;
begin
  while (FPos <= FText.Length) and CharInSet(FText[FPos], [' ', #9]) do
    Inc(FPos);
  if FPos <= FText.Length then
    Result := FText[FPos]
  else
    Result := #0;
end;

procedure TParser.Fail(const AMessage: string);
begin
  raise ECalculatorDomainError.Create('expression: ' + AMessage);
end;

procedure TParser.Unexpected;
begin
  if Peek = #0 then
    Fail('incomplete, something is missing at the end')
  else
    Fail(Format('unexpected "%s" at position %d', [FText[FPos], FPos]));
end;

procedure TParser.Expect(const AChar: Char);
begin
  if Peek <> AChar then
    Unexpected;
  Inc(FPos);
end;

// 2pi, 2sin(30), 3(4 + 1), 2 sqrt-sign 3: a factor that follows another one without an operator.
// Not a digit or a dot: "2 3" and "1.2.3" stay errors
function TParser.StartsImplicitFactor(const AChar: Char): Boolean;
begin
  Result := IsLetter(AChar) or CharInSet(AChar, ['(']) or
    (AChar = PI_SIGN) or (AChar = TAU_SIGN) or (AChar = PHI_SIGN) or (AChar = SQUARE_ROOT);
end;

function TParser.Parse: Double;
begin
  Result := ParseSum;
  if Peek <> #0 then
    Unexpected;
end;

function TParser.ParseSum: Double;
var
  LChar: Char;
begin
  Result := ParseProduct;
  while True do
  begin
    LChar := Peek;
    if LChar = '+' then
    begin
      Inc(FPos);
      Result := EnsureFinite(Result + ParseProduct, 'addition');
    end
    else if (LChar = '-') or (LChar = MINUS_SIGN) then
    begin
      Inc(FPos);
      Result := EnsureFinite(Result - ParseProduct, 'subtraction');
    end
    else
      Exit;
  end;
end;

function TParser.ParseProduct: Double;
var
  LChar: Char;
  LDivisor: Double;
begin
  Result := ParseUnary;
  while True do
  begin
    LChar := Peek;
    if (LChar = '*') or (LChar = TIMES_SIGN) or (LChar = DOT_OPERATOR) then
    begin
      Inc(FPos);
      Result := EnsureFinite(Result * ParseUnary, 'multiplication');
    end
    else if (LChar = '/') or (LChar = DIVISION_SIGN) then
    begin
      Inc(FPos);
      LDivisor := ParseUnary;
      if LDivisor = 0 then
        Fail('division by zero');
      Result := EnsureFinite(Result / LDivisor, 'division');
    end
    else if StartsImplicitFactor(LChar) then
      Result := EnsureFinite(Result * ParsePower, 'multiplication')
    else
      Exit;
  end;
end;

function TParser.ParseUnary: Double;
var
  LChar: Char;
begin
  Inc(FDepth);
  if FDepth > TExpressionEvaluator.MAX_DEPTH then
    Fail(Format('more than %d nested levels', [TExpressionEvaluator.MAX_DEPTH]));
  LChar := Peek;
  if (LChar = '-') or (LChar = MINUS_SIGN) then
  begin
    Inc(FPos);
    Result := -ParseUnary;
  end
  else if LChar = '+' then
  begin
    Inc(FPos);
    Result := ParseUnary;
  end
  else
    Result := ParsePower;
  Dec(FDepth);
end;

function TParser.ParsePower: Double;
begin
  Result := ParsePostfix;
  if Peek = '^' then
  begin
    Inc(FPos);
    // The exponent may have a sign and is itself a power: 2^-1, 2^3^2 = 2^9
    Result := TElementaryMath.Power(Result, ParseUnary);
  end;
end;

function TParser.ParsePostfix: Double;
var
  LChar: Char;
begin
  Result := ParsePrimary;
  while True do
  begin
    LChar := Peek;
    if LChar = '!' then
    begin
      Inc(FPos);
      if (Frac(Result) <> 0) or (Result < 0) or (Result > TElementaryMath.MAX_FACTORIAL) then
        Fail(Format('factorial: n must be a whole number between 0 and %d', [TElementaryMath.MAX_FACTORIAL]));
      Result := TElementaryMath.Factorial(Round(Result));
    end
    else if LChar = SUPERSCRIPT_TWO then
    begin
      Inc(FPos);
      Result := TElementaryMath.Power(Result, 2);
    end
    else if LChar = SUPERSCRIPT_THREE then
    begin
      Inc(FPos);
      Result := TElementaryMath.Power(Result, 3);
    end
    else
      Exit;
  end;
end;

function TParser.ParsePrimary: Double;
var
  LChar: Char;
begin
  LChar := Peek;
  if LChar = '(' then
  begin
    Inc(FPos);
    Result := ParseSum;
    Expect(')');
  end
  else if IsDigit(LChar) or (LChar = '.') then
    Result := ParseNumber
  else if LChar = SQUARE_ROOT then
  begin
    Inc(FPos);
    Result := TElementaryMath.Root(ParsePostfix, 2);
  end
  else if LChar = PI_SIGN then
  begin
    Inc(FPos);
    Result := Pi;
  end
  else if LChar = TAU_SIGN then
  begin
    Inc(FPos);
    Result := 2 * Pi;
  end
  else if LChar = PHI_SIGN then
  begin
    Inc(FPos);
    Result := (1 + Sqrt(5)) / 2;
  end
  else if IsLetter(LChar) then
    Result := ParseName
  else
  begin
    Unexpected;
    Result := 0; // not reached
  end;
end;

function TParser.ParseNumber: Double;
var
  LStart: Integer;
begin
  LStart := FPos;
  while (FPos <= FText.Length) and IsDigit(FText[FPos]) do
    Inc(FPos);
  if (FPos <= FText.Length) and (FText[FPos] = '.') then
  begin
    Inc(FPos);
    while (FPos <= FText.Length) and IsDigit(FText[FPos]) do
      Inc(FPos);
  end;
  // Exponent: uppercase E only, a lowercase e is the constant (2e = 2 * e)
  if (FPos < FText.Length) and (FText[FPos] = 'E') and
    (IsDigit(FText[FPos + 1]) or
     (CharInSet(FText[FPos + 1], ['+', '-']) and (FPos + 1 < FText.Length) and IsDigit(FText[FPos + 2]))) then
  begin
    Inc(FPos, 2);
    while (FPos <= FText.Length) and IsDigit(FText[FPos]) do
      Inc(FPos);
  end;
  if not TryStrToFloat(FText.Substring(LStart - 1, FPos - LStart), Result, TFormatSettings.Invariant) then
    Fail(Format('"%s" at position %d is not a number', [FText.Substring(LStart - 1, FPos - LStart), LStart]));
  Result := EnsureFinite(Result, 'number');
end;

function TParser.ParseName: Double;
var
  LStart: Integer;
  LName: string;
begin
  LStart := FPos;
  while (FPos <= FText.Length) and IsLetter(FText[FPos]) do
    Inc(FPos);
  LName := FText.Substring(LStart - 1, FPos - LStart).ToLower;
  if LName = 'pi' then
    Exit(Pi);
  if LName = 'e' then
    Exit(Exp(1));
  if LName = 'tau' then
    Exit(2 * Pi);
  if LName = 'phi' then
    Exit((1 + Sqrt(5)) / 2);
  if Peek <> '(' then
  begin
    FPos := LStart;
    Fail(Format('unknown name "%s" at position %d', [LName, LStart]));
  end;
  Inc(FPos);
  Result := ParseSum;
  Expect(')');
  Result := ApplyFunction(LName, Result);
end;

function TParser.ApplyFunction(const AName: string; const AArgument: Double): Double;
begin
  if (AName = 'sin') or (AName = 'cos') or (AName = 'tan') or
    (AName = 'asin') or (AName = 'acos') or (AName = 'atan') then
    Result := TElementaryMath.Trigonometric(TTrigFunction.Parse(AName), AArgument, FUnit)
  else if AName = 'sqrt' then
    Result := TElementaryMath.Root(AArgument, 2)
  else if AName = 'cbrt' then
    Result := TElementaryMath.Root(AArgument, 3)
  else if AName = 'ln' then
  begin
    if AArgument <= 0 then
      Fail('ln: the value must be greater than 0');
    Result := Ln(AArgument);
  end
  else if AName = 'log' then
    Result := TElementaryMath.Logarithm(AArgument, 10)
  else if AName = 'abs' then
    Result := Abs(AArgument)
  else if AName = 'exp' then
    Result := EnsureFinite(Exp(AArgument), 'exp')
  else
  begin
    Fail(Format('unknown function "%s"', [AName]));
    Result := 0; // not reached
  end;
end;

{ TExpressionEvaluator }

class function TExpressionEvaluator.Evaluate(const AExpression: string; const AUnit: TAngleUnit): Double;
var
  LParser: TParser;
begin
  if AExpression.Trim.IsEmpty then
    raise ECalculatorDomainError.Create('expression: the expression is empty');
  if AExpression.Length > MAX_LENGTH then
    raise ECalculatorDomainError.CreateFmt('expression: at most %d characters', [MAX_LENGTH]);
  LParser := TParser.Create(AExpression, AUnit);
  try
    try
      Result := EnsureFinite(LParser.Parse, 'expression');
    except
      // Overflow and the like, when the FPU raises instead of returning infinity
      on E: EMathError do
        raise ECalculatorDomainError.Create('expression: the result is not a finite number');
    end;
  finally
    LParser.Free;
  end;
end;

end.
