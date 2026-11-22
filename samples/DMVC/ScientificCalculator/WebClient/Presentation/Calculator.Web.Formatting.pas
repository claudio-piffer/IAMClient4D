unit Calculator.Web.Formatting;

{ Numbers in and out of the web client, culture independent (the API speaks
  JSON, the server may run with any Windows locale), and the TemplatePro
  filters of the views. }

interface

uses
  System.Rtti,
  TemplatePro.Types;

/// <summary>
/// A number typed by the user: decimal point or a single comma, exponent,
/// or the name of a constant (pi, tau, e, phi).
/// </summary>
function TryParseNumber(const AText: string; out AValue: Double): Boolean;
function TryParseInteger(const AText: string; out AValue: Int64): Boolean;
/// <summary>Numbers separated by spaces, commas, semicolons or new lines (decimal point only).</summary>
function TryParseNumberList(const AText: string; out AValues: TArray<Double>; out ABadItem: string): Boolean;

/// <summary>The number for the API (invariant, round trip).</summary>
function ApiNumber(const AValue: Double): string;
/// <summary>The number for a person: 12 significant digits, scientific notation when huge or tiny.</summary>
function DisplayNumber(const AValue: Double): string;

/// <summary>A local path to go back to after the login, or '/'.</summary>
function SafeLocalPath(const APath: string): string;

/// <summary>Registers the filters below and keeps includes inside the views folder.</summary>
procedure ConfigureTemplatePro(const AViewPath: string);

implementation

uses
  System.SysUtils,
  System.Math,
  TemplatePro;

function TryParseNumber(const AText: string; out AValue: Double): Boolean;
var
  LText: string;
begin
  LText := AText.Trim.ToLower.Replace(' ', '');
  if (LText = 'pi') or (LText = #$03C0) then
    AValue := Pi
  else if (LText = 'tau') or (LText = #$03C4) then
    AValue := 2 * Pi
  else if LText = 'e' then
    AValue := Exp(1)
  else if (LText = 'phi') or (LText = #$03C6) then
    AValue := (1 + Sqrt(5)) / 2
  else
  begin
    if (not LText.Contains('.')) and (LText.CountChar(',') = 1) then
      LText := LText.Replace(',', '.');
    if not TryStrToFloat(LText, AValue, TFormatSettings.Invariant) then
      Exit(False);
  end;
  Result := not (IsNan(AValue) or IsInfinite(AValue));
end;

function TryParseInteger(const AText: string; out AValue: Int64): Boolean;
begin
  Result := TryStrToInt64(AText.Trim, AValue);
end;

function TryParseNumberList(const AText: string; out AValues: TArray<Double>; out ABadItem: string): Boolean;
var
  LItem: string;
  LValue: Double;
begin
  AValues := nil;
  ABadItem := '';
  for LItem in AText.Split([' ', ',', ';', #9, #10, #13], TStringSplitOptions.ExcludeEmpty) do
  begin
    if not TryStrToFloat(LItem, LValue, TFormatSettings.Invariant) or IsNan(LValue) or IsInfinite(LValue) then
    begin
      ABadItem := LItem;
      Exit(False);
    end;
    AValues := AValues + [LValue];
  end;
  Result := True;
end;

function ApiNumber(const AValue: Double): string;
begin
  Result := FloatToStr(AValue, TFormatSettings.Invariant);
end;

function DisplayNumber(const AValue: Double): string;
var
  LAbs: Double;
begin
  LAbs := Abs(AValue);
  if (LAbs <> 0) and ((LAbs >= 1E15) or (LAbs < 1E-6)) then
    Result := FormatFloat('0.###########E+0', AValue, TFormatSettings.Invariant)
  else
    Result := FloatToStrF(AValue, ffGeneral, 12, 0, TFormatSettings.Invariant);
  if Result = '-0' then
    Result := '0';
end;

function SafeLocalPath(const APath: string): string;
var
  C: Char;
begin
  // One leading '/', not '//'; no backslash and no control character (browsers read them as '/')
  if (not APath.StartsWith('/')) or APath.StartsWith('//') then
    Exit('/');
  for C in APath do
    if (C < ' ') or (C = #127) or (C = '\') then
      Exit('/');
  Result := APath;
end;

// {{:value|num}}: JSON numbers reach the templates as invariant strings
function NumFilter(const AValue: TValue; const AParameters: TArray<TFilterParameter>): TValue;
var
  LNumber: Double;
begin
  if AValue.IsEmpty then
    Exit('');
  case AValue.Kind of
    tkInteger, tkInt64:
      Result := AValue.AsInt64.ToString;
    tkFloat:
      Result := DisplayNumber(AValue.AsExtended);
  else
    if TryStrToFloat(AValue.ToString, LNumber, TFormatSettings.Invariant) then
      Result := DisplayNumber(LNumber)
    else
      Result := AValue.ToString;
  end;
end;

procedure ConfigureTemplatePro(const AViewPath: string);
var
  LViewPath: string;
begin
  LViewPath := AViewPath;
  TTProConfiguration.OnContextConfiguration :=
    procedure(const ACompiledTemplate: ITProCompiledTemplate)
    begin
      ACompiledTemplate.IncludeRootPath := LViewPath;
      ACompiledTemplate.AddFilter('num', NumFilter);
    end;
end;

end.
