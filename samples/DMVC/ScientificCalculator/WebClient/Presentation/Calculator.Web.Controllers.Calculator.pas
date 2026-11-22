unit Calculator.Web.Controllers.Calculator;

{ The calculator page and its operations (role calculator-user on the API).
  Every form posts here with HTMX; the action reads and checks the fields,
  calls the API and answers the result card (templates/results). }

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  JsonDataObjects,
  Calculator.Web.ApiClient,
  Calculator.Web.Controllers.Base;

type
  [MVCPath('/calculator')]
  TCalculatorController = class(TWebController)
  private
    /// <summary>The result card; a successful call adds to the history (historyChanged).</summary>
    function Answer(const AView: string; const AResult: TJsonObject): string;
  protected
    function PageId: string; override;
  public
    [MVCPath]
    [MVCHTTPMethod([httpGET])]
    function Index: string;

    [MVCPath('/power')]
    [MVCHTTPMethod([httpPOST])]
    function Power: string;

    [MVCPath('/root')]
    [MVCHTTPMethod([httpPOST])]
    function Root: string;

    [MVCPath('/log')]
    [MVCHTTPMethod([httpPOST])]
    function Logarithm: string;

    [MVCPath('/factorial')]
    [MVCHTTPMethod([httpPOST])]
    function Factorial: string;

    [MVCPath('/trigonometry')]
    [MVCHTTPMethod([httpPOST])]
    function Trigonometry: string;

    [MVCPath('/prime')]
    [MVCHTTPMethod([httpPOST])]
    function Prime: string;

    [MVCPath('/combinatorics')]
    [MVCHTTPMethod([httpPOST])]
    function Combinatorics: string;
  end;

implementation

uses
  System.SysUtils,
  System.StrUtils,
  MVCFramework.HTMX;

const
  VALUE_VIEW = 'results/_value';
  TRIG_FUNCTIONS: array [0 .. 5] of string = ('sin', 'cos', 'tan', 'asin', 'acos', 'atan');

function TCalculatorController.PageId: string;
begin
  Result := 'calculator';
end;

function TCalculatorController.Answer(const AView: string; const AResult: TJsonObject): string;
begin
  if AResult.B['ok'] then
    Context.Response.HXTriggerClientEvent('historyChanged');
  Result := RenderResult(AView, AResult);
end;

function TCalculatorController.Index: string;
begin
  Result := RenderView('calculator/index');
end;

function TCalculatorController.Power: string;
var
  LBase, LExponent: string;
begin
  FieldNumber('base', Text('calculator.base'), LBase);
  FieldNumber('exponent', Text('calculator.exponent'), LExponent);
  if HasInputErrors then
    Exit(RenderInputErrors(VALUE_VIEW));
  Result := Answer(VALUE_VIEW, Api(httpGET, '/api/elementary/power', [Q('base', LBase), Q('exponent', LExponent)]));
end;

function TCalculatorController.Root: string;
var
  LValue: string;
  LDegree: Int64;
begin
  FieldNumber('value', Text('calculator.value'), LValue);
  FieldInteger('degree', Text('calculator.degree'), LDegree);
  if HasInputErrors then
    Exit(RenderInputErrors(VALUE_VIEW));
  Result := Answer(VALUE_VIEW, Api(httpGET, '/api/elementary/root', [Q('value', LValue), Q('degree', LDegree.ToString)]));
end;

function TCalculatorController.Logarithm: string;
var
  LValue, LBase: string;
begin
  FieldNumber('value', Text('calculator.value'), LValue);
  FieldNumber('base', Text('calculator.base'), LBase);
  if HasInputErrors then
    Exit(RenderInputErrors(VALUE_VIEW));
  Result := Answer(VALUE_VIEW, Api(httpGET, '/api/elementary/log', [Q('value', LValue), Q('base', LBase)]));
end;

function TCalculatorController.Factorial: string;
var
  LN: Int64;
begin
  if not FieldInteger('n', 'n', LN) then
    Exit(RenderInputErrors(VALUE_VIEW));
  Result := Answer(VALUE_VIEW, Api(httpGET, '/api/elementary/factorial/' + LN.ToString));
end;

function TCalculatorController.Trigonometry: string;
var
  LFunction, LValue, LUnit: string;
begin
  // The function goes into the URL path: only the known names
  LFunction := Context.Request.ContentParam('fn');
  if not MatchStr(LFunction, TRIG_FUNCTIONS) then
    Exit(RenderResult(VALUE_VIEW, TCalculatorApi.InputError(Backend, Text('input.unknown_function'))));
  LUnit := IfThen(Context.Request.ContentParam('unit') = 'rad', 'rad', 'deg');
  if not FieldNumber('value', Text('calculator.value'), LValue) then
    Exit(RenderInputErrors(VALUE_VIEW));
  Result := Answer(VALUE_VIEW, Api(httpGET, '/api/trigonometry/' + LFunction, [Q('value', LValue), Q('unit', LUnit)]));
end;

function TCalculatorController.Prime: string;
var
  LN: Int64;
begin
  if not FieldInteger('n', 'n', LN) then
    Exit(RenderInputErrors('results/_prime'));
  Result := Answer('results/_prime', Api(httpGET, '/api/number-theory/prime/' + LN.ToString));
end;

function TCalculatorController.Combinatorics: string;
var
  LN, LK: Int64;
begin
  FieldInteger('n', 'n', LN);
  FieldInteger('k', 'k', LK);
  if HasInputErrors then
    Exit(RenderInputErrors('results/_combinatorics'));
  Result := Answer('results/_combinatorics', Api(httpGET, '/api/number-theory/combinatorics',
    [Q('n', LN.ToString), Q('k', LK.ToString)]));
end;

end.
