unit Calculator.Web.Controllers.Advanced;

{ Statistics and equations (role calculator-advanced on the API). The page
  opens for every signed-in user: without the role the API answers 403, and
  the page shows it. The keypad (Calculator.Web.Controllers.Keypad) posts its
  advanced keys here too, with the values typed on its display. }

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  Calculator.Web.Controllers.Base;

type
  [MVCPath('/advanced')]
  TAdvancedController = class(TWebController)
  private
    function DescribeValues(const AValuesText: string; const ASample: Boolean): string;
    function SolveQuadratic(const AA, AB, AC: string): string;
  protected
    function PageId: string; override;
  public
    [MVCPath]
    [MVCHTTPMethod([httpGET])]
    function Index: string;

    [MVCPath('/statistics')]
    [MVCHTTPMethod([httpPOST])]
    function Statistics: string;

    [MVCPath('/quadratic')]
    [MVCHTTPMethod([httpPOST])]
    function Quadratic: string;

    /// <summary>Keypad: the display is the list of values; sample = on for the sample statistics.</summary>
    [MVCPath('/keypad/statistics')]
    [MVCHTTPMethod([httpPOST])]
    function KeypadStatistics: string;

    /// <summary>Keypad: the display is the list a; b; c of the coefficients.</summary>
    [MVCPath('/keypad/quadratic')]
    [MVCHTTPMethod([httpPOST])]
    function KeypadQuadratic: string;
  end;

implementation

uses
  System.SysUtils,
  JsonDataObjects,
  MVCFramework.HTMX,
  Calculator.Web.ApiClient,
  Calculator.Web.Formatting;

const
  MAX_VALUES = 1000;
  STATISTICS_VIEW = 'results/_statistics';
  QUADRATIC_VIEW = 'results/_quadratic';
  // Name of the display field of the keypad
  KEYPAD_FIELD = 'expression';

// root.text ("1.5", "-0.5 + 1.2i") and realRoots (data-roots of the plot)
procedure DescribeRoots(const AResult: TJsonObject);
var
  LRoots: TJsonArray;
  LRoot: TJsonObject;
  LReal: string;
  I: Integer;
begin
  LReal := '';
  LRoots := AResult.O['data'].A['roots'];
  for I := 0 to LRoots.Count - 1 do
  begin
    LRoot := LRoots.O[I];
    if LRoot.F['im'] = 0 then
    begin
      LRoot.S['text'] := DisplayNumber(LRoot.F['re']);
      LReal := LReal + ApiNumber(LRoot.F['re']) + ' ';
    end
    else if LRoot.F['im'] > 0 then
      LRoot.S['text'] := DisplayNumber(LRoot.F['re']) + ' + ' + DisplayNumber(LRoot.F['im']) + 'i'
    else
      LRoot.S['text'] := DisplayNumber(LRoot.F['re']) + ' - ' + DisplayNumber(-LRoot.F['im']) + 'i';
  end;
  AResult.S['realRoots'] := LReal.Trim;
end;

function TAdvancedController.PageId: string;
begin
  Result := 'advanced';
end;

function TAdvancedController.Index: string;
begin
  Result := RenderView('advanced/index');
end;

function TAdvancedController.DescribeValues(const AValuesText: string; const ASample: Boolean): string;
var
  LValues: TArray<Double>;
  LBad: string;
  LBody, LResult: TJsonObject;
  LValue: Double;
begin
  if not TryParseNumberList(AValuesText, LValues, LBad) then
    Exit(RenderResult(STATISTICS_VIEW, TCalculatorApi.InputError(Backend,
      Text('input.list_not_number', ['value', LBad]))));
  if Length(LValues) > MAX_VALUES then
    Exit(RenderResult(STATISTICS_VIEW, TCalculatorApi.InputError(Backend,
      Text('input.too_many_values', ['max', IntToStr(MAX_VALUES)]))));

  LBody := TJsonObject.Create;
  try
    for LValue in LValues do
      LBody.A['values'].Add(LValue);
    LBody.B['sample'] := ASample;
    LResult := Api(httpPOST, '/api/statistics/describe', nil, LBody);
    // The values again, for the chart (data-values attribute)
    LResult.S['valuesJson'] := LBody.A['values'].ToJSON(True);
  finally
    LBody.Free;
  end;
  if LResult.B['ok'] then
    Context.Response.HXTriggerClientEvent('historyChanged');
  Result := RenderResult(STATISTICS_VIEW, LResult);
end;

// AA, AB, AC: invariant numbers
function TAdvancedController.SolveQuadratic(const AA, AB, AC: string): string;
var
  LBody, LResult: TJsonObject;
begin
  LBody := TJsonObject.Create;
  try
    LBody.F['a'] := StrToFloat(AA, TFormatSettings.Invariant);
    LBody.F['b'] := StrToFloat(AB, TFormatSettings.Invariant);
    LBody.F['c'] := StrToFloat(AC, TFormatSettings.Invariant);
    LResult := Api(httpPOST, '/api/equations/quadratic', nil, LBody);
    // The coefficients again, for the plot
    LResult.S['a'] := AA;
    LResult.S['b'] := AB;
    LResult.S['c'] := AC;
  finally
    LBody.Free;
  end;
  if LResult.B['ok'] then
  begin
    DescribeRoots(LResult);
    Context.Response.HXTriggerClientEvent('historyChanged');
  end;
  Result := RenderResult(QUADRATIC_VIEW, LResult);
end;

function TAdvancedController.Statistics: string;
begin
  Result := DescribeValues(Context.Request.ContentParam('values'), Context.Request.ContentParam('sample') = 'on');
end;

function TAdvancedController.Quadratic: string;
var
  LA, LB, LC: string;
begin
  FieldNumber('a', 'a', LA);
  FieldNumber('b', 'b', LB);
  FieldNumber('c', 'c', LC);
  if HasInputErrors then
    Exit(RenderInputErrors(QUADRATIC_VIEW));
  Result := SolveQuadratic(LA, LB, LC);
end;

function TAdvancedController.KeypadStatistics: string;
begin
  Result := DescribeValues(Context.Request.ContentParam(KEYPAD_FIELD), Context.Request.ContentParam('sample') = 'on');
end;

function TAdvancedController.KeypadQuadratic: string;
var
  LValues: TArray<Double>;
  LBad: string;
begin
  if not TryParseNumberList(Context.Request.ContentParam(KEYPAD_FIELD), LValues, LBad) then
    Exit(RenderResult(QUADRATIC_VIEW, TCalculatorApi.InputError(Backend,
      Text('input.list_not_number', ['value', LBad]))));
  if Length(LValues) <> 3 then
    Exit(RenderResult(QUADRATIC_VIEW, TCalculatorApi.InputError(Backend,
      Text('input.three_coefficients', ['count', IntToStr(Length(LValues))]))));
  Result := SolveQuadratic(ApiNumber(LValues[0]), ApiNumber(LValues[1]), ApiNumber(LValues[2]));
end;

end.
