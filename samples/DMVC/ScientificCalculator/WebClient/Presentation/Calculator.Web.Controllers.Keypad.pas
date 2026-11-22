unit Calculator.Web.Controllers.Keypad;

{ The keypad calculator: the display is an expression, "=" sends it to
  /api/expressions/evaluate (role calculator-user). The statistics and
  equation keys post to TAdvancedController (role calculator-advanced): the
  page disables them without the role, the API refuses them anyway. }

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  Calculator.Web.Controllers.Base;

type
  [MVCPath('/keypad')]
  TKeypadController = class(TWebController)
  protected
    function PageId: string; override;
  public
    [MVCPath]
    [MVCHTTPMethod([httpGET])]
    function Index: string;

    [MVCPath('/evaluate')]
    [MVCHTTPMethod([httpPOST])]
    function Evaluate: string;
  end;

implementation

uses
  System.SysUtils,
  System.StrUtils,
  JsonDataObjects,
  MVCFramework.HTMX,
  Calculator.Web.ApiClient;

const
  VALUE_VIEW = 'results/_value';
  // The limit of the API: longer ones are not sent
  MAX_EXPRESSION = 256;

function TKeypadController.PageId: string;
begin
  Result := 'keypad';
end;

function TKeypadController.Index: string;
begin
  Result := RenderView('keypad/index');
end;

function TKeypadController.Evaluate: string;
var
  LExpression: string;
  LBody, LResult: TJsonObject;
begin
  LExpression := Context.Request.ContentParam('expression').Trim;
  if LExpression.IsEmpty then
    Exit(RenderResult(VALUE_VIEW, TCalculatorApi.InputError(Backend, Text('input.empty_expression'))));
  if LExpression.Length > MAX_EXPRESSION then
    Exit(RenderResult(VALUE_VIEW, TCalculatorApi.InputError(Backend,
      Text('input.expression_too_long', ['max', IntToStr(MAX_EXPRESSION)]))));

  LBody := TJsonObject.Create;
  try
    LBody.S['expression'] := LExpression;
    LBody.S['unit'] := IfThen(Context.Request.ContentParam('unit') = 'rad', 'rad', 'deg');
    LResult := Api(httpPOST, '/api/expressions/evaluate', nil, LBody);
  finally
    LBody.Free;
  end;
  if LResult.B['ok'] then
    Context.Response.HXTriggerClientEvent('historyChanged');
  Result := RenderResult(VALUE_VIEW, LResult);
end;

end.
