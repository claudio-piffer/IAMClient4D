unit Calculator.Presentation.Errors;

{ Presentation layer, shared by both servers: domain errors become 422
  problem+json; 400 and 403 (RequireAnyRole) of DMVC and a missing required
  parameter of a controller action become 400/403 problem+json, as the Minimal
  API writes them. Reached by controller actions and Minimal API handlers alike;
  everything else keeps the DMVC default (401 of IAMClient4D, 500). }

interface

uses
  MVCFramework;

procedure UseCalculatorErrorHandling(const AEngine: TMVCEngine);

implementation

uses
  System.SysUtils,
  JsonDataObjects,
  MVCFramework.Commons,
  MVCFramework.Logger,
  Calculator.Domain.Errors;

procedure WriteProblem(const AContext: TWebContext; const AStatus: Integer; const ADetail: string);
var
  LProblem: TJsonObject;
begin
  LProblem := TJsonObject.Create;
  try
    LProblem.S['type'] := 'about:blank';
    LProblem.S['title'] := ReasonPhraseFor(AStatus);
    LProblem.I['status'] := AStatus;
    LProblem.S['detail'] := ADetail;
    LProblem.S['instance'] := AContext.Request.PathInfo;
    AContext.Response.StatusCode := AStatus;
    AContext.Response.ContentType := 'application/problem+json; charset=' + TMVCCharSet.UTF_8;
    AContext.Response.Content := LProblem.ToJSON;
  finally
    LProblem.Free;
  end;
end;

// DMVC raises a plain EMVCException (status 500) for an action parameter without a default
// value that the request lacks, e.g. Required parameter "exponent" injected using ...
function TryGetMissingParameter(const E: Exception; out AName: string): Boolean;
const
  CPrefix = 'Required parameter "';
var
  LEnd: Integer;
begin
  Result := (E.ClassType = EMVCException) and
    (EMVCException(E).HTTPStatusCode = HTTP_STATUS.InternalServerError) and E.Message.StartsWith(CPrefix);
  if Result then
  begin
    LEnd := E.Message.IndexOf('"', CPrefix.Length);
    Result := LEnd > CPrefix.Length;
    if Result then
      AName := E.Message.Substring(CPrefix.Length, LEnd - CPrefix.Length);
  end;
end;

procedure UseCalculatorErrorHandling(const AEngine: TMVCEngine);
begin
  AEngine.SetExceptionHandler(
    procedure(E: Exception; SelectedController: TMVCController; WebContext: TWebContext;
      var ExceptionHandled: Boolean)
    var
      LName: string;
    begin
      if E is ECalculatorDomainError then
      begin
        LogI('Domain error on ' + WebContext.Request.PathInfo + ': ' + E.Message);
        WriteProblem(WebContext, HTTP_STATUS.UnprocessableEntity, E.Message);
        ExceptionHandled := True;
      end
      else if TryGetMissingParameter(E, LName) then
      begin
        LogI('Missing parameter on ' + WebContext.Request.PathInfo + ': ' + LName);
        WriteProblem(WebContext, HTTP_STATUS.BadRequest, Format('Required parameter "%s" is missing', [LName]));
        ExceptionHandled := True;
      end
      else if (E is EMVCException) and ((EMVCException(E).HTTPStatusCode = HTTP_STATUS.BadRequest) or
        (EMVCException(E).HTTPStatusCode = HTTP_STATUS.Forbidden)) then
      begin
        // E.g. a malformed number, or RequireAnyRole in OnBeforeAction of a controller (the
        // WWW-Authenticate challenge is already on the response)
        WriteProblem(WebContext, EMVCException(E).HTTPStatusCode, E.Message);
        ExceptionHandled := True;
      end;
    end);
end;

end.
