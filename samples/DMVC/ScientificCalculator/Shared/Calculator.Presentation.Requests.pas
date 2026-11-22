unit Calculator.Presentation.Requests;

{ Presentation layer, shared by both servers: request bodies read by hand.
  DMVC 3.5.0-rc10 cannot bind a JSON array of integers (or of integers and
  decimals) to a TArray<Double> property, so the statistics body is parsed
  here; malformed input is a 400. }

interface

uses
  MVCFramework,
  Calculator.Application.DTO;

/// <summary>{"values": [numbers], "sample": boolean}; the caller owns the result.</summary>
function StatisticsRequestFromBody(const AContext: TWebContext): TStatisticsRequest;

implementation

uses
  System.SysUtils,
  JsonDataObjects,
  MVCFramework.Commons;

procedure BadRequest(const AMessage: string);
begin
  raise EMVCException.Create(HTTP_STATUS.BadRequest, AMessage);
end;

function StatisticsRequestFromBody(const AContext: TWebContext): TStatisticsRequest;
var
  LParsed: TJsonBaseObject;
  LBody: TJsonObject;
  LValues: TJsonArray;
  LNumbers: TArray<Double>;
  LIndex: Integer;
begin
  if AContext.Request.Body.Trim.IsEmpty then
    BadRequest('The request body is required');
  try
    LParsed := TJsonBaseObject.Parse(AContext.Request.Body);
  except
    on E: EJsonParserException do
    begin
      BadRequest('The request body is not valid JSON: ' + E.Message);
      LParsed := nil; // not reached
    end;
  end;
  try
    if not (LParsed is TJsonObject) then
      BadRequest('The request body must be a JSON object');
    LBody := TJsonObject(LParsed);

    if LBody.Types['values'] <> jdtArray then
      BadRequest('"values" must be an array of numbers');
    LValues := LBody.A['values'];
    SetLength(LNumbers, LValues.Count);
    for LIndex := 0 to LValues.Count - 1 do
      case LValues.Types[LIndex] of
        jdtInt, jdtLong, jdtULong, jdtFloat:
          LNumbers[LIndex] := LValues.F[LIndex];
      else
        BadRequest(Format('"values"[%d] is not a number', [LIndex]));
      end;

    if not (LBody.Types['sample'] in [jdtNone, jdtBool]) then
      BadRequest('"sample" must be a boolean');

    Result := TStatisticsRequest.Create;
    Result.Values := LNumbers;
    Result.Sample := LBody.B['sample'];
  finally
    LParsed.Free;
  end;
end;

end.
