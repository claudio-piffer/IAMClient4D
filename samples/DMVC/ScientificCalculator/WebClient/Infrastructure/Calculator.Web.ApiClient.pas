unit Calculator.Web.ApiClient;

{ Calls the calculator REST servers with the access token of the session
  (DMVC IMVCRESTClient) and turns every answer into a JSON view model that
  the templates render as it is:

    ok, status, backend, backendLabel, baseUrl, method, resource, elapsedMs,
    data   the "data" member of a successful answer
    error  kind (input, bad-request, unauthorized, forbidden, not-found,
           domain, server, unreachable), title, detail, challenge }

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  JsonDataObjects,
  MVCFramework.Commons,
  Calculator.Web.Settings;

type
  TQueryParam = TPair<string, string>;

  TCalculatorApi = class
  public
    /// <summary>The caller owns the result.</summary>
    class function Call(const ABackend: TCalculatorBackend; const AAccessToken: string;
      const AMethod: TMVCHTTPMethodType; const AResource: string;
      const AQuery: TArray<TQueryParam> = nil; const ABody: TJsonObject = nil;
      const ATimeoutMs: Integer = 10000): TJsonObject;
    /// <summary>A view model with an error of kind "input" (nothing sent).</summary>
    class function InputError(const ABackend: TCalculatorBackend; const ADetail: string): TJsonObject;
  end;

function Q(const AName, AValue: string): TQueryParam;

implementation

uses
  System.Diagnostics,
  System.NetEncoding,
  MVCFramework.RESTClient,
  MVCFramework.RESTClient.Intf;

function Q(const AName, AValue: string): TQueryParam;
begin
  Result := TQueryParam.Create(AName, AValue);
end;

function NewViewModel(const ABackend: TCalculatorBackend): TJsonObject;
begin
  Result := TJsonObject.Create;
  Result.B['ok'] := False;
  Result.S['backend'] := BACKEND_IDS[ABackend];
  Result.S['backendLabel'] := BACKEND_LABELS[ABackend];
  Result.S['baseUrl'] := Settings.BackendURLs[ABackend];
end;

function HttpMethodName(const AMethod: TMVCHTTPMethodType): string;
begin
  case AMethod of
    httpGET: Result := 'GET';
    httpPOST: Result := 'POST';
    httpDELETE: Result := 'DELETE';
  else
    Result := '?';
  end;
end;

function ErrorKind(const AStatus: Integer): string;
begin
  case AStatus of
    400: Result := 'bad-request';
    401: Result := 'unauthorized';
    403: Result := 'forbidden';
    404: Result := 'not-found';
    422: Result := 'domain';
  else
    Result := 'server';
  end;
end;

// problem+json (title, detail) or the classic DMVC error JSON (message)
procedure ReadError(const AResponse: IMVCRESTResponse; const AError: TJsonObject);
var
  LJson: TJsonBaseObject;
  LBody: TJsonObject;
begin
  AError.S['kind'] := ErrorKind(AResponse.StatusCode);
  AError.S['title'] := AResponse.StatusText;
  AError.S['challenge'] := AResponse.HeaderValue('WWW-Authenticate');
  if AResponse.Content.Trim.IsEmpty then
    Exit;
  try
    LJson := TJsonObject.Parse(AResponse.Content);
  except
    AError.S['detail'] := AResponse.Content;
    Exit;
  end;
  try
    if LJson is TJsonObject then
    begin
      LBody := TJsonObject(LJson);
      if LBody.Contains('title') then
        AError.S['title'] := LBody.S['title'];
      if LBody.Contains('detail') then
        AError.S['detail'] := LBody.S['detail']
      else if LBody.Contains('message') then
        AError.S['detail'] := LBody.S['message'];
    end;
  finally
    LJson.Free;
  end;
end;

class function TCalculatorApi.Call(const ABackend: TCalculatorBackend; const AAccessToken: string;
  const AMethod: TMVCHTTPMethodType; const AResource: string; const AQuery: TArray<TQueryParam>;
  const ABody: TJsonObject; const ATimeoutMs: Integer): TJsonObject;
var
  LClient: IMVCRESTClient;
  LResponse: IMVCRESTResponse;
  LParam: TQueryParam;
  LShown: string;
  LJson: TJsonBaseObject;
  LWatch: TStopwatch;
begin
  Result := NewViewModel(ABackend);
  try
    LShown := AResource;
    LClient := TMVCRESTClient.New
      .BaseURL(Settings.BackendURLs[ABackend])
      .ConnectTimeout(3000)
      .ReadTimeout(ATimeoutMs)
      .Accept(TMVCMediaType.APPLICATION_JSON);
    if not AAccessToken.IsEmpty then
      LClient.SetBearerAuthorization(AAccessToken);
    for LParam in AQuery do
    begin
      LClient.AddQueryStringParam(LParam.Key, LParam.Value);
      if LShown = AResource then
        LShown := LShown + '?'
      else
        LShown := LShown + '&';
      LShown := LShown + LParam.Key + '=' + TNetEncoding.URL.EncodeQuery(LParam.Value);
    end;
    Result.S['method'] := HttpMethodName(AMethod);
    Result.S['resource'] := LShown;
    if Assigned(ABody) then
      Result.S['requestBody'] := ABody.ToJSON(True);

    LWatch := TStopwatch.StartNew;
    case AMethod of
      httpGET: LResponse := LClient.Get(AResource);
      httpPOST:
        if Assigned(ABody) then
          LResponse := LClient.Post(AResource, ABody.ToJSON(True))
        else
          LResponse := LClient.Post(AResource);
      httpDELETE: LResponse := LClient.Delete(AResource);
    else
      raise EArgumentException.Create('Unsupported method');
    end;
    Result.I['elapsedMs'] := LWatch.ElapsedMilliseconds;
    Result.I['status'] := LResponse.StatusCode;

    if LResponse.Success then
    begin
      Result.B['ok'] := True;
      if LResponse.Content.Trim.IsEmpty then
        Result.O['data'] := TJsonObject.Create
      else
      begin
        LJson := TJsonObject.Parse(LResponse.Content);
        try
          if (LJson is TJsonObject) and (TJsonObject(LJson).Types['data'] = jdtObject) then
            Result.O['data'] := TJsonObject(LJson).O['data'].Clone as TJsonObject
          else
            Result.O['data'] := TJsonObject.Create;
        finally
          LJson.Free;
        end;
      end;
    end
    else
      ReadError(LResponse, Result.O['error']);
  except
    on E: Exception do
    begin
      Result.B['ok'] := False;
      Result.O['error'].S['kind'] := 'unreachable';
      Result.O['error'].S['title'] := 'Server not reachable';
      Result.O['error'].S['detail'] := E.Message;
    end;
  end;
end;

class function TCalculatorApi.InputError(const ABackend: TCalculatorBackend; const ADetail: string): TJsonObject;
begin
  Result := NewViewModel(ABackend);
  Result.O['error'].S['kind'] := 'input';
  Result.O['error'].S['title'] := 'Check the input';
  Result.O['error'].S['detail'] := ADetail;
end;

end.
