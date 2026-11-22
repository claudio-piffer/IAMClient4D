{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.DMVC.Internal.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2025 Claudio Piffer
  License    : Apache License, Version 2.0, January 2004
  Source URL : https://github.com/claudio-piffer/IAMClient4D

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  ---------------------------------------------------------------------------
}

/// <summary>
/// Code shared by the IAMClient4D DMVC filters (IAMClient4D.DMVC.Filters) and by the deprecated
/// TIAM4DJWTMiddleware. Not part of the public API: use the filters.
/// </summary>
unit IAMClient4D.DMVC.Internal;

interface

uses
  MVCFramework;

type
  /// <summary>
  /// Thread-safe cache of the [IAM4DPublic] attribute of controller actions (class or method level).
  /// </summary>
  IIAM4DPublicActionCache = interface
    ['{3C8F2A17-5B64-4E0D-9A21-7D4E6B19C053}']
    function IsPublic(const AControllerQualifiedClassName, AActionName: string): Boolean;
  end;

function NewIAM4DPublicActionCache: IIAM4DPublicActionCache;

/// <summary>
/// When the request is a GET of a Swagger/OpenAPI JSON document, adds the bearer security scheme
/// and the global security requirement to the response already rendered. Runs after the document
/// has been produced (OnAfterRouting of the middleware, after ANext() in the HTTP filter).
/// </summary>
procedure IAM4DInjectSwaggerSecurityInResponse(AContext: TWebContext);

implementation

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Rtti,
  System.Generics.Collections,
  Web.HTTPApp,
  MVCFramework.Commons,
  MVCFramework.Logger,
  IAMClient4D.DMVC.Attributes;

const
  // Same scheme name used by DMVC Swagger (SECURITY_BEARER_NAME)
  SWAGGER_BEARER_SCHEME = 'bearer';

type
  TIAM4DPublicActionCache = class(TInterfacedObject, IIAM4DPublicActionCache)
  private
    FCache: TDictionary<string, Boolean>;
    FLock: TMultiReadExclusiveWriteSynchronizer;
  public
    constructor Create;
    destructor Destroy; override;
    function IsPublic(const AControllerQualifiedClassName, AActionName: string): Boolean;
  end;

function NewIAM4DPublicActionCache: IIAM4DPublicActionCache;
begin
  Result := TIAM4DPublicActionCache.Create;
end;

{ TIAM4DPublicActionCache }

constructor TIAM4DPublicActionCache.Create;
begin
  inherited Create;
  FCache := TDictionary<string, Boolean>.Create;
  FLock := TMultiReadExclusiveWriteSynchronizer.Create;
end;

destructor TIAM4DPublicActionCache.Destroy;
begin
  FCache.Free;
  FLock.Free;
  inherited;
end;

function TIAM4DPublicActionCache.IsPublic(const AControllerQualifiedClassName, AActionName: string): Boolean;
var
  LCacheKey: string;
  LFound: Boolean;
  LIsPublic: Boolean;
  LRttiCtx: TRttiContext;
  LRttiType: TRttiType;
  LRttiMethod: TRttiMethod;
  LAttr: TCustomAttribute;
begin
  LCacheKey := AControllerQualifiedClassName + '.' + AActionName;

  // Fast path: read from cache
  FLock.BeginRead;
  try
    LFound := FCache.TryGetValue(LCacheKey, LIsPublic);
  finally
    FLock.EndRead;
  end;

  if LFound then
    Exit(LIsPublic);

  // Slow path: RTTI inspection
  LIsPublic := False;
  LRttiCtx := TRttiContext.Create;
  try
    LRttiType := LRttiCtx.FindType(AControllerQualifiedClassName);
    // FindType sees only the types of the interface sections, and the context carries the class
    // name only: a controller declared in the implementation section stays protected (once per
    // action, the result is cached)
    if not Assigned(LRttiType) then
      LogW(Format('[IAM4DPublic] not readable for %s.%s: the controller is not declared in the interface ' +
        'section of its unit, the action requires a token', [AControllerQualifiedClassName, AActionName]));
    if Assigned(LRttiType) then
    begin
      // Class-level attribute
      for LAttr in LRttiType.GetAttributes do
        if LAttr is IAM4DPublicAttribute then
        begin
          LIsPublic := True;
          Break;
        end;

      // Method-level attribute
      if not LIsPublic then
      begin
        LRttiMethod := LRttiType.GetMethod(AActionName);
        if Assigned(LRttiMethod) then
          for LAttr in LRttiMethod.GetAttributes do
            if LAttr is IAM4DPublicAttribute then
            begin
              LIsPublic := True;
              Break;
            end;
      end;
    end;
  finally
    LRttiCtx.Free;
  end;

  FLock.BeginWrite;
  try
    FCache.AddOrSetValue(LCacheKey, LIsPublic);
  finally
    FLock.EndWrite;
  end;

  Result := LIsPublic;
end;

{ Swagger / OpenAPI }

function IsSwaggerDocumentRequest(AContext: TWebContext): Boolean;
var
  LPathInfo, LFileName: string;
begin
  LPathInfo := LowerCase(AContext.Request.PathInfo);
  // The file name only (/api/swagger-v1.json, /openapi3.json): a directory named swagger does
  // not make every .json under it a document
  LFileName := LPathInfo.Substring(LPathInfo.LastIndexOf('/') + 1);
  Result :=
    (AContext.Request.HTTPMethod = TMVCHTTPMethodType.httpGET) and
    (LFileName.Contains('swagger') or
     LFileName.Contains('openapi') or
     LFileName.Contains('api-docs')) and
    LFileName.EndsWith('.json');
end;

function InjectSwaggerSecurity(var AJSON: string): Boolean;

  function EnsureObject(AParent: TJSONObject; const AName: string): TJSONObject;
  var
    LValue: TJSONValue;
  begin
    LValue := AParent.Values[AName];
    if LValue is TJSONObject then
      Exit(TJSONObject(LValue));
    if Assigned(LValue) then
      AParent.RemovePair(AName).Free;
    Result := TJSONObject.Create;
    AParent.AddPair(AName, Result);
  end;

  procedure EnsureGlobalBearerRequirement(ARoot: TJSONObject);
  var
    LValue: TJSONValue;
    LSecArr: TJSONArray;
    LSecArrObj: TJSONObject;
    LIndex: Integer;
  begin
    LValue := ARoot.Values['security'];
    if not (LValue is TJSONArray) then
    begin
      if Assigned(LValue) then
        ARoot.RemovePair('security').Free;
      LSecArr := TJSONArray.Create;
      ARoot.AddPair('security', LSecArr);
    end
    else
      LSecArr := TJSONArray(LValue);

    for LIndex := 0 to LSecArr.Count - 1 do
      if (LSecArr.Items[LIndex] is TJSONObject) and
        Assigned(TJSONObject(LSecArr.Items[LIndex]).Values[SWAGGER_BEARER_SCHEME]) then
        Exit;

    LSecArrObj := TJSONObject.Create;
    LSecArrObj.AddPair(SWAGGER_BEARER_SCHEME, TJSONArray.Create);
    LSecArr.AddElement(LSecArrObj);
  end;

var
  LValue: TJSONValue;
  LRoot, LSchemes, LScheme: TJSONObject;
begin
  Result := False;
  try
    LValue := TJSONObject.ParseJSONValue(AJSON);
    if not (LValue is TJSONObject) then
    begin
      LValue.Free;
      LogW('Swagger security injection skipped: response is not a JSON object');
      Exit;
    end;

    LRoot := TJSONObject(LValue);
    try
      if Assigned(LRoot.Values['openapi']) then
      begin
        // OpenAPI 3.x: HTTP bearer scheme, Swagger UI adds the "Bearer " prefix itself
        LSchemes := EnsureObject(EnsureObject(LRoot, 'components'), 'securitySchemes');
        if not (LSchemes.Values[SWAGGER_BEARER_SCHEME] is TJSONObject) then
        begin
          LScheme := TJSONObject.Create;
          LScheme.AddPair('type', 'http');
          LScheme.AddPair('scheme', 'bearer');
          LScheme.AddPair('bearerFormat', 'JWT');
          LScheme.AddPair('description', 'JWT Bearer token issued by the identity provider (paste the token without the "Bearer " prefix).');
          LSchemes.AddPair(SWAGGER_BEARER_SCHEME, LScheme);
        end;
      end
      else if Assigned(LRoot.Values['swagger']) then
      begin
        // Swagger 2.0 has no bearer scheme: API key in the Authorization header
        LSchemes := EnsureObject(LRoot, 'securityDefinitions');
        if not (LSchemes.Values[SWAGGER_BEARER_SCHEME] is TJSONObject) then
        begin
          LScheme := TJSONObject.Create;
          LScheme.AddPair('type', 'apiKey');
          LScheme.AddPair('name', 'Authorization');
          LScheme.AddPair('in', 'header');
          LScheme.AddPair('description', 'JWT Bearer token. Format: Bearer <token>. Example: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...');
          LSchemes.AddPair(SWAGGER_BEARER_SCHEME, LScheme);
        end;
      end
      else
      begin
        LogW('Swagger security injection skipped: neither a Swagger 2.0 nor an OpenAPI 3 document');
        Exit;
      end;

      EnsureGlobalBearerRequirement(LRoot);

      AJSON := LRoot.ToJSON;
      Result := True;
    finally
      LRoot.Free;
    end;
  except
    on E: Exception do
      LogW('Failed to inject Swagger security definitions: ' + E.Message + sLineBreak +
        'Stack trace: ' + E.StackTrace);
  end;
end;

procedure IAM4DInjectSwaggerSecurityInResponse(AContext: TWebContext);
var
  LResponse: TMVCWebResponse;
  LStream: TStream;
  LBody: string;
  LBytes: TBytes;
begin
  if not IsSwaggerDocumentRequest(AContext) then
    Exit;

  LResponse := AContext.Response;

  // Compressed payloads cannot be rewritten
  if (LResponse.ContentEncoding <> '') or (LResponse.GetCustomHeader('Content-Encoding') <> '') then
    Exit;

  // Document rendered as text
  LBody := LResponse.Content;
  if not LBody.IsEmpty then
  begin
    if InjectSwaggerSecurity(LBody) then
      LResponse.Content := LBody;
    Exit;
  end;

  // Document rendered as stream (SwaggerHTTPFilter and TMVCSwaggerMiddleware use SetContentStream).
  // The stream is rewritten in place: replacing it would leak the previous one
  // on Indy Direct, whose response does not free a replaced ContentStream.
  LStream := LResponse.ContentStream;
  if not (LStream is TMemoryStream) or (LStream.Size = 0) then
    Exit;

  SetLength(LBytes, LStream.Size);
  LStream.Position := 0;
  LStream.ReadBuffer(LBytes, Length(LBytes));
  LStream.Position := 0;
  LBody := TEncoding.UTF8.GetString(LBytes);

  if not InjectSwaggerSecurity(LBody) then
    Exit;

  LBytes := TEncoding.UTF8.GetBytes(LBody);
  LStream.Size := 0;
  LStream.WriteBuffer(LBytes, Length(LBytes));
  LStream.Position := 0;

  // WebBroker computes Content-Length when the stream is assigned
  if Assigned(LResponse.RawWebResponse) then
    LResponse.RawWebResponse.ContentLength := LStream.Size;
end;

end.
