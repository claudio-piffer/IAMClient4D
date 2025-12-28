{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.DMVC.Middleware.pas
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

unit IAMClient4D.DMVC.Middleware;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  MVCFramework,
  MVCFramework.Commons,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.JWT,
  IAMClient4D.Security.JWT.JWKS,
  IAMClient4D.Common.Security,
  IAMClient4D.Core,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// Configuration for JWT middleware in DelphiMVCFramework applications.
  /// </summary>
  /// <remarks>
  /// When Issuer is provided, the middleware automatically uses TIAM4DJWKSProvider
  /// with TLightweightMREW for optimal multi-threaded performance and auto-discovery.
  /// JWKS_URL is optional when using auto-discovery (recommended).
  /// </remarks>
  TIAM4DJWTMiddlewareConfig = record
    Issuer: string;
    Audience: string;
    JWKS_URL: string; // Optional when using auto-discovery (Issuer-based)
    JWKSCacheDurationMinutes: Integer;
    ClockSkewSeconds: Integer;
    TokenHeaderName: string; // default 'Authorization'
    TokenPrefix: string; // default 'Bearer '
    SubjectClaimName: string; // default 'sub'
    RolesClaimName: string; // default 'roles'
    AllowAnonymous: Boolean; // default False
    SSLValidationMode: TIAM4DSSLValidationMode;
    ExpectedAzp: string; // default '' (not validated). Set to client_id for multi-tenant scenarios
    RequireAzpWhenMultipleAud: Boolean; // default True (OIDC spec compliance)
    HTTPConnectTimeoutMs: Integer; // default 30000 (30 seconds)
    HTTPReceiveTimeoutMs: Integer; // default 60000 (60 seconds)

    class function Create(const AIssuer, AAudience, AJWKS_URL: string): TIAM4DJWTMiddlewareConfig; static;
  end;

  /// <summary>
  /// DMVC middleware for JWT authentication and authorization.
  /// </summary>
  TIAM4DJWTMiddleware = class(TInterfacedObject, IMVCMiddleware)
  private
    FConfig: TIAM4DJWTMiddlewareConfig;
    FJWTValidator: IIAM4DJWTValidator;

    function CreateHTTPConfig(const ASSLValidationMode: TIAM4DSSLValidationMode): TIAM4DHTTPClientConfig;
    procedure ConfigureValidatorAzp(const AExpectedAzp: string; ARequireAzpWhenMultipleAud: Boolean);
    function ExtractToken(AContext: TWebContext): string;
    function WantsAuthentication(AContext: TWebContext): Boolean;
    procedure HandleAuthenticationError(AContext: TWebContext; const AMessage: string);

    function IsSwaggerRequest(AContext: TWebContext): Boolean;
    procedure InjectSwaggerSecurity(var AJSON: string);
  protected
    procedure OnBeforeRouting(AContext: TWebContext; var AHandled: Boolean);
    procedure OnBeforeControllerAction(AContext: TWebContext; const AControllerQualifiedClassName, AActionName: string; var AHandled: Boolean);
    procedure OnAfterControllerAction(AContext: TWebContext; const AControllerQualifiedClassName, AActionName: string; const AHandled: Boolean);
    procedure OnAfterRouting(AContext: TWebContext; const AHandled: Boolean);
  public
    /// <summary>
    /// Creates middleware with configuration. Uses JWKS Provider with auto-discovery when Issuer is provided.
    /// </summary>
    constructor Create(const AConfig: TIAM4DJWTMiddlewareConfig); overload;

    /// <summary>
    /// Creates middleware with issuer, audience, and optional JWKS URL. Uses auto-discovery if issuer provided.
    /// </summary>
    constructor Create(const AIssuer, AAudience, AJWKS_URL: string; const AExpectedAzp: string = ''); overload;

    /// <summary>
    /// Creates middleware with auto-discovery. Recommended for production use with OIDC providers.
    /// Uses singleton TIAM4DJWKSProvider for optimal performance.
    /// </summary>
    constructor Create(const AIssuer, AAudience: string; const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict; const AExpectedAzp: string = ''); overload;

    /// <summary>
    /// Creates middleware with custom JWT validator (advanced use cases).
    /// Allows full control over JWT validation, useful for:
    /// - Custom validation logic beyond standard JWT validation
    /// - Unit testing with mocked validators
    /// - Multi-tenant scenarios with dynamic issuer/audience
    /// - Integration with third-party JWT validation libraries
    /// </summary>
    /// <remarks>
    /// Middleware behavior (like Create):
    /// - Applies automatic configurations from AConfig (ClockSkew, Azp, etc.)
    /// - Validator lifecycle managed automatically via interface reference counting
    /// - No manual memory management needed (interfaces handle it)
    ///
    /// Validator configuration:
    /// - Validator can be passed partially or fully configured
    /// - Middleware will apply settings from AConfig on top
    /// - JWKS is handled automatically via internal provider with auto-discovery
    ///
    /// Memory management:
    /// - Validator is an interface: reference counting is automatic
    /// - When middleware is destroyed, validator reference is released
    /// - Validator object is destroyed when all references are gone
    /// </remarks>
    constructor Create(
      const AValidator: IIAM4DJWTValidator;
      const AConfig: TIAM4DJWTMiddlewareConfig); overload;

    destructor Destroy; override;

    /// <summary>
    /// Sets expected authorized party (azp) for JWT validation. Useful for multi-tenant scenarios.
    /// </summary>
    procedure SetExpectedAzp(const AValue: string);

    /// <summary>
    /// Configures whether azp is required when audience contains multiple values (default: True for OIDC compliance).
    /// </summary>
    procedure SetRequireAzpWhenMultipleAud(const AValue: Boolean);
  end;

implementation

uses
  System.StrUtils,
  System.Generics.Collections,
  Web.HTTPApp,
  IAMClient4D.DMVC.DTO,
  IAMClient4D.DMVC.Common,
  MVCFramework.Logger;

{ TIAM4DJWTMiddlewareConfig }

class function TIAM4DJWTMiddlewareConfig.Create(const AIssuer, AAudience, AJWKS_URL: string): TIAM4DJWTMiddlewareConfig;
begin
  Result.Issuer := AIssuer;
  Result.Audience := AAudience;
  Result.JWKS_URL := AJWKS_URL;
  Result.JWKSCacheDurationMinutes := 60;
  Result.ClockSkewSeconds := 60;
  Result.TokenHeaderName := 'Authorization';
  Result.TokenPrefix := 'Bearer ';
  Result.SubjectClaimName := 'sub';
  Result.RolesClaimName := 'roles';
  Result.AllowAnonymous := False;
  Result.SSLValidationMode := svmStrict;
  Result.ExpectedAzp := '';
  Result.RequireAzpWhenMultipleAud := True;
  Result.HTTPConnectTimeoutMs := 30000;
  Result.HTTPReceiveTimeoutMs := 60000;
end;

{ TIAM4DJWTMiddleware }

function TIAM4DJWTMiddleware.CreateHTTPConfig(const ASSLValidationMode: TIAM4DSSLValidationMode): TIAM4DHTTPClientConfig;
begin
  Result := TIAM4DHTTPClientConfig.Create(
    FConfig.HTTPConnectTimeoutMs,
    FConfig.HTTPReceiveTimeoutMs,
    ASSLValidationMode);
end;

procedure TIAM4DJWTMiddleware.ConfigureValidatorAzp(const AExpectedAzp: string; ARequireAzpWhenMultipleAud: Boolean);
begin
  if (FJWTValidator is TIAM4DJWTValidator) then
  begin
    if not AExpectedAzp.Trim.IsEmpty then
      TIAM4DJWTValidator(FJWTValidator).SetExpectedAzp(AExpectedAzp);
    TIAM4DJWTValidator(FJWTValidator).SetRequireAzpWhenMultipleAud(ARequireAzpWhenMultipleAud);
  end
  else
  begin
    LogW('Custom validator does not support azp configuration. Skipping azp setup.');
  end;
end;

constructor TIAM4DJWTMiddleware.Create(const AConfig: TIAM4DJWTMiddlewareConfig);
var
  LHTTPConfig: TIAM4DHTTPClientConfig;
  LJWKSProvider: IIAM4DJWKSProvider;
begin
  inherited Create;
  FConfig := AConfig;

  LHTTPConfig := CreateHTTPConfig(FConfig.SSLValidationMode);

  // Use singleton JWKS provider for optimal performance and thread-safety
  LJWKSProvider := TIAM4DJWKSProvider.GetInstance;
  LJWKSProvider.SetSSLValidationMode(FConfig.SSLValidationMode);

  if FConfig.JWKSCacheDurationMinutes > 0 then
    LJWKSProvider.SetCacheTTL(FConfig.JWKSCacheDurationMinutes * 60);

  FJWTValidator := TIAM4DJWTValidator.Create(
    FConfig.Issuer,
    FConfig.Audience,
    LJWKSProvider,
    LHTTPConfig);

  LogI('JWT middleware initialized. Issuer=' + FConfig.Issuer + ' Audience=' + FConfig.Audience);

  FJWTValidator.ClockSkewSeconds := FConfig.ClockSkewSeconds;

  ConfigureValidatorAzp(FConfig.ExpectedAzp, FConfig.RequireAzpWhenMultipleAud);
end;

constructor TIAM4DJWTMiddleware.Create(const AIssuer, AAudience, AJWKS_URL: string; const AExpectedAzp: string);
var
  LConfig: TIAM4DJWTMiddlewareConfig;
begin
  LConfig := TIAM4DJWTMiddlewareConfig.Create(AIssuer, AAudience, AJWKS_URL);
  LConfig.ExpectedAzp := AExpectedAzp;
  Create(LConfig);
end;

constructor TIAM4DJWTMiddleware.Create(const AIssuer, AAudience: string; const ASSLValidationMode: TIAM4DSSLValidationMode; const AExpectedAzp: string);
var
  LConfig: TIAM4DJWTMiddlewareConfig;
  LHTTPConfig: TIAM4DHTTPClientConfig;
  LJWKSProvider: IIAM4DJWKSProvider;
begin
  inherited Create;

  LConfig := TIAM4DJWTMiddlewareConfig.Create(AIssuer, AAudience, '');
  LConfig.SSLValidationMode := ASSLValidationMode;
  LConfig.ExpectedAzp := AExpectedAzp;
  FConfig := LConfig;

  LHTTPConfig := CreateHTTPConfig(ASSLValidationMode);
  LJWKSProvider := TIAM4DJWKSProvider.Create(LHTTPConfig);

  FJWTValidator := TIAM4DJWTValidator.Create(
    AIssuer,
    AAudience,
    LJWKSProvider,
    LHTTPConfig);

  FJWTValidator.ClockSkewSeconds := FConfig.ClockSkewSeconds;

  ConfigureValidatorAzp(FConfig.ExpectedAzp, FConfig.RequireAzpWhenMultipleAud);

  LogI('JWT middleware initialized (auto-discovery). Issuer=' + AIssuer);
end;

constructor TIAM4DJWTMiddleware.Create(
  const AValidator: IIAM4DJWTValidator;
  const AConfig: TIAM4DJWTMiddlewareConfig);
begin
  inherited Create;

  if not Assigned(AValidator) then
    raise EIAM4DInvalidConfigurationException.Create('Custom validator cannot be nil. ' +
      'Create a validator instance using TIAM4DJWTValidator.Create() before passing it to the middleware.');

  FConfig := AConfig;
  FJWTValidator := AValidator;

  FJWTValidator.ClockSkewSeconds := FConfig.ClockSkewSeconds;

  ConfigureValidatorAzp(FConfig.ExpectedAzp, FConfig.RequireAzpWhenMultipleAud);

  LogI('JWT middleware initialized with custom validator. ' +
    'Issuer=' + FConfig.Issuer + ' Audience=' + FConfig.Audience);
end;

destructor TIAM4DJWTMiddleware.Destroy;
begin
  FJWTValidator := nil;
  inherited;
end;

procedure TIAM4DJWTMiddleware.SetExpectedAzp(const AValue: string);
begin
  FConfig.ExpectedAzp := AValue;
  ConfigureValidatorAzp(AValue, FConfig.RequireAzpWhenMultipleAud);
end;

procedure TIAM4DJWTMiddleware.SetRequireAzpWhenMultipleAud(const AValue: Boolean);
begin
  FConfig.RequireAzpWhenMultipleAud := AValue;
  ConfigureValidatorAzp(FConfig.ExpectedAzp, AValue);
end;

function TIAM4DJWTMiddleware.ExtractToken(AContext: TWebContext): string;
var
  LAuthHeader: string;
begin
  Result := '';
  LAuthHeader := AContext.Request.Headers[FConfig.TokenHeaderName];
  if LAuthHeader.IsEmpty then
    Exit;

  // RFC 7235: Authentication scheme is case-insensitive (Bearer, bearer, BEARER all valid)
  if not LAuthHeader.StartsWith(FConfig.TokenPrefix, True) then
    Exit;

  Result := Trim(LAuthHeader.Substring(FConfig.TokenPrefix.Length));
end;

function TIAM4DJWTMiddleware.WantsAuthentication(AContext: TWebContext): Boolean;
var
  LHasToken: Boolean;
begin
  if (AContext.Request.HTTPMethod = TMVCHTTPMethodType.httpOPTIONS) then
    Exit(False);

  LHasToken := ExtractToken(AContext) <> '';
  if FConfig.AllowAnonymous then
    Result := LHasToken
  else
    Result := True;
end;

procedure TIAM4DJWTMiddleware.HandleAuthenticationError(AContext: TWebContext; const AMessage: string);
var
  LError: TJSONObject;
begin
  LogW('Authentication failed: ' + AMessage);

  if Assigned(AContext.Response.RawWebResponse) then
  begin
    AContext.Response.RawWebResponse.SetCustomHeader('WWW-Authenticate', '');
    AContext.Response.RawWebResponse.WWWAuthenticate :=
      Format('Bearer realm="%s", error="invalid_token", error_description="%s"',
      [FConfig.Audience, AMessage.Replace('"', '''')]);
  end
  else
  begin
    AContext.Response.SetCustomHeader('WWW-Authenticate',
      Format('Bearer realm="%s"', [FConfig.Audience]));
  end;

  AContext.Response.StatusCode := HTTP_STATUS.Unauthorized;
  AContext.Response.ContentType := TMVCMediaType.APPLICATION_JSON;

  LError := TJSONObject.Create;
  try
    LError.AddPair('error', 'unauthorized');
    LError.AddPair('message', AMessage);
    LError.AddPair('status', TJSONNumber.Create(401));

    AContext.Response.StatusCode := HTTP_STATUS.Unauthorized;
    AContext.Response.ContentType := TMVCMediaType.APPLICATION_JSON;
    AContext.Response.RawWebResponse.Content := LError.ToJSON;
  finally
    LError.Free;
  end;
end;

procedure TIAM4DJWTMiddleware.InjectSwaggerSecurity(var AJSON: string);
var
  LRoot, LSecDefs, LBearerObj, LSecArrObj: TJSONObject;
  LSecArr: TJSONArray;
  LIndex: Integer;
  LHasBearer: Boolean;
begin
  try
    try
      LRoot := TJSONObject.ParseJSONValue(AJSON) as TJSONObject;
      if not Assigned(LRoot) then
      begin
        LogW('InjectSwaggerSecurity: Failed to parse JSON (returned nil)');
        Exit;
      end;
    except
      on E: Exception do
      begin
        LogW('Failed to parse Swagger JSON for security injection: ' + E.Message + sLineBreak +
          'Stack trace: ' + E.StackTrace);
        Exit;
      end;
    end;

    try
      if not Assigned(LRoot.Values['swagger']) then
      begin
        LogW('Swagger security injection skipped: Not a Swagger 2.0 document');
        Exit;
      end;

      if not (LRoot.Values['securityDefinitions'] is TJSONObject) then
      begin
        LSecDefs := TJSONObject.Create;
        LRoot.AddPair('securityDefinitions', LSecDefs);
      end
      else
        LSecDefs := LRoot.Values['securityDefinitions'] as TJSONObject;

      if not (LSecDefs.Values['bearer'] is TJSONObject) then
      begin
        LBearerObj := TJSONObject.Create;
        LBearerObj.AddPair('type', 'apiKey');
        LBearerObj.AddPair('name', 'Authorization');
        LBearerObj.AddPair('in', 'header');
        LBearerObj.AddPair('description', 'JWT Bearer token. Format: Bearer <token>. Example: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...');
        LSecDefs.AddPair('bearer', LBearerObj);
      end;

      if not (LRoot.Values['security'] is TJSONArray) then
      begin
        LSecArr := TJSONArray.Create;
        LSecArrObj := TJSONObject.Create;
        LSecArrObj.AddPair('bearer', TJSONArray.Create);
        LSecArr.AddElement(LSecArrObj);
        LRoot.AddPair('security', LSecArr);
      end
      else
      begin
        LSecArr := LRoot.Values['security'] as TJSONArray;
        LHasBearer := False;

        for LIndex := 0 to LSecArr.Count - 1 do
        begin
          if (LSecArr.Items[LIndex] is TJSONObject) and
            Assigned((LSecArr.Items[LIndex] as TJSONObject).Values['bearer']) then
          begin
            LHasBearer := True;
            Break;
          end;
        end;

        if not LHasBearer then
        begin
          LSecArrObj := TJSONObject.Create;
          LSecArrObj.AddPair('bearer', TJSONArray.Create);
          LSecArr.AddElement(LSecArrObj);
        end;
      end;

      AJSON := LRoot.ToJSON;
    finally
      LRoot.Free;
    end;
  except
    on E: Exception do
      LogW('Failed to inject Swagger security definitions: ' + E.Message + sLineBreak +
        'Stack trace: ' + E.StackTrace);
  end;
end;

function TIAM4DJWTMiddleware.IsSwaggerRequest(AContext: TWebContext): Boolean;
var
  LPathInfo: string;
begin
  LPathInfo := LowerCase(AContext.Request.PathInfo);
  Result :=
    (AContext.Request.HTTPMethod = TMVCHTTPMethodType.httpGET) and
    (LPathInfo.Contains('swagger') or
     LPathInfo.Contains('openapi') or
     LPathInfo.Contains('api-docs')) and
    LPathInfo.EndsWith('.json');
end;

procedure TIAM4DJWTMiddleware.OnBeforeRouting(AContext: TWebContext; var AHandled: Boolean);
var
  LToken: string;
  LClaims: TJSONObject;
  LResponseOK: Boolean;
  LSubject: string;
  LStdClaims: TIAM4DJWTClaims;
  LKCClaims: TIAM4DKeycloakClaims;
  LStdJSON, LKCJSON: TJSONObject;
  LUser: TUser;
  LUserName: string;
  LRole: string;
  LIndex: Integer;
  LRoleSet: TDictionary<string, Boolean>;
begin
  if (AContext.Request.HTTPMethod = TMVCHTTPMethodType.httpOPTIONS) or IsSwaggerRequest(AContext) then
    Exit;

  if not WantsAuthentication(AContext) then
    Exit;

  LToken := ExtractToken(AContext);
  if LToken.IsEmpty then
  begin
    HandleAuthenticationError(AContext, 'Missing or invalid Authorization header');
    AHandled := True;
    Exit;
  end;

  LClaims := nil;
  try
    try
      LResponseOK := FJWTValidator.ValidateToken(LToken, LClaims);
      if not LResponseOK then
      begin
        HandleAuthenticationError(AContext, 'Invalid or expired JWT token');
        AHandled := True;
        Exit;
      end;

      if Assigned(LClaims) then
      begin
        AContext.Data[CONTEXT_KEY_JWT_CLAIMS] := LClaims.ToJSON;
        AContext.Data[CONTEXT_KEY_JWT_TOKEN] := LToken;

        LStdClaims := TIAM4DJWTClaims.ParseFromPayload(LClaims);
        LKCClaims := TIAM4DKeycloakClaims.ParseFromPayload(LClaims);

        LStdJSON := LStdClaims.ToJSON;
        try
          AContext.Data[CONTEXT_KEY_STD_JSON] := LStdJSON.ToJSON;
        finally
          LStdJSON.Free;
        end;

        LKCJSON := LKCClaims.ToJSON;
        try
          AContext.Data[CONTEXT_KEY_KC_JSON] := LKCJSON.ToJSON;
        finally
          LKCJSON.Free;
        end;

        if not LClaims.TryGetValue<string>(FConfig.SubjectClaimName, LSubject) then
          LSubject := LStdClaims.Subject;

        LUser := AContext.LoggedUser;

        LUserName := LStdClaims.PreferredUsername;
        if LUserName.IsEmpty then
          LUserName := LStdClaims.Email;
        if LUserName.IsEmpty then
          LUserName := LStdClaims.Subject;

        LUser.UserName := LUserName;

        LUser.Realm := LStdClaims.AuthorizedParty;
        if LUser.Realm.IsEmpty then
          LUser.Realm := FConfig.Audience;

        if LStdClaims.IssuedAtTime > 0 then
          LUser.LoggedSince := LStdClaims.IssuedAtTime
        else
          LUser.LoggedSince := Now;

        LUser.Roles.Clear;
        LRoleSet := TDictionary<string, Boolean>.Create(CaseInsensitiveComparer);
        try
          for LRole in LStdClaims.Roles do
            if not LRoleSet.ContainsKey(LRole) then
              LRoleSet.Add(LRole, True);

          for LRole in LKCClaims.RealmAccess.Roles do
            if not LRoleSet.ContainsKey(LRole) then
              LRoleSet.Add(LRole, True);

          for LIndex := 0 to High(LKCClaims.ResourceAccess) do
            for LRole in LKCClaims.ResourceAccess[LIndex].Roles do
              if not LRoleSet.ContainsKey(LRole) then
                LRoleSet.Add(LRole, True);

          for LRole in LRoleSet.Keys do
            LUser.Roles.Add(LRole);
        finally
          LRoleSet.Free;
        end;

        if not Assigned(LUser.CustomData) then
          LUser.CustomData := TMVCCustomData.Create
        else
          LUser.CustomData.Clear;

        if not LStdClaims.Subject.IsEmpty then
          LUser.CustomData.AddOrSetValue('sub', LStdClaims.Subject);
        if not LStdClaims.Email.IsEmpty then
        begin
          LUser.CustomData.AddOrSetValue('email', LStdClaims.Email);
          LUser.CustomData.AddOrSetValue('email_verified', BoolToStr(LStdClaims.EmailVerified, True));
        end;
        if not LStdClaims.GivenName.IsEmpty then
          LUser.CustomData.AddOrSetValue('given_name', LStdClaims.GivenName);
        if not LStdClaims.FamilyName.IsEmpty then
          LUser.CustomData.AddOrSetValue('family_name', LStdClaims.FamilyName);
        if not LStdClaims.Name.IsEmpty then
          LUser.CustomData.AddOrSetValue('name', LStdClaims.Name);
        if not LStdClaims.Issuer.IsEmpty then
          LUser.CustomData.AddOrSetValue('iss', LStdClaims.Issuer);
        if not LStdClaims.SessionId.IsEmpty then
          LUser.CustomData.AddOrSetValue('sid', LStdClaims.SessionId);
        if not LStdClaims.Acr.IsEmpty then
          LUser.CustomData.AddOrSetValue('acr', LStdClaims.Acr);

        if LStdClaims.ExpirationTime > 0 then
          LUser.CustomData.AddOrSetValue('exp', DateTimeToStr(LStdClaims.ExpirationTime));
        if LStdClaims.IssuedAtTime > 0 then
          LUser.CustomData.AddOrSetValue('iat', DateTimeToStr(LStdClaims.IssuedAtTime));
        if LStdClaims.AuthTime > 0 then
          LUser.CustomData.AddOrSetValue('auth_time', DateTimeToStr(LStdClaims.AuthTime));

        if Length(LStdClaims.Scopes) > 0 then
          LUser.CustomData.AddOrSetValue('scopes', string.Join(',', LStdClaims.Scopes));

        if Length(LKCClaims.Groups) > 0 then
          LUser.CustomData.AddOrSetValue('groups', string.Join(',', LKCClaims.Groups));

        LogD(Format('JWT validated. Subject="%s", Username="%s", Realm="%s", Roles=%d',
          [LSubject, LUserName, LUser.Realm, LUser.Roles.Count]));
      end;
    except
      on E: Exception do
      begin
        LogE(Format('Unexpected JWT error [%s]: %s | Stack: %s',
          [E.ClassName, E.Message, E.StackTrace]));
        HandleAuthenticationError(AContext, 'Authentication error: ' + E.Message);
        AHandled := True;
      end;
    end;
  finally
    if Assigned(LClaims) then
      LClaims.Free;
  end;
end;

procedure TIAM4DJWTMiddleware.OnBeforeControllerAction(AContext: TWebContext; const AControllerQualifiedClassName, AActionName: string; var AHandled: Boolean);
begin
  //don't remove
end;

procedure TIAM4DJWTMiddleware.OnAfterControllerAction(AContext: TWebContext; const AControllerQualifiedClassName, AActionName: string; const AHandled: Boolean);
begin
  //don't remove
end;

procedure TIAM4DJWTMiddleware.OnAfterRouting(AContext: TWebContext; const AHandled: Boolean);
var
  LBody: string;
  LEncoding: string;
  LResponse: TWebResponse;
begin
  if not IsSwaggerRequest(AContext) then
    Exit;

  LResponse := AContext.Response.RawWebResponse;
  if Assigned(LResponse) then
    LEncoding := LResponse.GetCustomHeader('Content-Encoding')
  else
    LEncoding := '';
  if LEncoding <> '' then
    Exit;

  LBody := AContext.Response.Content;

  if (LBody = '') and Assigned(LResponse) and Assigned(LResponse.ContentStream) then
  begin
    if LResponse.ContentStream.Size > 0 then
    begin
      LResponse.ContentStream.Position := 0;
      var LStringStream := TStringStream.Create('', TEncoding.UTF8);
      try
        LStringStream.CopyFrom(LResponse.ContentStream, LResponse.ContentStream.Size);
        LBody := LStringStream.DataString;
      finally
        LStringStream.Free;
      end;
    end;
  end;

  if LBody = '' then
    Exit;

  InjectSwaggerSecurity(LBody);

  AContext.Response.ContentType := TMVCMediaType.APPLICATION_JSON;
  AContext.Response.Content := LBody;
end;

end.