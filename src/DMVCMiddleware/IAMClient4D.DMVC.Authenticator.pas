{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.DMVC.Authenticator.pas
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
/// JWT authentication core of the DMVC integration: configuration record, authenticator interface
/// and class, shared by the filter bundle, the endpoint filter (IAMClient4D.DMVC.Filters) and the
/// deprecated middleware (IAMClient4D.DMVC.Middleware).
/// </summary>
unit IAMClient4D.DMVC.Authenticator;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.SyncObjs,
  System.Generics.Collections,
  MVCFramework,
  MVCFramework.Commons,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.JWT,
  IAMClient4D.Security.JWT.JWKS,
  IAMClient4D.Common.Security,
  IAMClient4D.Core,
  IAMClient4D.Exceptions,
  IAMClient4D.DMVC.ClaimsTransformation,
  IAMClient4D.DMVC.Internal;

type
  /// <summary>
  /// Configuration for JWT middleware in DelphiMVCFramework applications.
  /// </summary>
  /// <remarks>
  /// Issuer is required (EIAM4DInvalidConfigurationException when empty): the middleware uses
  /// TIAM4DJWKSProvider with auto-discovery for that issuer only.
  /// JWKS_URL is optional: when set, the keys are fetched from it without discovery.
  /// With a custom validator, JWKS_URL and the JWKS/HTTP settings are not used.
  /// Every variable of this type starts with the defaults of Create (Initialize operator), also a
  /// local variable filled field by field: anonymous access stays off unless AllowAnonymous is set.
  /// </remarks>
  TIAM4DJWTMiddlewareConfig = record
    Issuer: string;
    Audience: string;
    AudienceValidationEnabled: Boolean; // default True
    JWKS_URL: string; // default '' (OIDC discovery from Issuer); set: JWKS endpoint of Issuer, no discovery
    JWKSCacheDurationMinutes: Integer;
    ClockSkewSeconds: Integer;
    TokenHeaderName: string; // default 'Authorization'
    TokenPrefix: string; // default 'Bearer '
    SubjectClaimName: string; // default 'sub': LoggedUser.CustomData['sub'], last fallback of LoggedUser.UserName
    RolesClaimName: string; // default 'roles': top-level claim added to LoggedUser.Roles ('' = none)
    AllowAnonymous: Boolean; // default False
    SSLValidationMode: TIAM4DSSLValidationMode;
    // default nil: SHA-256 hashes of the public key of the identity provider certificate (format of
    // IIAM4DClient.AddPinnedPublicKeys), checked for discovery and JWKS. Not supported on Linux
    // (ENotSupportedException). Not used with a custom validator
    PinnedPublicKeys: TArray<string>;
    // default nil: certificate validator of discovery and JWKS (e.g. with pins of its own); its mode
    // is set to SSLValidationMode. Not with PinnedPublicKeys: add them to it. It is called only in
    // svmAllowSelfSigned, with pins, or on Android: in svmStrict without pins the platform alone
    // validates, and its OnCertificateValidation is not raised
    SSLValidator: IIAM4DSSLCertificateValidator;
    ExpectedAzp: string; // default '' (not validated). Set to client_id for multi-tenant scenarios
    RequireAzpWhenMultipleAud: Boolean; // default True (OIDC spec compliance)
    HTTPConnectTimeoutMs: Integer; // default 10000 (10 seconds): discovery and JWKS run in the request thread
    HTTPReceiveTimeoutMs: Integer; // default 15000 (15 seconds)
    // default 'Bearer': typ claim of Keycloak access tokens, so an ID token ('ID') is refused; a token
    // without typ passes. '' = not checked. Not used with a custom validator
    ExpectedTokenType: string;
    // default ['JWT', 'at+jwt']: header typ of the access tokens; at+jwt is RFC 9068 (Keycloak client
    // option "Use 'at+jwt' as access token header type"). ['at+jwt'] accepts only those. Not used
    // with a custom validator
    AllowedHeaderTypes: TArray<string>;
    // default 10: one warning per interval for the rejected tokens (with the count of the others),
    // the others at debug level; the client chooses how many it sends. 0 = a warning for each
    RejectedTokenWarningIntervalSec: Integer;
    // default nil. Enriches LoggedUser after a valid token (e.g. roles from the application
    // database, see TIAM4DRolesClaimsTransformer); an exception rejects the request with 503
    ClaimsTransformer: IIAM4DClaimsTransformer;

    class operator Initialize(out Dest: TIAM4DJWTMiddlewareConfig);
    class function Create(const AIssuer, AAudience, AJWKS_URL: string): TIAM4DJWTMiddlewareConfig; static;
  end;

  /// <summary>
  /// JWT authentication core of the IAMClient4D DMVC filters (IAM4DJWTBundle, IAM4DJWTEndpointFilter
  /// in IAMClient4D.DMVC.Filters) and of the deprecated TIAM4DJWTMiddleware.
  /// </summary>
  IIAM4DJWTAuthenticator = interface
    ['{8E3A51C2-4F7D-4B19-A6C0-2D95E1B7F438}']
    function GetConfig: TIAM4DJWTMiddlewareConfig;

    /// <summary>
    /// Validates the bearer token (if present) and publishes the result in the request context:
    /// auth status and claims in Context.Data, identity and roles in Context.LoggedUser.
    /// Never blocks the request: enforcement is done by AuthorizeRequest.
    /// Runs once per request: a second call on the same context (e.g. bundle and group filter) does nothing.
    /// </summary>
    procedure AuthenticateRequest(AContext: TWebContext);

    /// <summary>
    /// Applies the access policy to a request already processed by AuthenticateRequest.
    /// Returns True when the request may proceed; otherwise writes the response on AContext.Response
    /// and returns False: 401 with a WWW-Authenticate challenge (RFC 6750), or 503 with Retry-After
    /// when the token could not be validated because the identity provider is unavailable.
    /// Body: application/json {"error", "message", "status"}, also for an action whose
    /// [MVCProduces] is not JSON.
    /// </summary>
    function AuthorizeRequest(AContext: TWebContext): Boolean;

    /// <summary>
    /// Sets the expected authorized party (azp); '' clears the check.
    /// Not thread-safe, as every setter of this interface: call it before the server starts
    /// handling requests (they change the configuration and the validator without a lock).
    /// </summary>
    procedure SetExpectedAzp(const AValue: string);

    /// <summary>
    /// Requires azp when aud has several values (default True). Set it before the server starts handling requests.
    /// </summary>
    procedure SetRequireAzpWhenMultipleAud(const AValue: Boolean);

    /// <summary>
    /// Enables/disables the audience (aud) validation. Set it before the server starts handling requests.
    /// </summary>
    procedure SetAudienceValidationEnabled(const AValue: Boolean);

    /// <summary>
    /// Sets the claims transformer (Config.ClaimsTransformer; nil = none).
    /// Set it before the server starts handling requests.
    /// </summary>
    procedure SetClaimsTransformer(const AValue: IIAM4DClaimsTransformer);

    property Config: TIAM4DJWTMiddlewareConfig read GetConfig;
  end;

  /// <summary>
  /// Default IIAM4DJWTAuthenticator implementation based on TIAM4DJWTValidator.
  /// </summary>
  TIAM4DJWTAuthenticator = class(TInterfacedObject, IIAM4DJWTAuthenticator)
  private
    FConfig: TIAM4DJWTMiddlewareConfig;
    FJWTValidator: IIAM4DJWTValidator;
    FContextMarker: string;
    // Rejected tokens: one warning per RejectedTokenWarningIntervalSec, the others at debug level
    FLastRejectLogTick: Int64;
    FSuppressedRejects: Integer;
    // Validator built from the configuration: its expected audience is FConfig.Audience
    FBuiltInValidator: Boolean;

    class procedure RaiseAudienceRequired; static;
    procedure ConfigureValidatorOptions(AApplyEmptyAzp: Boolean);
    /// <summary>Warnings at startup for settings that weaken the validation</summary>
    procedure LogRiskySettings(ACustomValidator: Boolean);
    /// <summary>
    /// Logs a rejected token: a warning at most every RejectedTokenWarningIntervalSec (with the count
    /// of the ones in between), the others at debug level.
    /// </summary>
    procedure LogRejected(const AMessage: string);
    function ExtractToken(AContext: TWebContext): string;
    procedure ClearAuthenticationData(AContext: TWebContext);
    procedure PopulateContext(AContext: TWebContext; const AToken: string; AClaims: TJSONObject);
    procedure HandleAuthenticationError(AContext: TWebContext; const AError, AMessage: string);
    procedure HandleUnavailable(AContext: TWebContext);
  public
    /// <summary>
    /// Creates the authenticator with a dedicated TIAM4DJWKSProvider (auto-discovery from Issuer).
    /// Raises EIAM4DInvalidConfigurationException when AConfig.Issuer is empty, or AConfig.Audience
    /// is empty with AudienceValidationEnabled (set it to False to accept any client of the realm).
    /// </summary>
    constructor Create(const AConfig: TIAM4DJWTMiddlewareConfig); overload;

    /// <summary>
    /// Creates the authenticator with a custom JWT validator. Settings from AConfig
    /// (ClockSkew, audience, azp) are applied on top of the validator.
    /// </summary>
    constructor Create(
      const AValidator: IIAM4DJWTValidator;
      const AConfig: TIAM4DJWTMiddlewareConfig); overload;

    destructor Destroy; override;

    function GetConfig: TIAM4DJWTMiddlewareConfig;
    procedure AuthenticateRequest(AContext: TWebContext);
    function AuthorizeRequest(AContext: TWebContext): Boolean;
    // Setters: not thread-safe, call them before the server starts handling requests
    procedure SetExpectedAzp(const AValue: string);
    procedure SetRequireAzpWhenMultipleAud(const AValue: Boolean);
    procedure SetAudienceValidationEnabled(const AValue: Boolean);
    procedure SetClaimsTransformer(const AValue: IIAM4DClaimsTransformer);
  end;

implementation

uses
  System.StrUtils,
  System.DateUtils,
  Web.HTTPApp,
  IAMClient4D.Common.Constants,
  IAMClient4D.DMVC.DTO,
  IAMClient4D.DMVC.Common,
  MVCFramework.Logger;

{ TIAM4DJWTMiddlewareConfig }

class operator TIAM4DJWTMiddlewareConfig.Initialize(out Dest: TIAM4DJWTMiddlewareConfig);
begin
  Dest.Issuer := '';
  Dest.Audience := '';
  Dest.AudienceValidationEnabled := True;
  Dest.JWKS_URL := '';
  Dest.JWKSCacheDurationMinutes := 60;
  Dest.ClockSkewSeconds := 60;
  Dest.TokenHeaderName := 'Authorization';
  Dest.TokenPrefix := 'Bearer ';
  Dest.SubjectClaimName := 'sub';
  Dest.RolesClaimName := 'roles';
  Dest.AllowAnonymous := False;
  Dest.SSLValidationMode := svmStrict;
  Dest.PinnedPublicKeys := nil;
  Dest.SSLValidator := nil;
  Dest.ExpectedAzp := '';
  Dest.RequireAzpWhenMultipleAud := True;
  Dest.HTTPConnectTimeoutMs := 10000;
  Dest.HTTPReceiveTimeoutMs := 15000;
  Dest.ExpectedTokenType := IAM4D_KEYCLOAK_TOKEN_TYPE_BEARER;
  Dest.AllowedHeaderTypes := ['JWT', 'at+jwt'];
  Dest.RejectedTokenWarningIntervalSec := 10;
  Dest.ClaimsTransformer := nil;
end;

class function TIAM4DJWTMiddlewareConfig.Create(const AIssuer, AAudience, AJWKS_URL: string): TIAM4DJWTMiddlewareConfig;
var
  LConfig: TIAM4DJWTMiddlewareConfig; // defaults from Initialize
begin
  LConfig.Issuer := AIssuer;
  LConfig.Audience := AAudience;
  LConfig.JWKS_URL := AJWKS_URL;
  Result := LConfig;
end;

{ TIAM4DJWTAuthenticator }

constructor TIAM4DJWTAuthenticator.Create(const AConfig: TIAM4DJWTMiddlewareConfig);
var
  LHTTPConfig: TIAM4DHTTPClientConfig;
  LJWKSProviderObj: TIAM4DJWKSProvider;
  LJWKSProvider: IIAM4DJWKSProvider;
  LValidatorObj: TIAM4DJWTValidator;
  LSSLValidator: IIAM4DSSLCertificateValidator;
begin
  inherited Create;
  FContextMarker := IntToHex(NativeUInt(Pointer(Self)), SizeOf(Pointer) * 2);

  // Keys are discovered for the configured issuer only: without it every token would be rejected
  if AConfig.Issuer.Trim.TrimRight(['/']).IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('TIAM4DJWTMiddlewareConfig.Issuer is required: ' +
      'set it to the issuer URL of the identity provider (e.g. https://keycloak.example.com/realms/myrealm).');

  if AConfig.TokenHeaderName.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('TIAM4DJWTMiddlewareConfig.TokenHeaderName is required ' +
      '(default ''Authorization'').');

  // Checked aud with no expected value: every token would be rejected
  if AConfig.AudienceValidationEnabled and AConfig.Audience.Trim.IsEmpty then
    RaiseAudienceRequired;

  FConfig := AConfig;
  FBuiltInValidator := True;

  LHTTPConfig := TIAM4DHTTPClientConfig.Create(
    FConfig.HTTPConnectTimeoutMs,
    FConfig.HTTPReceiveTimeoutMs,
    FConfig.SSLValidationMode);

  LSSLValidator := FConfig.SSLValidator;
  if Length(FConfig.PinnedPublicKeys) > 0 then
  begin
    if Assigned(LSSLValidator) then
      raise EIAM4DInvalidConfigurationException.Create('TIAM4DJWTMiddlewareConfig: PinnedPublicKeys and ' +
        'SSLValidator together; add the pins to the validator (AddPinnedPublicKeys).');
    LSSLValidator := TIAM4DSSLCertificateValidator.Create;
    try
      LSSLValidator.AddPinnedPublicKeys(FConfig.PinnedPublicKeys);
    except
      on E: EArgumentException do
        raise EIAM4DInvalidConfigurationException.Create('TIAM4DJWTMiddlewareConfig.PinnedPublicKeys: ' + E.Message);
    end;
  end;

  // The validator of discovery and JWKS (called as TIAM4DHTTPClientSSLHelper.IsCallbackNeeded says)
  if Assigned(LSSLValidator) then
    LJWKSProviderObj := TIAM4DJWKSProvider.Create(LHTTPConfig, LSSLValidator)
  else
    LJWKSProviderObj := TIAM4DJWKSProvider.Create(LHTTPConfig);
  LJWKSProvider := LJWKSProviderObj;

  if FConfig.JWKSCacheDurationMinutes > 0 then
    LJWKSProvider.SetCacheTTL(FConfig.JWKSCacheDurationMinutes * 60);

  // Explicit JWKS endpoint: no OIDC discovery
  if not FConfig.JWKS_URL.Trim.IsEmpty then
    LJWKSProviderObj.SetJWKSUri(FConfig.Issuer, FConfig.JWKS_URL);

  LValidatorObj := TIAM4DJWTValidator.Create(
    FConfig.Issuer,
    FConfig.Audience,
    LJWKSProvider,
    LHTTPConfig);
  FJWTValidator := LValidatorObj;
  LValidatorObj.SetExpectedTokenType(FConfig.ExpectedTokenType);
  try
    LValidatorObj.SetAllowedHeaderTypes(FConfig.AllowedHeaderTypes);
  except
    on E: EArgumentException do
      raise EIAM4DInvalidConfigurationException.Create('TIAM4DJWTMiddlewareConfig.AllowedHeaderTypes: ' + E.Message);
  end;

  FJWTValidator.ClockSkewSeconds := FConfig.ClockSkewSeconds;

  ConfigureValidatorOptions(False);

  LogI('JWT authentication initialized. Issuer=' + FConfig.Issuer + ' Audience=' + FConfig.Audience +
    IfThen(FConfig.JWKS_URL.Trim.IsEmpty, '', ' JWKS=' + FConfig.JWKS_URL.Trim) +
    IfThen(Length(FConfig.PinnedPublicKeys) = 0, '', Format(' PinnedPublicKeys=%d', [Length(FConfig.PinnedPublicKeys)])));
  LogRiskySettings(False);
end;

constructor TIAM4DJWTAuthenticator.Create(
  const AValidator: IIAM4DJWTValidator;
  const AConfig: TIAM4DJWTMiddlewareConfig);
begin
  inherited Create;
  FContextMarker := IntToHex(NativeUInt(Pointer(Self)), SizeOf(Pointer) * 2);

  if not Assigned(AValidator) then
    raise EIAM4DInvalidConfigurationException.Create('Custom validator cannot be nil. ' +
      'Create a validator instance using TIAM4DJWTValidator.Create() before passing it to the middleware.');

  // Referenced before any other check: a validator created in the call (TMyValidator.Create) has no
  // reference yet, and the destructor run by an exception releases it
  FJWTValidator := AValidator;

  if AConfig.TokenHeaderName.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('TIAM4DJWTMiddlewareConfig.TokenHeaderName is required ' +
      '(default ''Authorization'').');

  FConfig := AConfig;

  FJWTValidator.ClockSkewSeconds := FConfig.ClockSkewSeconds;

  // An azp already set on the validator is kept when the configuration has none
  ConfigureValidatorOptions(False);

  if not FConfig.JWKS_URL.Trim.IsEmpty then
    LogW('JWKS_URL is not used with a custom validator: configure the JWKS provider of the validator.');
  if (Length(FConfig.PinnedPublicKeys) > 0) or Assigned(FConfig.SSLValidator) then
    LogW('PinnedPublicKeys and SSLValidator are not used with a custom validator: give them to its JWKS provider.');

  LogI('JWT authentication initialized with custom validator. ' +
    'Issuer=' + FConfig.Issuer + ' Audience=' + FConfig.Audience);
  LogRiskySettings(True);
end;

procedure TIAM4DJWTAuthenticator.LogRiskySettings(ACustomValidator: Boolean);
begin
  if not FConfig.AudienceValidationEnabled then
    LogW('JWT audience validation is disabled: tokens issued for any client of the realm are accepted.')
  else if ACustomValidator and FConfig.Audience.Trim.IsEmpty then
    LogI('JWT Audience is empty in the configuration: the custom validator checks its own expected audience.');
  if FConfig.AllowAnonymous then
    LogI('JWT AllowAnonymous is on: requests without a token pass unauthenticated.');
  // The SSL settings reach only the validator built here
  if (not ACustomValidator) and (FConfig.SSLValidationMode = svmAllowSelfSigned) then
    LogW('JWT SSLValidationMode is svmAllowSelfSigned: discovery and JWKS accept any certificate (test only).');
end;

procedure TIAM4DJWTAuthenticator.LogRejected(const AMessage: string);
var
  LNow, LLast: Int64;
  LSuppressed: Integer;
begin
  if FConfig.RejectedTokenWarningIntervalSec <= 0 then
  begin
    LogW(AMessage);
    Exit;
  end;
  LNow := Int64(TThread.GetTickCount64);
  LLast := TInterlocked.Read(FLastRejectLogTick);
  if ((LLast = 0) or (LNow - LLast >= Int64(FConfig.RejectedTokenWarningIntervalSec) * 1000)) and
    (TInterlocked.CompareExchange(FLastRejectLogTick, LNow, LLast) = LLast) then
  begin
    LSuppressed := TInterlocked.Exchange(FSuppressedRejects, 0);
    if LSuppressed > 0 then
      LogW(Format('%s (%d more rejected since the last warning)', [AMessage, LSuppressed]))
    else
      LogW(AMessage);
  end
  else
  begin
    TInterlocked.Increment(FSuppressedRejects);
    LogD(AMessage);
  end;
end;

destructor TIAM4DJWTAuthenticator.Destroy;
begin
  FJWTValidator := nil;
  inherited;
end;

function TIAM4DJWTAuthenticator.GetConfig: TIAM4DJWTMiddlewareConfig;
begin
  Result := FConfig;
end;

procedure TIAM4DJWTAuthenticator.ConfigureValidatorOptions(AApplyEmptyAzp: Boolean);
var
  LConfigurable: IIAM4DJWTValidatorConfigurable;
begin
  if Supports(FJWTValidator, IIAM4DJWTValidatorConfigurable, LConfigurable) then
  begin
    LConfigurable.SetAudienceValidationEnabled(FConfig.AudienceValidationEnabled);
    if AApplyEmptyAzp or not FConfig.ExpectedAzp.Trim.IsEmpty then
      LConfigurable.SetExpectedAzp(FConfig.ExpectedAzp.Trim);
    LConfigurable.SetRequireAzpWhenMultipleAud(FConfig.RequireAzpWhenMultipleAud);
  end
  else
  begin
    LogW('Custom validator does not support advanced JWT claim configuration. Skipping audience/azp setup.');
  end;
end;

procedure TIAM4DJWTAuthenticator.SetExpectedAzp(const AValue: string);
begin
  FConfig.ExpectedAzp := AValue;
  // Explicit call: an empty value clears the azp check
  ConfigureValidatorOptions(True);
end;

procedure TIAM4DJWTAuthenticator.SetRequireAzpWhenMultipleAud(const AValue: Boolean);
begin
  FConfig.RequireAzpWhenMultipleAud := AValue;
  ConfigureValidatorOptions(False);
end;

class procedure TIAM4DJWTAuthenticator.RaiseAudienceRequired;
begin
  raise EIAM4DInvalidConfigurationException.Create('TIAM4DJWTMiddlewareConfig.Audience is required while ' +
    'AudienceValidationEnabled is True: set it to the client ID of this API (the aud of its tokens), or set ' +
    'AudienceValidationEnabled to False to accept the tokens of any client of the realm.');
end;

procedure TIAM4DJWTAuthenticator.SetAudienceValidationEnabled(const AValue: Boolean);
begin
  if AValue and FBuiltInValidator and FConfig.Audience.Trim.IsEmpty then
    RaiseAudienceRequired;
  FConfig.AudienceValidationEnabled := AValue;
  ConfigureValidatorOptions(False);
end;

procedure TIAM4DJWTAuthenticator.SetClaimsTransformer(const AValue: IIAM4DClaimsTransformer);
begin
  FConfig.ClaimsTransformer := AValue;
end;

function TIAM4DJWTAuthenticator.ExtractToken(AContext: TWebContext): string;
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

procedure TIAM4DJWTAuthenticator.ClearAuthenticationData(AContext: TWebContext);
begin
  // Another authenticator may have processed the request (middleware + endpoint filter):
  // never leave its claims next to a failed validation.
  AContext.Data.Remove(CONTEXT_KEY_JWT_CLAIMS);
  AContext.Data.Remove(CONTEXT_KEY_JWT_TOKEN);
  AContext.Data.Remove(CONTEXT_KEY_RETRY_AFTER);
end;

procedure TIAM4DJWTAuthenticator.HandleAuthenticationError(AContext: TWebContext; const AError, AMessage: string);
var
  LError: TJSONObject;
  LDescription: string;
begin
  LogD('Authentication failed: ' + AMessage);

  // RFC 6750 3.1: no error code when the request carries no bearer token
  if AError.IsEmpty then
    LDescription := ''
  else
    LDescription := AMessage;

  // TMVCWebResponse.SetCustomHeader works on every DMVC host (WebBroker, Indy Direct, HTTP.sys),
  // while RawWebResponse is available only under WebBroker.
  AContext.Response.SetCustomHeader('WWW-Authenticate',
    BearerChallenge(FConfig.Audience, AError, LDescription));

  LError := TJSONObject.Create;
  try
    LError.AddPair('error', 'unauthorized');
    LError.AddPair('message', AMessage);
    LError.AddPair('status', TJSONNumber.Create(HTTP_STATUS.Unauthorized));

    AContext.Response.StatusCode := HTTP_STATUS.Unauthorized;
    AContext.Response.ContentType := TMVCMediaType.APPLICATION_JSON;
    AContext.Response.Content := LError.ToJSON;
  finally
    LError.Free;
  end;
end;

procedure TIAM4DJWTAuthenticator.HandleUnavailable(AContext: TWebContext);
var
  LError: TJSONObject;
  LRetryAfter: string;
begin
  // The token was not judged: 503, the client may retry later with the same token
  LRetryAfter := AContext.Data[CONTEXT_KEY_RETRY_AFTER];
  if LRetryAfter <> '' then
    AContext.Response.SetCustomHeader('Retry-After', LRetryAfter);

  LError := TJSONObject.Create;
  try
    LError.AddPair('error', 'temporarily_unavailable');
    LError.AddPair('message', 'Token validation temporarily unavailable');
    LError.AddPair('status', TJSONNumber.Create(HTTP_STATUS.ServiceUnavailable));

    AContext.Response.StatusCode := HTTP_STATUS.ServiceUnavailable;
    AContext.Response.ContentType := TMVCMediaType.APPLICATION_JSON;
    AContext.Response.Content := LError.ToJSON;
  finally
    LError.Free;
  end;
end;

procedure TIAM4DJWTAuthenticator.PopulateContext(AContext: TWebContext; const AToken: string; AClaims: TJSONObject);
var
  LSubject: string;
  LStdClaims: TIAM4DJWTClaims;
  LKCClaims: TIAM4DKeycloakClaims;
  LUser: TMVCUser;
  LUserName: string;
  LRole: string;
  LClientID: string;
  LIndex: Integer;
  LRoleSet: TDictionary<string, Boolean>;
  LRolesValue, LItem: TJSONValue;

  procedure AddRole(const ARole: string);
  begin
    if (ARole <> '') and not LRoleSet.ContainsKey(ARole) then
      LRoleSet.Add(ARole, True);
  end;

begin
  AContext.Data[CONTEXT_KEY_JWT_CLAIMS] := AClaims.ToJSON;
  AContext.Data[CONTEXT_KEY_JWT_TOKEN] := AToken;

  LStdClaims := TIAM4DJWTClaims.ParseFromPayload(AClaims);
  LKCClaims := TIAM4DKeycloakClaims.ParseFromPayload(AClaims);

  // Subject: the configured claim (a key, not a JSON path: namespaced names have '.'), else "sub"
  LSubject := '';
  if FConfig.SubjectClaimName <> '' then
  begin
    LItem := AClaims.Values[FConfig.SubjectClaimName];
    if not (Assigned(LItem) and LItem.TryGetValue<string>(LSubject)) then
      LSubject := '';
  end;
  if LSubject.IsEmpty then
    LSubject := LStdClaims.Subject;

  LUser := AContext.LoggedUser;

  // TMVCUser.LoggedSince can be assigned only once: reset the user, which may have been
  // loaded from the session or populated by another authentication component.
  LUser.Clear;

  LUserName := LStdClaims.PreferredUsername;
  if LUserName.IsEmpty then
    LUserName := LStdClaims.Email;
  if LUserName.IsEmpty then
    LUserName := LSubject;

  LUser.UserName := LUserName;

  LUser.Realm := LStdClaims.AuthorizedParty;
  if LUser.Realm.IsEmpty then
    LUser.Realm := FConfig.Audience;

  // UTC, as the token times
  if LStdClaims.IssuedAtTime > 0 then
    LUser.LoggedSince := LStdClaims.IssuedAtTime
  else
    LUser.LoggedSince := TDateTime.NowUTC;

  // Case-sensitive, as Keycloak: "Admin" and "admin" are two roles
  LRoleSet := TDictionary<string, Boolean>.Create;
  try
    // Top-level roles claim (RolesClaimName): array of strings or a single string
    if FConfig.RolesClaimName <> '' then
    begin
      LRolesValue := AClaims.Values[FConfig.RolesClaimName];
      if LRolesValue is TJSONArray then
      begin
        for LItem in TJSONArray(LRolesValue) do
          if LItem is TJSONString then
            AddRole(TJSONString(LItem).Value);
      end
      else if LRolesValue is TJSONString then
        AddRole(TJSONString(LRolesValue).Value);
    end;

    for LRole in LKCClaims.RealmAccess.Roles do
      AddRole(LRole);

    // Client roles only of this API (Audience) and of the expected caller (ExpectedAzp):
    // a role of any other client must not satisfy RequireRole here
    for LIndex := 0 to High(LKCClaims.ResourceAccess) do
    begin
      LClientID := LKCClaims.ResourceAccess[LIndex].ClientID;
      if LClientID.IsEmpty or
         ((LClientID <> FConfig.Audience) and (LClientID <> FConfig.ExpectedAzp)) then
        Continue;
      for LRole in LKCClaims.ResourceAccess[LIndex].Roles do
        AddRole(LRole);
    end;

    for LRole in LRoleSet.Keys do
      LUser.Roles.Add(LRole);
  finally
    LRoleSet.Free;
  end;

  if not Assigned(LUser.CustomData) then
    LUser.CustomData := TMVCCustomData.Create
  else
    LUser.CustomData.Clear;

  if not LSubject.IsEmpty then
    LUser.CustomData.AddOrSetValue('sub', LSubject);
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

  // ISO 8601 in UTC (e.g. 2026-01-01T00:00:00.000Z), independent of the server locale
  if LStdClaims.ExpirationTime > 0 then
    LUser.CustomData.AddOrSetValue('exp', DateToISO8601(LStdClaims.ExpirationTime, True));
  if LStdClaims.IssuedAtTime > 0 then
    LUser.CustomData.AddOrSetValue('iat', DateToISO8601(LStdClaims.IssuedAtTime, True));
  if LStdClaims.AuthTime > 0 then
    LUser.CustomData.AddOrSetValue('auth_time', DateToISO8601(LStdClaims.AuthTime, True));

  if Length(LStdClaims.Scopes) > 0 then
    LUser.CustomData.AddOrSetValue('scopes', string.Join(',', LStdClaims.Scopes));

  if Length(LKCClaims.Groups) > 0 then
    LUser.CustomData.AddOrSetValue('groups', string.Join(',', LKCClaims.Groups));

  if IsDebugEnabled then
    LogD(Format('JWT validated. Subject="%s", Username="%s", Realm="%s", Roles=%d',
      [SanitizeLogText(LSubject), SanitizeLogText(LUserName), SanitizeLogText(LUser.Realm), LUser.Roles.Count]));
end;

procedure TIAM4DJWTAuthenticator.AuthenticateRequest(AContext: TWebContext);
var
  LToken: string;
  LClaims: TJSONObject;
  LPopulating, LTransforming: Boolean;
  LTransformer: IIAM4DClaimsTransformer;
begin
  // Middleware and endpoint filter sharing this authenticator: validate once per request
  if AContext.Data[CONTEXT_KEY_AUTHENTICATED_BY] = FContextMarker then
    Exit;

  ClearAuthenticationData(AContext);
  AContext.Data[CONTEXT_KEY_AUTHENTICATED_BY] := FContextMarker;
  AContext.Data[CONTEXT_KEY_REALM] := FConfig.Audience;
  AContext.Data[CONTEXT_KEY_AUTH_STATUS] := AUTH_STATUS_NOT_AUTHENTICATED;

  // No token present: mark as not authenticated but do NOT block.
  // The actual enforcement happens in AuthorizeRequest.
  LToken := ExtractToken(AContext);
  if LToken.IsEmpty then
    Exit;

  // A token was sent: invalid until validated
  AContext.Data[CONTEXT_KEY_AUTH_STATUS] := AUTH_STATUS_INVALID_TOKEN;
  LClaims := nil;
  LPopulating := False;
  LTransforming := False;
  try
    try
      if not FJWTValidator.ValidateToken(LToken, LClaims) then
      begin
        LogRejected('JWT rejected by the validator');
        Exit;
      end;

      // A (custom) validator accepting the token without its claims: no identity to publish,
      // the request cannot be authenticated
      if not Assigned(LClaims) then
      begin
        LogRejected('JWT validator returned no claims: token rejected');
        Exit;
      end;

      LPopulating := True;
      PopulateContext(AContext, LToken, LClaims);

      LTransformer := FConfig.ClaimsTransformer;
      if Assigned(LTransformer) then
      begin
        LTransforming := True;
        LTransformer.Transform(AContext, LClaims, AContext.LoggedUser);
      end;

      AContext.Data[CONTEXT_KEY_AUTH_STATUS] := AUTH_STATUS_AUTHENTICATED;
    except
      on E: Exception do
      begin
        ClearAuthenticationData(AContext);
        if LPopulating then
        begin
          // TMVCUser.Clear keeps CustomData: a public action must not see sub, email, iss
          // of a token that did not authenticate the request
          AContext.LoggedUser.Clear;
          if Assigned(AContext.LoggedUser.CustomData) then
            AContext.LoggedUser.CustomData.Clear;
        end;

        if LTransforming then
        begin
          // Valid token, the application data (e.g. roles database) is not available: 503
          LogE('Claims transformation failed [' + E.ClassName + ']: ' + SanitizeLogText(E.Message));
          AContext.Data[CONTEXT_KEY_AUTH_STATUS] := AUTH_STATUS_UNAVAILABLE;
        end
        else if E is EIAM4DJWKSUnavailableException then
        begin
          // Infrastructure failure, not the token: 503
          LogE('JWT validation unavailable [' + E.ClassName + ']: ' + SanitizeLogText(E.Message));
          AContext.Data[CONTEXT_KEY_AUTH_STATUS] := AUTH_STATUS_UNAVAILABLE;
          if EIAM4DJWKSUnavailableException(E).RetryAfterSeconds > 0 then
            AContext.Data[CONTEXT_KEY_RETRY_AFTER] := IntToStr(EIAM4DJWKSUnavailableException(E).RetryAfterSeconds);
        end
        else if E is EIAM4DSecurityValidationException then
          // Expected traffic; the reason may carry text chosen by the client (iss, alg, kid)
          LogRejected('JWT rejected [' + E.ClassName + ']: ' + SanitizeLogText(E.Message))
        else
          LogE('Unexpected JWT validation error [' + E.ClassName + ']: ' + SanitizeLogText(E.Message));
      end;
    end;
  finally
    LClaims.Free;
  end;
end;

function TIAM4DJWTAuthenticator.AuthorizeRequest(AContext: TWebContext): Boolean;
var
  LStatus: string;
begin
  // No exemption for OPTIONS: an action without [MVCHTTPMethod] answers it too.
  // CORS preflight is answered earlier by CORSHTTPFilter or TMVCCORSMiddleware (before routing).
  LStatus := AContext.Data[CONTEXT_KEY_AUTH_STATUS];
  if LStatus = AUTH_STATUS_AUTHENTICATED then
    Exit(True);

  Result := False;
  if LStatus = AUTH_STATUS_UNAVAILABLE then
    HandleUnavailable(AContext)
  else if LStatus = AUTH_STATUS_INVALID_TOKEN then
    // Also with AllowAnonymous: a token that fails validation is always rejected
    HandleAuthenticationError(AContext, 'invalid_token', 'Invalid or expired JWT token')
  else if FConfig.AllowAnonymous then
    Result := True
  else
    HandleAuthenticationError(AContext, '', 'Missing or invalid Authorization header');
end;
end.
