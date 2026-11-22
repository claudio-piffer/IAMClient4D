{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.DMVC.Filters.pas
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

unit IAMClient4D.DMVC.Filters;

interface

uses
  MVCFramework,
  MVCFramework.MinimalAPI,
  IAMClient4D.Common.Security,
  IAMClient4D.DMVC.Authenticator;

/// <summary>
/// IAMClient4D JWT authentication as a DMVC filter bundle: the check of the bearer token
/// (endpoint filter, IAM4DJWTEndpointFilter) and the bearer scheme in the Swagger/OpenAPI
/// documents (HTTP filter, IAM4DSwaggerSecurityHTTPFilter).
/// </summary>
/// <remarks>
/// Engine-wide, in ConfigureEngine, it protects every controller action and every Minimal API route:
///   AEngine.Use(CORSHTTPFilter('https://app.example.com', False,
///     'WWW-Authenticate,Retry-After'));                      // first: answers the preflight
///   AEngine.Use(IAM4DJWTBundle(LConfig));                    // before SwaggerHTTPFilter
///   AEngine.Use(SwaggerHTTPFilter(...));
/// A controller action (or controller) marked [IAM4DPublic] is public. A Minimal API route under
/// the engine-wide bundle always requires a token, as with the DMVC authentication bundles:
/// to keep some Minimal API routes public, put the bundle on the protected groups instead
///   LApi := AEngine.Prefix('/api').Use(IAM4DJWTBundle(LConfig));
/// and keep the public routes in a group without it. A bundle is registered once: the same
/// bundle on the engine and on a group raises EMVCConfigException. The HTTP part of a bundle
/// on a group is added to the engine after the filters of ConfigureEngine, so it does not see the
/// documents of SwaggerHTTPFilter: register IAM4DSwaggerSecurityHTTPFilter() in ConfigureEngine.
/// Answers: 401 with a WWW-Authenticate challenge (RFC 6750), 503 with Retry-After when the
/// identity provider or the claims transformer is unavailable.
/// </remarks>
function IAM4DJWTBundle(const AConfig: TIAM4DJWTMiddlewareConfig): IMVCFilterBundle; overload;

/// <summary>
/// Creates the bundle with auto-discovery from the issuer.
/// </summary>
function IAM4DJWTBundle(const AIssuer, AAudience: string;
  const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict;
  const AExpectedAzp: string = ''): IMVCFilterBundle; overload;

/// <summary>
/// Creates the bundle on an existing authenticator (TIAM4DJWTAuthenticator, or a custom one),
/// e.g. to share validator and JWKS cache with other filters.
/// </summary>
function IAM4DJWTBundle(const AAuthenticator: IIAM4DJWTAuthenticator): IMVCFilterBundle; overload;

/// <summary>
/// DMVC endpoint filter enforcing IAMClient4D JWT authentication: the check part of IAM4DJWTBundle.
/// Same validation, claims mapping (Context.JWT, Context.Keycloak, Context.LoggedUser)
/// and 401/503 responses.
/// </summary>
/// <remarks>
/// On a Minimal API route group:  LEngine.Prefix('/api').Use(IAM4DJWTEndpointFilter(LConfig)).MapGet(...);
/// Engine-wide (AEngine.Use) it also checks every controller action; [IAM4DPublic] actions pass.
/// Prefer IAM4DJWTBundle, which also documents the bearer scheme in Swagger/OpenAPI.
/// </remarks>
function IAM4DJWTEndpointFilter(const AConfig: TIAM4DJWTMiddlewareConfig): TMVCEndpointFilter; overload;

/// <summary>
/// Creates the endpoint filter with auto-discovery from the issuer.
/// </summary>
function IAM4DJWTEndpointFilter(const AIssuer, AAudience: string;
  const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict;
  const AExpectedAzp: string = ''): TMVCEndpointFilter; overload;

/// <summary>
/// Creates the endpoint filter on an existing authenticator, to share validator and JWKS cache
/// between filters (e.g. several route groups, or TIAM4DJWTMiddleware.Authenticator).
/// </summary>
function IAM4DJWTEndpointFilter(const AAuthenticator: IIAM4DJWTAuthenticator): TMVCEndpointFilter; overload;

/// <summary>
/// HTTP filter adding the bearer security scheme and the global security requirement to the
/// Swagger 2.0 / OpenAPI 3 JSON documents (GET of a path containing swagger, openapi or api-docs
/// and ending in .json). Part of IAM4DJWTBundle; register it before SwaggerHTTPFilter.
/// </summary>
function IAM4DSwaggerSecurityHTTPFilter: TMVCHTTPFilter;

implementation

uses
  IAMClient4D.Exceptions,
  IAMClient4D.DMVC.Internal;

function IAM4DJWTBundle(const AConfig: TIAM4DJWTMiddlewareConfig): IMVCFilterBundle;
var
  LAuthenticator: IIAM4DJWTAuthenticator;
begin
  LAuthenticator := TIAM4DJWTAuthenticator.Create(AConfig);
  Result := IAM4DJWTBundle(LAuthenticator);
end;

function IAM4DJWTBundle(const AIssuer, AAudience: string;
  const ASSLValidationMode: TIAM4DSSLValidationMode;
  const AExpectedAzp: string): IMVCFilterBundle;
var
  LConfig: TIAM4DJWTMiddlewareConfig;
begin
  LConfig := TIAM4DJWTMiddlewareConfig.Create(AIssuer, AAudience, '');
  LConfig.SSLValidationMode := ASSLValidationMode;
  LConfig.ExpectedAzp := AExpectedAzp;
  Result := IAM4DJWTBundle(LConfig);
end;

function IAM4DJWTBundle(const AAuthenticator: IIAM4DJWTAuthenticator): IMVCFilterBundle;
var
  LHTTPFilter: TMVCHTTPFilter;
  LEndpointFilter: TMVCEndpointFilter;
begin
  if not Assigned(AAuthenticator) then
    raise EIAM4DInvalidConfigurationException.Create('IAM4DJWTBundle: authenticator cannot be nil.');

  LHTTPFilter := IAM4DSwaggerSecurityHTTPFilter();
  LEndpointFilter := IAM4DJWTEndpointFilter(AAuthenticator);
  // Casts: inside [...] a filter held in a variable would be called instead of passed
  Result := TMVCFilterBundle.Create([TMVCHTTPFilter(LHTTPFilter)], [TMVCEndpointFilter(LEndpointFilter)]);
end;

function IAM4DJWTEndpointFilter(const AConfig: TIAM4DJWTMiddlewareConfig): TMVCEndpointFilter;
var
  LAuthenticator: IIAM4DJWTAuthenticator;
begin
  LAuthenticator := TIAM4DJWTAuthenticator.Create(AConfig);
  Result := IAM4DJWTEndpointFilter(LAuthenticator);
end;

function IAM4DJWTEndpointFilter(const AIssuer, AAudience: string;
  const ASSLValidationMode: TIAM4DSSLValidationMode;
  const AExpectedAzp: string): TMVCEndpointFilter;
var
  LConfig: TIAM4DJWTMiddlewareConfig;
begin
  LConfig := TIAM4DJWTMiddlewareConfig.Create(AIssuer, AAudience, '');
  LConfig.SSLValidationMode := ASSLValidationMode;
  LConfig.ExpectedAzp := AExpectedAzp;
  Result := IAM4DJWTEndpointFilter(LConfig);
end;

function IAM4DJWTEndpointFilter(const AAuthenticator: IIAM4DJWTAuthenticator): TMVCEndpointFilter;
var
  LAuthenticator: IIAM4DJWTAuthenticator;
  LPublicActions: IIAM4DPublicActionCache;
begin
  if not Assigned(AAuthenticator) then
    raise EIAM4DInvalidConfigurationException.Create('IAM4DJWTEndpointFilter: authenticator cannot be nil.');

  LAuthenticator := AAuthenticator;
  LPublicActions := NewIAM4DPublicActionCache;
  Result :=
    function(const AContext: TWebContext; const ANext: TMVCEndpointFilterNext): IMVCResponse
    begin
      // Always authenticate: a public action still sees LoggedUser when a valid token is sent
      LAuthenticator.AuthenticateRequest(AContext);

      // Controller action marked [IAM4DPublic]. A Minimal API route has no controller
      // (empty class name): it is always checked
      if (AContext.ControllerQualifiedClassName <> '') and
        LPublicActions.IsPublic(AContext.ControllerQualifiedClassName, AContext.ActionName) then
        Exit(ANext());

      // 401 or 503 already written on AContext.Response: nil, nothing more to render.
      // Its application/json survives an action with a different [MVCProduces]: the content
      // type of a controller is the one of Context.Response (TMVCRenderer.GetContentType).
      // Returning an IMVCResponse instead would wrap the body ({"data":...}, {"message":...})
      if not LAuthenticator.AuthorizeRequest(AContext) then
        Exit(nil);
      Result := ANext();
    end;
end;

function IAM4DSwaggerSecurityHTTPFilter: TMVCHTTPFilter;
begin
  Result :=
    procedure(const AContext: TWebContext; const ANext: TMVCHTTPFilterNext)
    begin
      // The document exists only after the inner filters (SwaggerHTTPFilter) have run
      ANext();
      IAM4DInjectSwaggerSecurityInResponse(AContext);
    end;
end;

end.
