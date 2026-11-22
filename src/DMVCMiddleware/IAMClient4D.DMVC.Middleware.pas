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

{$WARN SYMBOL_DEPRECATED OFF} // the class is deprecated for its users, not inside its own unit

interface

uses
  MVCFramework,
  IAMClient4D.Security.Core,
  IAMClient4D.Common.Security,
  IAMClient4D.DMVC.ClaimsTransformation,
  IAMClient4D.DMVC.Internal,
  IAMClient4D.DMVC.Authenticator;

type
  // Declared in IAMClient4D.DMVC.Authenticator: the aliases keep the code that uses this unit compiling
  TIAM4DJWTMiddlewareConfig = IAMClient4D.DMVC.Authenticator.TIAM4DJWTMiddlewareConfig;
  IIAM4DJWTAuthenticator = IAMClient4D.DMVC.Authenticator.IIAM4DJWTAuthenticator;
  TIAM4DJWTAuthenticator = IAMClient4D.DMVC.Authenticator.TIAM4DJWTAuthenticator;

  /// <summary>
  /// DMVC classic middleware for JWT authentication and authorization.
  /// </summary>
  /// <remarks>
  /// Deprecated, as every DMVC classic middleware in DMVC 3.5 (removed in DMVC 4): use
  /// AEngine.Use(IAM4DJWTBundle(...)) of IAMClient4D.DMVC.Filters, which also protects the
  /// Minimal API routes. Same checks and answers: this class runs the code of the filters.
  /// Protects controller-based routes only. Minimal API routes (MapGet, MapPost, ...) are dispatched
  /// before controller routing and never reach OnBeforeControllerAction.
  /// </remarks>
  TIAM4DJWTMiddleware = class(TInterfacedObject, IMVCMiddleware)
  private
    FAuthenticator: IIAM4DJWTAuthenticator;
    FPublicActions: IIAM4DPublicActionCache;
  protected
    procedure OnBeforeRouting(AContext: TWebContext; var AHandled: Boolean);
    procedure OnBeforeControllerAction(AContext: TWebContext; const AControllerQualifiedClassName, AActionName: string; var AHandled: Boolean);
    procedure OnAfterControllerAction(AContext: TWebContext; const AControllerQualifiedClassName, AActionName: string; const AHandled: Boolean);
    procedure OnAfterRouting(AContext: TWebContext; const AHandled: Boolean);
  public
    /// <summary>
    /// Creates middleware with configuration. Uses JWKS Provider with auto-discovery for the Issuer (required).
    /// </summary>
    constructor Create(const AConfig: TIAM4DJWTMiddlewareConfig); overload;

    /// <summary>
    /// Creates middleware with issuer (required), audience, and optional JWKS URL. Uses auto-discovery.
    /// </summary>
    constructor Create(const AIssuer, AAudience, AJWKS_URL: string; const AExpectedAzp: string = ''); overload;

    /// <summary>
    /// Creates middleware with auto-discovery. Recommended for production use with OIDC providers.
    /// Uses a dedicated TIAM4DJWKSProvider instance for isolated configuration.
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
    /// - JWKS is handled by the validator (JWKS_URL and HTTP settings of AConfig are not used)
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
    /// Not thread-safe, as every setter of this class: call it before the server starts handling requests.
    /// </summary>
    procedure SetExpectedAzp(const AValue: string);

    /// <summary>
    /// Configures whether azp is required when audience contains multiple values (default: True for OIDC compliance).
    /// Set it before the server starts handling requests.
    /// </summary>
    procedure SetRequireAzpWhenMultipleAud(const AValue: Boolean);

    /// <summary>
    /// Enables/disables audience (aud) validation on the underlying validator.
    /// Set it before the server starts handling requests.
    /// </summary>
    procedure SetAudienceValidationEnabled(const AValue: Boolean);

    /// <summary>
    /// Sets the claims transformer of the authenticator (see IIAM4DClaimsTransformer).
    /// Set it before the server starts handling requests.
    /// </summary>
    procedure SetClaimsTransformer(const AValue: IIAM4DClaimsTransformer);

    /// <summary>
    /// Authentication core used by this middleware. Pass it to IAM4DJWTEndpointFilter() to protect
    /// Minimal API route groups with the same validator and JWKS cache.
    /// </summary>
    property Authenticator: IIAM4DJWTAuthenticator read FAuthenticator;
  end deprecated 'Use the IAMClient4D JWT filter bundle (IAMClient4D.DMVC.Filters): AEngine.Use(IAM4DJWTBundle(...))';

implementation

{ TIAM4DJWTMiddleware }

constructor TIAM4DJWTMiddleware.Create(const AConfig: TIAM4DJWTMiddlewareConfig);
begin
  inherited Create;
  FPublicActions := NewIAM4DPublicActionCache;
  FAuthenticator := TIAM4DJWTAuthenticator.Create(AConfig);
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
begin
  LConfig := TIAM4DJWTMiddlewareConfig.Create(AIssuer, AAudience, '');
  LConfig.SSLValidationMode := ASSLValidationMode;
  LConfig.ExpectedAzp := AExpectedAzp;
  Create(LConfig);
end;

constructor TIAM4DJWTMiddleware.Create(
  const AValidator: IIAM4DJWTValidator;
  const AConfig: TIAM4DJWTMiddlewareConfig);
begin
  inherited Create;
  FPublicActions := NewIAM4DPublicActionCache;
  FAuthenticator := TIAM4DJWTAuthenticator.Create(AValidator, AConfig);
end;

destructor TIAM4DJWTMiddleware.Destroy;
begin
  FAuthenticator := nil;
  FPublicActions := nil;
  inherited;
end;

procedure TIAM4DJWTMiddleware.SetExpectedAzp(const AValue: string);
begin
  FAuthenticator.SetExpectedAzp(AValue);
end;

procedure TIAM4DJWTMiddleware.SetRequireAzpWhenMultipleAud(const AValue: Boolean);
begin
  FAuthenticator.SetRequireAzpWhenMultipleAud(AValue);
end;

procedure TIAM4DJWTMiddleware.SetAudienceValidationEnabled(const AValue: Boolean);
begin
  FAuthenticator.SetAudienceValidationEnabled(AValue);
end;

procedure TIAM4DJWTMiddleware.SetClaimsTransformer(const AValue: IIAM4DClaimsTransformer);
begin
  FAuthenticator.SetClaimsTransformer(AValue);
end;

procedure TIAM4DJWTMiddleware.OnBeforeRouting(AContext: TWebContext; var AHandled: Boolean);
begin
  FAuthenticator.AuthenticateRequest(AContext);
end;

procedure TIAM4DJWTMiddleware.OnBeforeControllerAction(AContext: TWebContext; const AControllerQualifiedClassName, AActionName: string; var AHandled: Boolean);
begin
  // Public endpoints bypass authentication.
  // Swagger/OpenAPI documents are served by middleware in OnBeforeRouting and never get here:
  // a controller serving its own document must be marked [IAM4DPublic].
  if FPublicActions.IsPublic(AControllerQualifiedClassName, AActionName) then
    Exit;

  if not FAuthenticator.AuthorizeRequest(AContext) then
    AHandled := True;
end;

procedure TIAM4DJWTMiddleware.OnAfterControllerAction(AContext: TWebContext; const AControllerQualifiedClassName, AActionName: string; const AHandled: Boolean);
begin
  //don't remove
end;

procedure TIAM4DJWTMiddleware.OnAfterRouting(AContext: TWebContext; const AHandled: Boolean);
begin
  IAM4DInjectSwaggerSecurityInResponse(AContext);
end;

end.
