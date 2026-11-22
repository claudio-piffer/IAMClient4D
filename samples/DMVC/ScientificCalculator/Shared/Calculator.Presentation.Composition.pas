unit Calculator.Presentation.Composition;

{ Composition root shared by both servers: the only place that knows every
  layer. It wires the infrastructure into the use cases (DI container) and
  sets up the engine pieces both servers have in common. }

interface

uses
  MVCFramework,
  IAMClient4D.DMVC.Authenticator,
  Calculator.Presentation.Settings;

/// <summary>Reads the configuration; call it first.</summary>
procedure LoadSettings(const APortKey: string; const ADefaultPort: Integer);
function Settings: TCalculatorSettings;

/// <summary>ICalculatorService in the DMVC service container.</summary>
procedure RegisterCalculatorServices;

type
  /// <summary>Where the bearer token is checked.</summary>
  TCalculatorProtection = (
    /// <summary>AEngine.Use(IAM4DJWTBundle): every controller action and Minimal API
    /// route; [IAM4DPublic] controllers stay public.</summary>
    cpEngine,
    /// <summary>Only the route groups that use IAM4DJWTEndpointFilter(Result):
    /// a Minimal API server with a public group.</summary>
    cpRouteGroups);

/// <summary>
/// Error mapping, CORS, IAMClient4D JWT filters, OpenAPI document and Swagger UI.
/// Returns the authenticator (validator and JWKS cache of the realm): with
/// cpRouteGroups pass it to IAM4DJWTEndpointFilter on the protected groups.
/// </summary>
function ConfigureCalculatorEngine(const AEngine: TMVCEngine; const ATitle: string;
  const AProtection: TCalculatorProtection): IIAM4DJWTAuthenticator;

implementation

uses
  System.SysUtils,
  MVCFramework.Commons,
  MVCFramework.Container,
  MVCFramework.Serializer.Commons,
  MVCFramework.Filters,
  MVCFramework.Filters.OpenAPI,
  MVCFramework.OpenAPI3,
  IAMClient4D.DMVC.Filters,
  Calculator.Application.Ports,
  Calculator.Application.UseCases,
  Calculator.Infrastructure.History,
  Calculator.Presentation.Errors,
  Calculator.Presentation.SwaggerUI;

var
  GSettings: TCalculatorSettings;
  GSettingsLoaded: Boolean;

procedure LoadSettings(const APortKey: string; const ADefaultPort: Integer);
begin
  GSettings := TCalculatorSettings.Load(APortKey, ADefaultPort);
  GSettingsLoaded := True;
end;

function Settings: TCalculatorSettings;
begin
  if not GSettingsLoaded then
    raise EInvalidOpException.Create('LoadSettings has not been called');
  Result := GSettings;
end;

procedure RegisterCalculatorServices;
var
  LHistory: ICalculationHistory;
  LClock: IClock;
begin
  LHistory := TInMemoryCalculationHistory.Create;
  LClock := TSystemClock.Create;
  DefaultMVCServiceContainer.RegisterType(
    function: TInterfacedObject
    begin
      Result := TCalculatorService.Create(LHistory, LClock);
    end,
    ICalculatorService, TRegistrationType.Singleton);
  DefaultMVCServiceContainer.Build;
end;

function ConfigureCalculatorEngine(const AEngine: TMVCEngine; const ATitle: string;
  const AProtection: TCalculatorProtection): IIAM4DJWTAuthenticator;
var
  LInfo: TMVCOpenAPIInfo;
  LConfig: TIAM4DJWTMiddlewareConfig;
begin
  // DTOs stay free of serialization attributes
  MVCNameCaseDefault := TMVCNameCase.ncCamelCase;

  // ECalculatorDomainError -> 422 problem+json
  UseCalculatorErrorHandling(AEngine);

  LInfo := Default(TMVCOpenAPIInfo);
  LInfo.Title := ATitle;
  LInfo.Version := '1.0';
  LInfo.Description := 'Scientific calculator secured by IAMClient4D and Keycloak. ' +
    'Get an access token for the "' + Settings.Audience + '" audience from ' + Settings.Issuer +
    ' and paste it in "Authorize". Roles: calculator-user, calculator-advanced.';
  LInfo.LicenseName := 'Apache-2.0';

  // First: CORS answers the preflight before any token is asked. A browser client reads the
  // challenge of a 401/403 and the delay of a 503 only through the exposed headers
  AEngine.Use(CORSHTTPFilter(Settings.CorsOrigins, False, 'WWW-Authenticate,Retry-After'));

  // Validates the bearer token (issuer, audience, signature through the realm JWKS)
  LConfig := TIAM4DJWTMiddlewareConfig.Create(Settings.Issuer, Settings.Audience, '');
  LConfig.SSLValidationMode := Settings.SSLValidationMode;
  Result := TIAM4DJWTAuthenticator.Create(LConfig);

  // Before OpenAPIHTTPFilter: the bearer scheme is added to the document on the way out
  if AProtection = cpEngine then
    AEngine.Use(IAM4DJWTBundle(Result))
  else
    AEngine.Use(IAM4DSwaggerSecurityHTTPFilter());

  // Answer before routing: the token check (an endpoint filter) does not apply to them
  AEngine.Use(SwaggerUIHTTPFilter(ATitle, OPENAPI_URL, SWAGGER_UI_PATH));
  AEngine.Use(OpenAPIHTTPFilter(AEngine, LInfo, OPENAPI_URL));
end;

end.
