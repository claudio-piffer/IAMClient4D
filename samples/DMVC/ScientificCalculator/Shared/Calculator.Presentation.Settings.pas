unit Calculator.Presentation.Settings;

{ Presentation layer, shared by both servers: configuration read through
  DMVC dotEnv (environment variables, or a .env file next to the executable). }

interface

uses
  IAMClient4D.Common.Security;

type
  TCalculatorSettings = record
    /// <summary>Keycloak realm URL (IAM4D_ISSUER).</summary>
    Issuer: string;
    /// <summary>Client whose roles the API checks (IAM4D_AUDIENCE).</summary>
    Audience: string;
    /// <summary>Accept a self-signed Keycloak certificate (IAM4D_ALLOW_SELF_SIGNED).</summary>
    AllowSelfSigned: Boolean;
    /// <summary>Allowed CORS origins, comma separated (CALC_CORS_ORIGINS).</summary>
    CorsOrigins: string;
    Port: Integer;
    class function Load(const APortKey: string; const ADefaultPort: Integer): TCalculatorSettings; static;
    function SSLValidationMode: TIAM4DSSLValidationMode;
  end;

  /// <summary>Public description of the service (GET /api/info).</summary>
  TServiceInfo = class
  private
    FName: string;
    FStyle: string;
    FIssuer: string;
    FAudience: string;
    FOpenAPI: string;
    FSwaggerUI: string;
    FRoles: TArray<string>;
  public
    constructor Create(const ASettings: TCalculatorSettings; const AStyle: string); reintroduce;
    property Name: string read FName write FName;
    /// <summary>controllers or minimal-api.</summary>
    property Style: string read FStyle write FStyle;
    /// <summary>Where to get a token.</summary>
    property Issuer: string read FIssuer write FIssuer;
    /// <summary>Client whose roles are checked.</summary>
    property Audience: string read FAudience write FAudience;
    property OpenAPI: string read FOpenAPI write FOpenAPI;
    property SwaggerUI: string read FSwaggerUI write FSwaggerUI;
    property Roles: TArray<string> read FRoles write FRoles;
  end;

const
  OPENAPI_URL = '/openapi.json';
  SWAGGER_UI_PATH = '/swagger';

implementation

uses
  System.SysUtils,
  MVCFramework.Commons,
  Calculator.Presentation.Security;

const
  // The Keycloak of Docker/ (start.cmd): override it with IAM4D_ISSUER
  DEFAULT_ISSUER = 'http://localhost:18180/auth/realms/iamclient4d';
  DEFAULT_AUDIENCE = 'api-server';

class function TCalculatorSettings.Load(const APortKey: string; const ADefaultPort: Integer): TCalculatorSettings;
begin
  Result.Issuer := dotEnv.Env('IAM4D_ISSUER', DEFAULT_ISSUER).TrimRight(['/']);
  Result.Audience := dotEnv.Env('IAM4D_AUDIENCE', DEFAULT_AUDIENCE);
  Result.AllowSelfSigned := dotEnv.Env('IAM4D_ALLOW_SELF_SIGNED', True);
  Result.CorsOrigins := dotEnv.Env('CALC_CORS_ORIGINS', '*');
  Result.Port := dotEnv.Env(APortKey, ADefaultPort);
end;

function TCalculatorSettings.SSLValidationMode: TIAM4DSSLValidationMode;
begin
  if AllowSelfSigned then
    Result := svmAllowSelfSigned
  else
    Result := svmStrict;
end;

{ TServiceInfo }

constructor TServiceInfo.Create(const ASettings: TCalculatorSettings; const AStyle: string);
begin
  inherited Create;
  FName := 'IAMClient4D Scientific Calculator';
  FStyle := AStyle;
  FIssuer := ASettings.Issuer;
  FAudience := ASettings.Audience;
  FOpenAPI := OPENAPI_URL;
  FSwaggerUI := SWAGGER_UI_PATH;
  FRoles := [ROLE_CALCULATOR_USER, ROLE_CALCULATOR_ADVANCED];
end;

end.
